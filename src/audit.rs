//! Turning a decoded module into findings.
//!
//! Two kinds of finding come out of here. Import findings say what the host
//! would have to grant for the module to instantiate at all, grouped by rule
//! so that twenty filesystem calls read as one capability rather than twenty
//! lines. Posture findings cover what the module hands back to the host and
//! what its memory and table declarations permit — an exported memory, a
//! mutable global the host can write, a memory with no ceiling, a start
//! function that runs before the host does anything.

use crate::capability::{Basis, Capability, Severity};
use crate::classify::{classify_import, detect_environments, HostEnvironment};
use crate::instr::CodeStats;
use crate::module::{ExternKind, Features, ImportDesc, Module};

/// One reported observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub capability: Option<Capability>,
    pub severity: Severity,
    pub basis: Basis,
    pub rationale: String,
    /// The specific names, counts or values the rule fired on. Sorted, so two
    /// runs over the same bytes produce byte-identical output.
    pub evidence: Vec<String>,
}

/// A memory as it will exist at run time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryView {
    pub imported: bool,
    pub min_pages: u64,
    pub max_pages: Option<u64>,
    pub shared: bool,
    pub index64: bool,
}

/// A table as it will exist at run time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableView {
    pub imported: bool,
    pub element: &'static str,
    pub min: u64,
    pub max: Option<u64>,
}

/// One import, as listed in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportView {
    pub module: String,
    pub name: String,
    pub kind: &'static str,
    pub capabilities: Vec<Capability>,
    pub rules: Vec<&'static str>,
}

/// One export, as listed in the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportView {
    pub name: String,
    pub kind: &'static str,
    pub index: u32,
    /// For a global export: whether the global is mutable. `None` when the
    /// index could not be resolved, which is itself worth seeing.
    pub mutable: Option<bool>,
}

/// Everything the auditor has to say about one module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub source: String,
    pub size_bytes: usize,
    pub environments: Vec<HostEnvironment>,
    /// The union of capabilities the import list asks for, in a stable order.
    pub capabilities: Vec<Capability>,
    pub findings: Vec<Finding>,
    pub imports: Vec<ImportView>,
    pub exports: Vec<ExportView>,
    pub memories: Vec<MemoryView>,
    pub tables: Vec<TableView>,
    pub start_function: Option<u32>,
    pub code: CodeStats,
    pub code_scanned: bool,
    pub features: Features,
    pub function_count: usize,
    pub type_count: usize,
    pub global_count: usize,
    pub element_segments: usize,
    pub data_segments: usize,
    pub custom_sections: Vec<(String, usize)>,
}

impl Report {
    /// The highest severity present, or `None` for a module with no findings.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Findings at or above a severity.
    pub fn findings_at_least(&self, min: Severity) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.severity >= min)
    }

    /// True when any finding reports an unidentified import.
    pub fn has_unknown_imports(&self) -> bool {
        self.capabilities.contains(&Capability::Unknown)
    }

    /// True when a memory is exported.
    pub fn exports_memory(&self) -> bool {
        self.exports.iter().any(|e| e.kind == "memory")
    }

    /// True when a mutable global is exported.
    pub fn exports_mutable_global(&self) -> bool {
        self.exports
            .iter()
            .any(|e| e.kind == "global" && e.mutable == Some(true))
    }

    /// Highest declared memory maximum, in pages; `None` when any memory is
    /// unbounded.
    pub fn memory_ceiling_pages(&self) -> Option<u64> {
        if self.memories.is_empty() {
            return Some(0);
        }
        let mut total = 0u64;
        for m in &self.memories {
            total = total.saturating_add(m.max_pages?);
        }
        Some(total)
    }
}

fn resolve_global_mutability(m: &Module, index: u32) -> Option<bool> {
    let imported: Vec<bool> = m
        .imports
        .iter()
        .filter_map(|i| match &i.desc {
            ImportDesc::Global(g) => Some(g.mutable),
            _ => None,
        })
        .collect();
    let idx = index as usize;
    if idx < imported.len() {
        return Some(imported[idx]);
    }
    m.globals.get(idx - imported.len()).map(|g| g.ty.mutable)
}

/// Audit a decoded module.
pub fn audit(module: &Module, source: &str, size_bytes: usize) -> Report {
    let mut findings: Vec<Finding> = Vec::new();
    let mut capabilities: Vec<Capability> = Vec::new();

    // --- imports -------------------------------------------------------
    // Group hits by rule so that a module with forty WASI filesystem calls
    // produces one filesystem finding listing forty names.
    let mut grouped: Vec<(crate::classify::Hit, Vec<String>)> = Vec::new();
    let mut imports: Vec<ImportView> = Vec::new();
    for imp in &module.imports {
        let hits = classify_import(imp);
        let mut caps: Vec<Capability> = hits.iter().map(|h| h.capability).collect();
        caps.sort();
        caps.dedup();
        let mut rules: Vec<&'static str> = hits.iter().map(|h| h.rule).collect();
        rules.sort_unstable();
        rules.dedup();
        imports.push(ImportView {
            module: imp.module.clone(),
            name: imp.name.clone(),
            kind: imp.desc.kind_name(),
            capabilities: caps,
            rules,
        });
        for h in hits {
            if !capabilities.contains(&h.capability) {
                capabilities.push(h.capability);
            }
            match grouped.iter_mut().find(|(g, _)| g.rule == h.rule) {
                Some((_, ev)) => ev.push(imp.qualified()),
                None => grouped.push((h, vec![imp.qualified()])),
            }
        }
    }
    for (h, mut evidence) in grouped {
        evidence.sort();
        evidence.dedup();
        findings.push(Finding {
            rule: h.rule,
            capability: Some(h.capability),
            severity: h.severity,
            basis: h.basis,
            rationale: h.rationale.to_string(),
            evidence,
        });
    }

    // --- capability combinations ---------------------------------------
    let has = |c: Capability| capabilities.contains(&c);
    let net = has(Capability::Network) || has(Capability::JsNetwork);
    let fs = has(Capability::Filesystem);
    if fs && net {
        findings.push(Finding {
            rule: "COMBO-FS-NET-001",
            capability: None,
            severity: Severity::Critical,
            basis: Basis::Documented,
            rationale: "the module holds both filesystem and network capability. \
                        Either alone is a bounded grant; together they are a read-and-send \
                        path, and a sandbox that permits both is not containing exfiltration."
                .to_string(),
            evidence: vec!["filesystem + network".to_string()],
        });
    }
    if has(Capability::ContractStorageWrite) && has(Capability::ContractCall) {
        findings.push(Finding {
            rule: "COMBO-STORAGE-CALL-001",
            capability: None,
            severity: Severity::High,
            basis: Basis::Documented,
            rationale: "the module both writes contract storage and calls out to other \
                        contracts, so it has a reentrancy surface. This says nothing about \
                        whether the ordering is wrong — only that the ordering is now \
                        something a reviewer has to check."
                .to_string(),
            evidence: vec!["contract-storage-write + contract-call".to_string()],
        });
    }
    if has(Capability::Unknown) {
        // Already reported per-import; the summary line makes it hard to miss.
        let unknown_count = imports
            .iter()
            .filter(|i| i.capabilities.contains(&Capability::Unknown))
            .count();
        findings.push(Finding {
            rule: "UNKNOWN-SUMMARY-001",
            capability: None,
            severity: Severity::Medium,
            basis: Basis::Documented,
            rationale: "some imports could not be classified. The capability set above is \
                        therefore a lower bound on what this module can do, not a \
                        description of it."
                .to_string(),
            evidence: vec![format!("{unknown_count} unclassified import(s)")],
        });
    }
    if module.imports.is_empty() {
        findings.push(Finding {
            rule: "NO-IMPORTS-001",
            capability: None,
            severity: Severity::Info,
            basis: Basis::Documented,
            rationale: "the module imports nothing, so it has no host authority at all: \
                        it can compute, and it can return values to whoever calls it."
                .to_string(),
            evidence: Vec::new(),
        });
    }

    // --- exports -------------------------------------------------------
    let mut exports: Vec<ExportView> = Vec::new();
    for e in &module.exports {
        let mutable = if e.kind == ExternKind::Global {
            resolve_global_mutability(module, e.index)
        } else {
            None
        };
        exports.push(ExportView {
            name: e.name.clone(),
            kind: e.kind.name(),
            index: e.index,
            mutable,
        });
    }

    let exported_memories: Vec<String> = exports
        .iter()
        .filter(|e| e.kind == "memory")
        .map(|e| e.name.clone())
        .collect();
    if !exported_memories.is_empty() {
        let mut evidence = exported_memories;
        evidence.sort();
        findings.push(Finding {
            rule: "EXPORT-MEMORY-001",
            capability: None,
            severity: Severity::High,
            basis: Basis::Documented,
            rationale: "the module exports its linear memory. Anything holding that export \
                        can read and write every byte the module owns, including buffers it \
                        believes are private, so secrets inside this module are only as \
                        private as the host's handling of the export."
                .to_string(),
            evidence,
        });
    }

    let mutable_global_exports: Vec<String> = exports
        .iter()
        .filter(|e| e.kind == "global" && e.mutable == Some(true))
        .map(|e| format!("{} (global {})", e.name, e.index))
        .collect();
    if !mutable_global_exports.is_empty() {
        let mut evidence = mutable_global_exports;
        evidence.sort();
        findings.push(Finding {
            rule: "EXPORT-MUT-GLOBAL-001",
            capability: None,
            severity: Severity::High,
            basis: Basis::Documented,
            rationale: "the module exports a mutable global, which is a write primitive \
                        into its own state: the host can change it between calls and the \
                        module will not know."
                .to_string(),
            evidence,
        });
    }

    let unresolved_global_exports: Vec<String> = exports
        .iter()
        .filter(|e| e.kind == "global" && e.mutable.is_none())
        .map(|e| format!("{} (global {})", e.name, e.index))
        .collect();
    if !unresolved_global_exports.is_empty() {
        let mut evidence = unresolved_global_exports;
        evidence.sort();
        findings.push(Finding {
            rule: "EXPORT-GLOBAL-UNRESOLVED-001",
            capability: None,
            severity: Severity::Low,
            basis: Basis::Documented,
            rationale: "a global export names an index outside the module's global space, \
                        so its mutability could not be determined. The module would not \
                        validate; treat the export as unanalysed rather than safe."
                .to_string(),
            evidence,
        });
    }

    let exported_tables: Vec<String> = exports
        .iter()
        .filter(|e| e.kind == "table")
        .map(|e| e.name.clone())
        .collect();
    if !exported_tables.is_empty() {
        let mut evidence = exported_tables;
        evidence.sort();
        findings.push(Finding {
            rule: "EXPORT-TABLE-001",
            capability: None,
            severity: Severity::Medium,
            basis: Basis::Documented,
            rationale: "the module exports a function table. Whoever holds it can replace \
                        entries, and every `call_indirect` in this module dispatches through \
                        that table."
                .to_string(),
            evidence,
        });
    }

    // --- memory and table posture --------------------------------------
    let mut memories: Vec<MemoryView> = Vec::new();
    for (mt, imported) in module.all_memories() {
        memories.push(MemoryView {
            imported,
            min_pages: mt.limits.min,
            max_pages: mt.limits.max,
            shared: mt.limits.shared,
            index64: mt.limits.index64,
        });
    }
    let unbounded: Vec<String> = memories
        .iter()
        .enumerate()
        .filter(|(_, m)| m.max_pages.is_none())
        .map(|(i, m)| format!("memory {} (min {} pages, no maximum)", i, m.min_pages))
        .collect();
    if !unbounded.is_empty() {
        findings.push(Finding {
            rule: "MEM-UNBOUNDED-001",
            capability: None,
            severity: Severity::Medium,
            basis: Basis::Documented,
            rationale: "a memory with no declared maximum will grow until the host refuses. \
                        In a multi-tenant runtime that is a memory-exhaustion vector against \
                        the host's other tenants, and it is the host's limit rather than the \
                        module's that has to stop it."
                .to_string(),
            evidence: unbounded,
        });
    }
    let shared: Vec<String> = memories
        .iter()
        .enumerate()
        .filter(|(_, m)| m.shared)
        .map(|(i, _)| format!("memory {i}"))
        .collect();
    if !shared.is_empty() {
        findings.push(Finding {
            rule: "MEM-SHARED-001",
            capability: None,
            severity: Severity::Medium,
            basis: Basis::Documented,
            rationale: "the memory is shared, so other instances or threads hold the same \
                        bytes and every read in this module is racy by construction."
                .to_string(),
            evidence: shared,
        });
    }
    let large: Vec<String> = memories
        .iter()
        .enumerate()
        .filter(|(_, m)| m.max_pages.is_some_and(|mx| mx >= 32768))
        .map(|(i, m)| {
            format!(
                "memory {} (maximum {} pages, about {} MiB)",
                i,
                m.max_pages.unwrap_or(0),
                m.max_pages.unwrap_or(0) / 16
            )
        })
        .collect();
    if !large.is_empty() {
        findings.push(Finding {
            rule: "MEM-LARGE-MAX-001",
            capability: None,
            severity: Severity::Low,
            basis: Basis::Documented,
            rationale: "the declared maximum is large enough that the limit is nominal; \
                        the host's own cap is what actually bounds this module."
                .to_string(),
            evidence: large,
        });
    }

    let mut tables: Vec<TableView> = Vec::new();
    for (tt, imported) in module.all_tables() {
        tables.push(TableView {
            imported,
            element: tt.elem.name(),
            min: tt.limits.min,
            max: tt.limits.max,
        });
    }
    let unbounded_tables: Vec<String> = tables
        .iter()
        .enumerate()
        .filter(|(_, t)| t.max.is_none())
        .map(|(i, t)| format!("table {} (min {}, no maximum)", i, t.min))
        .collect();
    if !unbounded_tables.is_empty() {
        findings.push(Finding {
            rule: "TABLE-UNBOUNDED-001",
            capability: None,
            severity: Severity::Low,
            basis: Basis::Documented,
            rationale: "a table with no declared maximum can be grown without limit where \
                        the reference-types proposal is available."
                .to_string(),
            evidence: unbounded_tables,
        });
    }

    // --- instantiation and control flow --------------------------------
    if let Some(start) = module.start {
        findings.push(Finding {
            rule: "START-FUNCTION-001",
            capability: None,
            severity: Severity::Medium,
            basis: Basis::Documented,
            rationale: "the module declares a start function, so code runs at \
                        instantiation, before the host calls anything. A host that \
                        validates a module and then instantiates it has already run this."
                .to_string(),
            evidence: vec![format!("function index {start}")],
        });
    }
    if module.code_scanned {
        if module.code.memory_grow > 0 {
            findings.push(Finding {
                rule: "MEMORY-GROW-001",
                capability: None,
                severity: Severity::Low,
                basis: Basis::Documented,
                rationale: "`memory.grow` is reachable, so the module's footprint is \
                            decided at run time rather than at load time."
                    .to_string(),
                evidence: vec![format!("{} site(s)", module.code.memory_grow)],
            });
        }
        if module.code.call_indirect > 0 || module.code.call_ref > 0 {
            findings.push(Finding {
                rule: "CALL-INDIRECT-001",
                capability: None,
                severity: Severity::Info,
                basis: Basis::Documented,
                rationale: "indirect calls dispatch on a run-time index into a table, so \
                            control-flow integrity here rests on the index being in range \
                            and the table holding what the module expects. This is where \
                            a corrupted index turns into a call to the wrong function."
                    .to_string(),
                evidence: vec![format!(
                    "{} call_indirect site(s), {} call_ref site(s)",
                    module.code.call_indirect, module.code.call_ref
                )],
            });
        }
    } else {
        findings.push(Finding {
            rule: "CODE-NOT-SCANNED-001",
            capability: None,
            severity: Severity::Info,
            basis: Basis::Documented,
            rationale: "code-section scanning was disabled, so the indirect-call, \
                        memory.grow and instruction-family counts are unavailable rather \
                        than zero."
                .to_string(),
            evidence: Vec::new(),
        });
    }
    if module.features.threads {
        findings.push(Finding {
            rule: "THREADS-001",
            capability: None,
            severity: Severity::Low,
            basis: Basis::Documented,
            rationale: "the module uses the threads proposal: shared memory, atomics, or \
                        both."
                .to_string(),
            evidence: Vec::new(),
        });
    }
    if module.features.bulk_memory {
        findings.push(Finding {
            rule: "BULK-MEMORY-001",
            capability: None,
            severity: Severity::Info,
            basis: Basis::Documented,
            rationale: "the module uses bulk-memory operations, which move spans of linear \
                        memory in one instruction."
                .to_string(),
            evidence: Vec::new(),
        });
    }
    if module.features.reference_types {
        findings.push(Finding {
            rule: "REF-TYPES-001",
            capability: None,
            severity: Severity::Info,
            basis: Basis::Documented,
            rationale: "the module uses reference types, so function and extern references \
                        are first-class values it can store and pass."
                .to_string(),
            evidence: Vec::new(),
        });
    }

    let custom_sections: Vec<(String, usize)> = module
        .customs
        .iter()
        .map(|c| (c.name.clone(), c.payload_len))
        .collect();
    if let Some(ns) = module.customs.iter().find(|c| c.name == "name") {
        findings.push(Finding {
            rule: "NAME-SECTION-001",
            capability: None,
            severity: Severity::Info,
            basis: Basis::Documented,
            rationale: "the module ships a name section, so function and local symbol names \
                        are present. Useful when reviewing it; also more than a release \
                        build needs to disclose."
                .to_string(),
            evidence: vec![format!("{} bytes", ns.payload_len)],
        });
    }

    capabilities.sort_by_key(|c| {
        Capability::ALL
            .iter()
            .position(|x| x == c)
            .unwrap_or(usize::MAX)
    });
    capabilities.dedup();

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule.cmp(b.rule))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });

    Report {
        source: source.to_string(),
        size_bytes,
        environments: detect_environments(&module.imports),
        capabilities,
        findings,
        imports,
        exports,
        memories,
        tables,
        start_function: module.start,
        code: module.code,
        code_scanned: module.code_scanned,
        features: module.features,
        function_count: module.functions.len(),
        type_count: module.types.len(),
        global_count: module.globals.len(),
        element_segments: module.elements.len(),
        data_segments: module.data.len(),
        custom_sections,
    }
}
