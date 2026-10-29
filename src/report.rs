//! Rendering a report, as text for a person and as JSON for a pipeline.
//!
//! Both renderings are deterministic: findings are already sorted by severity
//! and rule, evidence lists are sorted, and nothing iterates a hash map. Two
//! runs over the same bytes produce byte-identical output, which is what makes
//! the diff mode and CI assertions meaningful.

use crate::audit::Report;
use crate::capability::Severity;
use crate::json::{quote, string_array, Obj};
use std::fmt::Write as _;

/// Tool name, as reported in output.
pub const TOOL: &str = "wasm-capability-audit";
/// Tool version, taken from the manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn pages_to_kib(pages: u64) -> u64 {
    pages.saturating_mul(64)
}

/// Render the human-readable report.
pub fn render_text(r: &Report) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "{TOOL} {VERSION}");
    let _ = writeln!(s, "module: {} ({} bytes)", r.source, r.size_bytes);
    if r.environments.is_empty() {
        let _ = writeln!(
            s,
            "host environment: not recognised from the import module names"
        );
    } else {
        let names: Vec<&str> = r.environments.iter().map(|e| e.name()).collect();
        let _ = writeln!(s, "host environment (inferred): {}", names.join(", "));
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "CAPABILITY SET ({})", r.capabilities.len());
    if r.capabilities.is_empty() {
        let _ = writeln!(s, "  (none: the module asks the host for nothing)");
    } else {
        for c in &r.capabilities {
            let _ = writeln!(s, "  {:<24} {}", c.id(), c.describes());
        }
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "FINDINGS ({})", r.findings.len());
    if r.findings.is_empty() {
        let _ = writeln!(s, "  (none)");
    }
    for f in &r.findings {
        let _ = writeln!(
            s,
            "  [{}] {} ({})",
            f.severity.name(),
            f.rule,
            f.basis.tag()
        );
        if let Some(c) = f.capability {
            let _ = writeln!(s, "      capability: {}", c.id());
        }
        for line in wrap(&f.rationale, 76) {
            let _ = writeln!(s, "      {line}");
        }
        for e in &f.evidence {
            let _ = writeln!(s, "      - {e}");
        }
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "IMPORTS ({})", r.imports.len());
    if r.imports.is_empty() {
        let _ = writeln!(s, "  (none)");
    }
    for i in &r.imports {
        let caps: Vec<&str> = i.capabilities.iter().map(|c| c.id()).collect();
        let _ = writeln!(
            s,
            "  {:<48} {:<7} {:<28} {}",
            format!("{}.{}", i.module, i.name),
            i.kind,
            if caps.is_empty() {
                "-".to_string()
            } else {
                caps.join(",")
            },
            i.rules.join(",")
        );
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "EXPORTS ({})", r.exports.len());
    if r.exports.is_empty() {
        let _ = writeln!(s, "  (none)");
    }
    for e in &r.exports {
        let extra = match e.mutable {
            Some(true) => "  mutable",
            Some(false) => "  const",
            None => "",
        };
        let _ = writeln!(
            s,
            "  {:<40} {:<7} index {}{}",
            e.name, e.kind, e.index, extra
        );
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "MEMORY ({})", r.memories.len());
    if r.memories.is_empty() {
        let _ = writeln!(s, "  (none declared or imported)");
    }
    for (idx, m) in r.memories.iter().enumerate() {
        let max = match m.max_pages {
            Some(mx) => format!("max {} pages ({} KiB)", mx, pages_to_kib(mx)),
            None => "no maximum".to_string(),
        };
        let mut flags = String::new();
        if m.imported {
            flags.push_str(" imported");
        }
        if m.shared {
            flags.push_str(" shared");
        }
        if m.index64 {
            flags.push_str(" i64-index");
        }
        let _ = writeln!(
            s,
            "  memory {}: min {} pages ({} KiB), {}{}",
            idx,
            m.min_pages,
            pages_to_kib(m.min_pages),
            max,
            flags
        );
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "TABLES ({})", r.tables.len());
    if r.tables.is_empty() {
        let _ = writeln!(s, "  (none declared or imported)");
    }
    for (idx, t) in r.tables.iter().enumerate() {
        let max = match t.max {
            Some(mx) => format!("max {mx}"),
            None => "no maximum".to_string(),
        };
        let _ = writeln!(
            s,
            "  table {}: {}, min {}, {}{}",
            idx,
            t.element,
            t.min,
            max,
            if t.imported { " imported" } else { "" }
        );
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "CODE");
    if r.code_scanned {
        let _ = writeln!(
            s,
            "  bodies {}, instructions {}, locals {}, max block depth {}",
            r.code.functions, r.code.instructions, r.code.declared_locals, r.code.max_depth
        );
        let _ = writeln!(
            s,
            "  calls: {} direct, {} indirect (table), {} by reference, {} tail",
            r.code.call_direct, r.code.call_indirect, r.code.call_ref, r.code.tail_calls
        );
        let _ = writeln!(
            s,
            "  memory.grow {}, memory.size {}, bulk-memory ops {}, table ops {}",
            r.code.memory_grow, r.code.memory_size, r.code.bulk_memory_ops, r.code.table_ops
        );
        let _ = writeln!(
            s,
            "  ref ops {}, simd ops {}, atomic ops {}, throws {}",
            r.code.ref_ops, r.code.simd_ops, r.code.atomic_ops, r.code.throw_ops
        );
    } else {
        let _ = writeln!(s, "  not scanned (--no-code-scan)");
    }
    let feats = feature_list(r);
    let _ = writeln!(
        s,
        "  proposals used: {}",
        if feats.is_empty() {
            "none beyond the MVP".to_string()
        } else {
            feats.join(", ")
        }
    );
    let _ = writeln!(
        s,
        "  types {}, functions {}, globals {}, element segments {}, data segments {}",
        r.type_count, r.function_count, r.global_count, r.element_segments, r.data_segments
    );
    if !r.custom_sections.is_empty() {
        let parts: Vec<String> = r
            .custom_sections
            .iter()
            .map(|(n, l)| format!("{n} ({l} bytes)"))
            .collect();
        let _ = writeln!(s, "  custom sections: {}", parts.join(", "));
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "SUMMARY");
    for sev in Severity::ALL.iter().rev() {
        let n = r.findings.iter().filter(|f| f.severity == *sev).count();
        if n > 0 {
            let _ = writeln!(s, "  {:<9} {}", sev.name(), n);
        }
    }
    match r.max_severity() {
        Some(max) => {
            let _ = writeln!(s, "  highest severity: {}", max.name());
        }
        None => {
            let _ = writeln!(s, "  highest severity: none");
        }
    }
    s
}

/// Which post-MVP proposals the module's encoding used.
pub fn feature_list(r: &Report) -> Vec<&'static str> {
    let f = r.features;
    let mut out = Vec::new();
    if f.multi_value {
        out.push("multi-value");
    }
    if f.reference_types {
        out.push("reference-types");
    }
    if f.bulk_memory {
        out.push("bulk-memory");
    }
    if f.simd {
        out.push("simd");
    }
    if f.threads {
        out.push("threads");
    }
    if f.tail_call {
        out.push("tail-call");
    }
    if f.multi_memory {
        out.push("multi-memory");
    }
    if f.memory64 {
        out.push("memory64");
    }
    if f.exception_handling {
        out.push("exception-handling");
    }
    if f.typed_function_references {
        out.push("typed-function-references");
    }
    out
}

/// Render the report as a single line of JSON.
pub fn render_json(r: &Report) -> String {
    let capabilities: Vec<String> = r
        .capabilities
        .iter()
        .map(|c| {
            Obj::new()
                .str_field("id", c.id())
                .str_field("grants", c.describes())
                .finish()
        })
        .collect();
    let findings: Vec<String> = r
        .findings
        .iter()
        .map(|f| {
            let mut o = Obj::new()
                .str_field("rule", f.rule)
                .str_field("severity", f.severity.name())
                .str_field("basis", f.basis.tag());
            o = match f.capability {
                Some(c) => o.str_field("capability", c.id()),
                None => o.raw("capability", "null"),
            };
            o.str_field("rationale", &f.rationale)
                .raw("evidence", string_array(&f.evidence))
                .finish()
        })
        .collect();
    let imports: Vec<String> = r
        .imports
        .iter()
        .map(|i| {
            Obj::new()
                .str_field("module", &i.module)
                .str_field("name", &i.name)
                .str_field("kind", i.kind)
                .raw(
                    "capabilities",
                    string_array(i.capabilities.iter().map(|c| c.id())),
                )
                .raw("rules", string_array(&i.rules))
                .finish()
        })
        .collect();
    let exports: Vec<String> = r
        .exports
        .iter()
        .map(|e| {
            let o = Obj::new()
                .str_field("name", &e.name)
                .str_field("kind", e.kind)
                .num("index", u64::from(e.index));
            match e.mutable {
                Some(b) => o.bool_field("mutable", b),
                None => o.raw("mutable", "null"),
            }
            .finish()
        })
        .collect();
    let memories: Vec<String> = r
        .memories
        .iter()
        .map(|m| {
            Obj::new()
                .bool_field("imported", m.imported)
                .num("min_pages", m.min_pages)
                .opt_num("max_pages", m.max_pages)
                .bool_field("shared", m.shared)
                .bool_field("index64", m.index64)
                .finish()
        })
        .collect();
    let tables: Vec<String> = r
        .tables
        .iter()
        .map(|t| {
            Obj::new()
                .bool_field("imported", t.imported)
                .str_field("element", t.element)
                .num("min", t.min)
                .opt_num("max", t.max)
                .finish()
        })
        .collect();
    let code = Obj::new()
        .bool_field("scanned", r.code_scanned)
        .num("bodies", r.code.functions as u64)
        .num("instructions", r.code.instructions)
        .num("declared_locals", r.code.declared_locals)
        .num("call_direct", r.code.call_direct)
        .num("call_indirect", r.code.call_indirect)
        .num("call_ref", r.code.call_ref)
        .num("tail_calls", r.code.tail_calls)
        .num("memory_grow", r.code.memory_grow)
        .num("memory_size", r.code.memory_size)
        .num("bulk_memory_ops", r.code.bulk_memory_ops)
        .num("table_ops", r.code.table_ops)
        .num("ref_ops", r.code.ref_ops)
        .num("simd_ops", r.code.simd_ops)
        .num("atomic_ops", r.code.atomic_ops)
        .num("throw_ops", r.code.throw_ops)
        .num("max_block_depth", u64::from(r.code.max_depth))
        .finish();
    let counts = Obj::new()
        .num("types", r.type_count as u64)
        .num("functions", r.function_count as u64)
        .num("globals", r.global_count as u64)
        .num("element_segments", r.element_segments as u64)
        .num("data_segments", r.data_segments as u64)
        .finish();
    let customs: Vec<String> = r
        .custom_sections
        .iter()
        .map(|(n, l)| {
            Obj::new()
                .str_field("name", n)
                .num("payload_bytes", *l as u64)
                .finish()
        })
        .collect();
    let mut severity_counts = Obj::new();
    for sev in Severity::ALL.iter().rev() {
        let n = r.findings.iter().filter(|f| f.severity == *sev).count();
        severity_counts = severity_counts.num(sev.name(), n as u64);
    }
    let summary = Obj::new()
        .raw("by_severity", severity_counts.finish())
        .raw(
            "highest_severity",
            match r.max_severity() {
                Some(s) => quote(s.name()),
                None => "null".to_string(),
            },
        )
        .bool_field("unknown_imports", r.has_unknown_imports())
        .finish();

    Obj::new()
        .str_field("tool", TOOL)
        .str_field("version", VERSION)
        .str_field("source", &r.source)
        .num("size_bytes", r.size_bytes as u64)
        .raw(
            "host_environments",
            string_array(r.environments.iter().map(|e| e.name())),
        )
        .raw("capabilities", format!("[{}]", capabilities.join(",")))
        .raw("findings", format!("[{}]", findings.join(",")))
        .raw("imports", format!("[{}]", imports.join(",")))
        .raw("exports", format!("[{}]", exports.join(",")))
        .raw("memories", format!("[{}]", memories.join(",")))
        .raw("tables", format!("[{}]", tables.join(",")))
        .opt_num("start_function", r.start_function.map(u64::from))
        .raw("code", code)
        .raw("proposals_used", string_array(feature_list(r)))
        .raw("counts", counts)
        .raw("custom_sections", format!("[{}]", customs.join(",")))
        .raw("summary", summary)
        .finish()
}

/// Wrap prose at `width` columns on whitespace, for the text report.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
