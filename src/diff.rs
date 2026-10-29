//! Comparing two versions of a module.
//!
//! This is the mode that earns the tool a place in a dependency pipeline. A
//! module's capability set is stable across most releases; when it changes,
//! the change is almost always worth a human looking at, and nobody looks,
//! because the module arrives as a blob inside a package bump. A dependency
//! update that quietly adds `sock_send` is exactly the thing this prints.

use crate::audit::Report;
use crate::capability::Capability;
use crate::json::{string_array, Obj};
use crate::report::visible;
use std::fmt::Write as _;

/// The difference between two reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    pub old_source: String,
    pub new_source: String,
    pub added_capabilities: Vec<Capability>,
    pub removed_capabilities: Vec<Capability>,
    pub added_imports: Vec<String>,
    pub removed_imports: Vec<String>,
    pub added_exports: Vec<String>,
    pub removed_exports: Vec<String>,
    /// Posture changes, already phrased for a reader.
    pub posture_changes: Vec<String>,
}

impl Diff {
    /// True when the new module can do something the old one could not.
    pub fn capabilities_grew(&self) -> bool {
        !self.added_capabilities.is_empty()
    }
}

fn import_keys(r: &Report) -> Vec<String> {
    let mut v: Vec<String> = r
        .imports
        .iter()
        .map(|i| format!("{}.{} ({})", visible(&i.module), visible(&i.name), i.kind))
        .collect();
    v.sort();
    v.dedup();
    v
}

fn export_keys(r: &Report) -> Vec<String> {
    let mut v: Vec<String> = r
        .exports
        .iter()
        .map(|e| format!("{} ({})", visible(&e.name), e.kind))
        .collect();
    v.sort();
    v.dedup();
    v
}

fn added<'a>(old: &'a [String], new: &'a [String]) -> Vec<String> {
    new.iter().filter(|n| !old.contains(n)).cloned().collect()
}

/// Compare two reports.
pub fn diff(old: &Report, new: &Report) -> Diff {
    let order = |c: &Capability| {
        Capability::ALL
            .iter()
            .position(|x| x == c)
            .unwrap_or(usize::MAX)
    };
    let mut added_capabilities: Vec<Capability> = new
        .capabilities
        .iter()
        .filter(|c| !old.capabilities.contains(c))
        .copied()
        .collect();
    added_capabilities.sort_by_key(order);
    let mut removed_capabilities: Vec<Capability> = old
        .capabilities
        .iter()
        .filter(|c| !new.capabilities.contains(c))
        .copied()
        .collect();
    removed_capabilities.sort_by_key(order);

    let old_imports = import_keys(old);
    let new_imports = import_keys(new);
    let old_exports = export_keys(old);
    let new_exports = export_keys(new);

    let mut posture_changes = Vec::new();
    if !old.exports_memory() && new.exports_memory() {
        posture_changes
            .push("the new module exports its linear memory; the old one did not".to_string());
    }
    if old.exports_memory() && !new.exports_memory() {
        posture_changes.push("the new module no longer exports its memory".to_string());
    }
    if !old.exports_mutable_global() && new.exports_mutable_global() {
        posture_changes.push("the new module exports a mutable global".to_string());
    }
    if old.start_function.is_none() && new.start_function.is_some() {
        posture_changes.push(
            "the new module declares a start function, so code now runs at instantiation"
                .to_string(),
        );
    }
    if old.start_function.is_some() && new.start_function.is_none() {
        posture_changes.push("the new module no longer declares a start function".to_string());
    }
    match (old.memory_ceiling_pages(), new.memory_ceiling_pages()) {
        (Some(_), None) => posture_changes
            .push("a memory maximum was removed, so memory is now unbounded".to_string()),
        (None, Some(n)) => posture_changes.push(format!("memory is now bounded at {n} pages")),
        (Some(a), Some(b)) if b > a => posture_changes.push(format!(
            "the declared memory maximum grew from {a} to {b} pages"
        )),
        _ => {}
    }
    if !old.has_unknown_imports() && new.has_unknown_imports() {
        posture_changes.push(
            "the new module has imports this tool cannot classify; the capability \
             comparison is therefore incomplete"
                .to_string(),
        );
    }
    posture_changes.sort();

    Diff {
        old_source: old.source.clone(),
        new_source: new.source.clone(),
        added_capabilities,
        removed_capabilities,
        added_imports: added(&old_imports, &new_imports),
        removed_imports: added(&new_imports, &old_imports),
        added_exports: added(&old_exports, &new_exports),
        removed_exports: added(&new_exports, &old_exports),
        posture_changes,
    }
}

/// Render a diff as text.
pub fn render_text(d: &Diff) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "{} {}", crate::report::TOOL, crate::report::VERSION);
    let _ = writeln!(s, "old: {}", d.old_source);
    let _ = writeln!(s, "new: {}", d.new_source);
    let _ = writeln!(s);
    let _ = writeln!(s, "CAPABILITIES ADDED ({})", d.added_capabilities.len());
    if d.added_capabilities.is_empty() {
        let _ = writeln!(s, "  (none)");
    }
    for c in &d.added_capabilities {
        let _ = writeln!(s, "  + {:<24} {}", c.id(), c.describes());
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "CAPABILITIES REMOVED ({})", d.removed_capabilities.len());
    if d.removed_capabilities.is_empty() {
        let _ = writeln!(s, "  (none)");
    }
    for c in &d.removed_capabilities {
        let _ = writeln!(s, "  - {:<24} {}", c.id(), c.describes());
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "IMPORTS ADDED ({})", d.added_imports.len());
    for i in &d.added_imports {
        let _ = writeln!(s, "  + {i}");
    }
    let _ = writeln!(s, "IMPORTS REMOVED ({})", d.removed_imports.len());
    for i in &d.removed_imports {
        let _ = writeln!(s, "  - {i}");
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "EXPORTS ADDED ({})", d.added_exports.len());
    for e in &d.added_exports {
        let _ = writeln!(s, "  + {e}");
    }
    let _ = writeln!(s, "EXPORTS REMOVED ({})", d.removed_exports.len());
    for e in &d.removed_exports {
        let _ = writeln!(s, "  - {e}");
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "POSTURE CHANGES ({})", d.posture_changes.len());
    if d.posture_changes.is_empty() {
        let _ = writeln!(s, "  (none)");
    }
    for p in &d.posture_changes {
        let _ = writeln!(s, "  ! {p}");
    }
    s
}

/// Render a diff as a single line of JSON.
pub fn render_json(d: &Diff) -> String {
    Obj::new()
        .str_field("tool", crate::report::TOOL)
        .str_field("version", crate::report::VERSION)
        .str_field("mode", "diff")
        .str_field("old", &d.old_source)
        .str_field("new", &d.new_source)
        .raw(
            "capabilities_added",
            string_array(d.added_capabilities.iter().map(|c| c.id())),
        )
        .raw(
            "capabilities_removed",
            string_array(d.removed_capabilities.iter().map(|c| c.id())),
        )
        .raw("imports_added", string_array(&d.added_imports))
        .raw("imports_removed", string_array(&d.removed_imports))
        .raw("exports_added", string_array(&d.added_exports))
        .raw("exports_removed", string_array(&d.removed_exports))
        .raw("posture_changes", string_array(&d.posture_changes))
        .bool_field("capabilities_grew", d.capabilities_grew())
        .finish()
}
