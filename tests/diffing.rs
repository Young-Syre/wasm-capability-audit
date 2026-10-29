//! Diff mode: what changed between two versions of a module.

mod common;
use common::*;

use wasm_capability_audit::diff::{diff, render_json, render_text};

fn report_of(bytes: &[u8], name: &str) -> wasm_capability_audit::Report {
    wasm_capability_audit::audit_bytes(bytes, name).unwrap()
}

#[test]
fn a_module_diffed_against_itself_shows_no_change() {
    let a = report_of(&wasi_exfil(), "old");
    let b = report_of(&wasi_exfil(), "new");
    let d = diff(&a, &b);
    assert!(d.added_capabilities.is_empty());
    assert!(d.removed_capabilities.is_empty());
    assert!(d.added_imports.is_empty());
    assert!(d.removed_imports.is_empty());
    assert!(d.posture_changes.is_empty());
    assert!(!d.capabilities_grew());
}

#[test]
fn an_added_socket_import_is_an_added_network_capability() {
    let old = report_of(&wasi_clock_only(), "old.wasm");
    let new = report_of(&wasi_clock_and_socket(), "new.wasm");
    let d = diff(&old, &new);
    assert_eq!(
        d.added_capabilities
            .iter()
            .map(|c| c.id())
            .collect::<Vec<_>>(),
        vec!["network"]
    );
    assert!(d.capabilities_grew());
    assert_eq!(
        d.added_imports,
        vec!["wasi_snapshot_preview1.sock_send (func)".to_string()]
    );
    assert!(d.removed_imports.is_empty());
}

#[test]
fn a_removed_capability_is_reported_but_is_not_growth() {
    let old = report_of(&wasi_clock_and_socket(), "old");
    let new = report_of(&wasi_clock_only(), "new");
    let d = diff(&old, &new);
    assert_eq!(
        d.removed_capabilities
            .iter()
            .map(|c| c.id())
            .collect::<Vec<_>>(),
        vec!["network"]
    );
    assert!(d.added_capabilities.is_empty());
    assert!(!d.capabilities_grew());
    assert_eq!(
        d.removed_imports,
        vec!["wasi_snapshot_preview1.sock_send (func)".to_string()]
    );
}

#[test]
fn export_changes_are_reported() {
    let old = report_of(&wasi_clock_only(), "old");
    let new = report_of(&wasi_clock_and_socket(), "new");
    let d = diff(&old, &new);
    assert!(d.added_exports.is_empty());
    assert!(d.removed_exports.is_empty());

    let d2 = diff(
        &report_of(&clean_compute(), "a"),
        &report_of(&indirect_dispatch(), "b"),
    );
    assert!(d2.added_exports.contains(&"table (table)".to_string()));
    assert!(d2.removed_exports.contains(&"add (func)".to_string()));
}

#[test]
fn newly_exported_memory_is_a_posture_change() {
    let d = diff(
        &report_of(&wasi_clock_only(), "old"),
        &report_of(&wasi_exfil(), "new"),
    );
    assert!(d
        .posture_changes
        .iter()
        .any(|p| p.contains("exports its linear memory")));
    assert!(d
        .posture_changes
        .iter()
        .any(|p| p.contains("declares a start function")));
    assert!(d
        .posture_changes
        .iter()
        .any(|p| p.contains("memory maximum was removed")));
}

#[test]
fn a_tightened_module_reports_the_reverse_posture_changes() {
    let d = diff(
        &report_of(&wasi_exfil(), "old"),
        &report_of(&wasi_clock_only(), "new"),
    );
    assert!(d
        .posture_changes
        .iter()
        .any(|p| p.contains("no longer exports its memory")));
    assert!(d
        .posture_changes
        .iter()
        .any(|p| p.contains("no longer declares a start function")));
    assert!(d
        .posture_changes
        .iter()
        .any(|p| p.contains("now bounded at 16 pages")));
}

#[test]
fn a_grown_memory_ceiling_is_reported() {
    let small = module(&[section(5, &vector(&[limits(1, Some(2), false)]))]);
    let large = module(&[section(5, &vector(&[limits(1, Some(64), false)]))]);
    let d = diff(&report_of(&small, "a"), &report_of(&large, "b"));
    assert!(d
        .posture_changes
        .iter()
        .any(|p| p.contains("grew from 2 to 64 pages")));
}

#[test]
fn newly_unclassifiable_imports_caveat_the_comparison() {
    let d = diff(
        &report_of(&clean_compute(), "old"),
        &report_of(&unknown_host(), "new"),
    );
    assert!(d
        .posture_changes
        .iter()
        .any(|p| p.contains("comparison is therefore incomplete")));
    assert!(d.added_capabilities.iter().any(|c| c.id() == "unknown"));
}

#[test]
fn diff_text_output_names_both_modules_and_every_section() {
    let d = diff(
        &report_of(&wasi_clock_only(), "old.wasm"),
        &report_of(&wasi_clock_and_socket(), "new.wasm"),
    );
    let text = render_text(&d);
    assert!(text.contains("old: old.wasm"));
    assert!(text.contains("new: new.wasm"));
    for heading in [
        "CAPABILITIES ADDED",
        "CAPABILITIES REMOVED",
        "IMPORTS ADDED",
        "IMPORTS REMOVED",
        "EXPORTS ADDED",
        "EXPORTS REMOVED",
        "POSTURE CHANGES",
    ] {
        assert!(text.contains(heading), "missing {heading}");
    }
    assert!(text.contains("+ network"));
}

#[test]
fn diff_json_is_structured_and_states_whether_capabilities_grew() {
    let d = diff(
        &report_of(&wasi_clock_only(), "old.wasm"),
        &report_of(&wasi_clock_and_socket(), "new.wasm"),
    );
    let json = render_json(&d);
    assert!(json.contains(r#""mode":"diff""#));
    assert!(json.contains(r#""capabilities_added":["network"]"#));
    assert!(json.contains(r#""capabilities_removed":[]"#));
    assert!(json.contains(r#""capabilities_grew":true"#));
    assert_eq!(json.lines().count(), 1);
}

#[test]
fn diffing_is_deterministic() {
    let old = report_of(&wasi_clock_only(), "old");
    let new = report_of(&wasi_exfil(), "new");
    assert_eq!(diff(&old, &new), diff(&old, &new));
    assert_eq!(
        render_text(&diff(&old, &new)),
        render_text(&diff(&old, &new))
    );
}
