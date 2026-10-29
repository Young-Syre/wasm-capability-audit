//! Policy parsing and evaluation.

mod common;
use common::*;

use wasm_capability_audit::capability::{Capability, Severity};
use wasm_capability_audit::Policy;

fn report_of(bytes: &[u8]) -> wasm_capability_audit::Report {
    wasm_capability_audit::audit_bytes(bytes, "t").unwrap()
}

#[test]
fn an_empty_policy_constrains_nothing() {
    let p = Policy::parse("").unwrap();
    assert_eq!(p, Policy::default());
    assert!(p.evaluate(&report_of(&wasi_exfil())).is_empty());
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    let p = Policy::parse("# a comment\n\n   \nallow clock   # trailing comment\n\n# another\n")
        .unwrap();
    assert_eq!(p.allowed, Some(vec![Capability::Clock]));
}

#[test]
fn every_directive_parses() {
    let p = Policy::parse(
        "allow clock\n\
         allow network\n\
         max-severity medium\n\
         allow-unknown-imports no\n\
         allow-exported-memory no\n\
         allow-mutable-global-export no\n\
         allow-start-function no\n\
         require-memory-max yes\n\
         max-memory-pages 256\n",
    )
    .unwrap();
    assert_eq!(
        p.allowed,
        Some(vec![Capability::Network, Capability::Clock]),
        "capabilities are stored in the canonical order"
    );
    assert_eq!(p.max_severity, Some(Severity::Medium));
    assert_eq!(p.allow_unknown_imports, Some(false));
    assert_eq!(p.allow_exported_memory, Some(false));
    assert_eq!(p.allow_mutable_global_export, Some(false));
    assert_eq!(p.allow_start_function, Some(false));
    assert_eq!(p.require_memory_max, Some(true));
    assert_eq!(p.max_memory_pages, Some(256));
}

#[test]
fn boolean_spellings_are_accepted() {
    for yes in ["yes", "true", "on", "1"] {
        let p = Policy::parse(&format!("allow-start-function {yes}")).unwrap();
        assert_eq!(p.allow_start_function, Some(true), "{yes}");
    }
    for no in ["no", "false", "off", "0"] {
        let p = Policy::parse(&format!("allow-start-function {no}")).unwrap();
        assert_eq!(p.allow_start_function, Some(false), "{no}");
    }
}

#[test]
fn malformed_policies_report_the_line_and_the_reason() {
    let cases = [
        ("allow\n", 1, "needs a value"),
        ("allow not-a-capability\n", 1, "unknown capability"),
        ("\n\nmax-severity apocalyptic\n", 3, "unknown severity"),
        ("allow clock\nnonsense yes\n", 2, "unknown directive"),
        ("allow-start-function maybe\n", 1, "expected yes or no"),
        ("max-memory-pages lots\n", 1, "expected a page count"),
    ];
    for (text, line, needle) in cases {
        let e = Policy::parse(text).unwrap_err();
        assert_eq!(e.line, line, "{text:?}");
        assert!(
            e.message.contains(needle),
            "{text:?}: {:?} lacked {needle:?}",
            e.message
        );
        assert!(e.to_string().starts_with(&format!("policy line {line}")));
    }
}

#[test]
fn an_allow_list_rejects_a_capability_it_does_not_name() {
    let p = Policy::parse("allow clock\nallow randomness\n").unwrap();
    let v = p.evaluate(&report_of(&wasi_exfil()));
    assert!(v.iter().any(|m| m.contains("capability filesystem")));
    assert!(v.iter().any(|m| m.contains("capability network")));
    assert!(!v.iter().any(|m| m.contains("capability clock")));
}

#[test]
fn an_allow_list_that_covers_the_module_passes() {
    let p = Policy::parse("allow clock\nallow randomness\n").unwrap();
    assert!(p.evaluate(&report_of(&wasi_clock_only())).is_empty());
}

#[test]
fn a_severity_ceiling_is_enforced() {
    let p = Policy::parse("max-severity medium\n").unwrap();
    let v = p.evaluate(&report_of(&wasi_exfil()));
    assert!(v.iter().any(|m| m.contains("COMBO-FS-NET-001")));
    assert!(v.iter().any(|m| m.contains("is critical")));

    let lenient = Policy::parse("max-severity critical\n").unwrap();
    assert!(lenient.evaluate(&report_of(&wasi_exfil())).is_empty());
}

#[test]
fn unknown_imports_can_be_made_a_failure() {
    let p = Policy::parse("allow-unknown-imports no\n").unwrap();
    let v = p.evaluate(&report_of(&unknown_host()));
    assert_eq!(v.len(), 1);
    assert!(v[0].contains("could not classify"));

    let permissive = Policy::parse("allow-unknown-imports yes\n").unwrap();
    assert!(permissive.evaluate(&report_of(&unknown_host())).is_empty());
}

#[test]
fn exported_memory_and_globals_can_be_forbidden() {
    let p = Policy::parse("allow-exported-memory no\nallow-mutable-global-export no\n").unwrap();
    let v = p.evaluate(&report_of(&bindgen_browser()));
    assert!(v.iter().any(|m| m.contains("exports its linear memory")));
    assert!(v.iter().any(|m| m.contains("exports a mutable global")));
}

#[test]
fn a_start_function_can_be_forbidden() {
    let p = Policy::parse("allow-start-function no\n").unwrap();
    assert!(p
        .evaluate(&report_of(&wasi_exfil()))
        .iter()
        .any(|m| m.contains("start function")));
    assert!(p.evaluate(&report_of(&clean_compute())).is_empty());
}

#[test]
fn memory_bounds_are_enforced() {
    let require = Policy::parse("require-memory-max yes\n").unwrap();
    assert!(require
        .evaluate(&report_of(&wasi_exfil()))
        .iter()
        .any(|m| m.contains("declares no maximum")));
    assert!(require.evaluate(&report_of(&wasi_clock_only())).is_empty());

    let cap = Policy::parse("max-memory-pages 8\n").unwrap();
    let v = cap.evaluate(&report_of(&wasi_clock_only()));
    assert_eq!(v.len(), 1, "16 declared pages exceed a limit of 8");
    assert!(v[0].contains("16 pages"));

    let generous = Policy::parse("max-memory-pages 64\n").unwrap();
    assert!(generous.evaluate(&report_of(&wasi_clock_only())).is_empty());

    // An unbounded memory can never satisfy a page limit, and the message
    // says that rather than silently passing.
    let v = cap.evaluate(&report_of(&wasi_exfil()));
    assert!(v.iter().any(|m| m.contains("cannot be met")));
}

#[test]
fn violations_are_sorted_and_deduplicated() {
    let p = Policy::parse("allow clock\nmax-severity info\n").unwrap();
    let v = p.evaluate(&report_of(&wasi_exfil()));
    let mut sorted = v.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(v, sorted);
    assert!(!v.is_empty());
}

#[test]
fn the_committed_plugin_policy_passes_a_clean_module_and_fails_a_capable_one() {
    let text = include_str!("../policies/sandboxed-plugin.policy");
    let p = Policy::parse(text).expect("the committed policy must parse");
    // The clock-only module exports no memory, declares a maximum of 16
    // pages, and has no start function.
    assert!(
        p.evaluate(&report_of(&wasi_clock_only())).is_empty(),
        "{:?}",
        p.evaluate(&report_of(&wasi_clock_only()))
    );
    assert!(!p.evaluate(&report_of(&wasi_exfil())).is_empty());
}

#[test]
fn the_committed_cli_policy_allows_files_but_not_sockets() {
    let text = include_str!("../policies/wasi-cli-tool.policy");
    let p = Policy::parse(text).expect("the committed policy must parse");
    let v = p.evaluate(&report_of(&wasi_exfil()));
    assert!(v.iter().any(|m| m.contains("capability network")));
    assert!(!v.iter().any(|m| m.contains("capability filesystem")));
}
