//! The rule registry and the implementation cannot drift apart.

use wasm_capability_audit::rules::{rule_ids_in_source, RULE_IDS};

const CLASSIFY: &str = include_str!("../src/classify.rs");
const AUDIT: &str = include_str!("../src/audit.rs");

fn implemented() -> Vec<String> {
    let mut v = rule_ids_in_source(CLASSIFY);
    v.extend(rule_ids_in_source(AUDIT));
    v.sort();
    v.dedup();
    v
}

#[test]
fn the_extractor_recognises_a_rule_identifier() {
    let ids = rule_ids_in_source(r#"hit("WASI-FS-001", x); let s = "not-a-rule";"#);
    assert_eq!(ids, vec!["WASI-FS-001".to_string()]);
    assert!(rule_ids_in_source(r#""lowercase-rule-001""#).is_empty());
    assert!(rule_ids_in_source(r#""NOHYPHEN001""#).is_empty());
    assert_eq!(
        rule_ids_in_source(r#""THREADS-001""#),
        vec!["THREADS-001".to_string()],
        "a single-hyphen identifier is still a rule"
    );
    assert!(rule_ids_in_source(r#""WASI-FS-01""#).is_empty());
}

#[test]
fn every_implemented_rule_is_in_the_registry() {
    for id in implemented() {
        assert!(
            RULE_IDS.contains(&id.as_str()),
            "{id} is emitted by the code but missing from rules::RULE_IDS"
        );
    }
}

#[test]
fn every_registered_rule_is_implemented() {
    let impls = implemented();
    for id in RULE_IDS {
        assert!(
            impls.contains(&id.to_string()),
            "{id} is in rules::RULE_IDS but no code emits it"
        );
    }
}

#[test]
fn the_registry_is_sorted_and_unique() {
    let mut sorted: Vec<&str> = RULE_IDS.to_vec();
    sorted.sort_unstable();
    assert_eq!(RULE_IDS.to_vec(), sorted, "RULE_IDS must stay sorted");
    let mut deduped = sorted.clone();
    deduped.dedup();
    assert_eq!(deduped.len(), RULE_IDS.len(), "RULE_IDS has duplicates");
}

#[test]
fn the_readme_documents_every_rule() {
    const README: &str = include_str!("../README.md");
    let mut missing: Vec<&str> = Vec::new();
    for id in RULE_IDS {
        if !README.contains(id) {
            missing.push(id);
        }
    }
    assert!(
        missing.is_empty(),
        "the README does not mention these rules: {missing:?}"
    );
}
