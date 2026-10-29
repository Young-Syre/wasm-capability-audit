//! The rule registry.
//!
//! Every identifier a finding can carry is listed here. It is not decoration:
//! `tests/rule_registry.rs` reads the rule sources and fails if a rule
//! identifier exists in the code but not in this list, or the other way
//! round, so the documented rule set and the implemented one cannot drift
//! apart quietly.

/// Every rule identifier this tool can emit, sorted.
pub const RULE_IDS: &[&str] = &[
    "BINDGEN-CRYPTO-001",
    "BINDGEN-DOM-001",
    "BINDGEN-EVAL-001",
    "BINDGEN-GLUE-001",
    "BINDGEN-JS-001",
    "BINDGEN-MSG-001",
    "BINDGEN-NET-001",
    "BINDGEN-STORAGE-001",
    "BULK-MEMORY-001",
    "CALL-INDIRECT-001",
    "CODE-NOT-SCANNED-001",
    "COMBO-FS-NET-001",
    "COMBO-STORAGE-CALL-001",
    "COSMWASM-ADDR-001",
    "COSMWASM-CRYPTO-001",
    "COSMWASM-DB-READ-001",
    "COSMWASM-DB-WRITE-001",
    "COSMWASM-DEBUG-001",
    "COSMWASM-QUERY-001",
    "EMSC-GENERIC-001",
    "EMSC-INVOKE-001",
    "EMSC-JSEVAL-001",
    "EMSC-MEM-001",
    "EMSC-NET-001",
    "EMSC-SYSCALL-001",
    "EWASM-CALL-001",
    "EWASM-CREATE-001",
    "EWASM-DELEGATE-001",
    "EWASM-SELFDESTRUCT-001",
    "EWASM-STORAGE-READ-001",
    "EWASM-STORAGE-WRITE-001",
    "EXPORT-GLOBAL-UNRESOLVED-001",
    "EXPORT-MEMORY-001",
    "EXPORT-MUT-GLOBAL-001",
    "EXPORT-TABLE-001",
    "IC0-CALL-001",
    "IC0-CERTIFIED-001",
    "IC0-CONTEXT-001",
    "IC0-CYCLES-001",
    "IC0-DEBUG-001",
    "IC0-RAND-001",
    "IC0-STABLE-READ-001",
    "IC0-STABLE-WRITE-001",
    "IMPORT-GLOBAL-MUT-001",
    "IMPORT-MEMORY-001",
    "IMPORT-TABLE-001",
    "IMPORT-TAG-001",
    "MEM-LARGE-MAX-001",
    "MEM-SHARED-001",
    "MEM-UNBOUNDED-001",
    "MEMORY-GROW-001",
    "NAME-SECTION-001",
    "NEAR-ABORT-001",
    "NEAR-CALL-001",
    "NEAR-CONTEXT-001",
    "NEAR-CRYPTO-001",
    "NEAR-DELETE-ACCOUNT-001",
    "NEAR-DEPLOY-001",
    "NEAR-GAS-001",
    "NEAR-KEYS-001",
    "NEAR-LOG-001",
    "NEAR-RANDOM-001",
    "NEAR-REGISTER-001",
    "NEAR-STORAGE-READ-001",
    "NEAR-STORAGE-WRITE-001",
    "NEAR-TRANSFER-001",
    "NO-IMPORTS-001",
    "PATTERN-CALL-001",
    "PATTERN-CONTEXT-001",
    "PATTERN-CRYPTO-001",
    "PATTERN-DELEGATE-001",
    "PATTERN-DEPLOY-001",
    "PATTERN-DESTROY-001",
    "PATTERN-EVAL-001",
    "PATTERN-EXEC-001",
    "PATTERN-FS-001",
    "PATTERN-LOG-001",
    "PATTERN-NET-001",
    "PATTERN-RANDOM-001",
    "PATTERN-STORAGE-READ-001",
    "PATTERN-STORAGE-WRITE-001",
    "PATTERN-TRANSFER-001",
    "REF-TYPES-001",
    "SEAL-CALL-001",
    "SEAL-DELEGATE-001",
    "SEAL-INSTANTIATE-001",
    "SEAL-RANDOM-001",
    "SEAL-STORAGE-READ-001",
    "SEAL-STORAGE-WRITE-001",
    "SEAL-TERMINATE-001",
    "SEAL-TRANSFER-001",
    "SHIM-ABORT-001",
    "START-FUNCTION-001",
    "TABLE-UNBOUNDED-001",
    "THREADS-001",
    "UNKNOWN-IMPORT-001",
    "UNKNOWN-SUMMARY-001",
    "WASI-CLOCK-001",
    "WASI-ENV-001",
    "WASI-FS-001",
    "WASI-FS-002",
    "WASI-NET-001",
    "WASI-NET-002",
    "WASI-POLL-001",
    "WASI-PROC-001",
    "WASI-PROC-002",
    "WASI-RAND-001",
    "WASI-SCHED-001",
    "WASI-UNKNOWN-001",
    "WASI2-CLOCK-001",
    "WASI2-ENV-001",
    "WASI2-FS-001",
    "WASI2-HTTP-001",
    "WASI2-IO-001",
    "WASI2-IO-002",
    "WASI2-NET-001",
    "WASI2-PROC-001",
    "WASI2-RAND-001",
    "WASI2-UNKNOWN-001",
];

/// Pull every rule-shaped string literal out of a Rust source file.
///
/// A rule identifier is upper-case alphanumerics and hyphens ending in a
/// three-digit number. This is used by the registry test rather than at run
/// time.
pub fn rule_ids_in_source(src: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let bytes: Vec<char> = src.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == '"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != '"' {
                if bytes[j] == '\\' {
                    j += 1;
                }
                j += 1;
            }
            let literal: String = bytes[start..j.min(bytes.len())].iter().collect();
            if looks_like_rule_id(&literal) {
                out.push(literal);
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out.sort();
    out.dedup();
    out
}

fn looks_like_rule_id(s: &str) -> bool {
    let Some((head, tail)) = s.rsplit_once('-') else {
        return false;
    };
    if tail.len() != 3 || !tail.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    head.len() >= 3
        && head.starts_with(|c: char| c.is_ascii_uppercase())
        && head
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
}
