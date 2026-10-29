//! Capability classification.

mod common;
use common::*;

use wasm_capability_audit::capability::{Basis, Capability, Severity};

fn hits(module_name: &str, field: &str) -> Vec<&'static str> {
    rules_of(&audit_import(module_name, field))
}

const WASI: &str = "wasi_snapshot_preview1";

#[test]
fn wasi_filesystem_paths_and_descriptors_are_separated() {
    assert!(hits(WASI, "path_open").contains(&"WASI-FS-001"));
    assert!(hits(WASI, "fd_read").contains(&"WASI-FS-002"));
    assert!(hits(WASI, "fd_write").contains(&"WASI-FS-002"));
    assert!(hits(WASI, "fd_prestat_get").contains(&"WASI-FS-002"));
    assert!(hits(WASI, "fd_prestat_dir_name").contains(&"WASI-FS-001"));
    for name in ["path_open", "fd_read", "fd_write", "fd_prestat_get"] {
        assert_eq!(
            caps_of(&audit_import(WASI, name)),
            vec!["filesystem"],
            "{name} should be filesystem"
        );
    }
}

#[test]
fn wasi_network_calls_are_classified() {
    for name in ["sock_accept", "sock_recv", "sock_send", "sock_shutdown"] {
        let r = audit_import(WASI, name);
        assert!(rules_of(&r).contains(&"WASI-NET-001"), "{name}");
        assert_eq!(caps_of(&r), vec!["network"]);
        let f = r
            .findings
            .iter()
            .find(|f| f.rule == "WASI-NET-001")
            .unwrap();
        assert_eq!(f.basis, Basis::Documented);
        assert_eq!(f.severity, Severity::High);
    }
}

#[test]
fn wasix_socket_extensions_are_pattern_matched_and_labelled() {
    let r = audit_import(WASI, "sock_connect");
    let f = r
        .findings
        .iter()
        .find(|f| f.rule == "WASI-NET-002")
        .unwrap();
    assert_eq!(f.basis, Basis::Pattern);
    assert_eq!(f.capability, Some(Capability::Network));
}

#[test]
fn wasi_process_clock_random_and_environment() {
    assert_eq!(caps_of(&audit_import(WASI, "proc_exit")), vec!["process"]);
    assert_eq!(caps_of(&audit_import(WASI, "proc_raise")), vec!["process"]);
    assert_eq!(caps_of(&audit_import(WASI, "sched_yield")), vec!["process"]);
    assert_eq!(
        caps_of(&audit_import(WASI, "clock_time_get")),
        vec!["clock"]
    );
    assert_eq!(caps_of(&audit_import(WASI, "clock_res_get")), vec!["clock"]);
    assert_eq!(
        caps_of(&audit_import(WASI, "random_get")),
        vec!["randomness"]
    );
    assert_eq!(
        caps_of(&audit_import(WASI, "environ_get")),
        vec!["environment"]
    );
    assert_eq!(
        caps_of(&audit_import(WASI, "args_get")),
        vec!["environment"]
    );
    assert_eq!(caps_of(&audit_import(WASI, "poll_oneoff")), vec!["polling"]);
}

#[test]
fn an_unknown_wasi_name_is_reported_as_unknown() {
    let r = audit_import(WASI, "fd_teleport");
    assert!(rules_of(&r).contains(&"WASI-UNKNOWN-001"));
    assert!(r.has_unknown_imports());
}

#[test]
fn wasi_unstable_is_treated_as_preview1() {
    assert!(hits("wasi_unstable", "path_open").contains(&"WASI-FS-001"));
}

#[test]
fn filesystem_plus_network_is_the_combination_finding() {
    let r = wasm_capability_audit::audit_bytes(&wasi_exfil(), "t").unwrap();
    let combo = r
        .findings
        .iter()
        .find(|f| f.rule == "COMBO-FS-NET-001")
        .expect("the combination should be reported");
    assert_eq!(combo.severity, Severity::Critical);
    assert_eq!(r.max_severity(), Some(Severity::Critical));
}

#[test]
fn filesystem_alone_is_not_the_combination_finding() {
    let r = audit_import(WASI, "path_open");
    assert!(!rules_of(&r).contains(&"COMBO-FS-NET-001"));
    assert_eq!(r.max_severity(), Some(Severity::High));
}

#[test]
fn wasi_component_model_interfaces_are_matched_on_their_names() {
    let cases = [
        ("wasi:filesystem/types@0.2.0", "filesystem"),
        ("wasi:sockets/tcp@0.2.0", "network"),
        ("wasi:http/outgoing-handler@0.2.0", "network"),
        ("wasi:clocks/wall-clock@0.2.0", "clock"),
        ("wasi:random/random@0.2.0", "randomness"),
        ("wasi:cli/environment@0.2.0", "environment"),
        ("wasi:cli/exit@0.2.0", "process"),
        ("wasi:cli/stdout@0.2.0", "host-io"),
        ("wasi:io/streams@0.2.0", "host-io"),
    ];
    for (module_name, cap) in cases {
        let r = audit_import(module_name, "some-function");
        assert_eq!(caps_of(&r), vec![cap], "{module_name}");
    }
}

#[test]
fn an_unmodelled_wasi_package_is_reported_as_unknown() {
    let r = audit_import("wasi:keyvalue/store@0.2.0", "get");
    assert!(rules_of(&r).contains(&"WASI2-UNKNOWN-001"));
    assert_eq!(caps_of(&r), vec!["unknown"]);
}

#[test]
fn emscripten_raw_syscalls_are_critical() {
    for name in ["__syscall_openat", "__syscall214", "__sys_mmap"] {
        let r = audit_import("env", name);
        let f = r
            .findings
            .iter()
            .find(|f| f.rule == "EMSC-SYSCALL-001")
            .unwrap_or_else(|| panic!("{name} should match the syscall rule"));
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.capability, Some(Capability::RawSyscall));
        assert_eq!(f.basis, Basis::Pattern);
    }
}

#[test]
fn emscripten_invoke_trampolines_are_indirect_dispatch() {
    let r = audit_import("env", "invoke_viii");
    assert_eq!(caps_of(&r), vec!["indirect-js-dispatch"]);
    assert_eq!(
        r.findings
            .iter()
            .find(|f| f.rule == "EMSC-INVOKE-001")
            .unwrap()
            .severity,
        Severity::High
    );
}

#[test]
fn emscripten_script_evaluation_is_critical() {
    for name in ["emscripten_run_script", "emscripten_asm_const_int"] {
        let r = audit_import("env", name);
        assert!(rules_of(&r).contains(&"EMSC-JSEVAL-001"), "{name}");
        assert!(caps_of(&r).contains(&"js-eval"));
    }
}

#[test]
fn emscripten_network_and_memory_shims() {
    assert!(hits("env", "emscripten_fetch").contains(&"EMSC-NET-001"));
    assert!(hits("env", "emscripten_websocket_new").contains(&"EMSC-NET-001"));
    assert!(hits("env", "emscripten_resize_heap").contains(&"EMSC-MEM-001"));
    assert!(hits("env", "emscripten_get_now").contains(&"EMSC-GENERIC-001"));
}

#[test]
fn wasm_bindgen_glue_is_arbitrary_javascript() {
    let r = audit_import("wbg", "__wbindgen_object_drop_ref");
    assert!(rules_of(&r).contains(&"BINDGEN-GLUE-001"));
    assert!(caps_of(&r).contains(&"js-arbitrary"));
}

#[test]
fn wasm_bindgen_symbols_name_the_javascript_they_reach() {
    let cases: [(&str, &str, &str); 6] = [
        ("__wbg_fetch_deadbeef", "BINDGEN-NET-001", "js-network"),
        ("__wbg_newnoargs_12345678", "BINDGEN-EVAL-001", "js-eval"),
        (
            "__wbg_localStorage_abcdef01",
            "BINDGEN-STORAGE-001",
            "js-storage",
        ),
        (
            "__wbg_postMessage_11223344",
            "BINDGEN-MSG-001",
            "js-messaging",
        ),
        (
            "__wbg_getRandomValues_55667788",
            "BINDGEN-CRYPTO-001",
            "js-crypto",
        ),
        ("__wbg_document_99aabbcc", "BINDGEN-DOM-001", "js-dom"),
    ];
    for (name, rule, cap) in cases {
        let r = audit_import("wbg", name);
        assert!(rules_of(&r).contains(&rule), "{name} -> {rule}");
        assert!(caps_of(&r).contains(&cap), "{name} -> {cap}");
        let f = r.findings.iter().find(|f| f.rule == rule).unwrap();
        assert_eq!(f.basis, Basis::Pattern, "{name} must be labelled a guess");
    }
}

#[test]
fn near_host_functions_are_classified_by_privilege() {
    let cases: [(&str, &str); 10] = [
        ("storage_write", "contract-storage-write"),
        ("storage_read", "contract-storage-read"),
        ("promise_batch_create", "contract-call"),
        ("promise_batch_action_transfer", "contract-value-transfer"),
        (
            "promise_batch_action_deploy_contract",
            "contract-code-deploy",
        ),
        (
            "promise_batch_action_add_key_with_full_access",
            "contract-account-keys",
        ),
        (
            "promise_batch_action_delete_account",
            "contract-self-destruct",
        ),
        ("random_seed", "contract-randomness"),
        ("block_timestamp", "contract-chain-context"),
        ("keccak256", "contract-crypto"),
    ];
    for (name, cap) in cases {
        let r = audit_import("env", name);
        assert!(caps_of(&r).contains(&cap), "env.{name} should be {cap}");
    }
}

#[test]
fn near_account_key_grants_and_deletion_are_critical() {
    for name in [
        "promise_batch_action_add_key_with_full_access",
        "promise_batch_action_delete_account",
    ] {
        let r = audit_import("env", name);
        assert_eq!(r.max_severity(), Some(Severity::Critical), "{name}");
    }
}

#[test]
fn cosmwasm_host_functions_are_classified() {
    let cases: [(&str, &str); 6] = [
        ("db_write", "contract-storage-write"),
        ("db_remove", "contract-storage-write"),
        ("db_read", "contract-storage-read"),
        ("query_chain", "contract-call"),
        ("secp256k1_verify", "contract-crypto"),
        ("debug", "debug-logging"),
    ];
    for (name, cap) in cases {
        let r = audit_import("env", name);
        assert!(caps_of(&r).contains(&cap), "env.{name} should be {cap}");
    }
}

#[test]
fn internet_computer_host_functions_are_classified() {
    let cases: [(&str, &str); 6] = [
        ("stable64_write", "contract-storage-write"),
        ("stable64_read", "contract-storage-read"),
        ("call_perform", "contract-call"),
        ("msg_cycles_accept128", "contract-value-transfer"),
        ("raw_rand", "contract-randomness"),
        ("msg_caller_copy", "contract-chain-context"),
    ];
    for (name, cap) in cases {
        let r = audit_import("ic0", name);
        assert!(caps_of(&r).contains(&cap), "ic0.{name} should be {cap}");
    }
}

#[test]
fn pallet_contracts_names_are_classified_but_labelled_pattern_based() {
    let cases: [(&str, &str, &str); 8] = [
        (
            "set_storage",
            "SEAL-STORAGE-WRITE-001",
            "contract-storage-write",
        ),
        (
            "get_storage",
            "SEAL-STORAGE-READ-001",
            "contract-storage-read",
        ),
        ("call", "SEAL-CALL-001", "contract-call"),
        (
            "delegate_call",
            "SEAL-DELEGATE-001",
            "contract-delegate-call",
        ),
        (
            "instantiate",
            "SEAL-INSTANTIATE-001",
            "contract-code-deploy",
        ),
        ("transfer", "SEAL-TRANSFER-001", "contract-value-transfer"),
        ("terminate", "SEAL-TERMINATE-001", "contract-self-destruct"),
        ("random", "SEAL-RANDOM-001", "contract-randomness"),
    ];
    for (name, rule, cap) in cases {
        let r = audit_import("seal0", name);
        assert!(rules_of(&r).contains(&rule), "seal0.{name}");
        assert!(caps_of(&r).contains(&cap), "seal0.{name} -> {cap}");
        let f = r.findings.iter().find(|f| f.rule == rule).unwrap();
        assert_eq!(f.basis, Basis::Pattern, "seal0.{name} must be a guess");
    }
}

#[test]
fn delegate_call_is_critical_everywhere_it_is_recognised() {
    for (module_name, name) in [
        ("seal0", "delegate_call"),
        ("ethereum", "callDelegate"),
        ("vm_hooks", "delegate_call_contract"),
    ] {
        let r = audit_import(module_name, name);
        assert_eq!(
            r.max_severity(),
            Some(Severity::Critical),
            "{module_name}.{name}"
        );
        assert!(caps_of(&r).contains(&"contract-delegate-call"));
    }
}

#[test]
fn ewasm_eei_names_are_classified() {
    for (name, cap) in [
        ("storageStore", "contract-storage-write"),
        ("storageLoad", "contract-storage-read"),
        ("call", "contract-call"),
        ("create", "contract-code-deploy"),
        ("selfDestruct", "contract-self-destruct"),
    ] {
        let r = audit_import("ethereum", name);
        assert!(caps_of(&r).contains(&cap), "ethereum.{name} -> {cap}");
    }
}

#[test]
fn stylus_style_names_fall_through_to_the_generic_patterns() {
    let cases: [(&str, &str); 5] = [
        ("storage_cache_bytes32", "contract-storage-write"),
        ("storage_load_bytes32", "contract-storage-read"),
        ("call_contract", "contract-call"),
        ("create2", "contract-code-deploy"),
        ("block_timestamp", "contract-chain-context"),
    ];
    for (name, cap) in cases {
        let r = audit_import("vm_hooks", name);
        assert!(caps_of(&r).contains(&cap), "vm_hooks.{name} -> {cap}");
        assert!(
            r.findings
                .iter()
                .all(|f| f.basis == Basis::Pattern || f.capability.is_none()),
            "vm_hooks.{name} hits should be labelled as guesses"
        );
    }
}

#[test]
fn process_execution_patterns_are_critical() {
    for name in ["posix_spawn", "do_exec", "popen_wrapper", "run_shell"] {
        let r = audit_import("host", name);
        assert!(caps_of(&r).contains(&"process"), "{name}");
        assert_eq!(r.max_severity(), Some(Severity::Critical), "{name}");
    }
}

#[test]
fn a_wholly_unrecognised_import_is_reported_as_unknown() {
    for name in ["frobnicate", "blit_region", "quux"] {
        let r = audit_import("acme_runtime", name);
        assert!(rules_of(&r).contains(&"UNKNOWN-IMPORT-001"), "{name}");
        assert_eq!(caps_of(&r), vec!["unknown"], "{name}");
        assert!(r.has_unknown_imports());
    }
}

#[test]
fn unknown_imports_add_a_summary_finding_that_caveats_the_capability_set() {
    let r = wasm_capability_audit::audit_bytes(&unknown_host(), "t").unwrap();
    let summary = r
        .findings
        .iter()
        .find(|f| f.rule == "UNKNOWN-SUMMARY-001")
        .expect("unknown imports should be summarised");
    assert!(summary.rationale.contains("lower bound"));
    assert_eq!(
        summary.evidence,
        vec!["3 unclassified import(s)".to_string()]
    );
}

#[test]
fn an_imported_memory_is_a_capability() {
    let bytes = module(&[section(
        2,
        &vector(&[import_memory("env", "memory", 1, None)]),
    )]);
    let r = wasm_capability_audit::audit_bytes(&bytes, "t").unwrap();
    assert!(rules_of(&r).contains(&"IMPORT-MEMORY-001"));
    assert_eq!(caps_of(&r), vec!["host-memory"]);
    assert_eq!(r.memories.len(), 1);
    assert!(r.memories[0].imported);
}

#[test]
fn an_imported_immutable_global_is_not_a_capability() {
    let bytes = module(&[section(
        2,
        &vector(&[import_global("env", "base", I32, false)]),
    )]);
    let r = wasm_capability_audit::audit_bytes(&bytes, "t").unwrap();
    assert!(r.capabilities.is_empty());
    assert!(!rules_of(&r).contains(&"IMPORT-GLOBAL-MUT-001"));
}

#[test]
fn exported_memory_mutable_global_and_table_are_all_flagged() {
    let r = wasm_capability_audit::audit_bytes(&bindgen_browser(), "t").unwrap();
    assert!(rules_of(&r).contains(&"EXPORT-MEMORY-001"));
    assert!(rules_of(&r).contains(&"EXPORT-MUT-GLOBAL-001"));
    assert!(r.exports_memory());
    assert!(r.exports_mutable_global());

    let t = wasm_capability_audit::audit_bytes(&indirect_dispatch(), "t").unwrap();
    assert!(rules_of(&t).contains(&"EXPORT-TABLE-001"));
}

#[test]
fn a_global_export_pointing_outside_the_global_space_is_reported() {
    let bytes = module(&[section(7, &vector(&[export("g", EXPORT_GLOBAL, 7)]))]);
    let r = wasm_capability_audit::audit_bytes(&bytes, "t").unwrap();
    assert!(rules_of(&r).contains(&"EXPORT-GLOBAL-UNRESOLVED-001"));
    assert_eq!(r.exports[0].mutable, None);
}

#[test]
fn memory_posture_findings() {
    let unbounded = wasm_capability_audit::audit_bytes(&wasi_exfil(), "t").unwrap();
    assert!(rules_of(&unbounded).contains(&"MEM-UNBOUNDED-001"));
    assert_eq!(unbounded.memory_ceiling_pages(), None);

    let bounded = wasm_capability_audit::audit_bytes(&wasi_clock_only(), "t").unwrap();
    assert!(!rules_of(&bounded).contains(&"MEM-UNBOUNDED-001"));
    assert_eq!(bounded.memory_ceiling_pages(), Some(16));

    let shared = module(&[section(5, &vector(&[limits(1, Some(2), true)]))]);
    let r = wasm_capability_audit::audit_bytes(&shared, "t").unwrap();
    assert!(rules_of(&r).contains(&"MEM-SHARED-001"));
    assert!(rules_of(&r).contains(&"THREADS-001"));

    let huge = module(&[section(5, &vector(&[limits(1, Some(65536), false)]))]);
    let r = wasm_capability_audit::audit_bytes(&huge, "t").unwrap();
    assert!(rules_of(&r).contains(&"MEM-LARGE-MAX-001"));
}

#[test]
fn start_function_and_indirect_calls_are_reported() {
    let r = wasm_capability_audit::audit_bytes(&wasi_exfil(), "t").unwrap();
    assert!(rules_of(&r).contains(&"START-FUNCTION-001"));
    assert!(rules_of(&r).contains(&"MEMORY-GROW-001"));

    let i = wasm_capability_audit::audit_bytes(&indirect_dispatch(), "t").unwrap();
    assert!(rules_of(&i).contains(&"CALL-INDIRECT-001"));
    assert_eq!(i.code.call_indirect, 1);
}

#[test]
fn a_module_with_no_imports_says_so() {
    let r = wasm_capability_audit::audit_bytes(&clean_compute(), "t").unwrap();
    assert!(rules_of(&r).contains(&"NO-IMPORTS-001"));
    assert!(r.capabilities.is_empty());
    assert!(!r.has_unknown_imports());
}

#[test]
fn the_storage_write_plus_call_combination_is_reported() {
    let r = wasm_capability_audit::audit_bytes(&near_contract(), "t").unwrap();
    let combo = r
        .findings
        .iter()
        .find(|f| f.rule == "COMBO-STORAGE-CALL-001")
        .expect("reentrancy surface should be reported");
    assert_eq!(combo.severity, Severity::High);
    assert!(combo.rationale.contains("says nothing about"));
}

#[test]
fn skipping_the_code_section_is_reported_rather_than_silently_zeroed() {
    let r = wasm_capability_audit::audit_bytes_with(
        &wasi_exfil(),
        "t",
        wasm_capability_audit::ParseOptions { scan_code: false },
    )
    .unwrap();
    assert!(rules_of(&r).contains(&"CODE-NOT-SCANNED-001"));
    assert!(!rules_of(&r).contains(&"MEMORY-GROW-001"));
    assert!(!r.code_scanned);
}

#[test]
fn a_name_section_is_reported() {
    let mut body = name("name");
    body.extend_from_slice(&[0u8; 12]);
    let bytes = module(&[section(0, &body)]);
    let r = wasm_capability_audit::audit_bytes(&bytes, "t").unwrap();
    assert!(rules_of(&r).contains(&"NAME-SECTION-001"));
    assert_eq!(r.custom_sections, vec![("name".to_string(), 12)]);
}

#[test]
fn host_environments_are_inferred_from_import_module_names() {
    let r = wasm_capability_audit::audit_bytes(&wasi_exfil(), "t").unwrap();
    assert_eq!(r.environments.len(), 1);
    assert_eq!(r.environments[0].name(), "WASI preview1");

    let b = wasm_capability_audit::audit_bytes(&bindgen_browser(), "t").unwrap();
    assert_eq!(b.environments[0].name(), "wasm-bindgen (browser)");

    let n = wasm_capability_audit::audit_bytes(&near_contract(), "t").unwrap();
    assert_eq!(n.environments[0].name(), "NEAR contract runtime");

    let u = wasm_capability_audit::audit_bytes(&unknown_host(), "t").unwrap();
    assert!(u.environments.is_empty());
}

#[test]
fn findings_are_ordered_by_severity_then_rule() {
    let r = wasm_capability_audit::audit_bytes(&wasi_exfil(), "t").unwrap();
    for pair in r.findings.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        assert!(
            a.severity > b.severity || (a.severity == b.severity && a.rule <= b.rule),
            "{} ({}) should not precede {} ({})",
            a.rule,
            a.severity,
            b.rule,
            b.severity
        );
    }
}

#[test]
fn evidence_lists_are_sorted_and_deduplicated() {
    let r = wasm_capability_audit::audit_bytes(&wasi_exfil(), "t").unwrap();
    for f in &r.findings {
        let mut sorted = f.evidence.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(f.evidence, sorted, "{} evidence not canonical", f.rule);
    }
}

#[test]
fn auditing_is_deterministic() {
    let a = wasm_capability_audit::audit_bytes(&wasi_exfil(), "t").unwrap();
    let b = wasm_capability_audit::audit_bytes(&wasi_exfil(), "t").unwrap();
    assert_eq!(a, b);
}

#[test]
fn every_capability_identifier_round_trips() {
    for c in Capability::ALL {
        assert_eq!(Capability::parse(c.id()), Some(c));
        assert!(!c.describes().is_empty());
    }
    assert_eq!(Capability::parse("not-a-capability"), None);
}

#[test]
fn every_severity_identifier_round_trips() {
    for s in Severity::ALL {
        assert_eq!(Severity::parse(s.name()), Some(s));
        assert_eq!(Severity::parse(&s.name().to_uppercase()), Some(s));
    }
    assert_eq!(Severity::parse("catastrophic"), None);
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::Info < Severity::Low);
}
