//! Every documented rule is demonstrably reachable.
//!
//! A rule registry and a README table are only honest if every entry in them
//! can actually fire. This test drives one input per rule and asserts that the
//! union of everything emitted is exactly `rules::RULE_IDS` — so a rule that
//! becomes unreachable through a refactor fails the build, and a rule cannot
//! be documented without a worked example behind it.

mod common;
use common::*;

use wasm_capability_audit::rules::RULE_IDS;
use wasm_capability_audit::{audit_bytes, audit_bytes_with, ParseOptions, Report};

/// One import, as `(module, field)`, chosen to exercise exactly one rule
/// family. The comment on each group names the rules it is there for.
const IMPORT_PROBES: &[(&str, &str)] = &[
    // WASI preview1.
    ("wasi_snapshot_preview1", "path_open"),
    ("wasi_snapshot_preview1", "fd_read"),
    ("wasi_snapshot_preview1", "sock_send"),
    ("wasi_snapshot_preview1", "sock_connect"),
    ("wasi_snapshot_preview1", "proc_exit"),
    ("wasi_snapshot_preview1", "proc_raise"),
    ("wasi_snapshot_preview1", "sched_yield"),
    ("wasi_snapshot_preview1", "clock_time_get"),
    ("wasi_snapshot_preview1", "random_get"),
    ("wasi_snapshot_preview1", "environ_get"),
    ("wasi_snapshot_preview1", "poll_oneoff"),
    ("wasi_snapshot_preview1", "fd_teleport"),
    // WASI 0.2 component-model interface names.
    ("wasi:filesystem/types@0.2.0", "open-at"),
    ("wasi:sockets/tcp@0.2.0", "start-connect"),
    ("wasi:http/outgoing-handler@0.2.0", "handle"),
    ("wasi:clocks/monotonic-clock@0.2.0", "now"),
    ("wasi:random/random@0.2.0", "get-random-bytes"),
    ("wasi:cli/environment@0.2.0", "get-environment"),
    ("wasi:cli/exit@0.2.0", "exit-with-code"),
    ("wasi:cli/stdout@0.2.0", "get-stdout"),
    ("wasi:io/streams@0.2.0", "blocking-write-and-flush"),
    ("wasi:keyvalue/store@0.2.0", "get"),
    // Emscripten and toolchain shims.
    ("env", "__syscall_openat"),
    ("env", "invoke_viii"),
    ("env", "emscripten_run_script"),
    ("env", "emscripten_fetch"),
    ("env", "emscripten_resize_heap"),
    ("env", "emscripten_get_now"),
    ("env", "abort"),
    // wasm-bindgen.
    ("wbg", "__wbindgen_throw"),
    ("wbg", "__wbg_fetch_0011aabb"),
    ("wbg", "__wbg_newnoargs_0011aabb"),
    ("wbg", "__wbg_localStorage_0011aabb"),
    ("wbg", "__wbg_postMessage_0011aabb"),
    ("wbg", "__wbg_getRandomValues_0011aabb"),
    ("wbg", "__wbg_document_0011aabb"),
    // NEAR.
    ("env", "storage_write"),
    ("env", "storage_read"),
    ("env", "promise_batch_create"),
    ("env", "promise_batch_action_transfer"),
    ("env", "promise_batch_action_deploy_contract"),
    ("env", "promise_batch_action_add_key_with_full_access"),
    ("env", "promise_batch_action_delete_account"),
    ("env", "random_seed"),
    ("env", "block_timestamp"),
    ("env", "keccak256"),
    ("env", "read_register"),
    ("env", "log_utf8"),
    ("env", "panic_utf8"),
    ("env", "gas"),
    // CosmWasm.
    ("env", "db_write"),
    ("env", "db_read"),
    ("env", "query_chain"),
    ("env", "addr_validate"),
    ("env", "secp256k1_verify"),
    ("env", "debug"),
    // Internet Computer.
    ("ic0", "stable64_write"),
    ("ic0", "stable64_read"),
    ("ic0", "call_perform"),
    ("ic0", "msg_cycles_accept128"),
    ("ic0", "raw_rand"),
    ("ic0", "msg_caller_copy"),
    ("ic0", "certified_data_set"),
    ("ic0", "debug_print"),
    // Substrate pallet-contracts / ink!.
    ("seal0", "set_storage"),
    ("seal0", "get_storage"),
    ("seal0", "call"),
    ("seal0", "delegate_call"),
    ("seal0", "instantiate"),
    ("seal0", "transfer"),
    ("seal0", "terminate"),
    ("seal0", "random"),
    // ewasm.
    ("ethereum", "storageStore"),
    ("ethereum", "storageLoad"),
    ("ethereum", "callCode"),
    ("ethereum", "callDelegate"),
    ("ethereum", "create"),
    ("ethereum", "selfDestruct"),
    // Generic patterns, in a host interface the tool does not model.
    ("acme", "delegate_call_raw"),
    ("acme", "storage_cache_word"),
    ("acme", "storage_load_word"),
    ("acme", "call_contract"),
    ("acme", "transfer_value"),
    ("acme", "deploy_code"),
    ("acme", "selfdestruct_now"),
    ("acme", "get_random_bytes"),
    ("acme", "keccak_f1600"),
    ("acme", "block_number"),
    ("acme", "tcp_connect"),
    ("acme", "open_file_at"),
    ("acme", "do_exec"),
    ("acme", "eval_source"),
    ("acme", "print_line"),
    // The unknown.
    ("acme", "frobnicate"),
];

fn collect(report: &Report, into: &mut Vec<String>) {
    for f in &report.findings {
        if !into.contains(&f.rule.to_string()) {
            into.push(f.rule.to_string());
        }
    }
}

/// Module-level inputs, each built to trigger posture rules that no single
/// import can reach.
fn posture_inputs() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for (name, bytes) in all() {
        v.push((name, bytes));
    }
    // An imported memory, table, mutable global and exception tag.
    let mut tag = name("host");
    tag.extend_from_slice(&name("oops"));
    tag.extend_from_slice(&[0x04, 0x00]);
    tag.extend_from_slice(&uleb(0));
    let mut imported_table = name("host");
    imported_table.extend_from_slice(&name("table"));
    imported_table.push(0x01);
    imported_table.push(FUNCREF);
    imported_table.extend_from_slice(&limits(1, Some(1), false));
    v.push((
        "imported-externals",
        module(&[
            section(1, &vector(&[func_type(&[], &[])])),
            section(
                2,
                &vector(&[
                    import_memory("host", "memory", 1, Some(2)),
                    imported_table,
                    import_global("host", "tick", I32, true),
                    tag,
                ]),
            ),
        ]),
    ));
    // Shared memory, an unbounded table, a nominal maximum, a global export
    // pointing nowhere, and a name section.
    let mut unbounded_table = vec![FUNCREF];
    unbounded_table.extend_from_slice(&limits(1, None, false));
    let mut name_section = name("name");
    name_section.extend_from_slice(&[0u8; 4]);
    v.push((
        "posture-grab-bag",
        module(&[
            section(0, &name_section),
            section(4, &vector(&[unbounded_table])),
            section(5, &vector(&[limits(1, Some(65536), true)])),
            section(7, &vector(&[export("g", EXPORT_GLOBAL, 9)])),
        ]),
    ));
    // Bulk-memory and reference-type instructions in a body.
    v.push((
        "instruction-families",
        module_with_body(&[0xfc, 0x0b, 0x00, 0xd0, 0x70, 0x1a]),
    ));
    v
}

#[test]
fn every_registered_rule_is_reachable() {
    let mut seen: Vec<String> = Vec::new();
    for (module_name, field) in IMPORT_PROBES {
        collect(&audit_import(module_name, field), &mut seen);
    }
    for (label, bytes) in posture_inputs() {
        let r = audit_bytes(&bytes, label).unwrap_or_else(|e| panic!("{label}: {e}"));
        collect(&r, &mut seen);
    }
    // `--no-code-scan` is the only way to reach CODE-NOT-SCANNED-001.
    let r = audit_bytes_with(&wasi_exfil(), "t", ParseOptions { scan_code: false }).unwrap();
    collect(&r, &mut seen);

    let mut unreached: Vec<&str> = RULE_IDS
        .iter()
        .copied()
        .filter(|id| !seen.contains(&id.to_string()))
        .collect();
    unreached.sort_unstable();
    assert!(
        unreached.is_empty(),
        "these registered rules were never emitted by any probe, so they are \
         either unreachable or undemonstrated: {unreached:?}"
    );

    let mut unregistered: Vec<&String> = seen
        .iter()
        .filter(|id| !RULE_IDS.contains(&id.as_str()))
        .collect();
    unregistered.sort();
    assert!(
        unregistered.is_empty(),
        "these rules fired but are not registered: {unregistered:?}"
    );
}

#[test]
fn the_abort_shim_is_classified_in_any_host_module() {
    // Not inside a WASI module: there `abort` is not a WASI function, and
    // "an unrecognised name in a WASI module" is the more accurate answer.
    for module_name in ["env", "acme", "host", "ic0"] {
        let r = audit_import(module_name, "abort");
        assert!(
            caps_of(&r).contains(&"process"),
            "{module_name}.abort should be a process capability, got {:?}",
            caps_of(&r)
        );
        assert!(
            !r.has_unknown_imports(),
            "{module_name}.abort should not be unknown"
        );
    }
    let in_wasi = audit_import("wasi_snapshot_preview1", "abort");
    assert_eq!(caps_of(&in_wasi), vec!["unknown"]);
    assert!(rules_of(&in_wasi).contains(&"WASI-UNKNOWN-001"));
}

#[test]
fn no_probe_produces_an_unregistered_capability() {
    use wasm_capability_audit::Capability;
    for (module_name, field) in IMPORT_PROBES {
        let r = audit_import(module_name, field);
        for c in &r.capabilities {
            assert!(
                Capability::ALL.contains(c),
                "{module_name}.{field} produced an unlisted capability"
            );
        }
    }
}
