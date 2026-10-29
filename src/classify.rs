//! Import classification.
//!
//! Each rule turns an import into a capability, a severity and a reason. Two
//! things about the rule set are worth being explicit about, because they are
//! what makes the output trustworthy or not:
//!
//! * **Basis.** A rule is `documented` when it matches an exact name in an
//!   interface this tool models from that interface's own definition, and
//!   `pattern` when it matches a prefix or a substring. A pattern rule is a
//!   useful guess and is labelled as one. Nothing here claims more confidence
//!   than the match deserves.
//! * **The unknown is reported.** An import that matches nothing produces an
//!   `unknown` capability finding. Silence would be the one genuinely
//!   dangerous output for a tool like this.

use crate::capability::{Basis, Capability, Severity};
use crate::module::{Import, ImportDesc};

/// One rule firing on one import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub rule: &'static str,
    pub capability: Capability,
    pub severity: Severity,
    pub basis: Basis,
    pub rationale: &'static str,
}

const fn hit(
    rule: &'static str,
    capability: Capability,
    severity: Severity,
    basis: Basis,
    rationale: &'static str,
) -> Hit {
    Hit {
        rule,
        capability,
        severity,
        basis,
        rationale,
    }
}

/// The host environment a module appears to be built for, inferred from the
/// names of the modules it imports from. This is a hint for the reader; the
/// capability findings do not depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostEnvironment {
    WasiPreview1,
    WasiPreview2,
    Emscripten,
    WasmBindgen,
    Near,
    CosmWasm,
    PalletContracts,
    InternetComputer,
    Ewasm,
    ArbitrumStylus,
}

impl HostEnvironment {
    /// Name used in reports.
    pub fn name(self) -> &'static str {
        match self {
            HostEnvironment::WasiPreview1 => "WASI preview1",
            HostEnvironment::WasiPreview2 => "WASI 0.2 (component model)",
            HostEnvironment::Emscripten => "Emscripten / JS glue",
            HostEnvironment::WasmBindgen => "wasm-bindgen (browser)",
            HostEnvironment::Near => "NEAR contract runtime",
            HostEnvironment::CosmWasm => "CosmWasm contract runtime",
            HostEnvironment::PalletContracts => "Substrate pallet-contracts / ink!",
            HostEnvironment::InternetComputer => "Internet Computer (ic0)",
            HostEnvironment::Ewasm => "ewasm EEI (deprecated)",
            HostEnvironment::ArbitrumStylus => "Arbitrum Stylus (vm_hooks)",
        }
    }
}

const WASI_MODULES: [&str; 3] = [
    "wasi_snapshot_preview1",
    "wasi_unstable",
    "wasi_snapshot_preview2",
];

const WASI_FS_PATH: [&str; 11] = [
    "path_create_directory",
    "path_filestat_get",
    "path_filestat_set_times",
    "path_link",
    "path_open",
    "path_readlink",
    "path_remove_directory",
    "path_rename",
    "path_symlink",
    "path_unlink_file",
    "fd_prestat_dir_name",
];

const WASI_FS_FD: [&str; 20] = [
    "fd_advise",
    "fd_allocate",
    "fd_close",
    "fd_datasync",
    "fd_fdstat_get",
    "fd_fdstat_set_flags",
    "fd_fdstat_set_rights",
    "fd_filestat_get",
    "fd_filestat_set_size",
    "fd_filestat_set_times",
    "fd_pread",
    "fd_prestat_get",
    "fd_pwrite",
    "fd_read",
    "fd_readdir",
    "fd_renumber",
    "fd_seek",
    "fd_sync",
    "fd_tell",
    "fd_write",
];

const WASI_NET: [&str; 4] = ["sock_accept", "sock_recv", "sock_send", "sock_shutdown"];

const WASI_CLOCK: [&str; 2] = ["clock_res_get", "clock_time_get"];

const WASI_ENV: [&str; 4] = [
    "args_get",
    "args_sizes_get",
    "environ_get",
    "environ_sizes_get",
];

/// NEAR host functions. Grouped by what the function lets a contract do.
const NEAR_STORAGE_WRITE: [&str; 2] = ["storage_write", "storage_remove"];
const NEAR_STORAGE_READ: [&str; 6] = [
    "storage_read",
    "storage_has_key",
    "storage_iter_prefix",
    "storage_iter_range",
    "storage_iter_next",
    "storage_usage",
];
const NEAR_PROMISE_CALL: [&str; 11] = [
    "promise_create",
    "promise_then",
    "promise_and",
    "promise_batch_create",
    "promise_batch_then",
    "promise_batch_action_function_call",
    "promise_batch_action_function_call_weight",
    "promise_results_count",
    "promise_result",
    "promise_return",
    "promise_yield_create",
];
const NEAR_TRANSFER: [&str; 3] = [
    "promise_batch_action_transfer",
    "promise_batch_action_stake",
    "promise_batch_action_unstake",
];
const NEAR_DEPLOY: [&str; 2] = [
    "promise_batch_action_deploy_contract",
    "promise_batch_action_create_account",
];
const NEAR_KEYS: [&str; 3] = [
    "promise_batch_action_add_key_with_full_access",
    "promise_batch_action_add_key_with_function_call",
    "promise_batch_action_delete_key",
];
const NEAR_CONTEXT: [&str; 16] = [
    "current_account_id",
    "signer_account_id",
    "signer_account_pk",
    "predecessor_account_id",
    "input",
    "block_index",
    "block_height",
    "block_timestamp",
    "epoch_height",
    "account_balance",
    "account_locked_balance",
    "attached_deposit",
    "prepaid_gas",
    "used_gas",
    "validator_stake",
    "validator_total_stake",
];
const NEAR_CRYPTO: [&str; 9] = [
    "sha256",
    "keccak256",
    "keccak512",
    "ripemd160",
    "ecrecover",
    "ed25519_verify",
    "alt_bn128_g1_multiexp",
    "alt_bn128_g1_sum",
    "alt_bn128_pairing_check",
];
const NEAR_REGISTERS: [&str; 4] = [
    "read_register",
    "write_register",
    "register_len",
    "value_return",
];
const NEAR_LOG: [&str; 2] = ["log_utf8", "log_utf16"];
const NEAR_ABORT: [&str; 3] = ["panic", "panic_utf8", "abort"];

/// CosmWasm host functions.
const COSMWASM_DB_WRITE: [&str; 2] = ["db_write", "db_remove"];
const COSMWASM_DB_READ: [&str; 3] = ["db_read", "db_scan", "db_next"];
const COSMWASM_ADDR: [&str; 3] = ["addr_validate", "addr_canonicalize", "addr_humanize"];
const COSMWASM_CRYPTO: [&str; 7] = [
    "secp256k1_verify",
    "secp256k1_recover_pubkey",
    "secp256r1_verify",
    "secp256r1_recover_pubkey",
    "ed25519_verify",
    "ed25519_batch_verify",
    "bls12_381_pairing_equality",
];

/// Internet Computer `ic0` host functions.
const IC0_STABLE_WRITE: [&str; 4] = [
    "stable_write",
    "stable64_write",
    "stable_grow",
    "stable64_grow",
];
const IC0_STABLE_READ: [&str; 4] = [
    "stable_read",
    "stable64_read",
    "stable_size",
    "stable64_size",
];
const IC0_CALL: [&str; 8] = [
    "call_new",
    "call_perform",
    "call_data_append",
    "call_on_cleanup",
    "call_with_best_effort_response",
    "msg_reply",
    "msg_reply_data_append",
    "msg_reject",
];
const IC0_CYCLES: [&str; 8] = [
    "call_cycles_add",
    "call_cycles_add128",
    "msg_cycles_accept",
    "msg_cycles_accept128",
    "msg_cycles_available",
    "msg_cycles_available128",
    "msg_cycles_refunded",
    "msg_cycles_refunded128",
];
const IC0_CONTEXT: [&str; 10] = [
    "msg_caller_copy",
    "msg_caller_size",
    "msg_arg_data_copy",
    "msg_arg_data_size",
    "canister_self_copy",
    "canister_self_size",
    "canister_cycle_balance",
    "canister_cycle_balance128",
    "canister_status",
    "time",
];

/// Substrate `pallet-contracts` / ink! names, matched by name rather than
/// modelled from a version of the pallet: the set shifts between versions, so
/// every hit here is reported as pattern-based.
const SEAL_STORAGE_WRITE: [&str; 6] = [
    "set_storage",
    "clear_storage",
    "take_storage",
    "seal_set_storage",
    "seal_clear_storage",
    "seal_take_storage",
];
const SEAL_STORAGE_READ: [&str; 4] = [
    "get_storage",
    "contains_storage",
    "seal_get_storage",
    "seal_contains_storage",
];
const SEAL_CALL: [&str; 4] = [
    "call",
    "seal_call",
    "call_chain_extension",
    "seal_call_chain_extension",
];
const SEAL_DELEGATE: [&str; 2] = ["delegate_call", "seal_delegate_call"];
const SEAL_INSTANTIATE: [&str; 2] = ["instantiate", "seal_instantiate"];
const SEAL_TRANSFER: [&str; 2] = ["transfer", "seal_transfer"];
const SEAL_TERMINATE: [&str; 2] = ["terminate", "seal_terminate"];
const SEAL_RANDOM: [&str; 2] = ["random", "seal_random"];

/// The deprecated ewasm Ethereum Environment Interface, matched by name.
const EWASM_STORE: [&str; 1] = ["storageStore"];
const EWASM_LOAD: [&str; 1] = ["storageLoad"];
const EWASM_CALL: [&str; 3] = ["call", "callCode", "callStatic"];
const EWASM_DELEGATE: [&str; 1] = ["callDelegate"];
const EWASM_CREATE: [&str; 1] = ["create"];
const EWASM_DESTRUCT: [&str; 1] = ["selfDestruct"];

/// Browser-side JavaScript identifiers worth naming when they appear inside a
/// `wasm-bindgen` import symbol. Matched as substrings of the lower-cased
/// import name, so every hit is pattern-based.
const JS_NET_TOKENS: [&str; 6] = [
    "fetch",
    "xmlhttprequest",
    "websocket",
    "eventsource",
    "sendbeacon",
    "requestinit",
];
const JS_EVAL_TOKENS: [&str; 4] = ["eval", "importscripts", "newfunction", "newnoargs"];
const JS_STORAGE_TOKENS: [&str; 5] = [
    "localstorage",
    "sessionstorage",
    "indexeddb",
    "opendatabase",
    "cookie",
];
const JS_MSG_TOKENS: [&str; 5] = [
    "postmessage",
    "broadcastchannel",
    "messagechannel",
    "messageport",
    "worker",
];
const JS_CRYPTO_TOKENS: [&str; 3] = ["getrandomvalues", "subtle", "crypto"];
const JS_DOM_TOKENS: [&str; 6] = [
    "document",
    "innerhtml",
    "createelement",
    "queryselector",
    "appendchild",
    "location",
];

fn any_token(haystack: &str, tokens: &[&str]) -> bool {
    tokens.iter().any(|t| haystack.contains(t))
}

/// Infer the host environments a module's imports suggest.
pub fn detect_environments(imports: &[Import]) -> Vec<HostEnvironment> {
    let mut out: Vec<HostEnvironment> = Vec::new();
    let push = |e: HostEnvironment, out: &mut Vec<HostEnvironment>| {
        if !out.contains(&e) {
            out.push(e);
        }
    };
    for i in imports {
        let m = i.module.as_str();
        if WASI_MODULES.contains(&m) {
            push(HostEnvironment::WasiPreview1, &mut out);
        }
        if m.starts_with("wasi:") {
            push(HostEnvironment::WasiPreview2, &mut out);
        }
        if m == "wbg" || i.name.starts_with("__wbg_") || i.name.starts_with("__wbindgen_") {
            push(HostEnvironment::WasmBindgen, &mut out);
        }
        if i.name.starts_with("emscripten_")
            || i.name.starts_with("invoke_")
            || i.name.starts_with("__syscall")
        {
            push(HostEnvironment::Emscripten, &mut out);
        }
        if m == "ic0" {
            push(HostEnvironment::InternetComputer, &mut out);
        }
        if m == "ethereum" {
            push(HostEnvironment::Ewasm, &mut out);
        }
        if m == "vm_hooks" {
            push(HostEnvironment::ArbitrumStylus, &mut out);
        }
        if m.starts_with("seal") {
            push(HostEnvironment::PalletContracts, &mut out);
        }
        if m == "env" {
            let n = i.name.as_str();
            if NEAR_PROMISE_CALL.contains(&n)
                || NEAR_STORAGE_WRITE.contains(&n)
                || NEAR_STORAGE_READ.contains(&n)
                || NEAR_REGISTERS.contains(&n)
            {
                push(HostEnvironment::Near, &mut out);
            }
            if COSMWASM_DB_READ.contains(&n) || COSMWASM_DB_WRITE.contains(&n) {
                push(HostEnvironment::CosmWasm, &mut out);
            }
        }
    }
    out.sort();
    out
}

/// Classify one import. The result is ordered and deduplicated by the caller.
pub fn classify_import(import: &Import) -> Vec<Hit> {
    match &import.desc {
        ImportDesc::Func(_) => classify_function_import(&import.module, &import.name),
        ImportDesc::Memory(_) => vec![hit(
            "IMPORT-MEMORY-001",
            Capability::HostMemory,
            Severity::Medium,
            Basis::Documented,
            "the host supplies this module's linear memory, so whatever the module \
             stores is already readable and writable by the host and by anything \
             else holding that memory",
        )],
        ImportDesc::Table(_) => vec![hit(
            "IMPORT-TABLE-001",
            Capability::HostTable,
            Severity::Medium,
            Basis::Documented,
            "the host supplies a function table; entries the host installs become \
             call targets inside this module",
        )],
        ImportDesc::Global(g) => {
            if g.mutable {
                vec![hit(
                    "IMPORT-GLOBAL-MUT-001",
                    Capability::HostMutableGlobal,
                    Severity::Medium,
                    Basis::Documented,
                    "an imported mutable global is a two-way channel: the host can \
                     change it between calls and the module can change what the host reads",
                )]
            } else {
                Vec::new()
            }
        }
        ImportDesc::Tag(_) => vec![hit(
            "IMPORT-TAG-001",
            Capability::HostTag,
            Severity::Info,
            Basis::Documented,
            "an imported exception tag lets the host throw into this module",
        )],
    }
}

fn classify_function_import(module: &str, name: &str) -> Vec<Hit> {
    if let Some(hits) = classify_wasi(module, name) {
        return hits;
    }
    if let Some(hits) = classify_wasi_component(module, name) {
        return hits;
    }
    if let Some(hits) = classify_contract(module, name) {
        return hits;
    }
    if let Some(hits) = classify_js(module, name) {
        return hits;
    }
    let generic = classify_generic(name);
    if !generic.is_empty() {
        return generic;
    }
    vec![hit(
        "UNKNOWN-IMPORT-001",
        Capability::Unknown,
        Severity::Medium,
        Basis::Pattern,
        "no rule matched this import, so what the host grants through it is unknown; \
         an unrecognised host function is reviewed by hand or it is not reviewed at all",
    )]
}

fn classify_wasi(module: &str, name: &str) -> Option<Vec<Hit>> {
    if !WASI_MODULES.contains(&module) {
        return None;
    }
    let mut out = Vec::new();
    if WASI_FS_PATH.contains(&name) {
        out.push(hit(
            "WASI-FS-001",
            Capability::Filesystem,
            Severity::High,
            Basis::Documented,
            "resolves and opens paths relative to the directories the host preopened, \
             which is the grant that makes this module a filesystem client",
        ));
    } else if WASI_FS_FD.contains(&name) {
        out.push(hit(
            "WASI-FS-002",
            Capability::Filesystem,
            Severity::High,
            Basis::Documented,
            "reads or writes an open descriptor; descriptors 0-2 are stdio, and any \
             other descriptor comes from a preopened directory",
        ));
    }
    if WASI_NET.contains(&name) {
        out.push(hit(
            "WASI-NET-001",
            Capability::Network,
            Severity::High,
            Basis::Documented,
            "accepts, reads or writes a socket the host granted, which is an outbound \
             or inbound path off the machine",
        ));
    } else if name.starts_with("sock_") {
        out.push(hit(
            "WASI-NET-002",
            Capability::Network,
            Severity::High,
            Basis::Pattern,
            "a sock_* name outside the four calls preview1 defines, so most likely a \
             WASIX or runtime-specific socket extension with full connect/bind semantics",
        ));
    }
    match name {
        "proc_exit" => out.push(hit(
            "WASI-PROC-001",
            Capability::Process,
            Severity::Low,
            Basis::Documented,
            "ends the instance, which in a multi-tenant host is an availability concern \
             rather than a confidentiality one",
        )),
        "proc_raise" => out.push(hit(
            "WASI-PROC-002",
            Capability::Process,
            Severity::Medium,
            Basis::Documented,
            "raises a signal in the host process",
        )),
        "sched_yield" => out.push(hit(
            "WASI-SCHED-001",
            Capability::Process,
            Severity::Info,
            Basis::Documented,
            "yields the scheduler; usable as a timing primitive",
        )),
        "random_get" => out.push(hit(
            "WASI-RAND-001",
            Capability::Randomness,
            Severity::Low,
            Basis::Documented,
            "draws bytes from the host entropy source",
        )),
        "poll_oneoff" => out.push(hit(
            "WASI-POLL-001",
            Capability::Polling,
            Severity::Low,
            Basis::Documented,
            "waits on host events; combined with sockets or files it is how a module \
             runs an event loop",
        )),
        _ => {}
    }
    if WASI_CLOCK.contains(&name) {
        out.push(hit(
            "WASI-CLOCK-001",
            Capability::Clock,
            Severity::Low,
            Basis::Documented,
            "reads a host clock, which is both a fingerprinting and a timing-side-channel \
             primitive",
        ));
    }
    if WASI_ENV.contains(&name) {
        out.push(hit(
            "WASI-ENV-001",
            Capability::Environment,
            Severity::Medium,
            Basis::Documented,
            "reads the environment and argv, which in most deployments is where \
             credentials are",
        ));
    }
    if out.is_empty() {
        out.push(hit(
            "WASI-UNKNOWN-001",
            Capability::Unknown,
            Severity::Medium,
            Basis::Pattern,
            "imported from a WASI module name but not a function this tool knows, so \
             it is either a newer snapshot or a runtime-specific extension",
        ));
    }
    Some(out)
}

fn classify_wasi_component(module: &str, name: &str) -> Option<Vec<Hit>> {
    let rest = module.strip_prefix("wasi:")?;
    // `wasi:filesystem/types@0.2.0` -> interface path `filesystem/types`.
    let path = rest.split('@').next().unwrap_or(rest);
    let mut parts = path.split('/');
    let package = parts.next().unwrap_or("");
    let interface = parts.next().unwrap_or("");
    let cap = match (package, interface) {
        ("filesystem", _) => Some((
            "WASI2-FS-001",
            Capability::Filesystem,
            Severity::High,
            "the wasi:filesystem package; the module holds directory and file handles",
        )),
        ("sockets", _) => Some((
            "WASI2-NET-001",
            Capability::Network,
            Severity::High,
            "the wasi:sockets package; the module can open sockets directly",
        )),
        ("http", _) => Some((
            "WASI2-HTTP-001",
            Capability::Network,
            Severity::High,
            "the wasi:http package; the module can issue or serve HTTP requests",
        )),
        ("clocks", _) => Some((
            "WASI2-CLOCK-001",
            Capability::Clock,
            Severity::Low,
            "the wasi:clocks package",
        )),
        ("random", _) => Some((
            "WASI2-RAND-001",
            Capability::Randomness,
            Severity::Low,
            "the wasi:random package",
        )),
        ("cli", "environment") => Some((
            "WASI2-ENV-001",
            Capability::Environment,
            Severity::Medium,
            "wasi:cli/environment exposes the environment and argv",
        )),
        ("cli", "exit") => Some((
            "WASI2-PROC-001",
            Capability::Process,
            Severity::Low,
            "wasi:cli/exit ends the instance",
        )),
        ("cli", _) => Some((
            "WASI2-IO-001",
            Capability::HostIo,
            Severity::Low,
            "a wasi:cli stream or terminal interface",
        )),
        ("io", _) => Some((
            "WASI2-IO-002",
            Capability::HostIo,
            Severity::Low,
            "the wasi:io package carries the byte streams every other interface hands out",
        )),
        _ => None,
    };
    let _ = name;
    Some(match cap {
        Some((rule, capability, severity, rationale)) => vec![Hit {
            rule,
            capability,
            severity,
            basis: Basis::Pattern,
            rationale,
        }],
        None => vec![hit(
            "WASI2-UNKNOWN-001",
            Capability::Unknown,
            Severity::Medium,
            Basis::Pattern,
            "a wasi:* interface name this tool does not model",
        )],
    })
}

fn classify_js(module: &str, name: &str) -> Option<Vec<Hit>> {
    let lower = name.to_ascii_lowercase();
    let is_bindgen =
        module == "wbg" || name.starts_with("__wbg_") || name.starts_with("__wbindgen_");
    let is_emscripten = name.starts_with("emscripten_")
        || name.starts_with("invoke_")
        || name.starts_with("__syscall")
        || name.starts_with("__sys_");
    // The abort and exit shims are emitted by every C, C++ and Rust toolchain
    // that targets WebAssembly, not only by Emscripten, and they appear under
    // plain names in whatever module the toolchain chose. They are classified
    // here so that `env.abort` does not fall through to "unknown".
    let is_runtime_shim = matches!(
        name,
        "abort" | "_abort_js" | "__assert_fail" | "exit" | "_exit"
    );
    if !is_bindgen && !is_emscripten && !is_runtime_shim {
        return None;
    }
    let mut out = Vec::new();

    if name.starts_with("__syscall") || name.starts_with("__sys_") {
        out.push(hit(
            "EMSC-SYSCALL-001",
            Capability::RawSyscall,
            Severity::Critical,
            Basis::Pattern,
            "an Emscripten raw-syscall shim: the module is not asking for a narrow \
             capability but for a kernel interface, and whatever the host wires behind \
             it is the real sandbox boundary",
        ));
    }
    if name.starts_with("invoke_") {
        out.push(hit(
            "EMSC-INVOKE-001",
            Capability::IndirectJsDispatch,
            Severity::High,
            Basis::Pattern,
            "an Emscripten invoke_* trampoline: the module calls a host function-table \
             entry chosen at run time, so the call target is data rather than code",
        ));
    }
    if name.starts_with("emscripten_run_script") || name.starts_with("emscripten_asm_const") {
        out.push(hit(
            "EMSC-JSEVAL-001",
            Capability::JsEval,
            Severity::Critical,
            Basis::Documented,
            "Emscripten's script-evaluation shim: the module hands JavaScript source to \
             the host and the host runs it, which collapses the sandbox entirely",
        ));
    }
    if name.starts_with("emscripten_fetch")
        || name.starts_with("emscripten_wget")
        || name.starts_with("emscripten_async_wget")
        || name.starts_with("emscripten_websocket")
    {
        out.push(hit(
            "EMSC-NET-001",
            Capability::JsNetwork,
            Severity::High,
            Basis::Pattern,
            "an Emscripten network shim, implemented over fetch, XHR or WebSocket",
        ));
    }
    if matches!(
        name,
        "emscripten_resize_heap" | "emscripten_memcpy_big" | "emscripten_memcpy_js"
    ) {
        out.push(hit(
            "EMSC-MEM-001",
            Capability::HostMemory,
            Severity::Low,
            Basis::Documented,
            "an Emscripten memory shim; the host grows or copies the module's heap",
        ));
    }
    if is_runtime_shim {
        out.push(hit(
            "SHIM-ABORT-001",
            Capability::Process,
            Severity::Low,
            Basis::Documented,
            "a toolchain abort or exit shim; the module can end its own instance",
        ));
    }
    if out.is_empty() && name.starts_with("emscripten_") {
        out.push(hit(
            "EMSC-GENERIC-001",
            Capability::JsArbitrary,
            Severity::Medium,
            Basis::Pattern,
            "an Emscripten runtime function not otherwise classified; it is host \
             JavaScript, so read the glue to see what it does",
        ));
    }

    if name.starts_with("__wbindgen_") {
        out.push(hit(
            "BINDGEN-GLUE-001",
            Capability::JsArbitrary,
            Severity::High,
            Basis::Pattern,
            "wasm-bindgen runtime glue; through it the module creates, reads, calls and \
             throws arbitrary JavaScript values",
        ));
    } else if is_bindgen {
        out.push(hit(
            "BINDGEN-JS-001",
            Capability::JsArbitrary,
            Severity::High,
            Basis::Pattern,
            "a wasm-bindgen import shim; the symbol names the JavaScript the host will \
             call on the module's behalf",
        ));
    }

    if is_bindgen {
        if any_token(&lower, &JS_NET_TOKENS) {
            out.push(hit(
                "BINDGEN-NET-001",
                Capability::JsNetwork,
                Severity::High,
                Basis::Pattern,
                "the import symbol names a browser networking API, so the module can \
                 reach the network through the host",
            ));
        }
        if any_token(&lower, &JS_EVAL_TOKENS) {
            out.push(hit(
                "BINDGEN-EVAL-001",
                Capability::JsEval,
                Severity::Critical,
                Basis::Pattern,
                "the import symbol names eval, importScripts or the Function \
                 constructor (wasm-bindgen emits newnoargs for `new Function`), which \
                 turns module data into host code",
            ));
        }
        if any_token(&lower, &JS_STORAGE_TOKENS) {
            out.push(hit(
                "BINDGEN-STORAGE-001",
                Capability::JsStorage,
                Severity::Medium,
                Basis::Pattern,
                "the import symbol names browser-side storage, which is origin-scoped \
                 and often holds tokens",
            ));
        }
        if any_token(&lower, &JS_MSG_TOKENS) {
            out.push(hit(
                "BINDGEN-MSG-001",
                Capability::JsMessaging,
                Severity::Medium,
                Basis::Pattern,
                "the import symbol names a cross-context messaging API",
            ));
        }
        if any_token(&lower, &JS_CRYPTO_TOKENS) {
            out.push(hit(
                "BINDGEN-CRYPTO-001",
                Capability::JsCrypto,
                Severity::Low,
                Basis::Pattern,
                "the import symbol names the Web Crypto API",
            ));
        }
        if any_token(&lower, &JS_DOM_TOKENS) {
            out.push(hit(
                "BINDGEN-DOM-001",
                Capability::JsDom,
                Severity::Medium,
                Basis::Pattern,
                "the import symbol names a DOM API, so the module can read or change \
                 the host document",
            ));
        }
    }

    Some(out)
}

fn classify_contract(module: &str, name: &str) -> Option<Vec<Hit>> {
    let mut out = Vec::new();
    if module == "env" {
        classify_near(name, &mut out);
        classify_cosmwasm(name, &mut out);
    }
    if module == "ic0" {
        classify_ic0(name, &mut out);
    }
    if module.starts_with("seal") {
        classify_seal(name, &mut out);
    }
    if module == "ethereum" {
        classify_ewasm(name, &mut out);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn classify_near(name: &str, out: &mut Vec<Hit>) {
    if NEAR_STORAGE_WRITE.contains(&name) {
        out.push(hit(
            "NEAR-STORAGE-WRITE-001",
            Capability::ContractStorageWrite,
            Severity::High,
            Basis::Documented,
            "writes or removes contract storage; on NEAR this is the contract's whole \
             persistent state",
        ));
    }
    if NEAR_STORAGE_READ.contains(&name) {
        out.push(hit(
            "NEAR-STORAGE-READ-001",
            Capability::ContractStorageRead,
            Severity::Low,
            Basis::Documented,
            "reads contract storage",
        ));
    }
    if NEAR_PROMISE_CALL.contains(&name) {
        out.push(hit(
            "NEAR-CALL-001",
            Capability::ContractCall,
            Severity::High,
            Basis::Documented,
            "creates or chains a promise, which is how a NEAR contract calls another \
             contract; the callback boundary is where reentrancy lives",
        ));
    }
    if NEAR_TRANSFER.contains(&name) {
        out.push(hit(
            "NEAR-TRANSFER-001",
            Capability::ContractValueTransfer,
            Severity::High,
            Basis::Documented,
            "attaches a transfer or stake action to a promise, moving balance out of \
             the contract account",
        ));
    }
    if NEAR_DEPLOY.contains(&name) {
        out.push(hit(
            "NEAR-DEPLOY-001",
            Capability::ContractCodeDeploy,
            Severity::High,
            Basis::Documented,
            "deploys code or creates an account from inside the contract",
        ));
    }
    if NEAR_KEYS.contains(&name) {
        out.push(hit(
            "NEAR-KEYS-001",
            Capability::ContractAccountKeys,
            Severity::Critical,
            Basis::Documented,
            "adds or deletes an account access key; a full-access key added here is \
             account takeover",
        ));
    }
    if name == "promise_batch_action_delete_account" {
        out.push(hit(
            "NEAR-DELETE-ACCOUNT-001",
            Capability::ContractSelfDestruct,
            Severity::Critical,
            Basis::Documented,
            "deletes an account and sweeps its balance to a beneficiary",
        ));
    }
    if name == "random_seed" {
        out.push(hit(
            "NEAR-RANDOM-001",
            Capability::ContractRandomness,
            Severity::Medium,
            Basis::Documented,
            "reads the block's random seed, which is known to the block producer before \
             the contract sees it",
        ));
    }
    if NEAR_CONTEXT.contains(&name) {
        out.push(hit(
            "NEAR-CONTEXT-001",
            Capability::ContractChainContext,
            Severity::Info,
            Basis::Documented,
            "reads call or chain context",
        ));
    }
    if NEAR_CRYPTO.contains(&name) {
        out.push(hit(
            "NEAR-CRYPTO-001",
            Capability::ContractCrypto,
            Severity::Info,
            Basis::Documented,
            "a host hash or signature primitive",
        ));
    }
    if NEAR_REGISTERS.contains(&name) {
        out.push(hit(
            "NEAR-REGISTER-001",
            Capability::HostIo,
            Severity::Info,
            Basis::Documented,
            "moves bytes between the contract and a host register; NEAR's calling \
             convention rather than a privilege",
        ));
    }
    if NEAR_LOG.contains(&name) {
        out.push(hit(
            "NEAR-LOG-001",
            Capability::DebugLogging,
            Severity::Info,
            Basis::Documented,
            "writes a log line, which is part of the transaction outcome and therefore \
             public",
        ));
    }
    if NEAR_ABORT.contains(&name) && name != "abort" {
        out.push(hit(
            "NEAR-ABORT-001",
            Capability::Process,
            Severity::Info,
            Basis::Documented,
            "aborts the contract call",
        ));
    }
    if name == "gas" {
        out.push(hit(
            "NEAR-GAS-001",
            Capability::ContractChainContext,
            Severity::Info,
            Basis::Documented,
            "the gas-metering hook the runtime injects",
        ));
    }
}

fn classify_cosmwasm(name: &str, out: &mut Vec<Hit>) {
    if COSMWASM_DB_WRITE.contains(&name) {
        out.push(hit(
            "COSMWASM-DB-WRITE-001",
            Capability::ContractStorageWrite,
            Severity::High,
            Basis::Documented,
            "writes or removes a key in the contract's own store",
        ));
    }
    if COSMWASM_DB_READ.contains(&name) {
        out.push(hit(
            "COSMWASM-DB-READ-001",
            Capability::ContractStorageRead,
            Severity::Low,
            Basis::Documented,
            "reads or iterates the contract's store",
        ));
    }
    if name == "query_chain" {
        out.push(hit(
            "COSMWASM-QUERY-001",
            Capability::ContractCall,
            Severity::Medium,
            Basis::Documented,
            "runs a chain query, which reaches other modules and contracts read-only; \
             state-changing messages leave through the contract's response instead, so \
             the import list alone does not show them",
        ));
    }
    if COSMWASM_ADDR.contains(&name) {
        out.push(hit(
            "COSMWASM-ADDR-001",
            Capability::ContractChainContext,
            Severity::Info,
            Basis::Documented,
            "an address validation or conversion helper",
        ));
    }
    if COSMWASM_CRYPTO.contains(&name) {
        out.push(hit(
            "COSMWASM-CRYPTO-001",
            Capability::ContractCrypto,
            Severity::Info,
            Basis::Documented,
            "a host signature-verification primitive",
        ));
    }
    if name == "debug" {
        out.push(hit(
            "COSMWASM-DEBUG-001",
            Capability::DebugLogging,
            Severity::Info,
            Basis::Documented,
            "writes to the node's debug log; a no-op on most production nodes",
        ));
    }
}

fn classify_ic0(name: &str, out: &mut Vec<Hit>) {
    if IC0_STABLE_WRITE.contains(&name) {
        out.push(hit(
            "IC0-STABLE-WRITE-001",
            Capability::ContractStorageWrite,
            Severity::High,
            Basis::Documented,
            "writes or grows stable memory, which is the canister's state across upgrades",
        ));
    }
    if IC0_STABLE_READ.contains(&name) {
        out.push(hit(
            "IC0-STABLE-READ-001",
            Capability::ContractStorageRead,
            Severity::Low,
            Basis::Documented,
            "reads stable memory",
        ));
    }
    if IC0_CALL.contains(&name) {
        out.push(hit(
            "IC0-CALL-001",
            Capability::ContractCall,
            Severity::High,
            Basis::Documented,
            "builds or performs an inter-canister call, or replies to one",
        ));
    }
    if IC0_CYCLES.contains(&name) {
        out.push(hit(
            "IC0-CYCLES-001",
            Capability::ContractValueTransfer,
            Severity::High,
            Basis::Documented,
            "moves cycles, which on the Internet Computer are the thing with value",
        ));
    }
    if name == "raw_rand" {
        out.push(hit(
            "IC0-RAND-001",
            Capability::ContractRandomness,
            Severity::Medium,
            Basis::Documented,
            "requests randomness from the management canister",
        ));
    }
    if IC0_CONTEXT.contains(&name) {
        out.push(hit(
            "IC0-CONTEXT-001",
            Capability::ContractChainContext,
            Severity::Info,
            Basis::Documented,
            "reads message or canister context",
        ));
    }
    if name == "certified_data_set" {
        out.push(hit(
            "IC0-CERTIFIED-001",
            Capability::ContractStorageWrite,
            Severity::Medium,
            Basis::Documented,
            "sets the canister's certified data, which clients verify against the \
             subnet signature",
        ));
    }
    if matches!(name, "debug_print" | "trap") {
        out.push(hit(
            "IC0-DEBUG-001",
            Capability::DebugLogging,
            Severity::Info,
            Basis::Documented,
            "writes a debug line or traps the call",
        ));
    }
}

fn classify_seal(name: &str, out: &mut Vec<Hit>) {
    let mut push = |rule, cap, sev, why| out.push(hit(rule, cap, sev, Basis::Pattern, why));
    if SEAL_STORAGE_WRITE.contains(&name) {
        push(
            "SEAL-STORAGE-WRITE-001",
            Capability::ContractStorageWrite,
            Severity::High,
            "writes, clears or takes a contract storage key",
        );
    }
    if SEAL_STORAGE_READ.contains(&name) {
        push(
            "SEAL-STORAGE-READ-001",
            Capability::ContractStorageRead,
            Severity::Low,
            "reads a contract storage key",
        );
    }
    if SEAL_CALL.contains(&name) {
        push(
            "SEAL-CALL-001",
            Capability::ContractCall,
            Severity::High,
            "calls another contract, or a chain extension, which is host code outside \
             the contract sandbox",
        );
    }
    if SEAL_DELEGATE.contains(&name) {
        push(
            "SEAL-DELEGATE-001",
            Capability::ContractDelegateCall,
            Severity::Critical,
            "runs another code hash against this contract's own storage and balance; \
             whoever controls that code hash controls this contract",
        );
    }
    if SEAL_INSTANTIATE.contains(&name) {
        push(
            "SEAL-INSTANTIATE-001",
            Capability::ContractCodeDeploy,
            Severity::High,
            "instantiates a new contract",
        );
    }
    if SEAL_TRANSFER.contains(&name) {
        push(
            "SEAL-TRANSFER-001",
            Capability::ContractValueTransfer,
            Severity::High,
            "transfers balance out of the contract",
        );
    }
    if SEAL_TERMINATE.contains(&name) {
        push(
            "SEAL-TERMINATE-001",
            Capability::ContractSelfDestruct,
            Severity::Critical,
            "terminates the contract and sends its balance to a beneficiary",
        );
    }
    if SEAL_RANDOM.contains(&name) {
        push(
            "SEAL-RANDOM-001",
            Capability::ContractRandomness,
            Severity::Medium,
            "reads chain randomness, which is not safe against a producer that can \
             see it first",
        );
    }
}

fn classify_ewasm(name: &str, out: &mut Vec<Hit>) {
    let mut push = |rule, cap, sev, why| out.push(hit(rule, cap, sev, Basis::Pattern, why));
    if EWASM_STORE.contains(&name) {
        push(
            "EWASM-STORAGE-WRITE-001",
            Capability::ContractStorageWrite,
            Severity::High,
            "writes a 32-byte storage slot",
        );
    }
    if EWASM_LOAD.contains(&name) {
        push(
            "EWASM-STORAGE-READ-001",
            Capability::ContractStorageRead,
            Severity::Low,
            "reads a 32-byte storage slot",
        );
    }
    if EWASM_CALL.contains(&name) {
        push(
            "EWASM-CALL-001",
            Capability::ContractCall,
            Severity::High,
            "calls another contract",
        );
    }
    if EWASM_DELEGATE.contains(&name) {
        push(
            "EWASM-DELEGATE-001",
            Capability::ContractDelegateCall,
            Severity::Critical,
            "executes another contract's code in this contract's storage context",
        );
    }
    if EWASM_CREATE.contains(&name) {
        push(
            "EWASM-CREATE-001",
            Capability::ContractCodeDeploy,
            Severity::High,
            "deploys a new contract",
        );
    }
    if EWASM_DESTRUCT.contains(&name) {
        push(
            "EWASM-SELFDESTRUCT-001",
            Capability::ContractSelfDestruct,
            Severity::Critical,
            "destroys the contract and forwards its balance",
        );
    }
}

/// Cross-platform name patterns, used when nothing more specific matched.
/// Every hit here is a guess from the shape of the name and is labelled as
/// such; it exists so that a host interface this tool has never seen still
/// produces a useful first read rather than a wall of unknowns.
fn classify_generic(name: &str) -> Vec<Hit> {
    let n = name.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut push = |rule, cap, sev, why| out.push(hit(rule, cap, sev, Basis::Pattern, why));

    if n.contains("delegate") && n.contains("call") {
        push(
            "PATTERN-DELEGATE-001",
            Capability::ContractDelegateCall,
            Severity::Critical,
            "the name reads as a delegate call: foreign code against local state",
        );
    }
    if any_token(
        &n,
        &[
            "storage_write",
            "storage_set",
            "set_storage",
            "storagestore",
            "storage_store",
            "storage_cache",
            "storage_flush",
            "write_storage",
            "db_write",
            "state_write",
        ],
    ) {
        push(
            "PATTERN-STORAGE-WRITE-001",
            Capability::ContractStorageWrite,
            Severity::High,
            "the name reads as a storage write",
        );
    }
    if any_token(
        &n,
        &[
            "storage_read",
            "storage_load",
            "storageload",
            "get_storage",
            "storage_get",
            "db_read",
            "state_read",
        ],
    ) {
        push(
            "PATTERN-STORAGE-READ-001",
            Capability::ContractStorageRead,
            Severity::Low,
            "the name reads as a storage read",
        );
    }
    if any_token(
        &n,
        &[
            "call_contract",
            "contract_call",
            "cross_contract",
            "static_call",
            "callstatic",
            "callcode",
        ],
    ) {
        push(
            "PATTERN-CALL-001",
            Capability::ContractCall,
            Severity::High,
            "the name reads as a cross-contract call",
        );
    }
    if any_token(
        &n,
        &["transfer", "send_value", "msg_value", "withdraw", "payout"],
    ) {
        push(
            "PATTERN-TRANSFER-001",
            Capability::ContractValueTransfer,
            Severity::High,
            "the name reads as a value transfer",
        );
    }
    if any_token(&n, &["create1", "create2", "deploy", "instantiate"]) {
        push(
            "PATTERN-DEPLOY-001",
            Capability::ContractCodeDeploy,
            Severity::High,
            "the name reads as code deployment",
        );
    }
    if any_token(
        &n,
        &[
            "selfdestruct",
            "self_destruct",
            "suicide",
            "terminate",
            "delete_account",
        ],
    ) {
        push(
            "PATTERN-DESTROY-001",
            Capability::ContractSelfDestruct,
            Severity::Critical,
            "the name reads as contract or account destruction",
        );
    }
    if any_token(&n, &["random", "entropy", "_seed", "rng"]) {
        push(
            "PATTERN-RANDOM-001",
            Capability::ContractRandomness,
            Severity::Medium,
            "the name reads as a randomness source",
        );
    }
    if any_token(
        &n,
        &[
            "keccak",
            "sha256",
            "sha3",
            "blake2",
            "secp256",
            "ed25519",
            "ripemd",
            "ecrecover",
            "bls12",
            "poseidon",
        ],
    ) {
        push(
            "PATTERN-CRYPTO-001",
            Capability::ContractCrypto,
            Severity::Info,
            "the name reads as a host cryptographic primitive",
        );
    }
    if any_token(
        &n,
        &[
            "block_number",
            "block_timestamp",
            "block_height",
            "chainid",
            "chain_id",
            "tx_origin",
            "msg_sender",
            "gas_left",
            "gas_price",
        ],
    ) {
        push(
            "PATTERN-CONTEXT-001",
            Capability::ContractChainContext,
            Severity::Info,
            "the name reads as chain context",
        );
    }
    if any_token(
        &n,
        &[
            "socket", "sock_", "http_", "https", "tcp_", "udp_", "dns_", "fetch", "curl",
        ],
    ) {
        push(
            "PATTERN-NET-001",
            Capability::Network,
            Severity::High,
            "the name reads as network access",
        );
    }
    if any_token(
        &n,
        &[
            "fopen",
            "open_file",
            "file_read",
            "file_write",
            "readfile",
            "writefile",
            "path_",
            "unlink",
            "mkdir",
            "rmdir",
            "opendir",
            "fstat",
        ],
    ) {
        push(
            "PATTERN-FS-001",
            Capability::Filesystem,
            Severity::High,
            "the name reads as filesystem access",
        );
    }
    if any_token(
        &n,
        &[
            "exec",
            "spawn",
            "posix_spawn",
            "fork",
            "popen",
            "system_",
            "shell",
        ],
    ) {
        push(
            "PATTERN-EXEC-001",
            Capability::Process,
            Severity::Critical,
            "the name reads as process execution, which no sandboxed module should need",
        );
    }
    if any_token(&n, &["eval", "run_script", "compile_script"]) {
        push(
            "PATTERN-EVAL-001",
            Capability::JsEval,
            Severity::Critical,
            "the name reads as host-side evaluation of module-supplied source",
        );
    }
    if any_token(&n, &["debug", "log_", "_log", "print", "trace", "emit_log"]) {
        push(
            "PATTERN-LOG-001",
            Capability::DebugLogging,
            Severity::Info,
            "the name reads as logging or debug output",
        );
    }
    out
}
