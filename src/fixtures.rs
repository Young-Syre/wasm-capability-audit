//! Readable WebAssembly fixture construction.
//!
//! Test fixtures for a binary parser are usually opaque blobs, which makes
//! them impossible to review: a reader cannot tell whether the test asserts
//! the right thing about the bytes, because the bytes are unreadable. So the
//! fixtures here are built in code, field by field, with each field named in
//! a comment. `examples/make_fixtures.rs` writes them out to
//! `tests/fixtures/`, and `tests/fixtures.rs` asserts that the committed
//! files still match what this module produces — so the committed `.wasm`
//! files are derived artefacts, not mystery binaries.
//!
//! These are hand-assembled modules, not the output of a compiler. They are
//! well formed enough to decode and to exercise the capability rules; they
//! are not type-checked, because this tool does not type-check either.

/// Unsigned LEB128.
pub fn uleb(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// Signed LEB128.
pub fn sleb(mut value: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let sign_bit_set = byte & 0x40 != 0;
        if (value == 0 && !sign_bit_set) || (value == -1 && sign_bit_set) {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// A length-prefixed name.
pub fn name(s: &str) -> Vec<u8> {
    let mut out = uleb(s.len() as u64);
    out.extend_from_slice(s.as_bytes());
    out
}

/// A vector: element count followed by the elements.
pub fn vector(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = uleb(items.len() as u64);
    for i in items {
        out.extend_from_slice(i);
    }
    out
}

/// A section: id, byte length, body.
pub fn section(id: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    out.extend_from_slice(&uleb(body.len() as u64));
    out.extend_from_slice(body);
    out
}

/// The eight-byte preamble followed by the given sections.
pub fn module(sections: &[Vec<u8>]) -> Vec<u8> {
    // magic "\0asm", then version 1 as a little-endian u32.
    let mut out = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    for s in sections {
        out.extend_from_slice(s);
    }
    out
}

/// A function type: `0x60`, parameter types, result types.
pub fn func_type(params: &[u8], results: &[u8]) -> Vec<u8> {
    let mut out = vec![0x60];
    out.extend_from_slice(&uleb(params.len() as u64));
    out.extend_from_slice(params);
    out.extend_from_slice(&uleb(results.len() as u64));
    out.extend_from_slice(results);
    out
}

/// A function import: module name, field name, descriptor `0x00`, type index.
pub fn import_func(module_name: &str, field: &str, type_index: u64) -> Vec<u8> {
    let mut out = name(module_name);
    out.extend_from_slice(&name(field));
    out.push(0x00);
    out.extend_from_slice(&uleb(type_index));
    out
}

/// A memory import: module name, field name, descriptor `0x02`, limits.
pub fn import_memory(module_name: &str, field: &str, min: u64, max: Option<u64>) -> Vec<u8> {
    let mut out = name(module_name);
    out.extend_from_slice(&name(field));
    out.push(0x02);
    out.extend_from_slice(&limits(min, max, false));
    out
}

/// A global import: module name, field name, descriptor `0x03`, value type,
/// mutability.
pub fn import_global(module_name: &str, field: &str, val: u8, mutable: bool) -> Vec<u8> {
    let mut out = name(module_name);
    out.extend_from_slice(&name(field));
    out.push(0x03);
    out.push(val);
    out.push(u8::from(mutable));
    out
}

/// Limits: a flags byte, a minimum, and a maximum when the flags say so.
pub fn limits(min: u64, max: Option<u64>, shared: bool) -> Vec<u8> {
    let mut flags = 0u8;
    if max.is_some() {
        flags |= 0b001;
    }
    if shared {
        flags |= 0b010;
    }
    let mut out = vec![flags];
    out.extend_from_slice(&uleb(min));
    if let Some(m) = max {
        out.extend_from_slice(&uleb(m));
    }
    out
}

/// An export: name, kind byte, index.
pub fn export(export_name: &str, kind: u8, index: u64) -> Vec<u8> {
    let mut out = name(export_name);
    out.push(kind);
    out.extend_from_slice(&uleb(index));
    out
}

/// A function body: byte length, local declarations, instructions, `end`.
pub fn body(locals: &[(u64, u8)], code: &[u8]) -> Vec<u8> {
    let mut inner = uleb(locals.len() as u64);
    for (count, ty) in locals {
        inner.extend_from_slice(&uleb(*count));
        inner.push(*ty);
    }
    inner.extend_from_slice(code);
    inner.push(0x0b); // end
    let mut out = uleb(inner.len() as u64);
    out.extend_from_slice(&inner);
    out
}

/// Value type bytes, for readability at the call sites below.
pub const I32: u8 = 0x7f;
/// 64-bit integer value type.
pub const I64: u8 = 0x7e;
/// A nullable function reference, the element type of an MVP table.
pub const FUNCREF: u8 = 0x70;

/// Export kind bytes.
pub const EXPORT_FUNC: u8 = 0x00;
/// Table export kind.
pub const EXPORT_TABLE: u8 = 0x01;
/// Memory export kind.
pub const EXPORT_MEMORY: u8 = 0x02;
/// Global export kind.
pub const EXPORT_GLOBAL: u8 = 0x03;

/// A module that imports nothing, exports one function and a bounded memory,
/// and adds two integers. The baseline: no host authority at all.
pub fn clean_compute() -> Vec<u8> {
    module(&[
        // Type section: one type, (i32, i32) -> (i32).
        section(1, &vector(&[func_type(&[I32, I32], &[I32])])),
        // Function section: one function, of type 0.
        section(3, &vector(&[uleb(0)])),
        // Memory section: one memory, min 1 page, max 2 pages.
        section(5, &vector(&[limits(1, Some(2), false)])),
        // Export section: the function, and the memory.
        section(
            7,
            &vector(&[
                export("add", EXPORT_FUNC, 0),
                export("memory", EXPORT_MEMORY, 0),
            ]),
        ),
        // Code section: local.get 0, local.get 1, i32.add.
        section(10, &vector(&[body(&[], &[0x20, 0x00, 0x20, 0x01, 0x6a])])),
    ])
}

/// A WASI module holding both filesystem and network capability, with an
/// unbounded exported memory and a start function. The shape a sandbox
/// escape wants.
pub fn wasi_exfil() -> Vec<u8> {
    const W: &str = "wasi_snapshot_preview1";
    module(&[
        // Type section: () -> (), (i32) -> (), (i32,i32,i32,i32) -> (i32).
        section(
            1,
            &vector(&[
                func_type(&[], &[]),
                func_type(&[I32], &[]),
                func_type(&[I32, I32, I32, I32], &[I32]),
            ]),
        ),
        // Import section: eight WASI functions.
        section(
            2,
            &vector(&[
                import_func(W, "path_open", 2),
                import_func(W, "fd_read", 2),
                import_func(W, "fd_write", 2),
                import_func(W, "sock_send", 2),
                import_func(W, "clock_time_get", 2),
                import_func(W, "random_get", 2),
                import_func(W, "environ_get", 2),
                import_func(W, "proc_exit", 1),
            ]),
        ),
        // Function section: one function, of type 0.
        section(3, &vector(&[uleb(0)])),
        // Memory section: min 2 pages, no maximum.
        section(5, &vector(&[limits(2, None, false)])),
        // Export section: the memory, and _start.
        section(
            7,
            &vector(&[
                export("memory", EXPORT_MEMORY, 0),
                export("_start", EXPORT_FUNC, 8),
            ]),
        ),
        // Start section: function index 8, which is the first non-imported
        // function. It runs at instantiation.
        section(8, &uleb(8)),
        // Code section: i32.const 1, memory.grow 0, drop, i32.const 0,
        // call 7 (proc_exit).
        section(
            10,
            &vector(&[body(
                &[],
                &[
                    0x41, 0x01, // i32.const 1
                    0x40, 0x00, // memory.grow 0
                    0x1a, // drop
                    0x41, 0x00, // i32.const 0
                    0x10, 0x07, // call 7
                ],
            )]),
        ),
    ])
}

/// A WASI module that asks only for a clock and for randomness: the same
/// runtime, a far narrower grant.
pub fn wasi_clock_only() -> Vec<u8> {
    const W: &str = "wasi_snapshot_preview1";
    module(&[
        section(
            1,
            &vector(&[func_type(&[I32, I32], &[I32]), func_type(&[], &[])]),
        ),
        section(
            2,
            &vector(&[
                import_func(W, "clock_time_get", 0),
                import_func(W, "random_get", 0),
            ]),
        ),
        section(3, &vector(&[uleb(1)])),
        // Memory section: min 1 page, max 16 pages — a declared ceiling.
        section(5, &vector(&[limits(1, Some(16), false)])),
        section(7, &vector(&[export("run", EXPORT_FUNC, 2)])),
        section(10, &vector(&[body(&[], &[])])),
    ])
}

/// A browser module built the way `wasm-bindgen` builds them, naming fetch,
/// the `Function` constructor, local storage and `postMessage` in its import
/// symbols, and exporting both its memory and a mutable global.
pub fn bindgen_browser() -> Vec<u8> {
    module(&[
        // Type section: (i32) -> (), (i32) -> (i32), (i32,i32) -> ().
        section(
            1,
            &vector(&[
                func_type(&[I32], &[]),
                func_type(&[I32], &[I32]),
                func_type(&[I32, I32], &[]),
                func_type(&[], &[]),
            ]),
        ),
        // Import section: wasm-bindgen glue plus four named JS bindings.
        section(
            2,
            &vector(&[
                import_func("wbg", "__wbindgen_object_drop_ref", 0),
                import_func("wbg", "__wbindgen_throw", 2),
                import_func("wbg", "__wbg_fetch_a1b2c3d4e5f6", 1),
                import_func("wbg", "__wbg_newnoargs_1234abcd", 1),
                import_func("wbg", "__wbg_localStorage_0f0f0f0f", 1),
                import_func("wbg", "__wbg_postMessage_deadbeef", 2),
            ]),
        ),
        section(3, &vector(&[uleb(3)])),
        // Memory section: min 17 pages, no maximum, as a Rust build emits.
        section(5, &vector(&[limits(17, None, false)])),
        // Global section: one mutable i32, initialised to 0.
        section(
            6,
            &vector(&[{
                let mut g = vec![I32, 0x01]; // i32, mutable
                g.extend_from_slice(&[0x41, 0x00, 0x0b]); // i32.const 0, end
                g
            }]),
        ),
        // Export section: memory, the mutable global, and an entry point.
        section(
            7,
            &vector(&[
                export("memory", EXPORT_MEMORY, 0),
                export("__wbindgen_export_0", EXPORT_GLOBAL, 0),
                export("run", EXPORT_FUNC, 6),
            ]),
        ),
        // Code section: i32.const 0, call 2 (fetch), drop.
        section(10, &vector(&[body(&[], &[0x41, 0x00, 0x10, 0x02, 0x1a])])),
    ])
}

/// A NEAR contract: storage writes, a cross-contract promise, a balance
/// transfer and the block random seed.
pub fn near_contract() -> Vec<u8> {
    module(&[
        section(
            1,
            &vector(&[
                func_type(&[I64, I64, I64, I64], &[I64]),
                func_type(&[I64], &[]),
                func_type(&[], &[]),
            ]),
        ),
        section(
            2,
            &vector(&[
                import_func("env", "storage_write", 0),
                import_func("env", "storage_read", 0),
                import_func("env", "promise_batch_create", 0),
                import_func("env", "promise_batch_action_transfer", 0),
                import_func("env", "random_seed", 1),
                import_func("env", "attached_deposit", 1),
                import_func("env", "log_utf8", 0),
                import_func("env", "panic_utf8", 0),
            ]),
        ),
        section(3, &vector(&[uleb(2)])),
        section(5, &vector(&[limits(1, Some(1), false)])),
        section(
            7,
            &vector(&[
                export("memory", EXPORT_MEMORY, 0),
                export("transfer", EXPORT_FUNC, 8),
            ]),
        ),
        section(10, &vector(&[body(&[], &[])])),
    ])
}

/// A module whose host interface this tool has never seen. The point of the
/// fixture is that the output says so rather than reporting nothing.
pub fn unknown_host() -> Vec<u8> {
    module(&[
        section(
            1,
            &vector(&[func_type(&[I32], &[I32]), func_type(&[], &[])]),
        ),
        section(
            2,
            &vector(&[
                import_func("acme_runtime", "frobnicate", 0),
                import_func("acme_runtime", "blit_region", 0),
                import_func("acme_runtime", "quux", 0),
                import_global("acme_runtime", "tick", I32, true),
            ]),
        ),
        section(3, &vector(&[uleb(1)])),
        section(7, &vector(&[export("go", EXPORT_FUNC, 3)])),
        section(10, &vector(&[body(&[], &[])])),
    ])
}

/// A module with a table, an element segment and an indirect call, plus an
/// exported table: the `call_indirect` surface in miniature.
pub fn indirect_dispatch() -> Vec<u8> {
    module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(3, &vector(&[uleb(0)])),
        // Table section: one funcref table, min 2, max 2.
        section(
            4,
            &vector(&[{
                let mut t = vec![FUNCREF];
                t.extend_from_slice(&limits(2, Some(2), false));
                t
            }]),
        ),
        section(5, &vector(&[limits(1, Some(1), false)])),
        section(
            7,
            &vector(&[
                export("memory", EXPORT_MEMORY, 0),
                export("table", EXPORT_TABLE, 0),
                export("run", EXPORT_FUNC, 0),
            ]),
        ),
        // Element section: kind 0, offset (i32.const 0), one function index.
        section(
            9,
            &vector(&[{
                let mut e = uleb(0);
                e.extend_from_slice(&[0x41, 0x00, 0x0b]); // i32.const 0, end
                e.extend_from_slice(&vector(&[uleb(0)]));
                e
            }]),
        ),
        // Code section: i32.const 0, call_indirect type 0 table 0.
        section(10, &vector(&[body(&[], &[0x41, 0x00, 0x11, 0x00, 0x00])])),
    ])
}

/// The clock-only module with one extra import: `sock_send`. Paired with
/// [`wasi_clock_only`] it is the supply-chain case the diff mode exists for —
/// a dependency bump that quietly adds a way off the machine.
pub fn wasi_clock_and_socket() -> Vec<u8> {
    const W: &str = "wasi_snapshot_preview1";
    module(&[
        section(
            1,
            &vector(&[func_type(&[I32, I32], &[I32]), func_type(&[], &[])]),
        ),
        section(
            2,
            &vector(&[
                import_func(W, "clock_time_get", 0),
                import_func(W, "random_get", 0),
                import_func(W, "sock_send", 0),
            ]),
        ),
        section(3, &vector(&[uleb(1)])),
        section(5, &vector(&[limits(1, Some(16), false)])),
        section(7, &vector(&[export("run", EXPORT_FUNC, 3)])),
        section(10, &vector(&[body(&[], &[])])),
    ])
}

/// Every fixture, with the filename it is written to.
pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("clean-compute.wasm", clean_compute()),
        ("wasi-exfil.wasm", wasi_exfil()),
        ("wasi-clock-only.wasm", wasi_clock_only()),
        ("wasi-clock-and-socket.wasm", wasi_clock_and_socket()),
        ("bindgen-browser.wasm", bindgen_browser()),
        ("near-contract.wasm", near_contract()),
        ("unknown-host.wasm", unknown_host()),
        ("indirect-dispatch.wasm", indirect_dispatch()),
    ]
}
