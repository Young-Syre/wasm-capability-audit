# wasm-capability-audit

[![tests](https://github.com/Young-Syre/wasm-capability-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/wasm-capability-audit/actions/workflows/tests.yml)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](Cargo.toml)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](src/lib.rs)

What a WebAssembly module asks its host for, what the host would be granting,
and what the module hands back.

## Why this bug class exists

WebAssembly has no ambient authority. A module cannot open a file, read a
clock, allocate a socket or call into the page that loaded it unless the host
hands it a function that does. There is no equivalent of `open(2)` sitting in
the runtime waiting to be called: if the capability was not imported, it does
not exist for that module.

That property is the whole security argument for running untrusted code in
WebAssembly, and it has an unusually convenient consequence. A module's
authority is enumerated, by name, in its import section — a list you can read
in a few hundred bytes at a fixed offset near the front of the file.

In practice nobody reads it. The module arrives as a `.wasm` blob inside an
npm package, a plugin bundle, a smart-contract deployment or a sandboxed
extension, and the question "what can this thing actually do" is answered by
reading the glue code, or the documentation, or not at all. So the failures
look like this:

- A host that preopens a directory for a module that only needed stdin and
  stdout, because nobody checked which descriptors it asks for.
- A dependency update that adds `sock_send` to a module that previously only
  computed. The package version moved by a patch release; the capability set
  moved from "pure function" to "can send your bytes somewhere".
- An Emscripten build that imports `__syscall_openat`, which is not a narrow
  capability at all but a kernel interface, with whatever the JS glue chose to
  wire behind it as the real sandbox boundary.
- A module that exports its linear memory, which means every byte it holds —
  including the buffer it zeroes after use — is readable and writable by
  anything holding that export.
- A contract module that imports both a storage write and a cross-contract
  call, which is a reentrancy surface whether or not the author thought about
  ordering.
- A module with a declared memory minimum and no maximum, running in a
  multi-tenant host, where the only thing stopping it from eating the machine
  is a limit the host remembered to configure.

None of those are exotic. They are all visible in the first few hundred bytes
of the binary. This tool reads those bytes and says what it found.

## What it does

1. **Parses the WebAssembly binary format**, from the preamble to the data
   section, including LEB128 in both its unsigned and signed forms, the
   section ordering the format prescribes, and the encodings introduced by
   multi-value, reference types, bulk memory, SIMD, threads, tail calls,
   multi-memory, memory64 and both generations of exception handling. It walks
   function bodies instruction by instruction, because you cannot count
   `call_indirect` sites by looking for a byte.
2. **Classifies every import into a capability**, with a rule identifier, a
   severity, a rationale, and — this matters — a statement of whether the
   classification came from an interface the tool models or from a name that
   merely looks like something.
3. **Reports the effective capability set**: the union across the import list.
   `path_open` on its own is a file reader. `path_open` together with
   `sock_send` is an exfiltration path, and that combination gets its own
   critical finding.
4. **Reports the export surface** — exported memory, exported mutable
   globals, exported tables — because those are the module's authority running
   in the other direction.
5. **Reports memory and resource posture**: minimum and maximum pages, shared
   memory, unbounded tables, reachable `memory.grow`, a start function that
   runs code at instantiation before the host does anything, and the count of
   indirect call sites.
6. **Diffs two versions** of a module and reports the capabilities the newer
   one has gained.
7. **Enforces a policy** so it can sit in CI and fail a build when a module
   exceeds what it is allowed to be.

It depends on nothing outside `std`. There is no `wasmparser`, no `serde`, no
`anyhow`; the binary format is parsed here, which is the part of this
repository worth reading. `#![forbid(unsafe_code)]` is set crate-wide.

## Install

```sh
cargo install --path .
```

Or build it:

```sh
cargo build --release
./target/release/wasm-capability-audit module.wasm
```

Minimum supported Rust version is **1.74**, declared in `Cargo.toml` and built
in CI alongside stable.

## Usage

```
wasm-capability-audit [OPTIONS] <module.wasm>
wasm-capability-audit diff [OPTIONS] <old.wasm> <new.wasm>
wasm-capability-audit --list-capabilities
wasm-capability-audit --list-rules
```

| Option | Effect |
| --- | --- |
| `--json` | Machine-readable output, one line, on stdout. |
| `--policy <file>` | Check against a policy file; exit 1 on violation. |
| `--fail-on <severity>` | Exit 1 if any finding is at or above this severity. |
| `--no-code-scan` | Skip the code section. Loses indirect-call and `memory.grow` counts, and says so in the output rather than reporting zero. |
| `--list-capabilities` | Print the capability identifiers a policy may use. |
| `--list-rules` | Print every rule identifier the tool can emit. |
| `-h`, `--help` | Usage. |
| `-V`, `--version` | Version. |

### Auditing a module

Every fixture in `tests/fixtures/` is generated from the readable byte-builder
in `src/fixtures.rs`, so these runs are reproducible from a clean checkout.

```console
$ wasm-capability-audit tests/fixtures/wasi-exfil.wasm
wasm-capability-audit 0.1.0
module: tests/fixtures/wasi-exfil.wasm (363 bytes)
host environment (inferred): WASI preview1

CAPABILITY SET (6)
  filesystem               read and write host files, within whatever the host preopened
  network                  open, read and write network sockets
  process                  end or signal the process it runs in
  clock                    read host clocks
  randomness               draw bytes from the host's entropy source
  environment              read environment variables and argv

FINDINGS (12)
  [critical] COMBO-FS-NET-001 (documented)
      the module holds both filesystem and network capability. Either alone is a
      bounded grant; together they are a read-and-send path, and a sandbox that
      permits both is not containing exfiltration.
      - filesystem + network
  [high] EXPORT-MEMORY-001 (documented)
      the module exports its linear memory. Anything holding that export can read
      and write every byte the module owns, including buffers it believes are
      private, so secrets inside this module are only as private as the host's
      handling of the export.
      - memory
  [high] WASI-FS-001 (documented)
      capability: filesystem
      resolves and opens paths relative to the directories the host preopened,
      which is the grant that makes this module a filesystem client
      - wasi_snapshot_preview1.path_open
  [high] WASI-FS-002 (documented)
      capability: filesystem
      reads or writes an open descriptor; descriptors 0-2 are stdio, and any other
      descriptor comes from a preopened directory
      - wasi_snapshot_preview1.fd_read
      - wasi_snapshot_preview1.fd_write
  [high] WASI-NET-001 (documented)
      capability: network
      accepts, reads or writes a socket the host granted, which is an outbound or
      inbound path off the machine
      - wasi_snapshot_preview1.sock_send
  [medium] MEM-UNBOUNDED-001 (documented)
      a memory with no declared maximum will grow until the host refuses. In a
      multi-tenant runtime that is a memory-exhaustion vector against the host's
      other tenants, and it is the host's limit rather than the module's that has
      to stop it.
      - memory 0 (min 2 pages, no maximum)
  [medium] START-FUNCTION-001 (documented)
      the module declares a start function, so code runs at instantiation, before
      the host calls anything. A host that validates a module and then
      instantiates it has already run this.
      - function index 8
  [medium] WASI-ENV-001 (documented)
      capability: environment
      reads the environment and argv, which in most deployments is where
      credentials are
      - wasi_snapshot_preview1.environ_get
  [low] MEMORY-GROW-001 (documented)
      `memory.grow` is reachable, so the module's footprint is decided at run time
      rather than at load time.
      - 1 site(s)
  [low] WASI-CLOCK-001 (documented)
      capability: clock
      reads a host clock, which is both a fingerprinting and a timing-side-channel
      primitive
      - wasi_snapshot_preview1.clock_time_get
  [low] WASI-PROC-001 (documented)
      capability: process
      ends the instance, which in a multi-tenant host is an availability concern
      rather than a confidentiality one
      - wasi_snapshot_preview1.proc_exit
  [low] WASI-RAND-001 (documented)
      capability: randomness
      draws bytes from the host entropy source
      - wasi_snapshot_preview1.random_get

IMPORTS (8)
  wasi_snapshot_preview1.path_open                 func    filesystem                   WASI-FS-001
  wasi_snapshot_preview1.fd_read                   func    filesystem                   WASI-FS-002
  wasi_snapshot_preview1.fd_write                  func    filesystem                   WASI-FS-002
  wasi_snapshot_preview1.sock_send                 func    network                      WASI-NET-001
  wasi_snapshot_preview1.clock_time_get            func    clock                        WASI-CLOCK-001
  wasi_snapshot_preview1.random_get                func    randomness                   WASI-RAND-001
  wasi_snapshot_preview1.environ_get               func    environment                  WASI-ENV-001
  wasi_snapshot_preview1.proc_exit                 func    process                      WASI-PROC-001

EXPORTS (2)
  memory                                   memory  index 0
  _start                                   func    index 8

MEMORY (1)
  memory 0: min 2 pages (128 KiB), no maximum

TABLES (0)
  (none declared or imported)

CODE
  bodies 1, instructions 6, locals 0, max block depth 1
  calls: 1 direct, 0 indirect (table), 0 by reference, 0 tail
  memory.grow 1, memory.size 0, bulk-memory ops 0, table ops 0
  ref ops 0, simd ops 0, atomic ops 0, throws 0
  proposals used: none beyond the MVP
  types 3, functions 1, globals 0, element segments 0, data segments 0

SUMMARY
  critical  1
  high      4
  medium    3
  low       4
  highest severity: critical
```

### When a module cannot be classified

The honest handling of the unknown is the most important behaviour in the
tool. An import that matches no rule is reported as an unknown capability, and
the capability set is explicitly described as a lower bound rather than a
description:

```console
$ wasm-capability-audit tests/fixtures/unknown-host.wasm
wasm-capability-audit 0.1.0
module: tests/fixtures/unknown-host.wasm (134 bytes)
host environment: not recognised from the import module names

CAPABILITY SET (2)
  host-mutable-global      read and write a global the host owns
  unknown                  something this tool could not identify

FINDINGS (3)
  [medium] IMPORT-GLOBAL-MUT-001 (documented)
      capability: host-mutable-global
      an imported mutable global is a two-way channel: the host can change it
      between calls and the module can change what the host reads
      - acme_runtime.tick
  [medium] UNKNOWN-IMPORT-001 (pattern)
      capability: unknown
      no rule matched this import, so what the host grants through it is unknown;
      an unrecognised host function is reviewed by hand or it is not reviewed at
      all
      - acme_runtime.blit_region
      - acme_runtime.frobnicate
      - acme_runtime.quux
  [medium] UNKNOWN-SUMMARY-001 (documented)
      some imports could not be classified. The capability set above is therefore
      a lower bound on what this module can do, not a description of it.
      - 3 unclassified import(s)
```

### Diffing two versions

This is the mode that earns a place in a dependency pipeline. `diff` exits 1
when the new module has capabilities the old one did not, which is the
behaviour a CI job wants.

```console
$ wasm-capability-audit diff tests/fixtures/wasi-clock-only.wasm tests/fixtures/wasi-clock-and-socket.wasm
wasm-capability-audit 0.1.0
old: tests/fixtures/wasi-clock-only.wasm
new: tests/fixtures/wasi-clock-and-socket.wasm

CAPABILITIES ADDED (1)
  + network                  open, read and write network sockets

CAPABILITIES REMOVED (0)
  (none)

IMPORTS ADDED (1)
  + wasi_snapshot_preview1.sock_send (func)
IMPORTS REMOVED (0)

EXPORTS ADDED (0)
EXPORTS REMOVED (0)

POSTURE CHANGES (0)
  (none)

$ echo $?
1
```

### Policy mode

A policy is one directive per line, with `#` starting a comment. It is parsed
by this crate, not by a TOML library. A directive the file does not mention is
not checked — in particular, a policy with no `allow` line does not constrain
capabilities at all, because an allow-list that defaults to "everything" and
one that defaults to "nothing" are both surprising, and saying which it is
beats guessing.

```
allow <capability>                  # repeatable; opt-in allow-list
max-severity <severity>             # info | low | medium | high | critical
allow-unknown-imports <yes|no>
allow-exported-memory <yes|no>
allow-mutable-global-export <yes|no>
allow-start-function <yes|no>
require-memory-max <yes|no>
max-memory-pages <n>
```

Two worked policies are committed in `policies/`. Checking a browser module
against the sandboxed-plugin policy:

```console
$ wasm-capability-audit --policy policies/sandboxed-plugin.policy tests/fixtures/bindgen-browser.wasm
... (full report elided) ...

POLICY VIOLATIONS (9)
  ! a memory declares no maximum, so the policy limit of 256 pages cannot be met
  ! capability js-arbitrary is not allowed by the policy (call into host JavaScript)
  ! capability js-eval is not allowed by the policy (have the host evaluate JavaScript source it supplies)
  ! capability js-messaging is not allowed by the policy (post messages to other browsing contexts or workers)
  ! capability js-network is not allowed by the policy (make network requests through host JavaScript)
  ! capability js-storage is not allowed by the policy (read and write browser-side persistent storage)
  ! memory 0 declares no maximum
  ! module exports a mutable global
  ! module exports its linear memory

$ echo $?
1
```

### JSON output

One line, hand-serialised, deterministic. Names in the binary format are
arbitrary UTF-8, so the escaping is tested directly (see
`tests/output.rs`).

```console
$ wasm-capability-audit --json tests/fixtures/wasi-clock-only.wasm
{"tool":"wasm-capability-audit","version":"0.1.0","source":"tests/fixtures/wasi-clock-only.wasm","size_bytes":124,"host_environments":["WASI preview1"],"capabilities":[{"id":"clock","grants":"read host clocks"},{"id":"randomness","grants":"draw bytes from the host's entropy source"}],"findings":[{"rule":"WASI-CLOCK-001","severity":"low","basis":"documented","capability":"clock","rationale":"reads a host clock, which is both a fingerprinting and a timing-side-channel primitive","evidence":["wasi_snapshot_preview1.clock_time_get"]},{"rule":"WASI-RAND-001","severity":"low","basis":"documented","capability":"randomness","rationale":"draws bytes from the host entropy source","evidence":["wasi_snapshot_preview1.random_get"]}],"imports":[{"module":"wasi_snapshot_preview1","name":"clock_time_get","kind":"func","capabilities":["clock"],"rules":["WASI-CLOCK-001"]},{"module":"wasi_snapshot_preview1","name":"random_get","kind":"func","capabilities":["randomness"],"rules":["WASI-RAND-001"]}],"exports":[{"name":"run","kind":"func","index":2,"mutable":null}],"memories":[{"imported":false,"min_pages":1,"max_pages":16,"shared":false,"index64":false}],"tables":[],"start_function":null,"code":{"scanned":true,"bodies":1,"instructions":1,"declared_locals":0,"call_direct":0,"call_indirect":0,"call_ref":0,"tail_calls":0,"memory_grow":0,"memory_size":0,"bulk_memory_ops":0,"table_ops":0,"ref_ops":0,"simd_ops":0,"atomic_ops":0,"throw_ops":0,"max_block_depth":1},"proposals_used":[],"counts":{"types":2,"functions":1,"globals":0,"element_segments":0,"data_segments":0},"custom_sections":[],"summary":{"by_severity":{"critical":0,"high":0,"medium":0,"low":2,"info":0},"highest_severity":"low","unknown_imports":false}}
```

## Capability rules

`documented` means the rule matches an exact name in an interface this tool
models from that interface's own definition. `pattern` means it matches a
prefix, a module name or a substring — a useful guess, labelled as a guess in
every rendering of the output. The distinction is mechanical: exact name in a
modelled interface is documented, everything else is pattern. Run
`--list-rules` for the identifiers and `--list-capabilities` for the
capability set.

### WASI preview1 (`wasi_snapshot_preview1`, `wasi_unstable`, `wasi_snapshot_preview2`)

| Rule | Matches | Capability | Severity | Basis | What it grants |
| --- | --- | --- | --- | --- | --- |
| `WASI-FS-001` | `path_open`, `path_rename`, `path_link`, `path_symlink`, `path_readlink`, `path_unlink_file`, `path_create_directory`, `path_remove_directory`, `path_filestat_get`, `path_filestat_set_times`, `fd_prestat_dir_name` | `filesystem` | high | documented | Resolving and opening paths under the host's preopened directories |
| `WASI-FS-002` | `fd_read`, `fd_write`, `fd_pread`, `fd_pwrite`, `fd_seek`, `fd_readdir`, `fd_prestat_get`, `fd_close`, `fd_sync`, `fd_datasync`, `fd_tell`, `fd_advise`, `fd_allocate`, `fd_renumber`, `fd_fdstat_get`, `fd_fdstat_set_flags`, `fd_fdstat_set_rights`, `fd_filestat_get`, `fd_filestat_set_size`, `fd_filestat_set_times` | `filesystem` | high | documented | Reading and writing open descriptors (including stdio) |
| `WASI-NET-001` | `sock_accept`, `sock_recv`, `sock_send`, `sock_shutdown` | `network` | high | documented | The four socket calls preview1 defines |
| `WASI-NET-002` | any other `sock_*` | `network` | high | pattern | A WASIX or runtime-specific socket extension, usually with connect/bind semantics |
| `WASI-PROC-001` | `proc_exit` | `process` | low | documented | Ending the instance |
| `WASI-PROC-002` | `proc_raise` | `process` | medium | documented | Raising a signal in the host process |
| `WASI-SCHED-001` | `sched_yield` | `process` | info | documented | Yielding the scheduler; a timing primitive |
| `WASI-CLOCK-001` | `clock_time_get`, `clock_res_get` | `clock` | low | documented | Host clocks, hence fingerprinting and timing side channels |
| `WASI-RAND-001` | `random_get` | `randomness` | low | documented | The host entropy source |
| `WASI-ENV-001` | `environ_get`, `environ_sizes_get`, `args_get`, `args_sizes_get` | `environment` | medium | documented | Environment and argv, which is where credentials usually are |
| `WASI-POLL-001` | `poll_oneoff` | `polling` | low | documented | Waiting on host events |
| `WASI-UNKNOWN-001` | any other name in a WASI module | `unknown` | medium | pattern | A newer snapshot or a runtime extension this tool does not model |

### WASI 0.2 / component model (`wasi:<package>/<interface>`)

Matched on the interface-name convention rather than on function names, so
every hit is pattern-based.

| Rule | Matches | Capability | Severity | Basis |
| --- | --- | --- | --- | --- |
| `WASI2-FS-001` | `wasi:filesystem/*` | `filesystem` | high | pattern |
| `WASI2-NET-001` | `wasi:sockets/*` | `network` | high | pattern |
| `WASI2-HTTP-001` | `wasi:http/*` | `network` | high | pattern |
| `WASI2-CLOCK-001` | `wasi:clocks/*` | `clock` | low | pattern |
| `WASI2-RAND-001` | `wasi:random/*` | `randomness` | low | pattern |
| `WASI2-ENV-001` | `wasi:cli/environment` | `environment` | medium | pattern |
| `WASI2-PROC-001` | `wasi:cli/exit` | `process` | low | pattern |
| `WASI2-IO-001` | other `wasi:cli/*` | `host-io` | low | pattern |
| `WASI2-IO-002` | `wasi:io/*` | `host-io` | low | pattern |
| `WASI2-UNKNOWN-001` | any other `wasi:*` package | `unknown` | medium | pattern |

### Emscripten and JavaScript glue

| Rule | Matches | Capability | Severity | Basis | What it grants |
| --- | --- | --- | --- | --- | --- |
| `EMSC-SYSCALL-001` | `__syscall*`, `__sys_*` | `raw-syscall` | critical | pattern | Not a narrow capability but a kernel interface; whatever the glue wires behind it is the real boundary |
| `EMSC-INVOKE-001` | `invoke_*` | `indirect-js-dispatch` | high | pattern | Calling host function-table entries chosen at run time, so the call target is data |
| `EMSC-JSEVAL-001` | `emscripten_run_script*`, `emscripten_asm_const*` | `js-eval` | critical | documented | The module hands JavaScript source to the host and the host runs it |
| `EMSC-NET-001` | `emscripten_fetch*`, `emscripten_wget*`, `emscripten_async_wget*`, `emscripten_websocket*` | `js-network` | high | pattern | Network access over fetch, XHR or WebSocket |
| `EMSC-MEM-001` | `emscripten_resize_heap`, `emscripten_memcpy_big`, `emscripten_memcpy_js` | `host-memory` | low | documented | The host grows or copies the module's heap |
| `EMSC-GENERIC-001` | any other `emscripten_*` | `js-arbitrary` | medium | pattern | Host JavaScript not otherwise classified; read the glue |
| `SHIM-ABORT-001` | `abort`, `_abort_js`, `__assert_fail`, `exit`, `_exit`, in any module | `process` | low | documented | The abort and exit shims every WebAssembly toolchain emits; the module can end its own instance |

### wasm-bindgen (module `wbg`, or `__wbg_*` / `__wbindgen_*` names)

`wasm-bindgen` encodes the JavaScript it binds into the import symbol, so the
symbol names are searched for the APIs worth knowing about. Substring matching
on a mangled symbol is a guess and is reported as one.

| Rule | Matches | Capability | Severity | Basis | What it grants |
| --- | --- | --- | --- | --- | --- |
| `BINDGEN-GLUE-001` | `__wbindgen_*` | `js-arbitrary` | high | pattern | The runtime glue: creating, reading, calling and throwing arbitrary JS values |
| `BINDGEN-JS-001` | `__wbg_*`, or anything in module `wbg` | `js-arbitrary` | high | pattern | A specific JS binding; the symbol names what the host will call |
| `BINDGEN-NET-001` | symbol contains `fetch`, `xmlhttprequest`, `websocket`, `eventsource`, `sendbeacon`, `requestinit` | `js-network` | high | pattern | Network access through the host |
| `BINDGEN-EVAL-001` | symbol contains `eval`, `importscripts`, `newfunction`, `newnoargs` | `js-eval` | critical | pattern | `eval`, `importScripts` or the `Function` constructor (`newnoargs` is what wasm-bindgen emits for `new Function`) |
| `BINDGEN-STORAGE-001` | symbol contains `localstorage`, `sessionstorage`, `indexeddb`, `opendatabase`, `cookie` | `js-storage` | medium | pattern | Origin-scoped persistent storage, which often holds tokens |
| `BINDGEN-MSG-001` | symbol contains `postmessage`, `broadcastchannel`, `messagechannel`, `messageport`, `worker` | `js-messaging` | medium | pattern | Cross-context messaging |
| `BINDGEN-CRYPTO-001` | symbol contains `crypto`, `getrandomvalues`, `subtle` | `js-crypto` | low | pattern | Web Crypto |
| `BINDGEN-DOM-001` | symbol contains `document`, `innerhtml`, `createelement`, `queryselector`, `appendchild`, `location` | `js-dom` | medium | pattern | Reading or changing the host document |

### Smart-contract host interfaces

Coverage is listed precisely below, including what is **not** covered. No
host-function name in this tool was invented.

**NEAR** (module `env`) — documented. Classified by what the function does:

| Rule | Capability | Severity | Example names |
| --- | --- | --- | --- |
| `NEAR-STORAGE-WRITE-001` | `contract-storage-write` | high | `storage_write`, `storage_remove` |
| `NEAR-STORAGE-READ-001` | `contract-storage-read` | low | `storage_read`, `storage_has_key`, `storage_iter_*`, `storage_usage` |
| `NEAR-CALL-001` | `contract-call` | high | `promise_create`, `promise_then`, `promise_batch_*`, `promise_result` |
| `NEAR-TRANSFER-001` | `contract-value-transfer` | high | `promise_batch_action_transfer`, `..._stake`, `..._unstake` |
| `NEAR-DEPLOY-001` | `contract-code-deploy` | high | `promise_batch_action_deploy_contract`, `..._create_account` |
| `NEAR-KEYS-001` | `contract-account-keys` | critical | `promise_batch_action_add_key_with_full_access` and the other key actions |
| `NEAR-DELETE-ACCOUNT-001` | `contract-self-destruct` | critical | `promise_batch_action_delete_account` |
| `NEAR-RANDOM-001` | `contract-randomness` | medium | `random_seed`, which the block producer sees first |
| `NEAR-CONTEXT-001` | `contract-chain-context` | info | `signer_account_id`, `block_timestamp`, `attached_deposit`, … |
| `NEAR-CRYPTO-001` | `contract-crypto` | info | `sha256`, `keccak256`, `ecrecover`, `alt_bn128_*`, … |
| `NEAR-REGISTER-001` | `host-io` | info | `read_register`, `write_register`, `value_return` |
| `NEAR-LOG-001` | `debug-logging` | info | `log_utf8`, `log_utf16` |
| `NEAR-ABORT-001` | `process` | info | `panic`, `panic_utf8` (plain `abort` is handled by `SHIM-ABORT-001`) |
| `NEAR-GAS-001` | `contract-chain-context` | info | `gas` |

**CosmWasm** (module `env`) — documented:

| Rule | Capability | Severity | Names |
| --- | --- | --- | --- |
| `COSMWASM-DB-WRITE-001` | `contract-storage-write` | high | `db_write`, `db_remove` |
| `COSMWASM-DB-READ-001` | `contract-storage-read` | low | `db_read`, `db_scan`, `db_next` |
| `COSMWASM-QUERY-001` | `contract-call` | medium | `query_chain` |
| `COSMWASM-ADDR-001` | `contract-chain-context` | info | `addr_validate`, `addr_canonicalize`, `addr_humanize` |
| `COSMWASM-CRYPTO-001` | `contract-crypto` | info | `secp256k1_verify`, `ed25519_verify`, `bls12_381_pairing_equality`, … |
| `COSMWASM-DEBUG-001` | `debug-logging` | info | `debug` |

Note a real limitation here: a CosmWasm contract's state-changing messages
leave through its *response*, not through an import, so the import list cannot
show them. `COSMWASM-QUERY-001` says so in its rationale.

**Internet Computer** (module `ic0`) — documented:

| Rule | Capability | Severity | Names |
| --- | --- | --- | --- |
| `IC0-STABLE-WRITE-001` | `contract-storage-write` | high | `stable_write`, `stable64_write`, `stable_grow`, `stable64_grow` |
| `IC0-STABLE-READ-001` | `contract-storage-read` | low | `stable_read`, `stable64_read`, `stable_size`, `stable64_size` |
| `IC0-CALL-001` | `contract-call` | high | `call_new`, `call_perform`, `call_data_append`, `msg_reply`, … |
| `IC0-CYCLES-001` | `contract-value-transfer` | high | `call_cycles_add*`, `msg_cycles_accept*`, `msg_cycles_available*` |
| `IC0-RAND-001` | `contract-randomness` | medium | `raw_rand` |
| `IC0-CONTEXT-001` | `contract-chain-context` | info | `msg_caller_copy`, `msg_arg_data_copy`, `canister_self_copy`, `time`, … |
| `IC0-CERTIFIED-001` | `contract-storage-write` | medium | `certified_data_set` |
| `IC0-DEBUG-001` | `debug-logging` | info | `debug_print`, `trap` |

**Substrate `pallet-contracts` / ink!** (modules `seal0`, `seal1`, `seal2`, …)
— **pattern-based**. The names below are matched exactly, but the set shifts
between pallet versions, so every hit is reported as `pattern` rather than
`documented`:

| Rule | Capability | Severity | Names |
| --- | --- | --- | --- |
| `SEAL-STORAGE-WRITE-001` | `contract-storage-write` | high | `set_storage`, `clear_storage`, `take_storage`, and the `seal_`-prefixed forms |
| `SEAL-STORAGE-READ-001` | `contract-storage-read` | low | `get_storage`, `contains_storage`, and the `seal_`-prefixed forms |
| `SEAL-CALL-001` | `contract-call` | high | `call`, `call_chain_extension`, and the `seal_`-prefixed forms |
| `SEAL-DELEGATE-001` | `contract-delegate-call` | critical | `delegate_call`, `seal_delegate_call` |
| `SEAL-INSTANTIATE-001` | `contract-code-deploy` | high | `instantiate`, `seal_instantiate` |
| `SEAL-TRANSFER-001` | `contract-value-transfer` | high | `transfer`, `seal_transfer` |
| `SEAL-TERMINATE-001` | `contract-self-destruct` | critical | `terminate`, `seal_terminate` |
| `SEAL-RANDOM-001` | `contract-randomness` | medium | `random`, `seal_random` |

**ewasm** (module `ethereum`) — **pattern-based**, and note this is the
deprecated ewasm Ethereum Environment Interface, kept because modules built
against it still exist, not because the project is live:

| Rule | Capability | Severity | Names |
| --- | --- | --- | --- |
| `EWASM-STORAGE-WRITE-001` | `contract-storage-write` | high | `storageStore` |
| `EWASM-STORAGE-READ-001` | `contract-storage-read` | low | `storageLoad` |
| `EWASM-CALL-001` | `contract-call` | high | `call`, `callCode`, `callStatic` |
| `EWASM-DELEGATE-001` | `contract-delegate-call` | critical | `callDelegate` |
| `EWASM-CREATE-001` | `contract-code-deploy` | high | `create` |
| `EWASM-SELFDESTRUCT-001` | `contract-self-destruct` | critical | `selfDestruct` |

### Generic name patterns

These run when nothing more specific matched, so an unfamiliar host interface
still produces a useful first read instead of a wall of unknowns. Every hit is
`pattern`. This is how **Arbitrum Stylus** modules (module `vm_hooks`) are
classified: by the shape of names like `storage_cache_bytes32`,
`call_contract`, `delegate_call_contract` and `create2`, and not from a
modelled interface — the environment is named in the report, the
classifications are labelled guesses.

| Rule | Matches a name containing | Capability | Severity |
| --- | --- | --- | --- |
| `PATTERN-DELEGATE-001` | `delegate` and `call` | `contract-delegate-call` | critical |
| `PATTERN-STORAGE-WRITE-001` | `storage_write`, `set_storage`, `storage_cache`, `storage_flush`, `db_write`, … | `contract-storage-write` | high |
| `PATTERN-STORAGE-READ-001` | `storage_read`, `storage_load`, `get_storage`, `db_read`, … | `contract-storage-read` | low |
| `PATTERN-CALL-001` | `call_contract`, `contract_call`, `cross_contract`, `static_call`, `callcode` | `contract-call` | high |
| `PATTERN-TRANSFER-001` | `transfer`, `send_value`, `msg_value`, `withdraw`, `payout` | `contract-value-transfer` | high |
| `PATTERN-DEPLOY-001` | `create1`, `create2`, `deploy`, `instantiate` | `contract-code-deploy` | high |
| `PATTERN-DESTROY-001` | `selfdestruct`, `suicide`, `terminate`, `delete_account` | `contract-self-destruct` | critical |
| `PATTERN-RANDOM-001` | `random`, `entropy`, `_seed`, `rng` | `contract-randomness` | medium |
| `PATTERN-CRYPTO-001` | `keccak`, `sha256`, `blake2`, `secp256`, `ed25519`, `bls12`, … | `contract-crypto` | info |
| `PATTERN-CONTEXT-001` | `block_number`, `block_timestamp`, `chainid`, `tx_origin`, `msg_sender`, `gas_left`, … | `contract-chain-context` | info |
| `PATTERN-NET-001` | `socket`, `sock_`, `http_`, `tcp_`, `udp_`, `dns_`, `fetch`, `curl` | `network` | high |
| `PATTERN-FS-001` | `fopen`, `open_file`, `readfile`, `path_`, `unlink`, `mkdir`, `opendir`, `fstat`, … | `filesystem` | high |
| `PATTERN-EXEC-001` | `exec`, `spawn`, `fork`, `popen`, `system_`, `shell` | `process` | critical |
| `PATTERN-EVAL-001` | `eval`, `run_script`, `compile_script` | `js-eval` | critical |
| `PATTERN-LOG-001` | `debug`, `log_`, `_log`, `print`, `trace`, `emit_log` | `debug-logging` | info |

### Non-function imports, combinations and module posture

| Rule | Severity | Basis | What it reports |
| --- | --- | --- | --- |
| `IMPORT-MEMORY-001` | medium | documented | The host supplies the linear memory, so everything the module stores is already in the host's hands |
| `IMPORT-TABLE-001` | medium | documented | The host supplies a function table; entries the host installs become call targets inside the module |
| `IMPORT-GLOBAL-MUT-001` | medium | documented | An imported mutable global is a two-way channel. Immutable global imports produce no finding |
| `IMPORT-TAG-001` | info | documented | An imported exception tag lets the host throw into the module |
| `UNKNOWN-IMPORT-001` | medium | pattern | No rule matched; what this grants is unknown |
| `UNKNOWN-SUMMARY-001` | medium | documented | Some imports were unclassified, so the capability set is a lower bound |
| `COMBO-FS-NET-001` | critical | documented | Filesystem and network together: a read-and-send path |
| `COMBO-STORAGE-CALL-001` | high | documented | Storage writes plus cross-contract calls: a reentrancy surface a reviewer now has to check |
| `NO-IMPORTS-001` | info | documented | No imports at all, so no host authority |
| `EXPORT-MEMORY-001` | high | documented | The module's entire linear memory is readable and writable by whoever holds the export |
| `EXPORT-MUT-GLOBAL-001` | high | documented | An exported mutable global is a write primitive into the module's state |
| `EXPORT-GLOBAL-UNRESOLVED-001` | low | documented | A global export names an index outside the global space; mutability unknown, and the module would not validate |
| `EXPORT-TABLE-001` | medium | documented | An exported table is where every `call_indirect` in the module dispatches |
| `MEM-UNBOUNDED-001` | medium | documented | A memory with no maximum, which only the host's limit bounds |
| `MEM-SHARED-001` | medium | documented | Shared memory: other instances or threads hold the same bytes |
| `MEM-LARGE-MAX-001` | low | documented | A maximum of 32768 pages (2 GiB) or more, so the limit is nominal |
| `TABLE-UNBOUNDED-001` | low | documented | A table with no maximum |
| `START-FUNCTION-001` | medium | documented | Code runs at instantiation, before the host calls anything |
| `MEMORY-GROW-001` | low | documented | `memory.grow` is reachable |
| `CALL-INDIRECT-001` | info | documented | Indirect call sites, where control-flow integrity in WebAssembly actually lives |
| `CODE-NOT-SCANNED-001` | info | documented | `--no-code-scan` was used, so instruction counts are unavailable rather than zero |
| `THREADS-001` | low | documented | The threads proposal is in use |
| `BULK-MEMORY-001` | info | documented | Bulk-memory operations are in use |
| `REF-TYPES-001` | info | documented | Reference types are in use |
| `NAME-SECTION-001` | info | documented | A name section ships symbol names; useful to a reviewer, and more than a release build need disclose |

## Robustness

A binary parser's headline property is that hostile input does not break it,
so that is tested as the headline property. `tests/malformed.rs` is 46 tests
covering:

- a zero-byte file, and truncation at every length of the magic and version;
- **every prefix of every fixture** — roughly 1,400 truncations — asserting no
  panic, and that any reported offset is within the input;
- **every single-byte corruption** of a fixture at three replacement values,
  asserting no panic;
- a section length longer than the remaining bytes;
- a vector count longer than the remaining bytes, including `0xffffffff`
  elements declared in a four-byte section;
- a LEB128 that never terminates, one that runs to end of file, an over-long
  encoding (six bytes for a 32-bit value), and one whose final byte sets bits
  above the type's width;
- signed LEB128 over-length and sign-extension overflow;
- negative signed LEB round-trips, including `i32::MIN` and `i64::MIN`;
- a section whose contents do not fill its declared length, and a function
  body with bytes after its `end`;
- an unknown section id, a duplicate section, and sections out of the
  prescribed order;
- invalid UTF-8 in an import name and in an export name;
- unknown value types, reference types, type forms, import descriptors, export
  kinds, limits flags, mutability bytes, element-segment kinds and
  data-segment kinds;
- inverted limits (`max < min`);
- unknown opcodes, including the GC prefix `0xFB`, and unknown sub-opcodes
  behind the `0xFC` and `0xFD` prefixes;
- twenty thousand nested `block` instructions, which an implementation that
  recursed per block would meet with a stack overflow;
- an unterminated instruction sequence and an unterminated constant
  expression;
- an instruction that is not permitted in a constant expression.

Two further properties are asserted, not just claimed:

- **No allocation is ever sized from a number in the file.** A vector count or
  byte length is validated against the bytes that actually remain before
  anything is built from it, and the crate contains no `Vec::with_capacity(n)`
  or `.reserve(n)` where `n` came from input. A test
  (`the_parser_never_sizes_an_allocation_from_the_file`) reads the crate's own
  source and fails if one appears.
- **A section the parser cannot decode is an error, not a skip.** A parser
  that silently skipped an unknown section would cheerfully report "no network
  imports" for a module full of them. Every error names the section, the byte
  offset in hex and decimal, and what specifically was wrong.

A third property closes the loop on the documentation itself:

- **Every rule in the table above is demonstrably reachable.**
  `tests/reachability.rs` drives one input per rule and asserts that the union
  of everything emitted is exactly the registry, so a rule cannot be
  documented without a worked example behind it, and a rule that becomes
  unreachable through a refactor fails the build. (It has already caught one:
  an abort-shim rule that could never fire because an earlier branch claimed
  the import first.) A companion test in `tests/rule_registry.rs` reads
  `src/classify.rs` and `src/audit.rs` and fails if a rule identifier exists
  in the code but not in the registry, or in the registry but not in this
  README.

Run it — 203 tests, no network, no fixtures to download:

```sh
cargo test
```

## What this tool does not do

- **It does not execute the module.** There is no interpreter, no JIT, no
  `wasmtime`. It reads bytes.
- **It does not validate the module.** It does not type-check, does not
  resolve indices against their spaces (except for one case: resolving an
  exported global's mutability, where a failure to resolve is itself
  reported), and does not check that a module would instantiate. A module this
  tool parses may still be rejected by a real runtime.
- **It cannot tell you whether a capability is used.** An import is authority
  granted, not authority exercised. A module may import `sock_send` and never
  call it. Dead-code analysis is a different tool; what this reports is what
  the host must hand over for the module to load at all.
- **It does not decode the garbage-collection proposal** (`0xFB`-prefixed
  instructions, and the `rec`/`sub` type forms). It fails with the proposal
  named rather than guessing. `--no-code-scan` lets you still audit the import
  and export surface of such a module.
- **It does not read the component model.** A component binary has a different
  preamble version and is rejected as unsupported, naming the version it saw.
  Core modules that import `wasi:*` interface names are classified; the
  component wrapper itself is not parsed.
- **It does not resolve what a host actually implements.** `env.helper` tells
  you a function called `helper` is required, not what the host put behind it.
  For Emscripten and `wasm-bindgen`, the glue file is still the ground truth;
  the import list tells you where to look.
- **It does not cover Solana.** Solana programs are eBPF/SBF, not
  WebAssembly. Nor does it cover EVM bytecode. Contract platforms covered are
  NEAR, CosmWasm, the Internet Computer, Substrate `pallet-contracts`/ink!,
  the deprecated ewasm EEI, and — by generic name pattern only — Arbitrum
  Stylus. Anything else falls through to the generic patterns and then to
  `unknown`.
- **It makes no network requests** and reads nothing but the file paths you
  give it.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Audit completed; nothing exceeded the policy or the severity threshold. For `diff`, no capability was added. |
| `1` | A policy was violated, `--fail-on` was met, or `diff` found capabilities the old module did not have. |
| `2` | Usage error, or a policy file that could not be parsed. |
| `3` | The module could not be parsed. The message names the section and byte offset. |
| `4` | A file could not be read. |

A parse failure looks like this, and is a clean exit rather than a panic:

```console
$ head -c 100 tests/fixtures/wasi-exfil.wasm > truncated.wasm
$ wasm-capability-audit truncated.wasm
wasm-capability-audit: truncated.wasm: section header at byte 0x1b (27): declared length/count 286 exceeds the 71 byte(s) remaining
$ echo $?
3
```

## Test fixtures

`tests/fixtures/*.wasm` are not opaque binaries. Each is assembled field by
field, with comments naming every field, in `src/fixtures.rs`, and written out
by:

```sh
cargo run --example make_fixtures
```

`tests/fixtures.rs` asserts that the committed bytes still match what the
builder produces, and that the directory holds nothing the builder does not
generate — so a stale or hand-edited fixture fails the build. No `.wasm` file
here was downloaded from anywhere, and none is a real project's compiled
output.

## Layout

| Path | What is in it |
| --- | --- |
| `src/reader.rs` | Bounds-checked cursor; LEB128, signed and unsigned, with over-long and overflow rejection |
| `src/error.rs` | Error kinds, each naming the section, the offset and what was wrong |
| `src/module.rs` | Section decoder and the module structure |
| `src/instr.rs` | Instruction-by-instruction scanner for function bodies and constant expressions |
| `src/classify.rs` | The capability rules |
| `src/capability.rs` | Capabilities, severities, and the documented/pattern distinction |
| `src/audit.rs` | Findings: imports, combinations, exports, memory and code posture |
| `src/policy.rs` | The policy format and its evaluation |
| `src/diff.rs` | Comparing two versions of a module |
| `src/report.rs` | Text and JSON rendering |
| `src/json.rs` | The JSON writer, escaping included |
| `src/rules.rs` | The rule registry, kept in step with the code by a test |
| `src/fixtures.rs` | The readable fixture byte-builder |
| `src/main.rs` | The command-line interface and its exit codes |
| `policies/` | Two worked policy files |
| `tests/` | 203 tests; `malformed.rs` is the robustness battery |

## Licence

MIT. See [LICENSE](LICENSE).
