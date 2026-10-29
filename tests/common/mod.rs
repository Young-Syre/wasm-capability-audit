//! Shared helpers for the integration tests.
//!
//! Everything here builds module bytes by hand so that each test states
//! exactly which byte it is corrupting.

#![allow(dead_code)]

pub use wasm_capability_audit::fixtures::*;

use wasm_capability_audit::error::{Context, ErrorKind};
use wasm_capability_audit::{parse, ParseError};

/// Parse and expect failure, returning the error.
pub fn expect_err(bytes: &[u8]) -> ParseError {
    match parse(bytes) {
        Ok(m) => panic!(
            "expected a parse error, got a module with {} import(s)",
            m.imports.len()
        ),
        Err(e) => e,
    }
}

/// Parse and expect failure with a specific error kind.
pub fn expect_kind(bytes: &[u8], kind: ErrorKind) -> ParseError {
    let e = expect_err(bytes);
    assert_eq!(e.kind, kind, "wrong error kind (error was: {e})");
    e
}

/// Parse and expect failure in a specific section.
pub fn expect_context(bytes: &[u8], ctx: Context) -> ParseError {
    let e = expect_err(bytes);
    assert_eq!(e.context, ctx, "wrong context (error was: {e})");
    e
}

/// Parse and expect success.
pub fn expect_ok(bytes: &[u8]) -> wasm_capability_audit::Module {
    match parse(bytes) {
        Ok(m) => m,
        Err(e) => panic!("expected a module, got error: {e}"),
    }
}

/// A module with just the preamble.
pub fn preamble_only() -> Vec<u8> {
    module(&[])
}

/// A one-function module whose body is exactly `code`, followed by `end`.
pub fn module_with_body(code: &[u8]) -> Vec<u8> {
    module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(3, &vector(&[uleb(0)])),
        section(5, &vector(&[limits(1, Some(1), false)])),
        section(10, &vector(&[body(&[], code)])),
    ])
}

/// A module with one import of the given module and field names.
pub fn module_with_import(module_name: &str, field: &str) -> Vec<u8> {
    module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(2, &vector(&[import_func(module_name, field, 0)])),
    ])
}

/// Audit a module built with one import, and return the report.
pub fn audit_import(module_name: &str, field: &str) -> wasm_capability_audit::Report {
    let bytes = module_with_import(module_name, field);
    wasm_capability_audit::audit_bytes(&bytes, "test").expect("module should parse")
}

/// The rule identifiers a report produced, sorted.
pub fn rules_of(r: &wasm_capability_audit::Report) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = r.findings.iter().map(|f| f.rule).collect();
    v.sort_unstable();
    v
}

/// The capability identifiers a report produced, sorted.
pub fn caps_of(r: &wasm_capability_audit::Report) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = r.capabilities.iter().map(|c| c.id()).collect();
    v.sort_unstable();
    v
}
