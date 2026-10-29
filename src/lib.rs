//! A WebAssembly module capability and host-surface auditor.
//!
//! WebAssembly has no ambient authority. A module cannot open a file, read a
//! clock or reach the network unless the host hands it a function that does,
//! and every such function appears, by name, in the module's import section.
//! That makes a module's security posture very largely a question about a
//! list that is right there in the binary — and in practice nobody reads it,
//! because the module arrives as a `.wasm` blob inside a dependency, a
//! plugin, a contract runtime or a browser bundle.
//!
//! This crate decodes that list and says what each entry grants, what the
//! module hands back to the host in return, and what its memory and table
//! declarations permit. It parses the binary format itself and depends on
//! nothing outside `std`. It never executes the module.

#![forbid(unsafe_code)]

pub mod audit;
pub mod capability;
pub mod classify;
pub mod diff;
pub mod error;
pub mod fixtures;
pub mod instr;
pub mod json;
pub mod module;
pub mod policy;
pub mod reader;
pub mod report;
pub mod rules;

pub use audit::{audit, Report};
pub use capability::{Basis, Capability, Severity};
pub use error::{ErrorKind, ParseError};
pub use module::{parse, parse_with, Module, ParseOptions};
pub use policy::Policy;

/// Parse and audit a module in one step.
pub fn audit_bytes(bytes: &[u8], source: &str) -> Result<Report, ParseError> {
    audit_bytes_with(bytes, source, ParseOptions::default())
}

/// Parse and audit a module with explicit parse options.
pub fn audit_bytes_with(
    bytes: &[u8],
    source: &str,
    opts: ParseOptions,
) -> Result<Report, ParseError> {
    let m = parse_with(bytes, opts)?;
    Ok(audit(&m, source, bytes.len()))
}
