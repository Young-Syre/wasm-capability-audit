//! Policy files.
//!
//! A policy declares what a module is allowed to be, so the tool can sit in
//! CI and fail a build when a module exceeds it. The format is deliberately
//! small and parsed here rather than by a dependency: one directive per line,
//! `#` to end of line is a comment, blank lines ignored.
//!
//! ```text
//! # what this module may ask the host for
//! allow clock
//! allow randomness
//! allow host-io
//!
//! max-severity medium
//! allow-unknown-imports no
//! allow-exported-memory no
//! allow-mutable-global-export no
//! allow-start-function no
//! require-memory-max yes
//! max-memory-pages 256
//! ```
//!
//! A directive the file does not mention is not checked. In particular, a
//! policy with no `allow` line does not constrain capabilities at all — the
//! allow-list is opt-in, and saying so here is better than a default that
//! quietly passes everything or quietly fails everything.

use crate::audit::Report;
use crate::capability::{Capability, Severity};
use std::fmt;

/// A parsed policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// `None` when the file declared no `allow` directive.
    pub allowed: Option<Vec<Capability>>,
    pub max_severity: Option<Severity>,
    pub allow_unknown_imports: Option<bool>,
    pub allow_exported_memory: Option<bool>,
    pub allow_mutable_global_export: Option<bool>,
    pub allow_start_function: Option<bool>,
    pub require_memory_max: Option<bool>,
    pub max_memory_pages: Option<u64>,
}

/// A problem with the policy file itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for PolicyError {}

fn parse_bool(value: &str, line: usize) -> Result<bool, PolicyError> {
    match value {
        "yes" | "true" | "on" | "1" => Ok(true),
        "no" | "false" | "off" | "0" => Ok(false),
        other => Err(PolicyError {
            line,
            message: format!("expected yes or no, got {other:?}"),
        }),
    }
}

impl Policy {
    /// Parse a policy file's text.
    pub fn parse(text: &str) -> Result<Policy, PolicyError> {
        let mut p = Policy::default();
        for (idx, raw) in text.lines().enumerate() {
            let line = idx + 1;
            let without_comment = match raw.find('#') {
                Some(i) => &raw[..i],
                None => raw,
            };
            let trimmed = without_comment.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.splitn(2, char::is_whitespace);
            let key = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("").trim();
            if value.is_empty() {
                return Err(PolicyError {
                    line,
                    message: format!("directive {key:?} needs a value"),
                });
            }
            match key {
                "allow" => {
                    let cap = Capability::parse(value).ok_or_else(|| PolicyError {
                        line,
                        message: format!(
                            "unknown capability {value:?}; run --list-capabilities for the set"
                        ),
                    })?;
                    p.allowed.get_or_insert_with(Vec::new).push(cap);
                }
                "max-severity" => {
                    p.max_severity =
                        Some(Severity::parse(value).ok_or_else(|| PolicyError {
                            line,
                            message: format!(
                                "unknown severity {value:?}; expected info, low, medium, high or critical"
                            ),
                        })?);
                }
                "allow-unknown-imports" => p.allow_unknown_imports = Some(parse_bool(value, line)?),
                "allow-exported-memory" => p.allow_exported_memory = Some(parse_bool(value, line)?),
                "allow-mutable-global-export" => {
                    p.allow_mutable_global_export = Some(parse_bool(value, line)?)
                }
                "allow-start-function" => p.allow_start_function = Some(parse_bool(value, line)?),
                "require-memory-max" => p.require_memory_max = Some(parse_bool(value, line)?),
                "max-memory-pages" => {
                    p.max_memory_pages = Some(value.parse::<u64>().map_err(|_| PolicyError {
                        line,
                        message: format!("expected a page count, got {value:?}"),
                    })?);
                }
                other => {
                    return Err(PolicyError {
                        line,
                        message: format!("unknown directive {other:?}"),
                    })
                }
            }
        }
        if let Some(a) = p.allowed.as_mut() {
            a.sort();
            a.dedup();
        }
        Ok(p)
    }

    /// Check a report against the policy. An empty result means it passed.
    pub fn evaluate(&self, report: &Report) -> Vec<String> {
        let mut violations = Vec::new();
        if let Some(allowed) = &self.allowed {
            for cap in &report.capabilities {
                if !allowed.contains(cap) {
                    violations.push(format!(
                        "capability {} is not allowed by the policy ({})",
                        cap.id(),
                        cap.describes()
                    ));
                }
            }
        }
        if let Some(max) = self.max_severity {
            for f in report.findings_at_least(max) {
                if f.severity > max {
                    violations.push(format!(
                        "finding {} is {}, above the policy maximum of {}",
                        f.rule, f.severity, max
                    ));
                }
            }
        }
        if self.allow_unknown_imports == Some(false) && report.has_unknown_imports() {
            violations.push("module has imports this tool could not classify".to_string());
        }
        if self.allow_exported_memory == Some(false) && report.exports_memory() {
            violations.push("module exports its linear memory".to_string());
        }
        if self.allow_mutable_global_export == Some(false) && report.exports_mutable_global() {
            violations.push("module exports a mutable global".to_string());
        }
        if self.allow_start_function == Some(false) && report.start_function.is_some() {
            violations.push("module declares a start function".to_string());
        }
        if self.require_memory_max == Some(true) {
            for (i, m) in report.memories.iter().enumerate() {
                if m.max_pages.is_none() {
                    violations.push(format!("memory {i} declares no maximum"));
                }
            }
        }
        if let Some(limit) = self.max_memory_pages {
            match report.memory_ceiling_pages() {
                Some(total) if total > limit => violations.push(format!(
                    "declared memory maximum is {total} pages, above the policy limit of {limit}"
                )),
                None => violations.push(format!(
                    "a memory declares no maximum, so the policy limit of {limit} pages cannot be met"
                )),
                _ => {}
            }
        }
        violations.sort();
        violations.dedup();
        violations
    }
}
