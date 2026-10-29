//! Command-line interface.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use wasm_capability_audit::capability::{Capability, Severity};
use wasm_capability_audit::module::ParseOptions;
use wasm_capability_audit::policy::Policy;
use wasm_capability_audit::report::{self, TOOL, VERSION};
use wasm_capability_audit::rules::RULE_IDS;
use wasm_capability_audit::{audit, diff, parse_with};

/// Exit codes, documented in the README and asserted in CI.
mod exit {
    /// Audit completed; nothing exceeded the policy or the severity threshold.
    pub const OK: u8 = 0;
    /// A policy was violated, a severity threshold was met, or a diff found
    /// capabilities the old module did not have.
    pub const VIOLATION: u8 = 1;
    /// The command line, or a policy file, could not be understood.
    pub const USAGE: u8 = 2;
    /// The module could not be parsed.
    pub const PARSE: u8 = 3;
    /// A file could not be read.
    pub const IO: u8 = 4;
}

const HELP: &str = "\
wasm-capability-audit — what a WebAssembly module asks its host for

USAGE
    wasm-capability-audit [OPTIONS] <module.wasm>
    wasm-capability-audit diff [OPTIONS] <old.wasm> <new.wasm>
    wasm-capability-audit --list-capabilities
    wasm-capability-audit --list-rules

WebAssembly has no ambient authority: a module can only do what the host
hands it through imports. This reads the import section, says what each entry
grants, reports what the module exports back, and describes its memory and
table posture. It never executes the module and never touches the network.

OPTIONS
    --json                  Machine-readable output on stdout.
    --policy <file>         Check the module against a policy file. Exits 1 on
                            a violation. See POLICY below.
    --fail-on <severity>    Exit 1 if any finding is at or above this severity
                            (info, low, medium, high, critical).
    --no-code-scan          Skip the code section. Loses the indirect-call and
                            memory.grow counts; useful if a module uses an
                            instruction this parser does not decode.
    --list-capabilities     Print the capability identifiers a policy may use.
    --list-rules            Print every rule identifier this tool can emit.
    -h, --help              This text.
    -V, --version           Version.

POLICY
    One directive per line; '#' starts a comment. A directive the file does
    not mention is not checked.

        allow <capability>              repeatable; opt-in allow-list
        max-severity <severity>
        allow-unknown-imports <yes|no>
        allow-exported-memory <yes|no>
        allow-mutable-global-export <yes|no>
        allow-start-function <yes|no>
        require-memory-max <yes|no>
        max-memory-pages <n>

EXIT CODES
    0  audit completed, nothing exceeded the policy or threshold
    1  policy violation, severity threshold met, or diff added a capability
    2  usage error, or an unparsable policy file
    3  the module could not be parsed
    4  a file could not be read
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("{TOOL}: {}", message.text);
            ExitCode::from(message.code)
        }
    }
}

/// An error on its way to stderr, with the exit code it implies.
struct Failure {
    text: String,
    code: u8,
}

fn fail(code: u8, text: impl Into<String>) -> Failure {
    Failure {
        text: text.into(),
        code,
    }
}

#[derive(Default)]
struct Options {
    json: bool,
    policy: Option<String>,
    fail_on: Option<Severity>,
    no_code_scan: bool,
}

fn run(args: &[String]) -> Result<u8, Failure> {
    if args.is_empty() {
        print!("{HELP}");
        return Ok(exit::USAGE);
    }
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(exit::OK);
            }
            "-V" | "--version" => {
                println!("{TOOL} {VERSION}");
                return Ok(exit::OK);
            }
            "--list-capabilities" => {
                for c in Capability::ALL {
                    println!("{:<24} {}", c.id(), c.describes());
                }
                return Ok(exit::OK);
            }
            "--list-rules" => {
                for r in RULE_IDS {
                    println!("{r}");
                }
                return Ok(exit::OK);
            }
            _ => {}
        }
    }

    let mut opts = Options::default();
    let mut positional: Vec<String> = Vec::new();
    let mut subcommand: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "diff" if subcommand.is_none() && positional.is_empty() => {
                subcommand = Some("diff".to_string());
            }
            "--json" => opts.json = true,
            "--no-code-scan" => opts.no_code_scan = true,
            "--policy" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| fail(exit::USAGE, "--policy needs a file path"))?;
                opts.policy = Some(v.clone());
            }
            "--fail-on" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| fail(exit::USAGE, "--fail-on needs a severity"))?;
                opts.fail_on = Some(Severity::parse(v).ok_or_else(|| {
                    fail(
                        exit::USAGE,
                        format!(
                            "unknown severity {v:?}; expected info, low, medium, high or critical"
                        ),
                    )
                })?);
            }
            other if other.starts_with('-') && other != "-" => {
                return Err(fail(
                    exit::USAGE,
                    format!("unknown option {other:?}; try --help"),
                ));
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    let parse_opts = ParseOptions {
        scan_code: !opts.no_code_scan,
    };

    if subcommand.as_deref() == Some("diff") {
        if positional.len() != 2 {
            return Err(fail(
                exit::USAGE,
                "diff needs exactly two module paths: diff <old.wasm> <new.wasm>",
            ));
        }
        let old = load_report(&positional[0], parse_opts)?;
        let new = load_report(&positional[1], parse_opts)?;
        let d = diff::diff(&old, &new);
        if opts.json {
            println!("{}", diff::render_json(&d));
        } else {
            print!("{}", diff::render_text(&d));
        }
        return Ok(if d.capabilities_grew() {
            exit::VIOLATION
        } else {
            exit::OK
        });
    }

    if positional.len() != 1 {
        return Err(fail(
            exit::USAGE,
            format!(
                "expected exactly one module path, got {}; try --help",
                positional.len()
            ),
        ));
    }

    let report = load_report(&positional[0], parse_opts)?;

    let violations = match &opts.policy {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| fail(exit::IO, format!("cannot read policy {path}: {e}")))?;
            let policy =
                Policy::parse(&text).map_err(|e| fail(exit::USAGE, format!("{path}: {e}")))?;
            policy.evaluate(&report)
        }
        None => Vec::new(),
    };

    if opts.json {
        println!("{}", report::render_json(&report));
    } else {
        print!("{}", report::render_text(&report));
    }

    let mut failed = false;
    if !violations.is_empty() {
        if !opts.json {
            println!();
            println!("POLICY VIOLATIONS ({})", violations.len());
            for v in &violations {
                println!("  ! {v}");
            }
        } else {
            for v in &violations {
                eprintln!("policy violation: {v}");
            }
        }
        failed = true;
    }
    if let Some(min) = opts.fail_on {
        let n = report.findings_at_least(min).count();
        if n > 0 {
            eprintln!("{n} finding(s) at or above {min}");
            failed = true;
        }
    }
    Ok(if failed { exit::VIOLATION } else { exit::OK })
}

fn load_report(path: &str, opts: ParseOptions) -> Result<wasm_capability_audit::Report, Failure> {
    let bytes =
        std::fs::read(path).map_err(|e| fail(exit::IO, format!("cannot read {path}: {e}")))?;
    let module = parse_with(&bytes, opts).map_err(|e| fail(exit::PARSE, format!("{path}: {e}")))?;
    Ok(audit(&module, path, bytes.len()))
}
