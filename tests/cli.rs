//! The command-line interface, exercised as a subprocess.
//!
//! These assert the documented exit codes, because a tool meant for CI is
//! only as useful as its exit codes are reliable.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_wasm-capability-audit")
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> PathBuf {
    root().join("tests/fixtures").join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .output()
        .expect("the binary should run")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("the process should exit normally")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn path(name: &str) -> String {
    fixture(name).to_string_lossy().to_string()
}

#[test]
fn help_exits_zero_and_documents_the_exit_codes() {
    let out = run(&["--help"]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    assert!(text.contains("USAGE"));
    assert!(text.contains("EXIT CODES"));
    assert!(text.contains("--policy"));
    assert!(text.contains("--json"));
    assert!(text.contains("diff"));
    assert!(text.contains("no ambient authority"));
}

#[test]
fn version_exits_zero() {
    let out = run(&["--version"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("wasm-capability-audit"));
    assert!(stdout(&out).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn no_arguments_prints_help_and_exits_two() {
    let out = run(&[]);
    assert_eq!(code(&out), 2);
    assert!(stdout(&out).contains("USAGE"));
}

#[test]
fn list_capabilities_and_rules_exit_zero() {
    let caps = run(&["--list-capabilities"]);
    assert_eq!(code(&caps), 0);
    assert!(stdout(&caps).contains("filesystem"));
    assert!(stdout(&caps).contains("contract-delegate-call"));

    let rules = run(&["--list-rules"]);
    assert_eq!(code(&rules), 0);
    let listed = stdout(&rules);
    assert!(listed.contains("WASI-FS-001"));
    assert!(listed.contains("COMBO-FS-NET-001"));
    assert_eq!(
        listed.lines().count(),
        wasm_capability_audit::rules::RULE_IDS.len()
    );
}

#[test]
fn an_unknown_option_exits_two() {
    let out = run(&["--definitely-not-an-option", &path("clean-compute.wasm")]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("unknown option"));
}

#[test]
fn two_module_paths_without_diff_exits_two() {
    let out = run(&[&path("clean-compute.wasm"), &path("wasi-exfil.wasm")]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("exactly one module path"));
}

#[test]
fn a_missing_file_exits_four() {
    let out = run(&["does-not-exist.wasm"]);
    assert_eq!(code(&out), 4);
    assert!(stderr(&out).contains("cannot read"));
}

#[test]
fn the_wasi_fixture_reports_the_expected_capability_set() {
    let out = run(&[&path("wasi-exfil.wasm")]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    for cap in [
        "filesystem",
        "network",
        "process",
        "clock",
        "randomness",
        "environment",
    ] {
        assert!(text.contains(cap), "missing capability {cap}");
    }
    assert!(text.contains("COMBO-FS-NET-001"));
    assert!(text.contains("highest severity: critical"));
}

#[test]
fn the_clean_fixture_reports_no_capabilities() {
    let out = run(&[&path("clean-compute.wasm")]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    assert!(text.contains("CAPABILITY SET (0)"));
    assert!(text.contains("(none: the module asks the host for nothing)"));
    assert!(text.contains("NO-IMPORTS-001"));
}

#[test]
fn json_mode_emits_one_line_of_json() {
    let out = run(&["--json", &path("wasi-exfil.wasm")]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with('{'));
    assert!(text.trim_end().ends_with('}'));
    assert!(text.contains(r#""tool":"wasm-capability-audit""#));
}

#[test]
fn a_truncated_module_exits_three_with_a_located_error() {
    let dir = std::env::temp_dir().join("wasm-capability-audit-cli-tests");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let bytes = std::fs::read(fixture("wasi-exfil.wasm")).expect("fixture");
    let truncated: &Path = &dir.join("truncated.wasm");
    std::fs::write(truncated, &bytes[..bytes.len() - 5]).expect("write");
    let out = run(&[&truncated.to_string_lossy()]);
    assert_eq!(code(&out), 3, "stderr was: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("at byte 0x"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    let _ = std::fs::remove_file(truncated);
}

#[test]
fn a_file_that_is_not_webassembly_exits_three() {
    let dir = std::env::temp_dir().join("wasm-capability-audit-cli-tests");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let p = dir.join("not-wasm.bin");
    std::fs::write(&p, b"this is not a module").expect("write");
    let out = run(&[&p.to_string_lossy()]);
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("not a WebAssembly module"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn an_empty_file_exits_three() {
    let dir = std::env::temp_dir().join("wasm-capability-audit-cli-tests");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let p = dir.join("empty.wasm");
    std::fs::write(&p, b"").expect("write");
    let out = run(&[&p.to_string_lossy()]);
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("empty"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_policy_violation_exits_one_and_names_the_capability() {
    let policy = root().join("policies/sandboxed-plugin.policy");
    let out = run(&[
        "--policy",
        &policy.to_string_lossy(),
        &path("wasi-exfil.wasm"),
    ]);
    assert_eq!(code(&out), 1);
    let text = stdout(&out);
    assert!(text.contains("POLICY VIOLATIONS"));
    assert!(text.contains("capability filesystem"));
    assert!(text.contains("capability network"));
}

#[test]
fn a_satisfied_policy_exits_zero() {
    let policy = root().join("policies/sandboxed-plugin.policy");
    let out = run(&[
        "--policy",
        &policy.to_string_lossy(),
        &path("wasi-clock-only.wasm"),
    ]);
    assert_eq!(code(&out), 0, "stdout was: {}", stdout(&out));
    assert!(!stdout(&out).contains("POLICY VIOLATIONS"));
}

#[test]
fn an_unparsable_policy_exits_two() {
    let dir = std::env::temp_dir().join("wasm-capability-audit-cli-tests");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let p = dir.join("broken.policy");
    std::fs::write(&p, "allow not-a-capability\n").expect("write");
    let out = run(&[
        "--policy",
        &p.to_string_lossy(),
        &path("clean-compute.wasm"),
    ]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("unknown capability"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn a_missing_policy_file_exits_four() {
    let out = run(&["--policy", "no-such.policy", &path("clean-compute.wasm")]);
    assert_eq!(code(&out), 4);
}

#[test]
fn policy_without_a_value_exits_two() {
    let out = run(&["--policy"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("needs a file path"));
}

#[test]
fn fail_on_thresholds_are_honoured() {
    let high = run(&["--fail-on", "high", &path("wasi-exfil.wasm")]);
    assert_eq!(code(&high), 1);
    assert!(stderr(&high).contains("at or above high"));

    let critical = run(&["--fail-on", "critical", &path("wasi-clock-only.wasm")]);
    assert_eq!(code(&critical), 0);

    let bad = run(&["--fail-on", "nope", &path("clean-compute.wasm")]);
    assert_eq!(code(&bad), 2);
    assert!(stderr(&bad).contains("unknown severity"));
}

#[test]
fn diff_exits_one_when_a_capability_is_added() {
    let out = run(&[
        "diff",
        &path("wasi-clock-only.wasm"),
        &path("wasi-clock-and-socket.wasm"),
    ]);
    assert_eq!(code(&out), 1);
    let text = stdout(&out);
    assert!(text.contains("CAPABILITIES ADDED (1)"));
    assert!(text.contains("+ network"));
    assert!(text.contains("+ wasi_snapshot_preview1.sock_send"));
}

#[test]
fn diff_exits_zero_when_nothing_was_added() {
    let out = run(&[
        "diff",
        &path("wasi-clock-and-socket.wasm"),
        &path("wasi-clock-only.wasm"),
    ]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("CAPABILITIES ADDED (0)"));
    assert!(stdout(&out).contains("- network"));
}

#[test]
fn diff_of_identical_modules_exits_zero() {
    let out = run(&["diff", &path("wasi-exfil.wasm"), &path("wasi-exfil.wasm")]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("CAPABILITIES ADDED (0)"));
    assert!(stdout(&out).contains("POSTURE CHANGES (0)"));
}

#[test]
fn diff_json_mode_works() {
    let out = run(&[
        "diff",
        "--json",
        &path("wasi-clock-only.wasm"),
        &path("wasi-clock-and-socket.wasm"),
    ]);
    assert_eq!(code(&out), 1);
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains(r#""capabilities_grew":true"#));
}

#[test]
fn diff_with_the_wrong_number_of_paths_exits_two() {
    let out = run(&["diff", &path("wasi-exfil.wasm")]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).contains("exactly two module paths"));
}

#[test]
fn diff_of_an_unreadable_module_exits_four() {
    let out = run(&["diff", "missing-a.wasm", "missing-b.wasm"]);
    assert_eq!(code(&out), 4);
}

#[test]
fn no_code_scan_reports_the_omission_rather_than_zeroes() {
    let out = run(&["--no-code-scan", &path("wasi-exfil.wasm")]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    assert!(text.contains("CODE-NOT-SCANNED-001"));
    assert!(text.contains("not scanned (--no-code-scan)"));
}

#[test]
fn output_is_byte_identical_across_invocations() {
    let a = run(&["--json", &path("bindgen-browser.wasm")]);
    let b = run(&["--json", &path("bindgen-browser.wasm")]);
    assert_eq!(a.stdout, b.stdout);
}

#[test]
fn the_near_fixture_reports_contract_capabilities() {
    let out = run(&[&path("near-contract.wasm")]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    assert!(text.contains("contract-storage-write"));
    assert!(text.contains("contract-value-transfer"));
    assert!(text.contains("COMBO-STORAGE-CALL-001"));
    assert!(text.contains("NEAR contract runtime"));
}

#[test]
fn the_unknown_fixture_says_it_could_not_classify_the_imports() {
    let out = run(&[&path("unknown-host.wasm")]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    assert!(text.contains("UNKNOWN-IMPORT-001"));
    assert!(text.contains("UNKNOWN-SUMMARY-001"));
    assert!(text.contains("3 unclassified import(s)"));
}

/// A reader that stops reading must not be a crash.
///
/// Rust ignores SIGPIPE at startup, so a `println!` whose reader has gone away
/// fails, and a failed write inside a print macro is a panic. `--list-rules |
/// head -5` exited 101, which is not one of the documented codes. A Unix filter
/// stops quietly when its reader stops.
mod closed_pipe {
    use std::io::Read;
    use std::process::{Command, Stdio};

    use super::{binary, fixture};

    /// Spawn with a piped stdout, read one line, drop the pipe, and report the
    /// exit status. Dropping the handle is what closes the reader's end.
    fn exit_after_one_line(args: &[&str]) -> Option<i32> {
        let mut child = Command::new(binary())
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");

        {
            let mut stdout = child.stdout.take().expect("piped stdout");
            let mut one = [0u8; 1];
            // One byte is enough to prove the child started writing.
            let _ = stdout.read(&mut one);
        } // stdout dropped here: the read end is now closed.

        child.wait().expect("wait").code()
    }

    #[test]
    fn listing_rules_into_a_closed_pipe_exits_cleanly() {
        for args in [
            vec!["--list-rules"],
            vec!["--list-capabilities"],
            vec!["--help"],
        ] {
            let code = exit_after_one_line(&args);
            assert_ne!(code, Some(101), "{args:?} panicked on a closed pipe");
            assert!(
                matches!(code, Some(0)),
                "{args:?} exited {code:?}, expected 0"
            );
        }
    }

    #[test]
    fn an_audit_into_a_closed_pipe_exits_cleanly() {
        let path = fixture("near-contract.wasm");
        let arg = path.to_str().expect("utf-8 path");
        let code = exit_after_one_line(&[arg]);
        assert_ne!(code, Some(101), "the audit panicked on a closed pipe");
        assert!(matches!(code, Some(0)), "exited {code:?}, expected 0");
    }
}
