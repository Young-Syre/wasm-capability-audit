//! Output rendering: JSON escaping, determinism, and the text report.

mod common;
use common::*;

use wasm_capability_audit::json::{quote, string_array, Obj};
use wasm_capability_audit::report::{render_json, render_text};

#[test]
fn json_escapes_quotes_and_backslashes() {
    assert_eq!(quote(r#"a"b"#), r#""a\"b""#);
    assert_eq!(quote(r"a\b"), r#""a\\b""#);
    assert_eq!(quote(r#"\"#), r#""\\""#);
}

#[test]
fn json_escapes_the_named_control_characters() {
    assert_eq!(quote("a\nb"), r#""a\nb""#);
    assert_eq!(quote("a\rb"), r#""a\rb""#);
    assert_eq!(quote("a\tb"), r#""a\tb""#);
    assert_eq!(quote("a\u{08}b"), r#""a\bb""#);
    assert_eq!(quote("a\u{0c}b"), r#""a\fb""#);
}

#[test]
fn json_escapes_other_control_characters_as_four_hex_digits() {
    assert_eq!(quote("\u{00}"), r#""\u0000""#);
    assert_eq!(quote("\u{01}"), r#""\u0001""#);
    assert_eq!(quote("\u{1f}"), r#""\u001f""#);
    assert_eq!(quote("\u{0b}"), r#""\u000b""#);
}

#[test]
fn json_passes_non_ascii_through_as_utf8() {
    assert_eq!(quote("café"), "\"café\"");
    assert_eq!(quote("日本語"), "\"日本語\"");
    assert_eq!(quote("\u{1f600}"), "\"\u{1f600}\"");
    assert_eq!(quote("\u{7f}"), "\"\u{7f}\"");
}

#[test]
fn json_string_arrays_and_objects_render() {
    assert_eq!(string_array(Vec::<String>::new()), "[]");
    assert_eq!(string_array(["a", "b"]), r#"["a","b"]"#);
    assert_eq!(
        string_array([r#"a"b"#]),
        r#"["a\"b"]"#,
        "array elements are escaped too"
    );
    assert_eq!(Obj::new().finish(), "{}");
    assert_eq!(
        Obj::new().str_field("k", "v").num("n", 7).finish(),
        r#"{"k":"v","n":7}"#
    );
    assert_eq!(
        Obj::new()
            .bool_field("t", true)
            .bool_field("f", false)
            .opt_num("a", Some(1))
            .opt_num("b", None)
            .finish(),
        r#"{"t":true,"f":false,"a":1,"b":null}"#
    );
}

/// A module whose import and export names contain the characters that break
/// a naive JSON writer. Names in the binary format are arbitrary UTF-8.
fn awkward_names_module() -> Vec<u8> {
    module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(
            2,
            &vector(&[
                import_func("he\"llo", "back\\slash", 0),
                import_func("new\nline", "tab\there", 0),
                import_func("caf\u{e9}", "\u{1f600}", 0),
            ]),
        ),
        section(3, &vector(&[uleb(0)])),
        section(
            7,
            &vector(&[
                export("quote\"d", EXPORT_FUNC, 3),
                export("ctrl\u{01}", EXPORT_FUNC, 3),
            ]),
        ),
        section(10, &vector(&[body(&[], &[])])),
    ])
}

#[test]
fn awkward_names_survive_the_round_trip_to_json() {
    let bytes = awkward_names_module();
    let r = wasm_capability_audit::audit_bytes(&bytes, "awkward").unwrap();
    let json = render_json(&r);
    assert!(json.contains(r#""he\"llo""#), "quote not escaped: {json}");
    assert!(json.contains(r#""back\\slash""#), "backslash not escaped");
    assert!(json.contains(r#""new\nline""#), "newline not escaped");
    assert!(json.contains(r#""tab\there""#), "tab not escaped");
    assert!(json.contains("café"), "non-ASCII mangled");
    assert!(json.contains("\u{1f600}"), "astral plane mangled");
    assert!(json.contains(r#""ctrl\u0001""#), "control char not escaped");
    // No raw control character survives into the output.
    assert!(
        !json.chars().any(|c| (c as u32) < 0x20),
        "raw control character in JSON output"
    );
}

/// A deliberately small structural check: balanced braces and brackets
/// outside string literals, with escapes honoured. Enough to catch a writer
/// that forgets a comma or a closing brace, without pulling in a parser.
fn structurally_valid_json(s: &str) -> bool {
    let mut stack: Vec<char> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for c in s.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' | '[' => stack.push(c),
            '}' | ']' => {
                let opener = if c == '}' { '{' } else { '[' };
                if stack.pop() != Some(opener) {
                    return false;
                }
            }
            _ => {}
        }
    }
    stack.is_empty() && !in_string
}

#[test]
fn every_fixture_renders_structurally_valid_json() {
    for (name, bytes) in all() {
        let r = wasm_capability_audit::audit_bytes(&bytes, name).unwrap();
        let json = render_json(&r);
        assert!(structurally_valid_json(&json), "{name}: unbalanced JSON");
        assert!(json.starts_with('{') && json.ends_with('}'), "{name}");
        assert!(!json.contains(",}"), "{name}: trailing comma before }}");
        assert!(!json.contains(",]"), "{name}: trailing comma before ]");
        assert!(!json.contains("{,"), "{name}: leading comma");
    }
    assert!(structurally_valid_json(r#"{"a":"}"}"#), "braces in strings");
    assert!(!structurally_valid_json(r#"{"a":1"#));
}

#[test]
fn json_output_is_a_single_line() {
    for (_, bytes) in all() {
        let r = wasm_capability_audit::audit_bytes(&bytes, "t").unwrap();
        let json = render_json(&r);
        assert_eq!(json.lines().count(), 1);
    }
}

#[test]
fn json_output_is_byte_identical_across_runs() {
    let bytes = wasi_exfil();
    let a = render_json(&wasm_capability_audit::audit_bytes(&bytes, "t").unwrap());
    let b = render_json(&wasm_capability_audit::audit_bytes(&bytes, "t").unwrap());
    assert_eq!(a, b);
}

#[test]
fn json_carries_the_capability_set_and_the_summary() {
    let r = wasm_capability_audit::audit_bytes(&wasi_exfil(), "t").unwrap();
    let json = render_json(&r);
    assert!(json.contains(r#""id":"filesystem""#));
    assert!(json.contains(r#""id":"network""#));
    assert!(json.contains(r#""highest_severity":"critical""#));
    assert!(json.contains(r#""unknown_imports":false"#));
    assert!(json.contains(r#""start_function":8"#));
    assert!(json.contains(r#""max_pages":null"#));
    assert!(json.contains(r#""rule":"COMBO-FS-NET-001""#));
}

#[test]
fn json_reports_unknown_imports_truthfully() {
    let r = wasm_capability_audit::audit_bytes(&unknown_host(), "t").unwrap();
    let json = render_json(&r);
    assert!(json.contains(r#""unknown_imports":true"#));
    assert!(json.contains(r#""capability":"unknown""#));
}

#[test]
fn text_output_is_byte_identical_across_runs() {
    let bytes = bindgen_browser();
    let a = render_text(&wasm_capability_audit::audit_bytes(&bytes, "t").unwrap());
    let b = render_text(&wasm_capability_audit::audit_bytes(&bytes, "t").unwrap());
    assert_eq!(a, b);
}

#[test]
fn text_output_has_the_sections_a_reader_expects() {
    let r = wasm_capability_audit::audit_bytes(&wasi_exfil(), "t").unwrap();
    let text = render_text(&r);
    for heading in [
        "CAPABILITY SET",
        "FINDINGS",
        "IMPORTS",
        "EXPORTS",
        "MEMORY",
        "TABLES",
        "CODE",
        "SUMMARY",
    ] {
        assert!(text.contains(heading), "missing {heading}");
    }
    assert!(text.contains("highest severity: critical"));
    assert!(text.contains("proposals used: none beyond the MVP"));
}

#[test]
fn text_output_states_plainly_when_there_is_nothing_to_report() {
    let r = wasm_capability_audit::audit_bytes(&clean_compute(), "t").unwrap();
    let text = render_text(&r);
    assert!(text.contains("(none: the module asks the host for nothing)"));
    assert!(text.contains("host environment: not recognised"));
}

#[test]
fn text_output_never_claims_zero_when_code_was_not_scanned() {
    let r = wasm_capability_audit::audit_bytes_with(
        &wasi_exfil(),
        "t",
        wasm_capability_audit::ParseOptions { scan_code: false },
    )
    .unwrap();
    let text = render_text(&r);
    assert!(text.contains("not scanned (--no-code-scan)"));
    assert!(!text.contains("call_indirect site(s)"));
}

#[test]
fn proposals_used_lists_what_the_encoding_actually_contained() {
    let bytes = module_with_body(&[0xfc, 0x0b, 0x00, 0xd0, 0x70, 0x1a]);
    let r = wasm_capability_audit::audit_bytes(&bytes, "t").unwrap();
    let text = render_text(&r);
    let proposals = text
        .lines()
        .find(|l| l.contains("proposals used:"))
        .expect("the report lists the proposals used");
    assert!(proposals.contains("bulk-memory"), "{proposals}");
    assert!(proposals.contains("reference-types"), "{proposals}");
    assert!(!proposals.contains("simd"), "{proposals}");
    assert!(!proposals.contains("threads"), "{proposals}");
}

/// A name out of the file under audit must not be able to write the report.
///
/// WebAssembly names are arbitrary UTF-8 and the spec permits newlines, escape
/// bytes and bidirectional overrides. Printed raw, a crafted module forges its
/// own output: `\x1b[2J\x1b[0;0H` clears the terminal and the module supplies
/// a convincing `FINDINGS (0)` in its place, with the real findings pushed into
/// scrollback. The JSON path was never affected -- `json::quote` escapes the
/// same range -- which is what makes the text path's omission a gap rather
/// than a policy.
mod untrusted_names {
    use wasm_capability_audit::report::{render_text, visible};

    use crate::common::{audit_import, module_with_import};

    fn text_for(field: &str) -> String {
        let bytes = module_with_import("wasi_snapshot_preview1", field);
        render_text(&wasm_capability_audit::audit_bytes(&bytes, "t").expect("parses"))
    }

    #[test]
    fn an_ansi_clear_screen_cannot_forge_a_clean_report() {
        let evil = "f\u{1b}[2J\u{1b}[0;0HFINDINGS (0)\n  (none)\n\nSUMMARY\n  No findings.";
        let text = text_for(evil);
        assert!(
            !text.contains('\u{1b}'),
            "an escape byte reached the output"
        );
        assert!(
            text.contains("\\x1b[2J"),
            "the escape is shown as text: {text}"
        );
        // The real finding count survives, on its own line.
        assert!(
            text.lines()
                .any(|l| l.starts_with("FINDINGS (") && !l.contains("(0)")),
            "the real finding count was displaced: {text}"
        );
    }

    #[test]
    fn a_newline_cannot_invent_an_evidence_line() {
        let text = text_for("good\nCALLING HOME via env.sock_send\nnot_real");
        for line in text.lines() {
            assert!(
                !line.trim_start().starts_with("CALLING HOME"),
                "a name produced its own line: {line}"
            );
        }
        assert!(text.contains("\\x0a"), "the newline is shown as text");
    }

    #[test]
    fn a_bidi_override_cannot_disguise_a_capability() {
        // Trojan Source: the override reorders what a reader sees without
        // changing a byte of what the classifier matched.
        let text = text_for("sock_send\u{202e}\u{2066}harmless_log\u{2069}");
        assert!(!text.contains('\u{202e}'));
        assert!(
            text.contains("\\u{202e}"),
            "the override is shown as text: {text}"
        );
        // Still classified on what it really is.
        let report = audit_import(
            "wasi_snapshot_preview1",
            "sock_send\u{202e}\u{2066}harmless_log\u{2069}",
        );
        assert!(
            report.findings.iter().any(|f| f.rule == "WASI-NET-002"),
            "the real capability was not reported"
        );
    }

    #[test]
    fn a_zero_width_character_cannot_impersonate_another_name() {
        let text = text_for("sock\u{200b}send");
        assert!(
            text.contains("\\u{200b}"),
            "the zero-width space is shown: {text}"
        );
    }

    #[test]
    fn an_ordinary_non_ascii_name_is_left_alone() {
        let name = "journal_écrire_日本";
        assert_eq!(visible(name), name);
        assert!(text_for(name).contains(name));
    }

    #[test]
    fn visible_borrows_when_nothing_needs_escaping() {
        assert!(matches!(visible("fd_write"), std::borrow::Cow::Borrowed(_)));
        assert!(matches!(
            visible("fd\u{1b}write"),
            std::borrow::Cow::Owned(_)
        ));
    }
}
