//! The malformed-input battery.
//!
//! Robustness is the headline property of a binary parser, so it is tested as
//! one. Nothing here may panic, and nothing may cause an allocation sized
//! from an unvalidated number in the file.

mod common;
use common::*;

use wasm_capability_audit::error::{Context, ErrorKind};
use wasm_capability_audit::parse;

#[test]
fn empty_file() {
    let e = expect_kind(&[], ErrorKind::Empty);
    assert_eq!(e.offset, 0);
    assert!(e.to_string().contains("empty"));
}

#[test]
fn magic_truncated_at_every_length() {
    for n in 1..4usize {
        let e = expect_err(&[0x00, 0x61, 0x73, 0x6d][..n]);
        assert!(
            matches!(e.kind, ErrorKind::UnexpectedEof { .. }),
            "length {n} gave {e}"
        );
    }
}

#[test]
fn version_truncated_at_every_length() {
    for n in 4..8usize {
        let bytes = &module(&[])[..n];
        let e = expect_err(bytes);
        assert!(
            matches!(e.kind, ErrorKind::UnexpectedEof { .. }),
            "length {n} gave {e}"
        );
    }
}

#[test]
fn wrong_magic() {
    let e = expect_err(b"\x7fELF\x01\x00\x00\x00");
    assert!(matches!(e.kind, ErrorKind::BadMagic(_)));
    assert!(e.to_string().contains("not a WebAssembly module"));
}

#[test]
fn unsupported_version() {
    let mut bytes = module(&[]);
    bytes[4] = 0x02;
    expect_kind(&bytes, ErrorKind::UnsupportedVersion(2));
}

#[test]
fn component_preamble_is_rejected_with_its_version() {
    // A WebAssembly component starts with the same magic and version 0x0d.
    let mut bytes = module(&[]);
    bytes[4] = 0x0d;
    bytes[5] = 0x00;
    bytes[6] = 0x01;
    bytes[7] = 0x00;
    let e = expect_err(&bytes);
    assert!(matches!(e.kind, ErrorKind::UnsupportedVersion(_)));
}

#[test]
fn every_truncation_of_every_fixture_is_handled() {
    // The real assertion is the absence of a panic across every prefix of
    // every fixture. A prefix that happens to end on a section boundary is a
    // valid shorter module, so both outcomes are acceptable; what is not
    // acceptable is a crash or a hang.
    let mut errors = 0usize;
    let mut oks = 0usize;
    for (name, bytes) in all() {
        for n in 0..bytes.len() {
            match parse(&bytes[..n]) {
                Ok(_) => oks += 1,
                Err(e) => {
                    errors += 1;
                    assert!(
                        e.offset <= n,
                        "{name}: error offset {} past input length {n}",
                        e.offset
                    );
                }
            }
        }
        // One byte short of the full module always cuts the final section.
        let short = &bytes[..bytes.len() - 1];
        expect_err(short);
    }
    assert!(
        errors > 500,
        "expected many truncations to error, got {errors}"
    );
    assert!(oks > 0, "some prefixes should be valid shorter modules");
}

#[test]
fn section_length_longer_than_the_file() {
    // A type section claiming 0x7f bytes with none following.
    let mut bytes = module(&[]);
    bytes.extend_from_slice(&[0x01, 0x7f]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::LengthBeyondInput { declared: 127, .. }),
        "got {e}"
    );
}

#[test]
fn vector_count_longer_than_the_section() {
    // Import section of three bytes declaring 0x7f imports.
    let bytes = module(&[section(2, &[0x7f, 0x00, 0x00])]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::LengthBeyondInput { declared: 127, .. }),
        "got {e}"
    );
    assert_eq!(e.context, Context::ImportSection);
}

#[test]
fn enormous_vector_count_allocates_nothing() {
    // 0xffffffff imports declared in a four-byte section. If the parser sized
    // a buffer from this it would try for four billion elements.
    let bytes = module(&[section(2, &[0xff, 0xff, 0xff, 0xff, 0x0f])]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::LengthBeyondInput { .. }),
        "got {e}"
    );
}

#[test]
fn unterminated_leb128_in_a_section_length() {
    let mut bytes = module(&[]);
    bytes.push(0x01);
    bytes.extend_from_slice(&[0x80, 0x80, 0x80]);
    expect_kind(&bytes, ErrorKind::LebUnterminated);
}

#[test]
fn unterminated_leb128_running_to_end_of_file() {
    let mut bytes = module(&[]);
    bytes.push(0x01);
    bytes.extend_from_slice(&[0x80; 64]);
    let e = expect_err(&bytes);
    assert!(
        matches!(
            e.kind,
            ErrorKind::LebUnterminated | ErrorKind::LebTooLong { .. }
        ),
        "got {e}"
    );
}

#[test]
fn over_long_leb128_encoding_is_rejected() {
    // Six continuation bytes for a 32-bit value: one more than permitted.
    let mut bytes = module(&[]);
    bytes.push(0x01);
    bytes.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00]);
    expect_kind(&bytes, ErrorKind::LebTooLong { bits: 32 });
}

#[test]
fn leb128_value_out_of_range_is_rejected() {
    // Five bytes, but the fifth sets bits above 32.
    let mut bytes = module(&[]);
    bytes.push(0x01);
    bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x7f]);
    expect_kind(&bytes, ErrorKind::LebOverflow { bits: 32 });
}

#[test]
fn over_long_signed_leb128_in_a_constant_is_rejected() {
    // i32.const with six LEB bytes.
    let bytes = module_with_body(&[0x41, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x1a]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::LebTooLong { bits: 32 }),
        "got {e}"
    );
}

#[test]
fn signed_leb128_overflow_in_a_constant_is_rejected() {
    // Fifth byte carries bits that do not sign-extend the value.
    let bytes = module_with_body(&[0x41, 0xff, 0xff, 0xff, 0xff, 0x4f, 0x1a]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::LebOverflow { bits: 32 }),
        "got {e}"
    );
}

#[test]
fn section_body_with_trailing_bytes() {
    // A start section whose declared length is two bytes but which needs one.
    let bytes = module(&[section(8, &[0x00, 0x00])]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::SectionSizeMismatch { .. }),
        "got {e}"
    );
    assert_eq!(e.context, Context::StartSection);
}

#[test]
fn unknown_section_id_is_an_error_not_a_skip() {
    // The whole point: a parser that skipped this would report "no imports"
    // for a module whose imports it never looked at.
    let bytes = module(&[section(99, &[0x00, 0x00, 0x00])]);
    let e = expect_kind(&bytes, ErrorKind::UnknownSectionId(99));
    assert!(e.to_string().contains("refusing to skip"));
}

#[test]
fn duplicate_section_is_rejected() {
    let bytes = module(&[
        section(5, &vector(&[limits(1, None, false)])),
        section(5, &vector(&[limits(1, None, false)])),
    ]);
    expect_kind(&bytes, ErrorKind::DuplicateSection(5));
}

#[test]
fn out_of_order_sections_are_rejected() {
    let bytes = module(&[
        section(7, &vector(&[export("a", EXPORT_FUNC, 0)])),
        section(1, &vector(&[func_type(&[], &[])])),
    ]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::SectionOutOfOrder { id: 1, previous: 7 }),
        "got {e}"
    );
}

#[test]
fn invalid_utf8_in_an_import_name_is_rejected() {
    // Import module name of one byte, 0xff, which is not valid UTF-8.
    let mut imp = vec![0x01, 0xff];
    imp.extend_from_slice(&name("f"));
    imp.push(0x00);
    imp.extend_from_slice(&uleb(0));
    let bytes = module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(2, &vector(&[imp])),
    ]);
    let e = expect_kind(&bytes, ErrorKind::InvalidUtf8);
    assert_eq!(e.context, Context::ImportSection);
}

#[test]
fn invalid_utf8_in_an_export_name_is_rejected() {
    let mut exp = vec![0x02, 0xc3, 0x28];
    exp.push(EXPORT_FUNC);
    exp.extend_from_slice(&uleb(0));
    let bytes = module(&[section(7, &vector(&[exp]))]);
    expect_kind(&bytes, ErrorKind::InvalidUtf8);
}

#[test]
fn unknown_value_type_is_rejected() {
    let bytes = module(&[section(1, &vector(&[func_type(&[0x55], &[])]))]);
    expect_kind(&bytes, ErrorKind::UnknownValType(0x55));
}

#[test]
fn unsupported_type_form_is_named() {
    // 0x4e introduces a GC recursive type group, which this parser does not
    // decode. It says so rather than treating the bytes as a function type.
    let bytes = module(&[section(1, &vector(&[vec![0x4e, 0x00]]))]);
    let e = expect_kind(&bytes, ErrorKind::UnsupportedTypeForm(0x4e));
    assert!(e.to_string().contains("function types"));
}

#[test]
fn unknown_import_descriptor_is_rejected() {
    let mut imp = name("m");
    imp.extend_from_slice(&name("f"));
    imp.push(0x09);
    let bytes = module(&[section(2, &vector(&[imp]))]);
    expect_kind(&bytes, ErrorKind::UnknownDescriptor(0x09));
}

#[test]
fn unknown_export_kind_is_rejected() {
    let mut exp = name("e");
    exp.push(0x07);
    exp.extend_from_slice(&uleb(0));
    let bytes = module(&[section(7, &vector(&[exp]))]);
    expect_kind(&bytes, ErrorKind::UnknownDescriptor(0x07));
}

#[test]
fn unknown_limits_flags_are_rejected() {
    let mut mem = vec![0x08];
    mem.extend_from_slice(&uleb(1));
    let bytes = module(&[section(5, &vector(&[mem]))]);
    expect_kind(&bytes, ErrorKind::UnknownLimitsFlags(0x08));
}

#[test]
fn inverted_limits_are_rejected() {
    let mut mem = vec![0x01];
    mem.extend_from_slice(&uleb(10));
    mem.extend_from_slice(&uleb(2));
    let bytes = module(&[section(5, &vector(&[mem]))]);
    expect_kind(&bytes, ErrorKind::LimitsInverted { min: 10, max: 2 });
}

#[test]
fn invalid_mutability_byte_is_rejected() {
    let bytes = module(&[section(6, &vector(&[vec![I32, 0x02, 0x41, 0x00, 0x0b]]))]);
    expect_kind(&bytes, ErrorKind::InvalidMutability(0x02));
}

#[test]
fn unknown_element_segment_kind_is_rejected() {
    let bytes = module(&[section(9, &vector(&[uleb(9)]))]);
    expect_kind(&bytes, ErrorKind::UnknownElementKind(9));
}

#[test]
fn unknown_data_segment_kind_is_rejected() {
    let bytes = module(&[
        section(5, &vector(&[limits(1, Some(1), false)])),
        section(11, &vector(&[uleb(7)])),
    ]);
    expect_kind(&bytes, ErrorKind::UnknownDataKind(7));
}

#[test]
fn unknown_reference_type_in_a_table_is_rejected() {
    let mut t = vec![0x7f]; // i32 is not a reference type
    t.extend_from_slice(&limits(1, None, false));
    let bytes = module(&[section(4, &vector(&[t]))]);
    expect_kind(&bytes, ErrorKind::UnknownRefType(0x7f));
}

#[test]
fn unterminated_function_body_is_rejected() {
    // A body whose declared length holds one instruction and no `end`.
    let mut inner = uleb(0); // no locals
    inner.push(0x01); // nop
    let mut b = uleb(inner.len() as u64);
    b.extend_from_slice(&inner);
    let bytes = module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(3, &vector(&[uleb(0)])),
        section(10, &vector(&[b])),
    ]);
    expect_kind(&bytes, ErrorKind::UnterminatedExpression);
}

#[test]
fn unknown_opcode_is_named_with_its_byte() {
    // 0x27 is unassigned.
    let bytes = module_with_body(&[0x27]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::UnknownOpcode { opcode: 0x27, .. }),
        "got {e}"
    );
    assert!(e.to_string().contains("0x27"));
}

#[test]
fn gc_opcode_is_rejected_with_the_proposal_named() {
    let bytes = module_with_body(&[0xfb, 0x00, 0x00]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::UnknownOpcode { opcode: 0xfb, .. }),
        "got {e}"
    );
    assert!(e.to_string().contains("garbage-collection"));
}

#[test]
fn unknown_prefixed_opcode_is_named() {
    // 0xfc sub-opcode 90 is not assigned.
    let bytes = module_with_body(&[0xfc, 90]);
    let e = expect_err(&bytes);
    assert!(
        matches!(
            e.kind,
            ErrorKind::UnknownPrefixedOpcode {
                prefix: 0xfc,
                sub: 90
            }
        ),
        "got {e}"
    );
}

#[test]
fn unknown_simd_sub_opcode_is_named() {
    let bytes = module_with_body(&[0xfd, 0xff, 0x7f]);
    let e = expect_err(&bytes);
    assert!(
        matches!(
            e.kind,
            ErrorKind::UnknownPrefixedOpcode { prefix: 0xfd, .. }
        ),
        "got {e}"
    );
}

#[test]
fn body_with_trailing_bytes_after_end_is_rejected() {
    // Two `end` bytes: the first closes the body, the second is left over.
    let mut inner = uleb(0);
    inner.extend_from_slice(&[0x0b, 0x01]);
    let mut b = uleb(inner.len() as u64);
    b.extend_from_slice(&inner);
    let bytes = module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(3, &vector(&[uleb(0)])),
        section(10, &vector(&[b])),
    ]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::SectionSizeMismatch { .. }),
        "got {e}"
    );
}

#[test]
fn deeply_nested_blocks_hit_the_depth_limit_without_overflowing_the_stack() {
    // Twenty thousand `block` instructions: twice the scanner's limit. An
    // implementation that recursed per block would overflow the stack here.
    let mut code = Vec::new();
    for _ in 0..20_000 {
        code.extend_from_slice(&[0x02, 0x40]);
    }
    let bytes = module_with_body(&code);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::DepthLimitExceeded { .. }),
        "got {e}"
    );
}

#[test]
fn many_sequential_blocks_are_fine() {
    // The limit is on nesting, not on count: a thousand closed blocks parse.
    let mut code = Vec::new();
    for _ in 0..1000 {
        code.extend_from_slice(&[0x02, 0x40, 0x0b]);
    }
    let bytes = module_with_body(&code);
    let m = expect_ok(&bytes);
    assert_eq!(m.code.max_depth, 2);
}

#[test]
fn illegal_instruction_in_a_constant_expression_is_rejected() {
    // i32.add is permitted by the extended-const proposal; `call` is not.
    let g = vec![I32, 0x00, 0x10, 0x00, 0x0b];
    let bytes = module(&[section(6, &vector(&[g]))]);
    let e = expect_err(&bytes);
    assert!(
        matches!(e.kind, ErrorKind::UnknownOpcode { opcode: 0x10, .. }),
        "got {e}"
    );
    assert!(e.to_string().contains("constant expression"));
}

#[test]
fn unterminated_constant_expression_is_rejected() {
    let g = vec![I32, 0x00, 0x41, 0x00];
    let bytes = module(&[section(6, &vector(&[g]))]);
    expect_kind(&bytes, ErrorKind::UnterminatedExpression);
}

#[test]
fn truncated_memarg_is_rejected() {
    // i32.load with an alignment byte and no offset, and no `end` after it.
    let mut inner = uleb(0);
    inner.extend_from_slice(&[0x28, 0x02]);
    let mut b = uleb(inner.len() as u64);
    b.extend_from_slice(&inner);
    let bytes = module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(3, &vector(&[uleb(0)])),
        section(10, &vector(&[b])),
    ]);
    let e = expect_err(&bytes);
    assert!(
        matches!(
            e.kind,
            ErrorKind::LebUnterminated | ErrorKind::UnexpectedEof { .. }
        ),
        "got {e}"
    );
}

#[test]
fn every_single_byte_corruption_of_a_fixture_is_handled() {
    // Flip each byte of a fixture to a value unlikely to be valid there and
    // check that the parser either reports an error or returns a module, but
    // never panics.
    let original = wasi_exfil();
    let mut handled = 0usize;
    for i in 0..original.len() {
        for replacement in [0x00u8, 0x7f, 0xff] {
            let mut bytes = original.clone();
            if bytes[i] == replacement {
                continue;
            }
            bytes[i] = replacement;
            let _ = parse(&bytes);
            handled += 1;
        }
    }
    assert!(handled > 500, "expected many mutations, ran {handled}");
}

#[test]
fn error_messages_always_carry_an_offset_and_a_section() {
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        b"\x7fELF\x01\x00\x00\x00".to_vec(),
        module(&[section(99, &[])]),
        module(&[section(1, &vector(&[func_type(&[0x55], &[])]))]),
        module_with_body(&[0x27]),
    ];
    for bytes in cases {
        let e = expect_err(&bytes);
        let text = e.to_string();
        assert!(
            text.contains("at byte 0x"),
            "message lacked an offset: {text}"
        );
        assert!(!e.context.name().is_empty());
    }
}

#[test]
fn the_parser_never_sizes_an_allocation_from_the_file() {
    // The property the robustness tests rest on, asserted against the source
    // itself: no capacity is reserved anywhere from a number read out of the
    // input. The only `with_capacity` in the crate sizes a buffer from the
    // length of an in-memory string.
    const SOURCES: [(&str, &str); 12] = [
        ("audit.rs", include_str!("../src/audit.rs")),
        ("capability.rs", include_str!("../src/capability.rs")),
        ("classify.rs", include_str!("../src/classify.rs")),
        ("diff.rs", include_str!("../src/diff.rs")),
        ("error.rs", include_str!("../src/error.rs")),
        ("instr.rs", include_str!("../src/instr.rs")),
        ("json.rs", include_str!("../src/json.rs")),
        ("module.rs", include_str!("../src/module.rs")),
        ("policy.rs", include_str!("../src/policy.rs")),
        ("reader.rs", include_str!("../src/reader.rs")),
        ("report.rs", include_str!("../src/report.rs")),
        ("rules.rs", include_str!("../src/rules.rs")),
    ];
    for (file, src) in SOURCES {
        for (n, line) in src.lines().enumerate() {
            let is_comment = line.trim_start().starts_with("//");
            if is_comment {
                continue;
            }
            assert!(
                !line.contains(".reserve("),
                "{file}:{} reserves capacity: {line}",
                n + 1
            );
            if line.contains("with_capacity(") {
                assert!(
                    file == "json.rs" && line.contains("s.len()"),
                    "{file}:{} reserves capacity: {line}",
                    n + 1
                );
            }
        }
    }
}
