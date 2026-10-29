//! Parsing well-formed modules.

mod common;
use common::*;

use wasm_capability_audit::module::{ExternKind, ImportDesc, ValType};
use wasm_capability_audit::{parse, parse_with, ParseOptions};

#[test]
fn preamble_alone_is_a_valid_module() {
    let m = expect_ok(&preamble_only());
    assert_eq!(m.version, 1);
    assert!(m.imports.is_empty());
    assert!(m.exports.is_empty());
    assert!(m.sections.is_empty());
}

#[test]
fn clean_compute_fixture_decodes() {
    let m = expect_ok(&clean_compute());
    assert_eq!(m.types.len(), 1);
    assert_eq!(m.types[0].params, vec![ValType::I32, ValType::I32]);
    assert_eq!(m.types[0].results, vec![ValType::I32]);
    assert_eq!(m.functions, vec![0]);
    assert_eq!(m.memories.len(), 1);
    assert_eq!(m.memories[0].limits.min, 1);
    assert_eq!(m.memories[0].limits.max, Some(2));
    assert_eq!(m.exports.len(), 2);
    assert_eq!(m.exports[0].name, "add");
    assert_eq!(m.exports[0].kind, ExternKind::Func);
    assert_eq!(m.exports[1].kind, ExternKind::Memory);
    assert_eq!(m.code.functions, 1);
    // local.get, local.get, i32.add, end.
    assert_eq!(m.code.instructions, 4);
    assert_eq!(m.start, None);
}

#[test]
fn wasi_fixture_decodes_every_import() {
    let m = expect_ok(&wasi_exfil());
    assert_eq!(m.imports.len(), 8);
    assert_eq!(m.imports[0].module, "wasi_snapshot_preview1");
    assert_eq!(m.imports[0].name, "path_open");
    assert!(matches!(m.imports[0].desc, ImportDesc::Func(2)));
    assert_eq!(m.imported_func_count(), 8);
    assert_eq!(m.start, Some(8));
    assert_eq!(m.memories[0].limits.max, None);
    assert_eq!(m.code.memory_grow, 1);
    assert_eq!(m.code.call_direct, 1);
}

#[test]
fn indirect_fixture_counts_indirect_calls_and_elements() {
    let m = expect_ok(&indirect_dispatch());
    assert_eq!(m.code.call_indirect, 1);
    assert_eq!(m.code.call_direct, 0);
    assert_eq!(m.tables.len(), 1);
    assert_eq!(m.tables[0].elem, ValType::FuncRef);
    assert_eq!(m.tables[0].limits.max, Some(2));
    assert_eq!(m.elements.len(), 1);
    assert_eq!(m.elements[0].entries, 1);
}

#[test]
fn bindgen_fixture_has_a_mutable_global() {
    let m = expect_ok(&bindgen_browser());
    assert_eq!(m.globals.len(), 1);
    assert!(m.globals[0].ty.mutable);
    assert_eq!(m.globals[0].ty.val, ValType::I32);
    assert_eq!(m.imports.len(), 6);
}

#[test]
fn global_import_mutability_is_decoded() {
    let m = expect_ok(&unknown_host());
    let imported_globals: Vec<_> = m
        .imports
        .iter()
        .filter_map(|i| match &i.desc {
            ImportDesc::Global(g) => Some(g),
            _ => None,
        })
        .collect();
    assert_eq!(imported_globals.len(), 1);
    assert!(imported_globals[0].mutable);
}

#[test]
fn custom_sections_are_recorded_not_skipped() {
    let mut body = name("name");
    body.extend_from_slice(&[0x01, 0x02, 0x03]);
    let bytes = module(&[section(0, &body)]);
    let m = expect_ok(&bytes);
    assert_eq!(m.customs.len(), 1);
    assert_eq!(m.customs[0].name, "name");
    assert_eq!(m.customs[0].payload_len, 3);
}

#[test]
fn custom_sections_may_appear_between_ordered_sections() {
    let bytes = module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(0, &name("between")),
        section(3, &vector(&[uleb(0)])),
        section(0, &name("after")),
        section(10, &vector(&[body(&[], &[])])),
    ]);
    let m = expect_ok(&bytes);
    assert_eq!(m.customs.len(), 2);
    assert_eq!(m.code.functions, 1);
}

#[test]
fn data_count_section_precedes_code() {
    let bytes = module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(3, &vector(&[uleb(0)])),
        section(5, &vector(&[limits(1, Some(1), false)])),
        section(12, &uleb(1)),
        section(10, &vector(&[body(&[], &[])])),
        // Passive data segment: kind 1, then a byte vector.
        section(
            11,
            &vector(&[{
                let mut d = uleb(1);
                d.extend_from_slice(&uleb(2));
                d.extend_from_slice(&[0xaa, 0xbb]);
                d
            }]),
        ),
    ]);
    let m = expect_ok(&bytes);
    assert_eq!(m.data_count, Some(1));
    assert_eq!(m.data.len(), 1);
    assert_eq!(m.data[0].len, 2);
    assert!(m.features.bulk_memory);
}

#[test]
fn shared_memory_sets_the_threads_feature() {
    let bytes = module(&[section(5, &vector(&[limits(1, Some(2), true)]))]);
    let m = expect_ok(&bytes);
    assert!(m.memories[0].limits.shared);
    assert!(m.features.threads);
}

#[test]
fn memory64_limits_decode_a_64_bit_minimum() {
    // Flags 0b100: 64-bit index, no maximum.
    let mut limits64 = vec![0b100];
    limits64.extend_from_slice(&uleb(0x1_0000_0000));
    let bytes = module(&[section(5, &vector(&[limits64]))]);
    let m = expect_ok(&bytes);
    assert_eq!(m.memories[0].limits.min, 0x1_0000_0000);
    assert!(m.memories[0].limits.index64);
    assert!(m.features.memory64);
}

#[test]
fn a_large_declared_minimum_allocates_nothing() {
    // u32::MAX pages declared. Nothing in the parser sizes a buffer from it.
    let mut big = vec![0x00];
    big.extend_from_slice(&uleb(u64::from(u32::MAX)));
    let bytes = module(&[section(5, &vector(&[big]))]);
    let m = expect_ok(&bytes);
    assert_eq!(m.memories[0].limits.min, u64::from(u32::MAX));
}

#[test]
fn multi_value_block_type_is_recognised() {
    // A block whose type is type index 0, which only multi-value permits.
    let bytes = module(&[
        section(
            1,
            &vector(&[func_type(&[], &[]), func_type(&[], &[I32, I32])]),
        ),
        section(3, &vector(&[uleb(0)])),
        // block (type 1) ... end
        section(10, &vector(&[body(&[], &[0x02, 0x01, 0x0b])])),
    ]);
    let m = expect_ok(&bytes);
    assert!(m.features.multi_value);
    assert_eq!(m.code.max_depth, 2);
}

#[test]
fn multi_value_result_vector_is_recognised() {
    let bytes = module(&[section(1, &vector(&[func_type(&[I32], &[I32, I32])]))]);
    let m = expect_ok(&bytes);
    assert!(m.features.multi_value);
}

#[test]
fn reference_type_instructions_are_decoded() {
    // ref.null funcref (0xd0 0x70), ref.is_null (0xd1), drop (0x1a).
    let bytes = module_with_body(&[0xd0, 0x70, 0xd1, 0x1a]);
    let m = expect_ok(&bytes);
    assert!(m.features.reference_types);
    assert_eq!(m.code.ref_ops, 2);
}

#[test]
fn bulk_memory_instructions_are_decoded() {
    // memory.fill 0 (0xfc 0x0b 0x00), memory.copy 0 0 (0xfc 0x0a 0x00 0x00).
    let bytes = module_with_body(&[0xfc, 0x0b, 0x00, 0xfc, 0x0a, 0x00, 0x00]);
    let m = expect_ok(&bytes);
    assert!(m.features.bulk_memory);
    assert_eq!(m.code.bulk_memory_ops, 2);
}

#[test]
fn simd_const_and_lane_immediates_are_skipped_correctly() {
    // v128.const (0xfd 12) with sixteen immediate bytes, then
    // i8x16.extract_lane_s (0xfd 21) with a lane index, then drop.
    let mut code = vec![0xfd, 12];
    code.extend_from_slice(&[0xff; 16]);
    code.extend_from_slice(&[0xfd, 21, 0x03]);
    code.push(0x1a);
    let bytes = module_with_body(&code);
    let m = expect_ok(&bytes);
    assert!(m.features.simd);
    assert_eq!(m.code.simd_ops, 2);
}

#[test]
fn simd_lane_load_takes_memarg_and_lane() {
    // v128.load8_lane (0xfd 84): align, offset, lane.
    let bytes = module_with_body(&[0xfd, 84, 0x00, 0x00, 0x05, 0x1a]);
    let m = expect_ok(&bytes);
    assert_eq!(m.code.simd_ops, 1);
}

#[test]
fn atomic_instructions_are_decoded() {
    // atomic.fence (0xfe 0x03 0x00), i32.atomic.load (0xfe 0x10 align offset).
    let bytes = module_with_body(&[0xfe, 0x03, 0x00, 0xfe, 0x10, 0x02, 0x00, 0x1a]);
    let m = expect_ok(&bytes);
    assert!(m.features.threads);
    assert_eq!(m.code.atomic_ops, 2);
}

#[test]
fn tail_call_instructions_are_decoded() {
    // return_call 0 (0x12 0x00).
    let bytes = module_with_body(&[0x12, 0x00]);
    let m = expect_ok(&bytes);
    assert!(m.features.tail_call);
    assert_eq!(m.code.tail_calls, 1);
}

#[test]
fn multi_memory_memarg_encoding_is_decoded() {
    // i32.load with bit 6 of align set: align, offset, then a memory index.
    let bytes = module_with_body(&[0x28, 0x42, 0x00, 0x01, 0x1a]);
    let m = expect_ok(&bytes);
    assert!(m.features.multi_memory);
}

#[test]
fn br_table_label_vector_is_skipped() {
    // block, i32.const 0, br_table [0 0] 0, end.
    let bytes = module_with_body(&[0x02, 0x40, 0x41, 0x00, 0x0e, 0x02, 0x00, 0x00, 0x00, 0x0b]);
    let m = expect_ok(&bytes);
    assert_eq!(m.code.max_depth, 2);
}

#[test]
fn float_constants_consume_their_fixed_width_immediates() {
    // f32.const (four bytes), f64.const (eight bytes), drop, drop.
    let mut code = vec![0x43, 0x00, 0x00, 0x80, 0x3f];
    code.extend_from_slice(&[0x44, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f]);
    code.extend_from_slice(&[0x1a, 0x1a]);
    let bytes = module_with_body(&code);
    let m = expect_ok(&bytes);
    assert_eq!(m.code.instructions, 5);
}

#[test]
fn exception_handling_try_table_is_decoded() {
    // try_table (0x1f) with an empty block type and one catch_all clause.
    let bytes = module_with_body(&[0x1f, 0x40, 0x01, 0x02, 0x00, 0x0b]);
    let m = expect_ok(&bytes);
    assert!(m.features.exception_handling);
}

#[test]
fn imported_tag_sets_exception_handling() {
    let mut imp = name("host");
    imp.extend_from_slice(&name("oops"));
    imp.extend_from_slice(&[0x04, 0x00]);
    imp.extend_from_slice(&uleb(0));
    let bytes = module(&[
        section(1, &vector(&[func_type(&[], &[])])),
        section(2, &vector(&[imp])),
    ]);
    let m = expect_ok(&bytes);
    assert!(m.features.exception_handling);
    assert!(matches!(m.imports[0].desc, ImportDesc::Tag(0)));
}

#[test]
fn no_code_scan_skips_bodies_but_keeps_the_count() {
    let bytes = wasi_exfil();
    let m = parse_with(&bytes, ParseOptions { scan_code: false }).expect("parses");
    assert_eq!(m.code.functions, 1);
    assert_eq!(m.code.instructions, 0);
    assert!(!m.code_scanned);
    // The import list is unaffected, which is the point of the option.
    assert_eq!(m.imports.len(), 8);
}

#[test]
fn parsing_is_deterministic() {
    let bytes = wasi_exfil();
    let a = parse(&bytes).expect("parses");
    let b = parse(&bytes).expect("parses");
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
}

#[test]
fn signed_leb_round_trips_including_negatives() {
    // i32.const with a range of signed values, decoded back out of a body.
    for value in [
        0i64,
        1,
        -1,
        63,
        64,
        -64,
        -65,
        8191,
        -8192,
        2147483647,
        -2147483648,
    ] {
        let mut code = vec![0x41];
        code.extend_from_slice(&sleb(value));
        code.push(0x1a);
        let bytes = module_with_body(&code);
        let m = expect_ok(&bytes);
        assert_eq!(m.code.instructions, 3, "value {value} should decode");
    }
}

#[test]
fn sixty_four_bit_constants_round_trip() {
    for value in [0i64, -1, i64::MIN, i64::MAX, -9007199254740993] {
        let mut code = vec![0x42];
        code.extend_from_slice(&sleb(value));
        code.push(0x1a);
        let bytes = module_with_body(&code);
        let m = expect_ok(&bytes);
        assert_eq!(m.code.instructions, 3, "value {value} should decode");
    }
}

#[test]
fn multi_byte_unsigned_leb_round_trips() {
    for count in [0u64, 1, 127, 128, 16383, 16384, 2097151] {
        let encoded = uleb(count);
        // Use the value as a start-function index, which is a plain u32 LEB.
        let bytes = module(&[section(8, &encoded)]);
        let m = expect_ok(&bytes);
        assert_eq!(m.start, Some(count as u32));
    }
}
