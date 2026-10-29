//! Instruction scanning.
//!
//! The auditor needs three things out of function bodies: how many
//! `call_indirect` sites there are (that is where control-flow integrity in
//! WebAssembly actually lives), whether `memory.grow` is reachable, and which
//! post-MVP instruction families the module uses. None of that can be got by
//! pattern-matching bytes — an opcode byte means nothing unless you know
//! where instruction boundaries are — so this is a real decoder that walks
//! every instruction and skips its immediates.
//!
//! It decodes the MVP, sign extension, non-trapping float-to-int conversions,
//! bulk memory, reference types, typed function references, tail calls,
//! multi-memory, memory64, SIMD, threads/atomics, and both the legacy and the
//! current exception-handling encodings. It does **not** decode the
//! garbage-collection proposal (`0xFB`), and it says so rather than guessing:
//! an unknown opcode is an error naming the byte and its offset.

use crate::error::{ErrorKind, Result};
use crate::module::{read_valtype, Features};
use crate::reader::Reader;

/// Maximum block nesting the scanner will follow. Scanning is iterative, so
/// this is a sanity bound on malformed input rather than a stack guard.
const MAX_DEPTH: u32 = 10_000;

/// What the code section told us.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CodeStats {
    /// Function bodies in the code section.
    pub functions: usize,
    /// Instructions decoded, across all bodies.
    pub instructions: u64,
    /// Locals declared, across all bodies.
    pub declared_locals: u64,
    /// `call` — a direct call, to an import or a module-defined function.
    pub call_direct: u64,
    /// `call_indirect` — a dynamic call through a table.
    pub call_indirect: u64,
    /// `call_ref` — a dynamic call through a function reference.
    pub call_ref: u64,
    /// `return_call`, `return_call_indirect`, `return_call_ref`.
    pub tail_calls: u64,
    /// `memory.grow`.
    pub memory_grow: u64,
    /// `memory.size`.
    pub memory_size: u64,
    /// `memory.copy`, `memory.fill`, `memory.init`, `data.drop`.
    pub bulk_memory_ops: u64,
    /// `table.get`/`set`/`grow`/`size`/`fill`/`copy`/`init`, `elem.drop`.
    pub table_ops: u64,
    /// `ref.null`, `ref.func`, `ref.is_null`, and the typed-reference branches.
    pub ref_ops: u64,
    /// `0xFD`-prefixed vector instructions.
    pub simd_ops: u64,
    /// `0xFE`-prefixed atomic instructions.
    pub atomic_ops: u64,
    /// `throw`, `throw_ref`, `rethrow`.
    pub throw_ops: u64,
    /// Deepest block nesting seen in any body.
    pub max_depth: u32,
}

impl CodeStats {
    fn bump(counter: &mut u64) {
        *counter = counter.saturating_add(1);
    }
}

/// Scan one function body: its locals, then its instruction sequence.
pub fn scan_function_body(
    r: &mut Reader<'_>,
    stats: &mut CodeStats,
    f: &mut Features,
) -> Result<()> {
    let groups = r.vec_count()?;
    for _ in 0..groups {
        let count = r.u32_leb()?;
        let _ty = read_valtype(r, f)?;
        stats.declared_locals = stats.declared_locals.saturating_add(u64::from(count));
    }
    scan_expr(r, stats, f)?;
    if !r.is_empty() {
        return Err(r.error(ErrorKind::SectionSizeMismatch {
            declared: 0,
            consumed: r.remaining(),
        }));
    }
    Ok(())
}

/// Walk an instruction sequence to its matching `end`.
fn scan_expr(r: &mut Reader<'_>, stats: &mut CodeStats, f: &mut Features) -> Result<()> {
    let mut depth: u32 = 1;
    loop {
        if r.is_empty() {
            return Err(r.error(ErrorKind::UnterminatedExpression));
        }
        if depth > stats.max_depth {
            stats.max_depth = depth;
        }
        let op = r.u8()?;
        CodeStats::bump(&mut stats.instructions);
        match op {
            // Control, no immediate.
            0x00 | 0x01 | 0x05 | 0x0f => {}
            // block / loop / if: block type.
            0x02..=0x04 => {
                read_blocktype(r, f)?;
                depth = next_depth(r, depth)?;
            }
            // end.
            0x0b => {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            // Legacy exception handling: try / catch / catch_all / delegate.
            0x06 => {
                f.exception_handling = true;
                read_blocktype(r, f)?;
                depth = next_depth(r, depth)?;
            }
            0x07 => {
                f.exception_handling = true;
                let _tag = r.u32_leb()?;
            }
            0x19 => {
                f.exception_handling = true;
            }
            0x18 => {
                f.exception_handling = true;
                let _label = r.u32_leb()?;
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            // throw / throw_ref / rethrow.
            0x08 => {
                f.exception_handling = true;
                CodeStats::bump(&mut stats.throw_ops);
                let _tag = r.u32_leb()?;
            }
            0x0a => {
                f.exception_handling = true;
                CodeStats::bump(&mut stats.throw_ops);
            }
            0x09 => {
                f.exception_handling = true;
                CodeStats::bump(&mut stats.throw_ops);
                let _label = r.u32_leb()?;
            }
            // Current exception handling: try_table.
            0x1f => {
                f.exception_handling = true;
                read_blocktype(r, f)?;
                let clauses = r.vec_count()?;
                for _ in 0..clauses {
                    match r.u8()? {
                        0x00 | 0x01 => {
                            let _tag = r.u32_leb()?;
                            let _label = r.u32_leb()?;
                        }
                        0x02 | 0x03 => {
                            let _label = r.u32_leb()?;
                        }
                        other => {
                            return Err(r.error(ErrorKind::UnknownOpcode {
                                opcode: other,
                                note: "try_table catch clause",
                            }))
                        }
                    }
                }
                depth = next_depth(r, depth)?;
            }
            // br / br_if.
            0x0c | 0x0d => {
                let _label = r.u32_leb()?;
            }
            // br_table.
            0x0e => {
                let n = r.vec_count()?;
                for _ in 0..n {
                    let _label = r.u32_leb()?;
                }
                let _default = r.u32_leb()?;
            }
            // call.
            0x10 => {
                CodeStats::bump(&mut stats.call_direct);
                let _func = r.u32_leb()?;
            }
            // call_indirect.
            0x11 => {
                CodeStats::bump(&mut stats.call_indirect);
                let _ty = r.u32_leb()?;
                let table = r.u32_leb()?;
                if table > 0 {
                    f.reference_types = true;
                }
            }
            // return_call / return_call_indirect.
            0x12 => {
                f.tail_call = true;
                CodeStats::bump(&mut stats.tail_calls);
                CodeStats::bump(&mut stats.call_direct);
                let _func = r.u32_leb()?;
            }
            0x13 => {
                f.tail_call = true;
                CodeStats::bump(&mut stats.tail_calls);
                CodeStats::bump(&mut stats.call_indirect);
                let _ty = r.u32_leb()?;
                let _table = r.u32_leb()?;
            }
            // call_ref / return_call_ref.
            0x14 => {
                f.typed_function_references = true;
                CodeStats::bump(&mut stats.call_ref);
                let _ty = r.u32_leb()?;
            }
            0x15 => {
                f.typed_function_references = true;
                f.tail_call = true;
                CodeStats::bump(&mut stats.tail_calls);
                CodeStats::bump(&mut stats.call_ref);
                let _ty = r.u32_leb()?;
            }
            // drop / select.
            0x1a | 0x1b => {}
            // select with explicit result types.
            0x1c => {
                f.reference_types = true;
                let n = r.vec_count()?;
                for _ in 0..n {
                    read_valtype(r, f)?;
                }
            }
            // local.get / local.set / local.tee.
            0x20..=0x22 => {
                let _local = r.u32_leb()?;
            }
            // global.get / global.set.
            0x23 | 0x24 => {
                let _global = r.u32_leb()?;
            }
            // table.get / table.set.
            0x25 | 0x26 => {
                f.reference_types = true;
                CodeStats::bump(&mut stats.table_ops);
                let _table = r.u32_leb()?;
            }
            // Loads and stores.
            0x28..=0x3e => read_memarg(r, f)?,
            // memory.size / memory.grow.
            0x3f => {
                CodeStats::bump(&mut stats.memory_size);
                read_memidx(r, f)?;
            }
            0x40 => {
                CodeStats::bump(&mut stats.memory_grow);
                read_memidx(r, f)?;
            }
            // Constants.
            0x41 => {
                let _v = r.i32_leb()?;
            }
            0x42 => {
                let _v = r.i64_leb()?;
            }
            0x43 => {
                r.skip(4)?;
            }
            0x44 => {
                r.skip(8)?;
            }
            // Numeric operators, sign extension: no immediates.
            0x45..=0xc4 => {}
            // Reference instructions.
            0xd0 => {
                f.reference_types = true;
                CodeStats::bump(&mut stats.ref_ops);
                let _heap = r.i33_leb()?;
            }
            0xd1 => {
                f.reference_types = true;
                CodeStats::bump(&mut stats.ref_ops);
            }
            0xd2 => {
                f.reference_types = true;
                CodeStats::bump(&mut stats.ref_ops);
                let _func = r.u32_leb()?;
            }
            0xd3 | 0xd4 => {
                f.typed_function_references = true;
                CodeStats::bump(&mut stats.ref_ops);
            }
            0xd5 | 0xd6 => {
                f.typed_function_references = true;
                CodeStats::bump(&mut stats.ref_ops);
                let _label = r.u32_leb()?;
            }
            // Prefixed instruction families.
            0xfc => scan_fc(r, stats, f)?,
            0xfd => scan_fd(r, stats, f)?,
            0xfe => scan_fe(r, stats, f)?,
            0xfb => {
                return Err(r.error(ErrorKind::UnknownOpcode {
                    opcode: 0xfb,
                    note: "garbage-collection proposal; this parser does not decode it",
                }))
            }
            other => {
                return Err(r.error(ErrorKind::UnknownOpcode {
                    opcode: other,
                    note: "not a defined opcode in any proposal this parser decodes",
                }))
            }
        }
    }
}

fn next_depth(r: &Reader<'_>, depth: u32) -> Result<u32> {
    if depth >= MAX_DEPTH {
        return Err(r.error(ErrorKind::DepthLimitExceeded { limit: MAX_DEPTH }));
    }
    Ok(depth + 1)
}

/// `0xFC`: non-trapping conversions, bulk memory, table operations.
fn scan_fc(r: &mut Reader<'_>, stats: &mut CodeStats, f: &mut Features) -> Result<()> {
    let sub = r.u32_leb()?;
    match sub {
        // i32/i64.trunc_sat_f32/f64_s/u.
        0..=7 => {}
        // memory.init dataidx memidx.
        8 => {
            f.bulk_memory = true;
            CodeStats::bump(&mut stats.bulk_memory_ops);
            let _data = r.u32_leb()?;
            read_memidx(r, f)?;
        }
        // data.drop dataidx.
        9 => {
            f.bulk_memory = true;
            CodeStats::bump(&mut stats.bulk_memory_ops);
            let _data = r.u32_leb()?;
        }
        // memory.copy memidx memidx.
        10 => {
            f.bulk_memory = true;
            CodeStats::bump(&mut stats.bulk_memory_ops);
            read_memidx(r, f)?;
            read_memidx(r, f)?;
        }
        // memory.fill memidx.
        11 => {
            f.bulk_memory = true;
            CodeStats::bump(&mut stats.bulk_memory_ops);
            read_memidx(r, f)?;
        }
        // table.init elemidx tableidx.
        12 => {
            f.reference_types = true;
            CodeStats::bump(&mut stats.table_ops);
            let _elem = r.u32_leb()?;
            let _table = r.u32_leb()?;
        }
        // elem.drop elemidx.
        13 => {
            f.reference_types = true;
            CodeStats::bump(&mut stats.table_ops);
            let _elem = r.u32_leb()?;
        }
        // table.copy tableidx tableidx.
        14 => {
            f.reference_types = true;
            CodeStats::bump(&mut stats.table_ops);
            let _dst = r.u32_leb()?;
            let _src = r.u32_leb()?;
        }
        // table.grow / table.size / table.fill, each with a table index.
        15..=17 => {
            f.reference_types = true;
            CodeStats::bump(&mut stats.table_ops);
            let _table = r.u32_leb()?;
        }
        other => {
            return Err(r.error(ErrorKind::UnknownPrefixedOpcode {
                prefix: 0xfc,
                sub: other,
            }))
        }
    }
    Ok(())
}

/// `0xFD`: the vector (SIMD) instruction family.
fn scan_fd(r: &mut Reader<'_>, stats: &mut CodeStats, f: &mut Features) -> Result<()> {
    let sub = r.u32_leb()?;
    f.simd = true;
    CodeStats::bump(&mut stats.simd_ops);
    match sub {
        // v128 loads and v128.store: memarg.
        0..=11 => read_memarg(r, f)?,
        // v128.const: sixteen immediate bytes.
        12 => r.skip(16)?,
        // i8x16.shuffle: sixteen lane indices.
        13 => r.skip(16)?,
        // i8x16.swizzle and the splats.
        14..=20 => {}
        // extract_lane / replace_lane: one lane index.
        21..=34 => {
            let _lane = r.u8()?;
        }
        // Lane-wise load and store: memarg plus a lane index.
        84..=91 => {
            read_memarg(r, f)?;
            let _lane = r.u8()?;
        }
        // v128.load32_zero / v128.load64_zero: memarg.
        92 | 93 => read_memarg(r, f)?,
        // Everything else in the family takes no immediate. The highest
        // assigned sub-opcode in the fixed-width SIMD proposal is 275.
        35..=83 | 94..=275 => {}
        other => {
            return Err(r.error(ErrorKind::UnknownPrefixedOpcode {
                prefix: 0xfd,
                sub: other,
            }))
        }
    }
    Ok(())
}

/// `0xFE`: the atomic instruction family from the threads proposal.
fn scan_fe(r: &mut Reader<'_>, stats: &mut CodeStats, f: &mut Features) -> Result<()> {
    let sub = r.u32_leb()?;
    f.threads = true;
    CodeStats::bump(&mut stats.atomic_ops);
    match sub {
        // memory.atomic.notify / wait32 / wait64: memarg.
        0..=2 => read_memarg(r, f)?,
        // atomic.fence: a single reserved byte.
        3 => {
            let _reserved = r.u8()?;
        }
        // Atomic loads, stores and read-modify-write operations: memarg.
        0x10..=0x4e => read_memarg(r, f)?,
        other => {
            return Err(r.error(ErrorKind::UnknownPrefixedOpcode {
                prefix: 0xfe,
                sub: other,
            }))
        }
    }
    Ok(())
}

/// A memory operand: alignment, offset, and — when bit 6 of the alignment is
/// set, as the multi-memory proposal specifies — a memory index.
fn read_memarg(r: &mut Reader<'_>, f: &mut Features) -> Result<()> {
    let align = r.u32_leb()?;
    if align & 0x40 != 0 {
        f.multi_memory = true;
        let _offset = r.u64_leb()?;
        let _mem = r.u32_leb()?;
    } else {
        // The offset is 32-bit in the MVP and 64-bit under memory64; reading
        // it as a 64-bit LEB accepts both encodings.
        let _offset = r.u64_leb()?;
    }
    Ok(())
}

/// A bare memory index immediate, as carried by `memory.size`, `memory.grow`,
/// `memory.fill` and friends. It is `0x00` unless multi-memory is in use.
fn read_memidx(r: &mut Reader<'_>, f: &mut Features) -> Result<()> {
    let idx = r.u32_leb()?;
    if idx > 0 {
        f.multi_memory = true;
    }
    Ok(())
}

/// A block type: empty, a single value type, or a type index (multi-value).
fn read_blocktype(r: &mut Reader<'_>, f: &mut Features) -> Result<()> {
    let b = r.peek_u8()?;
    match b {
        0x40 => {
            let _ = r.u8()?;
        }
        0x7f | 0x7e | 0x7d | 0x7c | 0x7b | 0x70 | 0x6f | 0x63 | 0x64 => {
            read_valtype(r, f)?;
        }
        _ => {
            // A non-negative 33-bit signed LEB: an index into the type
            // section, which only the multi-value proposal permits here.
            let idx = r.i33_leb()?;
            if idx < 0 {
                return Err(r.error(ErrorKind::UnknownValType(b)));
            }
            f.multi_value = true;
        }
    }
    Ok(())
}

/// Walk a constant expression — the form used by global initialisers and by
/// element and data segment offsets — to its `end`.
///
/// The set of instructions permitted here is small, and this accepts the MVP
/// set plus `ref.null`/`ref.func` and the extended-constant arithmetic.
pub fn skip_const_expr(r: &mut Reader<'_>, f: &mut Features) -> Result<()> {
    let mut stats = CodeStats::default();
    let mut seen = 0usize;
    loop {
        if r.is_empty() {
            return Err(r.error(ErrorKind::UnterminatedExpression));
        }
        let op = r.peek_u8()?;
        match op {
            0x0b => {
                let _ = r.u8()?;
                return Ok(());
            }
            // i32.const, i64.const, f32.const, f64.const, global.get,
            // ref.null, ref.func.
            0x41 | 0x42 | 0x43 | 0x44 | 0x23 | 0xd0 | 0xd2 => {
                let _ = r.u8()?;
                match op {
                    0x41 => {
                        let _ = r.i32_leb()?;
                    }
                    0x42 => {
                        let _ = r.i64_leb()?;
                    }
                    0x43 => r.skip(4)?,
                    0x44 => r.skip(8)?,
                    0x23 => {
                        let _ = r.u32_leb()?;
                    }
                    0xd0 => {
                        f.reference_types = true;
                        let _ = r.i33_leb()?;
                    }
                    _ => {
                        f.reference_types = true;
                        let _ = r.u32_leb()?;
                    }
                }
            }
            // v128.const, via the 0xFD prefix.
            0xfd => {
                let _ = r.u8()?;
                scan_fd(r, &mut stats, f)?;
            }
            // Extended constant expressions: i32/i64 add, sub and mul.
            0x6a | 0x6b | 0x6c | 0x7c | 0x7d | 0x7e => {
                let _ = r.u8()?;
            }
            other => {
                return Err(r.error(ErrorKind::UnknownOpcode {
                    opcode: other,
                    note: "not permitted in a constant expression",
                }))
            }
        }
        seen += 1;
        if seen > 1024 {
            return Err(r.error(ErrorKind::DepthLimitExceeded { limit: 1024 }));
        }
    }
}
