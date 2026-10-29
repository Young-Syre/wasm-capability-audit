//! The module structure and the section decoder.
//!
//! This decodes the parts of the binary format that bear on a module's host
//! surface. It is not a validator: it does not type-check, and it does not
//! resolve indices. It does refuse to continue past anything it cannot
//! decode, which is the property that matters for an auditing tool — a
//! parser that silently skips a section it does not understand will happily
//! report "no network imports" for a module full of them.

use crate::error::{Context, ErrorKind, ParseError, Result};
use crate::instr::{self, CodeStats};
use crate::reader::Reader;

/// WebAssembly value types, including the reference types added by the
/// reference-types and typed-function-references proposals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
    /// `(ref null? ht)`. `heap` is the raw signed heap-type encoding: negative
    /// values are built-in heap types, non-negative ones are type indices.
    TypedRef {
        nullable: bool,
        heap: i64,
    },
}

impl ValType {
    /// Short name used in reports.
    pub fn name(self) -> &'static str {
        match self {
            ValType::I32 => "i32",
            ValType::I64 => "i64",
            ValType::F32 => "f32",
            ValType::F64 => "f64",
            ValType::V128 => "v128",
            ValType::FuncRef => "funcref",
            ValType::ExternRef => "externref",
            ValType::TypedRef { nullable: true, .. } => "ref null",
            ValType::TypedRef {
                nullable: false, ..
            } => "ref",
        }
    }

    /// True for the reference types.
    pub fn is_ref(self) -> bool {
        matches!(
            self,
            ValType::FuncRef | ValType::ExternRef | ValType::TypedRef { .. }
        )
    }
}

/// A function signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

/// Limits on a memory or table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub min: u64,
    pub max: Option<u64>,
    /// Set by the threads proposal: the memory is shared between instances.
    pub shared: bool,
    /// Set by the memory64 proposal: the index type is `i64`.
    pub index64: bool,
}

/// A table's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableType {
    pub elem: ValType,
    pub limits: Limits,
}

/// A memory's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemType {
    pub limits: Limits,
}

/// A global's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalType {
    pub val: ValType,
    pub mutable: bool,
}

/// What an import asks the host for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportDesc {
    Func(u32),
    Table(TableType),
    Memory(MemType),
    Global(GlobalType),
    /// Exception-handling proposal.
    Tag(u32),
}

impl ImportDesc {
    /// Short name used in reports.
    pub fn kind_name(&self) -> &'static str {
        match self {
            ImportDesc::Func(_) => "func",
            ImportDesc::Table(_) => "table",
            ImportDesc::Memory(_) => "memory",
            ImportDesc::Global(_) => "global",
            ImportDesc::Tag(_) => "tag",
        }
    }
}

/// One entry of the import section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub desc: ImportDesc,
}

impl Import {
    /// `module.name`, the form used in reports and policy files.
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.module, self.name)
    }
}

/// What an export hands back to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternKind {
    Func,
    Table,
    Memory,
    Global,
    Tag,
}

impl ExternKind {
    /// Short name used in reports.
    pub fn name(self) -> &'static str {
        match self {
            ExternKind::Func => "func",
            ExternKind::Table => "table",
            ExternKind::Memory => "memory",
            ExternKind::Global => "global",
            ExternKind::Tag => "tag",
        }
    }
}

/// One entry of the export section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    pub kind: ExternKind,
    pub index: u32,
}

/// A module-defined global.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalDef {
    pub ty: GlobalType,
}

/// How an element segment is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElemMode {
    /// Copied into a table at instantiation.
    Active { table: u32 },
    /// Available to `table.init` only.
    Passive,
    /// Declared for `ref.func` validation only.
    Declared,
}

/// One entry of the element section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElemSegment {
    pub mode: ElemMode,
    pub entries: u32,
}

/// How a data segment is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataMode {
    Active { memory: u32 },
    Passive,
}

/// One entry of the data section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataSegment {
    pub mode: DataMode,
    pub len: usize,
}

/// A custom section: its name and payload length. The payload itself is not
/// interpreted, but its presence is reported — a `name` section tells you the
/// module shipped with symbol names, and a large unknown custom section is
/// worth a look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomSection {
    pub name: String,
    pub payload_len: usize,
}

/// Which post-MVP proposals the module's encoding actually uses. These are
/// observations, not guesses: each is set only when a specific encoding was
/// decoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Features {
    pub multi_value: bool,
    pub reference_types: bool,
    pub bulk_memory: bool,
    pub simd: bool,
    pub threads: bool,
    pub tail_call: bool,
    pub multi_memory: bool,
    pub memory64: bool,
    pub exception_handling: bool,
    pub typed_function_references: bool,
}

/// A decoded module, limited to what bears on its host surface.
#[derive(Debug, Clone, Default)]
pub struct Module {
    pub version: u32,
    pub types: Vec<FuncType>,
    pub imports: Vec<Import>,
    /// Type index per module-defined function.
    pub functions: Vec<u32>,
    pub tables: Vec<TableType>,
    pub memories: Vec<MemType>,
    pub globals: Vec<GlobalDef>,
    pub exports: Vec<Export>,
    pub start: Option<u32>,
    pub elements: Vec<ElemSegment>,
    pub data: Vec<DataSegment>,
    pub data_count: Option<u32>,
    pub tags: u32,
    pub customs: Vec<CustomSection>,
    /// Statistics gathered from the code section.
    pub code: CodeStats,
    /// False when code-section scanning was disabled, which makes the
    /// instruction-level statistics unavailable rather than zero.
    pub code_scanned: bool,
    /// `(section id, payload length)` in file order.
    pub sections: Vec<(u8, usize)>,
    pub features: Features,
}

/// Options for the decoder.
#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    /// Scan function bodies. Disabling it skips the code section entirely,
    /// which loses the `call_indirect`/`memory.grow` statistics but lets the
    /// tool report on a module whose body uses an instruction this parser
    /// does not decode.
    pub scan_code: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        ParseOptions { scan_code: true }
    }
}

const SECTION_CUSTOM: u8 = 0;
const SECTION_TYPE: u8 = 1;
const SECTION_IMPORT: u8 = 2;
const SECTION_FUNCTION: u8 = 3;
const SECTION_TABLE: u8 = 4;
const SECTION_MEMORY: u8 = 5;
const SECTION_GLOBAL: u8 = 6;
const SECTION_EXPORT: u8 = 7;
const SECTION_START: u8 = 8;
const SECTION_ELEMENT: u8 = 9;
const SECTION_CODE: u8 = 10;
const SECTION_DATA: u8 = 11;
const SECTION_DATA_COUNT: u8 = 12;
const SECTION_TAG: u8 = 13;

/// The order the format prescribes. Lower rank must come first; custom
/// sections may appear anywhere and are not ranked.
fn section_rank(id: u8) -> Option<u8> {
    Some(match id {
        SECTION_TYPE => 1,
        SECTION_IMPORT => 2,
        SECTION_FUNCTION => 3,
        SECTION_TABLE => 4,
        SECTION_MEMORY => 5,
        SECTION_TAG => 6,
        SECTION_GLOBAL => 7,
        SECTION_EXPORT => 8,
        SECTION_START => 9,
        SECTION_ELEMENT => 10,
        SECTION_DATA_COUNT => 11,
        SECTION_CODE => 12,
        SECTION_DATA => 13,
        _ => return None,
    })
}

fn context_for(id: u8) -> Context {
    match id {
        SECTION_CUSTOM => Context::CustomSection,
        SECTION_TYPE => Context::TypeSection,
        SECTION_IMPORT => Context::ImportSection,
        SECTION_FUNCTION => Context::FunctionSection,
        SECTION_TABLE => Context::TableSection,
        SECTION_MEMORY => Context::MemorySection,
        SECTION_GLOBAL => Context::GlobalSection,
        SECTION_EXPORT => Context::ExportSection,
        SECTION_START => Context::StartSection,
        SECTION_ELEMENT => Context::ElementSection,
        SECTION_CODE => Context::CodeSection,
        SECTION_DATA => Context::DataSection,
        SECTION_DATA_COUNT => Context::DataCountSection,
        SECTION_TAG => Context::TagSection,
        _ => Context::SectionHeader,
    }
}

/// Decode a module with default options.
pub fn parse(bytes: &[u8]) -> Result<Module> {
    parse_with(bytes, ParseOptions::default())
}

/// Decode a module.
pub fn parse_with(bytes: &[u8], opts: ParseOptions) -> Result<Module> {
    if bytes.is_empty() {
        return Err(ParseError::new(0, Context::Preamble, ErrorKind::Empty));
    }
    let mut r = Reader::new(bytes);
    let magic: [u8; 4] = r.array()?;
    if magic != [0x00, 0x61, 0x73, 0x6d] {
        return Err(ParseError::new(
            0,
            Context::Preamble,
            ErrorKind::BadMagic(magic),
        ));
    }
    let version = r.u32_le()?;
    if version != 1 {
        return Err(ParseError::new(
            4,
            Context::Preamble,
            ErrorKind::UnsupportedVersion(version),
        ));
    }

    let mut m = Module {
        version,
        code_scanned: opts.scan_code,
        ..Module::default()
    };

    let mut last_rank: Option<(u8, u8)> = None; // (rank, id)
    while !r.is_empty() {
        r.set_context(Context::SectionHeader);
        let header_at = r.offset();
        let id = r.u8()?;
        let size = r.byte_len()?;
        let body_start = r.offset();
        let body = r.bytes(size)?;

        if id != SECTION_CUSTOM {
            let rank = section_rank(id).ok_or_else(|| {
                ParseError::new(
                    header_at,
                    Context::SectionHeader,
                    ErrorKind::UnknownSectionId(id),
                )
            })?;
            if let Some((prev_rank, prev_id)) = last_rank {
                if rank == prev_rank {
                    return Err(ParseError::new(
                        body_start,
                        context_for(id),
                        ErrorKind::DuplicateSection(id),
                    ));
                }
                if rank < prev_rank {
                    return Err(ParseError::new(
                        body_start,
                        context_for(id),
                        ErrorKind::SectionOutOfOrder {
                            id,
                            previous: prev_id,
                        },
                    ));
                }
            }
            last_rank = Some((rank, id));
        }

        m.sections.push((id, size));
        let mut sr = Reader::sub(body, body_start, context_for(id));
        decode_section(&mut m, id, &mut sr, opts)?;
        if !sr.is_empty() {
            return Err(ParseError::new(
                sr.offset(),
                context_for(id),
                ErrorKind::SectionSizeMismatch {
                    declared: size,
                    consumed: size - sr.remaining(),
                },
            ));
        }
    }
    Ok(m)
}

fn decode_section(m: &mut Module, id: u8, r: &mut Reader<'_>, opts: ParseOptions) -> Result<()> {
    match id {
        SECTION_CUSTOM => {
            let name = r.name()?;
            let payload_len = r.remaining();
            r.skip(payload_len)?;
            m.customs.push(CustomSection { name, payload_len });
        }
        SECTION_TYPE => {
            let n = r.vec_count()?;
            for _ in 0..n {
                let form = r.u8()?;
                if form != 0x60 {
                    return Err(r.error(ErrorKind::UnsupportedTypeForm(form)));
                }
                let params = read_valtype_vec(r, &mut m.features)?;
                let results = read_valtype_vec(r, &mut m.features)?;
                if results.len() > 1 {
                    m.features.multi_value = true;
                }
                m.types.push(FuncType { params, results });
            }
        }
        SECTION_IMPORT => {
            let n = r.vec_count()?;
            for _ in 0..n {
                let module = r.name()?;
                let name = r.name()?;
                let desc = read_import_desc(r, &mut m.features)?;
                m.imports.push(Import { module, name, desc });
            }
        }
        SECTION_FUNCTION => {
            let n = r.vec_count()?;
            for _ in 0..n {
                m.functions.push(r.u32_leb()?);
            }
        }
        SECTION_TABLE => {
            let n = r.vec_count()?;
            for _ in 0..n {
                m.tables.push(read_table_type(r, &mut m.features)?);
            }
        }
        SECTION_MEMORY => {
            let n = r.vec_count()?;
            for _ in 0..n {
                let limits = read_limits(r, &mut m.features)?;
                m.memories.push(MemType { limits });
            }
            if m.memories.len() + count_imported_memories(m) > 1 {
                m.features.multi_memory = true;
            }
        }
        SECTION_GLOBAL => {
            let n = r.vec_count()?;
            for _ in 0..n {
                let ty = read_global_type(r, &mut m.features)?;
                instr::skip_const_expr(r, &mut m.features)?;
                m.globals.push(GlobalDef { ty });
            }
        }
        SECTION_EXPORT => {
            let n = r.vec_count()?;
            for _ in 0..n {
                let name = r.name()?;
                let kind = match r.u8()? {
                    0x00 => ExternKind::Func,
                    0x01 => ExternKind::Table,
                    0x02 => ExternKind::Memory,
                    0x03 => ExternKind::Global,
                    0x04 => {
                        m.features.exception_handling = true;
                        ExternKind::Tag
                    }
                    other => return Err(r.error(ErrorKind::UnknownDescriptor(other))),
                };
                let index = r.u32_leb()?;
                m.exports.push(Export { name, kind, index });
            }
        }
        SECTION_START => {
            m.start = Some(r.u32_leb()?);
        }
        SECTION_ELEMENT => {
            let n = r.vec_count()?;
            for _ in 0..n {
                m.elements.push(read_elem_segment(r, &mut m.features)?);
            }
        }
        SECTION_CODE => {
            let n = r.vec_count()?;
            if !opts.scan_code {
                let rest = r.remaining();
                r.skip(rest)?;
                m.code.functions = n as usize;
                return Ok(());
            }
            m.code.functions = n as usize;
            for _ in 0..n {
                let body_len = r.byte_len()?;
                let at = r.offset();
                let body = r.bytes(body_len)?;
                let mut br = Reader::sub(body, at, Context::CodeSection);
                instr::scan_function_body(&mut br, &mut m.code, &mut m.features)?;
            }
        }
        SECTION_DATA => {
            let n = r.vec_count()?;
            for _ in 0..n {
                let flags = r.u32_leb()?;
                let mode = match flags {
                    0 => {
                        instr::skip_const_expr(r, &mut m.features)?;
                        DataMode::Active { memory: 0 }
                    }
                    1 => {
                        m.features.bulk_memory = true;
                        DataMode::Passive
                    }
                    2 => {
                        m.features.bulk_memory = true;
                        let memory = r.u32_leb()?;
                        if memory > 0 {
                            m.features.multi_memory = true;
                        }
                        instr::skip_const_expr(r, &mut m.features)?;
                        DataMode::Active { memory }
                    }
                    other => return Err(r.error(ErrorKind::UnknownDataKind(other))),
                };
                let len = r.byte_len()?;
                r.skip(len)?;
                m.data.push(DataSegment { mode, len });
            }
        }
        SECTION_DATA_COUNT => {
            m.features.bulk_memory = true;
            m.data_count = Some(r.u32_leb()?);
        }
        SECTION_TAG => {
            m.features.exception_handling = true;
            let n = r.vec_count()?;
            for _ in 0..n {
                let attr = r.u8()?;
                if attr != 0x00 {
                    return Err(r.error(ErrorKind::UnknownDescriptor(attr)));
                }
                let _ty = r.u32_leb()?;
                m.tags += 1;
            }
        }
        other => return Err(r.error(ErrorKind::UnknownSectionId(other))),
    }
    Ok(())
}

fn count_imported_memories(m: &Module) -> usize {
    m.imports
        .iter()
        .filter(|i| matches!(i.desc, ImportDesc::Memory(_)))
        .count()
}

fn read_valtype_vec(r: &mut Reader<'_>, f: &mut Features) -> Result<Vec<ValType>> {
    let n = r.vec_count()?;
    // `vec_count` has already checked `n` against the bytes remaining. Nothing
    // here reserves capacity from a file-supplied count either way.
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(read_valtype(r, f)?);
    }
    Ok(out)
}

/// Decode a value type.
pub fn read_valtype(r: &mut Reader<'_>, f: &mut Features) -> Result<ValType> {
    let b = r.u8()?;
    Ok(match b {
        0x7f => ValType::I32,
        0x7e => ValType::I64,
        0x7d => ValType::F32,
        0x7c => ValType::F64,
        0x7b => {
            f.simd = true;
            ValType::V128
        }
        0x70 => {
            f.reference_types = true;
            ValType::FuncRef
        }
        0x6f => {
            f.reference_types = true;
            ValType::ExternRef
        }
        0x63 | 0x64 => {
            f.typed_function_references = true;
            let heap = r.i33_leb()?;
            ValType::TypedRef {
                nullable: b == 0x63,
                heap,
            }
        }
        other => return Err(r.error(ErrorKind::UnknownValType(other))),
    })
}

fn read_reftype(r: &mut Reader<'_>, f: &mut Features) -> Result<ValType> {
    let b = r.peek_u8()?;
    match b {
        0x70 | 0x6f | 0x63 | 0x64 => read_valtype(r, f),
        other => Err(r.error(ErrorKind::UnknownRefType(other))),
    }
}

fn read_limits(r: &mut Reader<'_>, f: &mut Features) -> Result<Limits> {
    let flags = r.u8()?;
    // Bit 0: a maximum follows. Bit 1: shared (threads). Bit 2: 64-bit index
    // (memory64). Anything else is an encoding this parser does not know, and
    // guessing at it would mean reporting the wrong size for a memory.
    if flags & !0b0000_0111 != 0 {
        return Err(r.error(ErrorKind::UnknownLimitsFlags(flags)));
    }
    let has_max = flags & 0b001 != 0;
    let shared = flags & 0b010 != 0;
    let index64 = flags & 0b100 != 0;
    if shared {
        f.threads = true;
    }
    if index64 {
        f.memory64 = true;
    }
    let min = if index64 {
        r.u64_leb()?
    } else {
        u64::from(r.u32_leb()?)
    };
    let max = if has_max {
        Some(if index64 {
            r.u64_leb()?
        } else {
            u64::from(r.u32_leb()?)
        })
    } else {
        None
    };
    if let Some(mx) = max {
        if mx < min {
            return Err(r.error(ErrorKind::LimitsInverted { min, max: mx }));
        }
    }
    Ok(Limits {
        min,
        max,
        shared,
        index64,
    })
}

fn read_table_type(r: &mut Reader<'_>, f: &mut Features) -> Result<TableType> {
    let elem = read_reftype(r, f)?;
    let limits = read_limits(r, f)?;
    Ok(TableType { elem, limits })
}

fn read_global_type(r: &mut Reader<'_>, f: &mut Features) -> Result<GlobalType> {
    let val = read_valtype(r, f)?;
    let mutable = match r.u8()? {
        0x00 => false,
        0x01 => true,
        other => return Err(r.error(ErrorKind::InvalidMutability(other))),
    };
    Ok(GlobalType { val, mutable })
}

fn read_import_desc(r: &mut Reader<'_>, f: &mut Features) -> Result<ImportDesc> {
    Ok(match r.u8()? {
        0x00 => ImportDesc::Func(r.u32_leb()?),
        0x01 => ImportDesc::Table(read_table_type(r, f)?),
        0x02 => ImportDesc::Memory(MemType {
            limits: read_limits(r, f)?,
        }),
        0x03 => ImportDesc::Global(read_global_type(r, f)?),
        0x04 => {
            f.exception_handling = true;
            let attr = r.u8()?;
            if attr != 0x00 {
                return Err(r.error(ErrorKind::UnknownDescriptor(attr)));
            }
            ImportDesc::Tag(r.u32_leb()?)
        }
        other => return Err(r.error(ErrorKind::UnknownDescriptor(other))),
    })
}

fn read_elem_segment(r: &mut Reader<'_>, f: &mut Features) -> Result<ElemSegment> {
    let kind = r.u32_leb()?;
    if kind != 0 {
        f.reference_types = true;
    }
    let mode = match kind {
        0 => {
            instr::skip_const_expr(r, f)?;
            ElemMode::Active { table: 0 }
        }
        1 => {
            read_elem_kind(r)?;
            ElemMode::Passive
        }
        2 => {
            let table = r.u32_leb()?;
            instr::skip_const_expr(r, f)?;
            read_elem_kind(r)?;
            ElemMode::Active { table }
        }
        3 => {
            read_elem_kind(r)?;
            ElemMode::Declared
        }
        4 => {
            instr::skip_const_expr(r, f)?;
            ElemMode::Active { table: 0 }
        }
        5 => {
            read_reftype(r, f)?;
            ElemMode::Passive
        }
        6 => {
            let table = r.u32_leb()?;
            instr::skip_const_expr(r, f)?;
            read_reftype(r, f)?;
            ElemMode::Active { table }
        }
        7 => {
            read_reftype(r, f)?;
            ElemMode::Declared
        }
        other => return Err(r.error(ErrorKind::UnknownElementKind(other))),
    };
    let entries = r.vec_count()?;
    if kind < 4 {
        for _ in 0..entries {
            let _ = r.u32_leb()?;
        }
    } else {
        for _ in 0..entries {
            instr::skip_const_expr(r, f)?;
        }
    }
    Ok(ElemSegment { mode, entries })
}

fn read_elem_kind(r: &mut Reader<'_>) -> Result<()> {
    let b = r.u8()?;
    if b != 0x00 {
        return Err(r.error(ErrorKind::UnknownRefType(b)));
    }
    Ok(())
}

impl Module {
    /// Memories the module will have at run time: those it declares plus
    /// those the host hands it.
    pub fn all_memories(&self) -> Vec<(MemType, bool)> {
        let mut out = Vec::new();
        for i in &self.imports {
            if let ImportDesc::Memory(mt) = &i.desc {
                out.push((*mt, true));
            }
        }
        for mt in &self.memories {
            out.push((*mt, false));
        }
        out
    }

    /// Tables the module will have at run time.
    pub fn all_tables(&self) -> Vec<(TableType, bool)> {
        let mut out = Vec::new();
        for i in &self.imports {
            if let ImportDesc::Table(tt) = &i.desc {
                out.push((*tt, true));
            }
        }
        for tt in &self.tables {
            out.push((*tt, false));
        }
        out
    }

    /// Number of function imports, which is also the index offset applied to
    /// module-defined functions.
    pub fn imported_func_count(&self) -> usize {
        self.imports
            .iter()
            .filter(|i| matches!(i.desc, ImportDesc::Func(_)))
            .count()
    }
}
