//! Parse errors.
//!
//! Every error carries the byte offset at which the parser gave up and a
//! description specific enough to act on. The parser never recovers by
//! guessing: a section it cannot decode is an error, not a shrug.

use std::fmt;

/// Where in the module the parser was when it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    Preamble,
    SectionHeader,
    TypeSection,
    ImportSection,
    FunctionSection,
    TableSection,
    MemorySection,
    GlobalSection,
    ExportSection,
    StartSection,
    ElementSection,
    CodeSection,
    DataSection,
    DataCountSection,
    CustomSection,
    TagSection,
}

impl Context {
    /// Human-readable name used in error messages.
    pub fn name(self) -> &'static str {
        match self {
            Context::Preamble => "preamble",
            Context::SectionHeader => "section header",
            Context::TypeSection => "type section",
            Context::ImportSection => "import section",
            Context::FunctionSection => "function section",
            Context::TableSection => "table section",
            Context::MemorySection => "memory section",
            Context::GlobalSection => "global section",
            Context::ExportSection => "export section",
            Context::StartSection => "start section",
            Context::ElementSection => "element section",
            Context::CodeSection => "code section",
            Context::DataSection => "data section",
            Context::DataCountSection => "data count section",
            Context::CustomSection => "custom section",
            Context::TagSection => "tag section",
        }
    }
}

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// The file is empty.
    Empty,
    /// The first four bytes are not `\0asm`.
    BadMagic([u8; 4]),
    /// The version word is not one this parser understands.
    UnsupportedVersion(u32),
    /// Fewer bytes remain than the structure requires.
    UnexpectedEof { needed: usize, available: usize },
    /// A LEB128 integer ran past the end of the input.
    LebUnterminated,
    /// A LEB128 integer used more bytes than its width allows.
    LebTooLong { bits: u32 },
    /// A LEB128 integer's continuation bits encoded a value out of range.
    LebOverflow { bits: u32 },
    /// A declared length or count exceeds what is left in the file.
    LengthBeyondInput { declared: u64, available: usize },
    /// A section declared a size but its contents did not fill it exactly.
    SectionSizeMismatch { declared: usize, consumed: usize },
    /// A section id this parser has no decoder for.
    UnknownSectionId(u8),
    /// A section appeared twice where the format allows it only once.
    DuplicateSection(u8),
    /// A section appeared out of the order the format prescribes.
    SectionOutOfOrder { id: u8, previous: u8 },
    /// A name field was not valid UTF-8, which the format requires.
    InvalidUtf8,
    /// A value type byte this parser does not know.
    UnknownValType(u8),
    /// A reference type byte this parser does not know.
    UnknownRefType(u8),
    /// A type-section form this parser does not decode (e.g. GC rec/sub types).
    UnsupportedTypeForm(u8),
    /// An import/export descriptor byte this parser does not know.
    UnknownDescriptor(u8),
    /// A limits flags byte with bits this parser does not know.
    UnknownLimitsFlags(u8),
    /// `max < min` in a limits structure.
    LimitsInverted { min: u64, max: u64 },
    /// A mutability byte that is neither 0 nor 1.
    InvalidMutability(u8),
    /// An element-segment kind this parser does not decode.
    UnknownElementKind(u32),
    /// A data-segment kind this parser does not decode.
    UnknownDataKind(u32),
    /// An opcode this parser does not decode, with the proposal it belongs to
    /// when that is known.
    UnknownOpcode { opcode: u8, note: &'static str },
    /// A prefixed opcode (`0xFC`/`0xFD`/`0xFE`) this parser does not decode.
    UnknownPrefixedOpcode { prefix: u8, sub: u32 },
    /// An instruction sequence ended without its terminating `end`.
    UnterminatedExpression,
    /// Nesting depth in an expression exceeded the parser's limit.
    DepthLimitExceeded { limit: u32 },
}

/// A parse failure, with position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub offset: usize,
    pub context: Context,
    pub kind: ErrorKind,
}

impl ParseError {
    pub fn new(offset: usize, context: Context, kind: ErrorKind) -> Self {
        ParseError {
            offset,
            context,
            kind,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at byte 0x{:x} ({}): ",
            self.context.name(),
            self.offset,
            self.offset
        )?;
        match &self.kind {
            ErrorKind::Empty => write!(f, "file is empty"),
            ErrorKind::BadMagic(got) => write!(
                f,
                "not a WebAssembly module: expected magic 00 61 73 6d, got {:02x} {:02x} {:02x} {:02x}",
                got[0], got[1], got[2], got[3]
            ),
            ErrorKind::UnsupportedVersion(v) => {
                write!(f, "unsupported binary format version {v}; this parser handles version 1")
            }
            ErrorKind::UnexpectedEof { needed, available } => {
                write!(f, "truncated: need {needed} more byte(s), {available} available")
            }
            ErrorKind::LebUnterminated => {
                write!(f, "LEB128 integer is unterminated (no byte with the high bit clear)")
            }
            ErrorKind::LebTooLong { bits } => {
                write!(f, "LEB128 integer uses more bytes than a {bits}-bit value permits")
            }
            ErrorKind::LebOverflow { bits } => {
                write!(f, "LEB128 integer does not fit in {bits} bits")
            }
            ErrorKind::LengthBeyondInput { declared, available } => write!(
                f,
                "declared length/count {declared} exceeds the {available} byte(s) remaining"
            ),
            ErrorKind::SectionSizeMismatch { declared, consumed } => write!(
                f,
                "section declared {declared} byte(s) but its contents consumed {consumed}"
            ),
            ErrorKind::UnknownSectionId(id) => {
                write!(f, "unknown section id {id}; refusing to skip it silently")
            }
            ErrorKind::DuplicateSection(id) => {
                write!(f, "section id {id} appears more than once")
            }
            ErrorKind::SectionOutOfOrder { id, previous } => write!(
                f,
                "section id {id} follows section id {previous}, which is out of the prescribed order"
            ),
            ErrorKind::InvalidUtf8 => write!(f, "name is not valid UTF-8"),
            ErrorKind::UnknownValType(b) => write!(f, "unknown value type 0x{b:02x}"),
            ErrorKind::UnknownRefType(b) => write!(f, "unknown reference type 0x{b:02x}"),
            ErrorKind::UnsupportedTypeForm(b) => write!(
                f,
                "type form 0x{b:02x} is not decoded by this parser (function types, 0x60, only)"
            ),
            ErrorKind::UnknownDescriptor(b) => {
                write!(f, "unknown import/export descriptor 0x{b:02x}")
            }
            ErrorKind::UnknownLimitsFlags(b) => write!(f, "unknown limits flags 0x{b:02x}"),
            ErrorKind::LimitsInverted { min, max } => {
                write!(f, "limits maximum {max} is below minimum {min}")
            }
            ErrorKind::InvalidMutability(b) => {
                write!(f, "mutability byte 0x{b:02x} is neither 0x00 (const) nor 0x01 (var)")
            }
            ErrorKind::UnknownElementKind(k) => {
                write!(f, "element segment kind {k} is not one of the eight defined forms")
            }
            ErrorKind::UnknownDataKind(k) => {
                write!(f, "data segment kind {k} is not one of the three defined forms")
            }
            ErrorKind::UnknownOpcode { opcode, note } => {
                write!(f, "unknown opcode 0x{opcode:02x} ({note})")
            }
            ErrorKind::UnknownPrefixedOpcode { prefix, sub } => write!(
                f,
                "unknown opcode 0x{prefix:02x} 0x{sub:02x} (prefix 0x{prefix:02x}, sub-opcode {sub})"
            ),
            ErrorKind::UnterminatedExpression => {
                write!(f, "instruction sequence ended without a matching 0x0b (end)")
            }
            ErrorKind::DepthLimitExceeded { limit } => {
                write!(f, "block nesting exceeded the parser limit of {limit}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Result alias used throughout the parser.
pub type Result<T> = std::result::Result<T, ParseError>;
