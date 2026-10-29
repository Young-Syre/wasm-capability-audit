//! A bounds-checked cursor over module bytes, with LEB128 decoding.
//!
//! Three properties matter here and are tested directly:
//!
//! * every read is bounds-checked, so a truncated file produces an error
//!   rather than a panic;
//! * LEB128 decoding rejects both unterminated and over-long encodings,
//!   which is where hand-written parsers usually go wrong;
//! * a count or length read from the file is validated against the bytes
//!   that actually remain *before* anything is allocated for it. There is
//!   no `Vec::with_capacity(n)` anywhere in this crate where `n` came from
//!   the input.

use crate::error::{Context, ErrorKind, ParseError, Result};

/// A read cursor over a byte slice.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    /// Offset of `bytes[0]` within the whole file, so errors report absolute
    /// positions even when reading a sub-slice of one section.
    base: usize,
    ctx: Context,
}

impl<'a> Reader<'a> {
    /// A reader over a whole file.
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader {
            bytes,
            pos: 0,
            base: 0,
            ctx: Context::Preamble,
        }
    }

    /// A reader over a section body, reporting absolute file offsets.
    pub fn sub(bytes: &'a [u8], base: usize, ctx: Context) -> Self {
        Reader {
            bytes,
            pos: 0,
            base,
            ctx,
        }
    }

    /// Set the context reported by subsequent errors.
    pub fn set_context(&mut self, ctx: Context) {
        self.ctx = ctx;
    }

    /// Current context.
    pub fn context(&self) -> Context {
        self.ctx
    }

    /// Absolute offset of the cursor.
    pub fn offset(&self) -> usize {
        self.base + self.pos
    }

    /// Bytes left to read.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    /// True when the cursor is at the end.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn err(&self, kind: ErrorKind) -> ParseError {
        ParseError::new(self.offset(), self.ctx, kind)
    }

    /// Build an error at the current position with the current context.
    pub fn error(&self, kind: ErrorKind) -> ParseError {
        self.err(kind)
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(self.err(ErrorKind::UnexpectedEof {
                needed: 1,
                available: 0,
            }));
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Peek one byte without consuming it.
    pub fn peek_u8(&self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(self.err(ErrorKind::UnexpectedEof {
                needed: 1,
                available: 0,
            }));
        }
        Ok(self.bytes[self.pos])
    }

    /// Exactly `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(self.err(ErrorKind::UnexpectedEof {
                needed: n,
                available: self.remaining(),
            }));
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// A fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    /// Little-endian `u32`.
    pub fn u32_le(&mut self) -> Result<u32> {
        let b: [u8; 4] = self.array()?;
        Ok(u32::from_le_bytes(b))
    }

    /// Unsigned LEB128 in at most `bits` bits.
    ///
    /// Rejects an encoding that never terminates, one longer than `bits`
    /// allows, and one whose final byte sets bits above `bits`.
    fn uleb(&mut self, bits: u32) -> Result<u64> {
        let start = self.offset();
        let max_bytes = bits.div_ceil(7) as usize;
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        for i in 0..max_bytes {
            let byte = self
                .u8()
                .map_err(|_| ParseError::new(start, self.ctx, ErrorKind::LebUnterminated))?;
            let low = u64::from(byte & 0x7f);
            if i + 1 == max_bytes {
                // Final permitted byte: its value must fit the remaining bits.
                let remaining_bits = bits - shift;
                if remaining_bits < 7 && (low >> remaining_bits) != 0 {
                    return Err(ParseError::new(
                        start,
                        self.ctx,
                        ErrorKind::LebOverflow { bits },
                    ));
                }
            }
            result |= low << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
        Err(ParseError::new(
            start,
            self.ctx,
            ErrorKind::LebTooLong { bits },
        ))
    }

    /// Unsigned LEB128, 32-bit.
    pub fn u32_leb(&mut self) -> Result<u32> {
        Ok(self.uleb(32)? as u32)
    }

    /// Unsigned LEB128, 64-bit.
    pub fn u64_leb(&mut self) -> Result<u64> {
        self.uleb(64)
    }

    /// Signed LEB128 in at most `bits` bits, sign-extended into `i64`.
    fn sleb(&mut self, bits: u32) -> Result<i64> {
        let start = self.offset();
        let max_bytes = bits.div_ceil(7) as usize;
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        for i in 0..max_bytes {
            let byte = self
                .u8()
                .map_err(|_| ParseError::new(start, self.ctx, ErrorKind::LebUnterminated))?;
            let low = i64::from(byte & 0x7f);
            if i + 1 == max_bytes {
                // Final permitted byte. Its significant bits must be a correct
                // sign extension of the value so far.
                let remaining_bits = bits - shift;
                if remaining_bits < 7 {
                    let tail = (byte & 0x7f) >> (remaining_bits - 1);
                    let ones = (1u8 << (8 - remaining_bits)) - 1;
                    if tail != 0 && tail != ones {
                        return Err(ParseError::new(
                            start,
                            self.ctx,
                            ErrorKind::LebOverflow { bits },
                        ));
                    }
                }
            }
            result |= low << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                // Sign-extend from the bit just below `shift`.
                if shift < 64 && byte & 0x40 != 0 {
                    result |= -1i64 << shift;
                }
                return Ok(result);
            }
        }
        Err(ParseError::new(
            start,
            self.ctx,
            ErrorKind::LebTooLong { bits },
        ))
    }

    /// Signed LEB128, 32-bit.
    pub fn i32_leb(&mut self) -> Result<i32> {
        Ok(self.sleb(32)? as i32)
    }

    /// Signed LEB128, 33-bit. Used for block types and heap types, where a
    /// negative value is a built-in type and a non-negative one is a type
    /// index.
    pub fn i33_leb(&mut self) -> Result<i64> {
        self.sleb(33)
    }

    /// Signed LEB128, 64-bit.
    pub fn i64_leb(&mut self) -> Result<i64> {
        self.sleb(64)
    }

    /// A vector's element count, validated against the bytes that remain.
    ///
    /// Every vector element in the binary format occupies at least one byte,
    /// so a count larger than the remaining length is malformed. Checking it
    /// here is what makes it safe to reserve for the result elsewhere.
    pub fn vec_count(&mut self) -> Result<u32> {
        let at = self.offset();
        let n = self.u32_leb()?;
        if n as usize > self.remaining() {
            return Err(ParseError::new(
                at,
                self.ctx,
                ErrorKind::LengthBeyondInput {
                    declared: u64::from(n),
                    available: self.remaining(),
                },
            ));
        }
        Ok(n)
    }

    /// A byte-length prefix, validated against the bytes that remain.
    pub fn byte_len(&mut self) -> Result<usize> {
        let at = self.offset();
        let n = self.u32_leb()?;
        if n as usize > self.remaining() {
            return Err(ParseError::new(
                at,
                self.ctx,
                ErrorKind::LengthBeyondInput {
                    declared: u64::from(n),
                    available: self.remaining(),
                },
            ));
        }
        Ok(n as usize)
    }

    /// A UTF-8 name: a byte length followed by that many bytes.
    ///
    /// The format requires names to be valid UTF-8; invalid bytes are an
    /// error rather than something to paper over with a lossy conversion,
    /// because a name is what the capability rules match on.
    pub fn name(&mut self) -> Result<String> {
        let len = self.byte_len()?;
        let at = self.offset();
        let raw = self.bytes(len)?;
        match std::str::from_utf8(raw) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Err(ParseError::new(at, self.ctx, ErrorKind::InvalidUtf8)),
        }
    }

    /// Advance over `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }
}
