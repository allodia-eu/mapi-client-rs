//! Fallible little-endian reads over a borrowed buffer.

use crate::error::{Error, Result};

/// A cursor over a wire buffer.
///
/// Reads advance the position and never wrap: a field that does not fit returns
/// [`Error::Truncated`] carrying the offset, what was wanted and what was left.
#[derive(Clone, Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Starts at offset zero of `buf`.
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// The current offset, which is what error variants report.
    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    /// Bytes not yet read.
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Whether every byte has been read.
    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Everything from the current position on, without advancing.
    fn peek_rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or_default()
    }

    /// Advances over `n` bytes and hands them back.
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated {
            at: self.pos,
            need: n,
            have: self.remaining(),
        })?;
        let out = self.buf.get(self.pos..end).ok_or(Error::Truncated {
            at: self.pos,
            need: n,
            have: self.remaining(),
        })?;
        self.pos = end;
        Ok(out)
    }

    /// A fixed-size byte array, for GUIDs and other opaque blocks.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0_u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_le_bytes(self.array::<1>()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array::<2>()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }

    /// Exactly `n` bytes.
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }

    /// Everything left, consuming it.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let out = self.peek_rest();
        self.pos = self.buf.len();
        out
    }

    /// A null-terminated 8-bit string, as `Connect`'s `UserDn` and `RopLogon`'s `Essdn` carry it.
    ///
    /// Decoded lossily: these fields are code-page encoded rather than UTF-8, and a distinguished
    /// name that fails to round-trip is still worth reporting in an error message.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.1 — `UserDn`
    pub(crate) fn ascii_z(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.bytes_z()?).into_owned())
    }

    /// A null-terminated run of bytes, handed back undecoded and without its terminator.
    ///
    /// For the one field whose bytes are not text in any encoding [`ascii_z`](Self::ascii_z) knows:
    /// a *reduced* Unicode `TypedString` is UTF-16LE with every zero high byte removed, so byte
    /// `0xE9` there is `é` and not the first half of a UTF-8 sequence. Decoding lossily first turns
    /// it into a replacement character that no later widening can undo.
    ///
    /// [MS-OXCDATA] §2.11.7 — `TypedString`, `StringType` `0x03`
    pub(crate) fn bytes_z(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        let len = self
            .peek_rest()
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::Unterminated { at: start })?;
        let raw = self.take(len)?;
        self.take(1)?;
        Ok(raw)
    }

    /// A null-terminated UTF-16LE string, as every `PtypString` value carries it.
    ///
    /// [MS-OXCDATA] §2.11.1 — `PtypString`
    pub(crate) fn utf16_z(&mut self) -> Result<String> {
        let start = self.pos;
        let mut units = Vec::new();
        loop {
            let unit = self.u16().map_err(|_| Error::Unterminated { at: start })?;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        String::from_utf16(&units).map_err(|_| Error::InvalidUtf16 { at: start })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_scalars_in_little_endian_order() {
        let buf = [0x01, 0x03, 0x02, 0x07, 0x06, 0x05, 0x04];
        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 0x01);
        assert_eq!(r.u16().unwrap(), 0x0203);
        assert_eq!(r.u32().unwrap(), 0x0405_0607);
        assert!(r.is_empty());
    }

    #[test]
    fn reads_a_null_terminated_ascii_string() {
        let buf = b"/o=First Organization\0trailing";
        let mut r = Reader::new(buf);
        assert_eq!(r.ascii_z().unwrap(), "/o=First Organization");
        assert_eq!(r.rest(), b"trailing");
    }

    #[test]
    fn reads_a_null_terminated_utf16_string() {
        let mut buf: Vec<u8> = "Inbox".encode_utf16().flat_map(u16::to_le_bytes).collect();
        buf.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(Reader::new(&buf).utf16_z().unwrap(), "Inbox");
    }

    #[test]
    fn an_empty_utf16_string_is_just_the_terminator() {
        assert_eq!(Reader::new(&[0x00, 0x00]).utf16_z().unwrap(), "");
    }

    /// The reason every read returns `Result`: these are bytes from a server we do not control,
    /// and none of them may panic.
    #[test]
    fn hostile_input_errors_rather_than_panicking() {
        assert!(Reader::new(&[]).u8().is_err());
        assert!(Reader::new(&[0x01]).u32().is_err());
        assert!(Reader::new(&[0x01, 0x02, 0x03]).u64().is_err());
        assert!(Reader::new(b"no terminator").ascii_z().is_err());
        assert!(Reader::new(&[0x41]).utf16_z().is_err());
        assert!(Reader::new(&[0xFF, 0xFF]).bytes(9999).is_err());
        assert!(Reader::new(&[0xFF, 0xFF]).array::<32>().is_err());

        // A lying length prefix must not read out of bounds.
        let mut r = Reader::new(&[0x10, 0x00]);
        let claimed = usize::from(r.u16().unwrap());
        assert!(r.bytes(claimed).is_err());
    }

    #[test]
    fn a_length_that_overflows_the_address_space_is_an_error() {
        let mut r = Reader::new(&[0x01, 0x02]);
        assert!(r.bytes(usize::MAX).is_err());
        assert_eq!(r.position(), 0, "a failed read must not advance");
    }

    #[test]
    fn an_unpaired_surrogate_is_an_error_not_a_panic() {
        let buf = [0x00, 0xD8, 0x00, 0x00];
        assert!(matches!(
            Reader::new(&buf).utf16_z(),
            Err(Error::InvalidUtf16 { at: 0 })
        ));
    }

    #[test]
    fn a_truncation_error_reports_what_it_wanted_and_what_was_left() {
        let mut r = Reader::new(&[0xAA, 0xBB, 0xCC]);
        r.u8().unwrap();
        assert_eq!(
            r.u32(),
            Err(Error::Truncated {
                at: 1,
                need: 4,
                have: 2
            })
        );
    }

    #[test]
    fn rest_consumes_everything_left() {
        let mut r = Reader::new(&[1, 2, 3]);
        r.u8().unwrap();
        assert_eq!(r.rest(), &[2, 3]);
        assert!(r.is_empty());
        assert!(r.rest().is_empty());
    }
}
