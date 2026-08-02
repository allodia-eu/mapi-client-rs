//! Little-endian appends into an owned buffer.

/// Builds a wire buffer field by field.
///
/// Infallible by construction — every method appends — so encoding errors are raised where the
/// protocol's own length fields are computed, not here.
#[derive(Clone, Debug, Default)]
pub(crate) struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub(crate) const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    pub(crate) fn u16(&mut self, value: u16) -> &mut Self {
        self.bytes(&value.to_le_bytes())
    }

    pub(crate) fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes(&value.to_le_bytes())
    }

    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes(&value.to_le_bytes())
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// A null-terminated 8-bit string, as `Connect`'s `UserDn` and `RopLogon`'s `Essdn` carry it.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.1 — `UserDn`
    pub(crate) fn ascii_z(&mut self, value: &str) -> &mut Self {
        self.bytes(value.as_bytes()).u8(0)
    }

    /// A null-terminated UTF-16LE string, as every `PtypString` value carries it.
    ///
    /// The terminator is two zero bytes, not one. A caller passing a string with an interior NUL
    /// would produce a field that ends early and shifts every field after it, so the property
    /// encoder rejects that before reaching here rather than writing it.
    ///
    /// [MS-OXCDATA] §2.11.1 — `PtypString`
    pub(crate) fn utf16_z(&mut self, value: &str) -> &mut Self {
        for unit in value.encode_utf16() {
            self.u16(unit);
        }
        self.u16(0)
    }

    /// The bytes written so far.
    pub(crate) fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_scalars_in_little_endian_order() {
        let mut w = Writer::new();
        w.u8(0x01).u16(0x0203).u32(0x0405_0607);
        assert_eq!(w.finish(), vec![0x01, 0x03, 0x02, 0x07, 0x06, 0x05, 0x04]);
    }

    /// A property tag is written in the notation the specification uses, and the little-endian
    /// encoding of that `u32` *is* the wire form: type first, then id.
    #[test]
    fn little_endian_is_the_wire_order_not_the_native_one() {
        let mut w = Writer::new();
        w.u32(0x0037_001F); // PidTagSubject
        assert_eq!(w.finish(), vec![0x1F, 0x00, 0x37, 0x00]);
    }

    #[test]
    fn ascii_z_appends_the_terminator() {
        let mut w = Writer::new();
        w.ascii_z("/o=X");
        assert_eq!(w.finish(), b"/o=X\0");
    }

    /// A UTF-16 terminator is two zero bytes. One would leave a stray byte that shifts every
    /// field after it — the failure that looks like a protocol bug somewhere else.
    #[test]
    fn utf16_z_appends_a_two_byte_terminator() {
        let mut w = Writer::new();
        w.utf16_z("Hi");
        assert_eq!(w.finish(), vec![0x48, 0x00, 0x69, 0x00, 0x00, 0x00]);

        let mut w = Writer::new();
        w.utf16_z("");
        assert_eq!(w.finish(), vec![0x00, 0x00]);
    }

    /// A character outside the basic multilingual plane is a surrogate pair, so the encoded length
    /// is not the character count.
    #[test]
    fn utf16_z_encodes_a_surrogate_pair_as_two_units() {
        let mut w = Writer::new();
        w.utf16_z("\u{1F600}");
        assert_eq!(w.finish(), vec![0x3D, 0xD8, 0x00, 0xDE, 0x00, 0x00]);
    }

    #[test]
    fn u64_covers_all_eight_bytes() {
        let mut w = Writer::new();
        w.u64(0x0102_0304_0506_0708);
        assert_eq!(
            w.finish(),
            vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }
}
