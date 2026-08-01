//! The framing around a list of ROPs, and the three rules implementations get wrong.
//!
//! 1. **`RopSize` counts itself and the ROP list — not the handle table.** The wording is "the size
//!    of *both this field and the `RopsList` field*", so writing `rops.len()` is off by two.
//! 2. **The handle table is sized by the largest index used, not by the ROP count.** Its length is
//!    whatever remains after `RopSize` bytes, so a wrong size silently moves the boundary rather
//!    than failing.
//! 3. **Handles never appear inside a ROP body.** A ROP carries a 1-byte *index* into the table.
//!
//! [MS-OXCROPS] §2.2.1 — ROP input and output buffers
//! [MS-OXCROPS] §3.1.4.1 — creating a ROP input buffer

use crate::error::{Error, Result};
use crate::rop::ObjectHandle;
use crate::wire::{Reader, Writer};

/// `RPC_HEADER_EXT.Flags`: this is the last block in the buffer.
///
/// [MS-OXCRPC] §2.2.2.1 — `RPC_HEADER_EXT`
const RPC_HEADER_LAST: u16 = 0x0004;

/// `RPC_HEADER_EXT.Flags`: the payload is LZ77+DIRECT2 compressed.
const RPC_HEADER_COMPRESSED: u16 = 0x0001;

/// `RPC_HEADER_EXT.Flags`: the payload is obfuscated by XOR with 0xA5.
const RPC_HEADER_XOR_MAGIC: u16 = 0x0002;

/// A ROP list together with the handle table it indexes into.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RopBuffer {
    pub(crate) rops: Vec<u8>,
    pub(crate) handles: Vec<ObjectHandle>,
}

impl RopBuffer {
    /// Serialises to `RPC_HEADER_EXT || RopSize || RopsList || ServerObjectHandleTable`.
    ///
    /// # Errors
    ///
    /// [`Error::RopBufferTooLarge`] if the ROP list or the whole payload outgrows the 16-bit
    /// length fields that describe them.
    pub(crate) fn serialize(&self) -> Result<Vec<u8>> {
        let rop_size = self
            .rops
            .len()
            .checked_add(2)
            .and_then(|size| u16::try_from(size).ok())
            .ok_or(Error::RopBufferTooLarge {
                bytes: self.rops.len(),
                limit: usize::from(u16::MAX),
            })?;

        let mut payload = Writer::new();
        payload.u16(rop_size).bytes(&self.rops);
        for handle in &self.handles {
            payload.u32(handle.as_u32());
        }
        let payload = payload.finish();

        let size = u16::try_from(payload.len()).map_err(|_| Error::RopBufferTooLarge {
            bytes: payload.len(),
            limit: usize::from(u16::MAX),
        })?;

        // Version, Flags, Size, SizeActual. The two sizes are equal because nothing is compressed.
        let mut out = Writer::new();
        out.u16(0x0000)
            .u16(RPC_HEADER_LAST)
            .u16(size)
            .u16(size)
            .bytes(&payload);
        Ok(out.finish())
    }

    /// Parses a ROP output buffer, yielding the response bytes and the updated handle table.
    ///
    /// # Errors
    ///
    /// [`Error::ObfuscatedRopBuffer`] if the server compressed or obfuscated the payload after
    /// being asked not to, and [`Error::Truncated`] if any length field overruns the buffer.
    pub(crate) fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let _version = r.u16()?;
        let flags = r.u16()?;
        let size = usize::from(r.u16()?);
        let _size_actual = r.u16()?;

        if flags & (RPC_HEADER_COMPRESSED | RPC_HEADER_XOR_MAGIC) != 0 {
            return Err(Error::ObfuscatedRopBuffer { flags });
        }

        let mut payload = Reader::new(r.bytes(size)?);
        let rop_size = usize::from(payload.u16()?);
        // RopSize counts its own two bytes; a value below 2 would underflow the list length.
        let rops = payload.bytes(rop_size.saturating_sub(2))?.to_vec();

        let mut handles = Vec::new();
        while payload.remaining() >= 4 {
            handles.push(ObjectHandle::new(payload.u32()?));
        }

        Ok(Self { rops, handles })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector: one 3-byte ROP and a one-entry handle table.
    #[test]
    fn rop_size_counts_itself_and_the_rop_list_only() {
        let buffer = RopBuffer {
            rops: vec![0xFE, 0x00, 0x00],
            handles: vec![ObjectHandle::NONE],
        };

        #[rustfmt::skip]
        let expected = vec![
            0x00, 0x00,             // Version
            0x04, 0x00,             // Flags = Last
            0x09, 0x00,             // Size = 2 (RopSize) + 3 (rops) + 4 (handles)
            0x09, 0x00,             // SizeActual
            0x05, 0x00,             // RopSize = 2 + 3  <- not 3, and not 9
            0xFE, 0x00, 0x00,       // RopsList
            0xFF, 0xFF, 0xFF, 0xFF, // ServerObjectHandleTable[0]
        ];
        assert_eq!(buffer.serialize().unwrap(), expected);
    }

    #[test]
    fn round_trips_through_parse() {
        let buffer = RopBuffer {
            rops: vec![0xFE, 0x00, 0x01, 0x02],
            handles: vec![ObjectHandle::new(0x0000_002A), ObjectHandle::NONE],
        };
        let parsed = RopBuffer::parse(&buffer.serialize().unwrap()).unwrap();
        assert_eq!(parsed, buffer);
    }

    #[test]
    fn an_empty_buffer_still_frames_correctly() {
        let empty = RopBuffer::default();
        let bytes = empty.serialize().unwrap();
        assert_eq!(
            bytes,
            vec![0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00]
        );
        assert_eq!(RopBuffer::parse(&bytes).unwrap(), empty);
    }

    /// Decoding a compressed or obfuscated payload as plain bytes yields garbage that looks like a
    /// bug somewhere else, so it is refused where it happens.
    #[test]
    fn compressed_or_obfuscated_payloads_are_refused_not_misparsed() {
        for flags in [
            RPC_HEADER_LAST | RPC_HEADER_COMPRESSED,
            RPC_HEADER_LAST | RPC_HEADER_XOR_MAGIC,
        ] {
            let mut w = Writer::new();
            w.u16(0).u16(flags).u16(2).u16(2).u16(2);
            assert_eq!(
                RopBuffer::parse(&w.finish()),
                Err(Error::ObfuscatedRopBuffer { flags })
            );
        }
    }

    /// A `RopSize` below 2 would underflow the ROP-list length; that has to stay an empty list.
    #[test]
    fn a_rop_size_below_two_does_not_underflow() {
        let mut w = Writer::new();
        w.u16(0).u16(RPC_HEADER_LAST).u16(6).u16(6);
        w.u16(0).u32(ObjectHandle::NONE.as_u32());

        let parsed = RopBuffer::parse(&w.finish()).unwrap();
        assert!(parsed.rops.is_empty());
        assert_eq!(parsed.handles, vec![ObjectHandle::NONE]);
    }

    /// Trailing bytes that cannot form a whole handle are ignored rather than half-read.
    #[test]
    fn a_partial_handle_at_the_end_is_ignored() {
        let mut w = Writer::new();
        w.u16(0).u16(RPC_HEADER_LAST).u16(7).u16(7);
        w.u16(2).u32(1).u8(0xFF);

        let parsed = RopBuffer::parse(&w.finish()).unwrap();
        assert_eq!(parsed.handles, vec![ObjectHandle::new(1)]);
    }

    #[test]
    fn a_rop_list_past_the_length_field_is_an_error_not_a_wrap() {
        let buffer = RopBuffer {
            rops: vec![0; usize::from(u16::MAX)],
            handles: Vec::new(),
        };
        assert!(matches!(
            buffer.serialize(),
            Err(Error::RopBufferTooLarge { .. })
        ));
    }

    #[test]
    fn a_payload_past_the_length_field_is_an_error_not_a_wrap() {
        let buffer = RopBuffer {
            rops: vec![0; 60_000],
            handles: vec![ObjectHandle::NONE; 2_000],
        };
        assert!(matches!(
            buffer.serialize(),
            Err(Error::RopBufferTooLarge { .. })
        ));
    }

    #[test]
    fn hostile_buffers_never_panic() {
        for buf in [
            &b""[..],
            &[0x00, 0x00][..],
            &[0x00, 0x00, 0x04, 0x00, 0xFF, 0xFF, 0x00, 0x00][..], // Size lies
            &[0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02, 0x00, 0xFF, 0xFF][..], // RopSize lies
            &[0xFF; 32][..],
        ] {
            let _ = RopBuffer::parse(buf);
        }
    }
}
