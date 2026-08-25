//! The stream ROPs: opening a property as a stream, reading it, and asking how long it is.
//!
//! **This is the only honest way to read a body.** [MS-OXCPRPT] §2.2.3.2 has a property too large
//! for the response buffer come back as `NotEnoughMemory` rather than as a value, and any real HTML
//! body clears that bar — so a property fetch answers a short message with text and a long one with
//! an error, which is the most misleading pair of behaviours a body reader could have. A stream
//! answers whatever fits and leaves the cursor where it stopped.
//!
//! One number governs the whole module: **`DataSize` is two bytes**, so no single `RopReadStream`
//! can answer with more than 65,535 bytes however large `ByteCount` is. A caller asking for more
//! would get a short answer indistinguishable from the end of the stream, which is why
//! [`encode_read_stream`] refuses rather than clamping.
//!
//! Writing has one number of its own and one ordering rule. `DataSize` is two bytes there too, so
//! a value larger than that takes several `RopWriteStream`s — and **what has been written is not
//! the property until something says so**. [MS-OXCPRPT] §3.1.4.16 persists a Message or Attachment
//! object's stream through that object's own save ROP; §3.2.5.15 has `RopCommitStream` set the
//! property from the stream. The two are different claims about the same bytes, and this crate
//! sends the commit rather than choosing between them.
//!
//! [MS-OXCROPS] §2.2.9.1 — `RopOpenStream`
//! [MS-OXCROPS] §2.2.9.2 — `RopReadStream`
//! [MS-OXCROPS] §2.2.9.3 — `RopWriteStream`
//! [MS-OXCROPS] §2.2.9.5 — `RopCommitStream`
//! [MS-OXCROPS] §2.2.9.6 — `RopGetStreamSize`
//! [MS-OXCPRPT] §2.2.14 — semantics

use crate::error::{Error, Result};
use crate::oxcdata::PropertyTag;
use crate::rop::RopId;
use crate::rop::batch::LOGON_ID;
use crate::wire::{Reader, Writer};

/// How a stream is opened, which decides what opening it does to the property.
///
/// An enum rather than a flag byte, because the three are not degrees of the same thing:
/// [`Create`](Self::Create) *deletes the current property value* before opening, so a mistyped mode
/// on a body read would destroy the body — and it is also the only mode that works on a property
/// that has never been set, which is every property of an attachment created moments ago.
///
/// [MS-OXCPRPT] §2.2.14.1 — `OpenModeFlags`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum StreamMode {
    /// `0x00` — read the property, change nothing.
    #[default]
    ReadOnly,
    /// `0x01` — read and write, keeping whatever the property already holds.
    ReadWrite,
    /// `0x02` — **discard the current value** and open an empty stream.
    Create,
}

impl StreamMode {
    /// The `OpenModeFlags` byte this is written as.
    const fn flags(self) -> u8 {
        match self {
            Self::ReadOnly => 0x00,
            Self::ReadWrite => 0x01,
            Self::Create => 0x02,
        }
    }

    /// Whether a stream opened this way can be written to.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::ReadWrite | Self::Create)
    }
}

/// The most bytes one `RopReadStream` response can carry, because `DataSize` is two bytes.
///
/// [MS-OXCROPS] §2.2.9.2.2 — `DataSize`
pub(crate) const MAX_READ: usize = 0xFFFF;

/// The most bytes one `RopWriteStream` request can carry, for the same reason.
///
/// The ROP list is bounded below this anyway — `RopSize` is two bytes as well and counts every ROP
/// in the buffer — so a write this large is refused by the framing rather than by the field. Both
/// are checked, because the two limits move independently.
///
/// [MS-OXCROPS] §2.2.9.3.1 — `DataSize`
pub(crate) const MAX_WRITE: usize = 0xFFFF;

/// How long a stream is.
///
/// Both `RopOpenStream` and `RopGetStreamSize` answer with exactly this, which is why one type
/// serves both.
///
/// [MS-OXCROPS] §2.2.9.1.2 — `StreamSize`
/// [MS-OXCROPS] §2.2.9.6.2 — `StreamSize`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSizeResponse {
    rop: RopId,
    size: u32,
}

impl StreamSizeResponse {
    /// Which ROP reported it — the open or the explicit size request.
    #[must_use]
    pub const fn rop(self) -> RopId {
        self.rop
    }

    /// The number of bytes in the stream.
    ///
    /// A measurement at the moment it was taken, not a promise: the value that arrives with the
    /// open is what the property was then, and a client reading a mailbox somebody else is writing
    /// to can be handed fewer bytes or more.
    #[must_use]
    pub const fn size(self) -> u32 {
        self.size
    }

    pub(crate) fn read(r: &mut Reader<'_>, rop: RopId) -> Result<Self> {
        Ok(Self {
            rop,
            size: r.u32()?,
        })
    }
}

/// Bytes read from a stream.
///
/// [MS-OXCROPS] §2.2.9.2.2 — response buffer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadStreamResponse {
    data: Vec<u8>,
}

impl ReadStreamResponse {
    /// The bytes, exactly as many as `DataSize` claimed.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Whether the server answered with nothing, which is how the end of a stream is reported.
    ///
    /// There is no end-of-stream flag: a read past the last byte succeeds and returns zero bytes.
    #[must_use]
    pub fn is_end(&self) -> bool {
        self.data.is_empty()
    }

    /// Takes the bytes out.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let size = usize::from(r.u16()?);
        Ok(Self {
            data: r.bytes(size)?.to_vec(),
        })
    }
}

/// How much of a write reached the stream.
///
/// [MS-OXCROPS] §2.2.9.3.2 — response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteStreamResponse {
    written: u16,
}

impl WriteStreamResponse {
    /// The number of bytes the server says it wrote.
    ///
    /// **Worth comparing against what was sent.** A short write succeeds as a ROP, so a caller that
    /// only checked the return value would report a truncated attachment as a saved one — the
    /// write-side twin of a read that stops at the first short answer.
    #[must_use]
    pub const fn written(self) -> u16 {
        self.written
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self { written: r.u16()? })
    }
}

/// Encodes a `RopOpenStream` request.
///
/// [MS-OXCROPS] §2.2.9.1.1 — request buffer
pub(crate) fn encode_open_stream(
    w: &mut Writer,
    input: u8,
    output: u8,
    tag: PropertyTag,
    mode: StreamMode,
) {
    w.u8(RopId::OPEN_STREAM.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(output)
        .u32(tag.as_u32())
        .u8(mode.flags());
}

/// Encodes a `RopWriteStream` request.
///
/// # Errors
///
/// [`Error::StreamWriteTooLarge`] for more bytes than one request's `DataSize` can describe.
/// Refused rather than split here: splitting is a decision about round trips, which belongs to the
/// caller, and a silently short write is what this module exists to avoid.
///
/// [MS-OXCROPS] §2.2.9.3.1 — request buffer
pub(crate) fn encode_write_stream(w: &mut Writer, input: u8, data: &[u8]) -> Result<()> {
    let size = u16::try_from(data.len()).map_err(|_| Error::StreamWriteTooLarge {
        wanted: data.len(),
        limit: MAX_WRITE,
    })?;

    w.u8(RopId::WRITE_STREAM.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u16(size)
        .bytes(data);
    Ok(())
}

/// Encodes a `RopCommitStream` request.
///
/// [MS-OXCROPS] §2.2.9.5.1 — request buffer
pub(crate) fn encode_commit_stream(w: &mut Writer, input: u8) {
    w.u8(RopId::COMMIT_STREAM.as_u8()).u8(LOGON_ID).u8(input);
}

/// Encodes a `RopReadStream` request.
///
/// `ByteCount` is sent plainly rather than through the `0xBABE` escape. The escape exists so that
/// `MaximumByteCount` can name more than 65,535 bytes, and a response cannot carry more than that
/// anyway — so all it would buy is a request that promises what the answer cannot keep.
///
/// # Errors
///
/// [`Error::StreamReadTooLarge`] for a request no single response could answer. Refused rather
/// than clamped: a short answer is how the end of a stream is reported, so silently reading less
/// than was asked for would be indistinguishable from reaching it.
///
/// [MS-OXCROPS] §2.2.9.2.1 — request buffer
pub(crate) fn encode_read_stream(w: &mut Writer, input: u8, bytes: usize) -> Result<()> {
    let wanted = u16::try_from(bytes).map_err(|_| Error::StreamReadTooLarge {
        wanted: bytes,
        limit: MAX_READ,
    })?;

    w.u8(RopId::READ_STREAM.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u16(wanted);
    Ok(())
}

/// Encodes a `RopGetStreamSize` request.
///
/// [MS-OXCROPS] §2.2.9.6.1 — request buffer
pub(crate) fn encode_get_stream_size(w: &mut Writer, input: u8) {
    w.u8(RopId::GET_STREAM_SIZE.as_u8()).u8(LOGON_ID).u8(input);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_requests_match_the_spec_layouts() {
        let mut w = Writer::new();
        encode_open_stream(&mut w, 1, 2, PropertyTag::BODY, StreamMode::ReadOnly);
        assert_eq!(
            w.finish(),
            vec![0x2B, 0x00, 0x01, 0x02, 0x1F, 0x00, 0x00, 0x10, 0x00]
        );

        let mut w = Writer::new();
        encode_open_stream(
            &mut w,
            1,
            2,
            PropertyTag::ATTACH_DATA_BINARY,
            StreamMode::Create,
        );
        assert_eq!(
            w.finish(),
            vec![0x2B, 0x00, 0x01, 0x02, 0x02, 0x01, 0x01, 0x37, 0x02]
        );

        let mut w = Writer::new();
        encode_write_stream(&mut w, 2, &[0xAA, 0xBB]).expect("a short write");
        assert_eq!(w.finish(), vec![0x2D, 0x00, 0x02, 0x02, 0x00, 0xAA, 0xBB]);

        let mut w = Writer::new();
        encode_commit_stream(&mut w, 2);
        assert_eq!(w.finish(), vec![0x5D, 0x00, 0x02]);

        let mut w = Writer::new();
        encode_read_stream(&mut w, 2, 0x4000).expect("within one response");
        assert_eq!(w.finish(), vec![0x2C, 0x00, 0x02, 0x00, 0x40]);

        let mut w = Writer::new();
        encode_get_stream_size(&mut w, 2);
        assert_eq!(w.finish(), vec![0x5E, 0x00, 0x02]);
    }

    /// The check that keeps "the stream ended" and "you asked for more than a response holds"
    /// apart, which on the wire look identical.
    #[test]
    fn a_read_larger_than_one_response_is_refused_rather_than_clamped() {
        let mut w = Writer::new();
        assert!(encode_read_stream(&mut w, 0, MAX_READ).is_ok());

        let mut w = Writer::new();
        assert!(matches!(
            encode_read_stream(&mut w, 0, MAX_READ + 1),
            Err(Error::StreamReadTooLarge {
                wanted: 0x0001_0000,
                limit: 0xFFFF
            })
        ));
        assert!(w.finish().is_empty(), "a refused encode must write nothing");
    }

    #[test]
    fn a_stream_read_carries_exactly_the_bytes_it_claimed() {
        let mut w = Writer::new();
        w.u16(3).bytes(&[0x01, 0x02, 0x03]).u8(0xEE);
        let buf = w.finish();

        let mut r = Reader::new(&buf);
        let response = ReadStreamResponse::read(&mut r).unwrap();
        assert_eq!(response.data(), &[0x01, 0x02, 0x03]);
        assert!(!response.is_end());
        assert_eq!(r.rest(), &[0xEE]);
        assert_eq!(response.into_data(), vec![0x01, 0x02, 0x03]);
    }

    /// A read past the end succeeds and answers with nothing. There is no flag for it, so a caller
    /// that waited for one would loop forever.
    #[test]
    fn an_empty_read_is_how_the_end_of_a_stream_is_reported() {
        let response = ReadStreamResponse::read(&mut Reader::new(&[0x00, 0x00])).unwrap();
        assert!(response.is_end());
        assert!(response.data().is_empty());
    }

    #[test]
    fn both_size_reporting_ropes_read_the_same_four_bytes() {
        for rop in [RopId::OPEN_STREAM, RopId::GET_STREAM_SIZE] {
            let response =
                StreamSizeResponse::read(&mut Reader::new(&[0x00, 0x10, 0x00, 0x00]), rop).unwrap();
            assert_eq!(response.size(), 0x1000);
            assert_eq!(response.rop(), rop);
        }
    }

    /// Only `Create` works on a property that has never been set, and only `Create` destroys one
    /// that has. Both facts live in the same byte.
    #[test]
    fn the_three_open_modes_are_the_three_the_document_lists() {
        assert_eq!(StreamMode::default(), StreamMode::ReadOnly);
        for (mode, flags, writable) in [
            (StreamMode::ReadOnly, 0x00, false),
            (StreamMode::ReadWrite, 0x01, true),
            (StreamMode::Create, 0x02, true),
        ] {
            assert_eq!(mode.flags(), flags, "{mode:?}");
            assert_eq!(mode.is_writable(), writable, "{mode:?}");
        }
    }

    /// A short write succeeds as a ROP, so this count is the only thing that says the value is not
    /// all there.
    #[test]
    fn a_write_reports_how_much_of_it_landed() {
        let response = WriteStreamResponse::read(&mut Reader::new(&[0x00, 0x40])).expect("a count");
        assert_eq!(response.written(), 0x4000);
    }

    #[test]
    fn a_write_larger_than_one_request_is_refused_rather_than_split() {
        let mut w = Writer::new();
        assert!(matches!(
            encode_write_stream(&mut w, 0, &vec![0_u8; MAX_WRITE + 1]),
            Err(Error::StreamWriteTooLarge {
                wanted: 0x0001_0000,
                limit: 0xFFFF
            })
        ));
        assert!(w.finish().is_empty(), "a refused encode must write nothing");
    }

    #[test]
    fn truncated_stream_responses_never_panic() {
        for buf in [&b""[..], &[0x01][..], &[0xFF, 0xFF][..], &[0x00, 0x01][..]] {
            let _ = ReadStreamResponse::read(&mut Reader::new(buf));
            let _ = StreamSizeResponse::read(&mut Reader::new(buf), RopId::OPEN_STREAM);
            let _ = WriteStreamResponse::read(&mut Reader::new(buf));
        }
    }
}
