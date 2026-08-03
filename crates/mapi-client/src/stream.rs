//! Reading a property that does not fit in a response buffer.
//!
//! **The reason this exists rather than a bigger property fetch.** [MS-OXCPRPT] §2.2.3.2 has a
//! value too large for the response buffer come back as `NotEnoughMemory` instead of as a value.
//! Any real HTML body clears that bar, so `RopGetPropertiesSpecific` answers a short message with
//! text and a long one with an error — a body reader built on it works in testing and fails on the
//! first message anybody actually wrote.
//!
//! The read is deliberately **not** bounded by the size the open reported. A stream has no
//! end-of-stream flag: a read past the last byte succeeds and returns nothing, and that is the only
//! signal there is. Trusting the reported size instead would truncate a property somebody else
//! extended between the open and the read, which is the same silent data loss one layer up.
//!
//! [MS-OXCROPS] §2.2.9 — the stream ROPs
//! [MS-OXCPRPT] §2.2.14 — semantics

use mapi_proto::{
    ObjectHandle, PropertyTag, PropertyType, ReadStreamResponse, RopBatch, RopResponse,
};

use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::target::Target;

/// Bytes per `RopReadStream`.
///
/// `DataSize` is two bytes, so 65,535 is the ceiling the protocol imposes. **The server has a
/// lower one that no document states and that `MaxRopOut` cannot raise**, which is why this is
/// 16 KiB rather than the largest read that would fit.
///
/// Measured on Exchange Server SE `15.02.2562.045`, against one message whose opening batch adds 99
/// bytes of other responses to the read:
///
/// * `MaxRopOut` is honoured directly below the ceiling — a 21,099-byte output buffer succeeds at
///   `MaxRopOut` 40,000, and a 24,675-byte one is refused at 20,000 and succeeds at 65,536.
/// * The ceiling is about 32 KiB and `MaxRopOut` does not move it. At 65,536 a read of **32,662**
///   bytes succeeds and 32,663 does not; **32,663 is refused identically at `0x00040000`**, the
///   maximum [MS-OXCRPC] §3.1.4.2 allows. So the effective size is `min(MaxRopOut, ~32 KiB)`.
/// * Every refusal reports a `SizeNeeded` of 32,767, whatever was asked for and whatever
///   `MaxRopOut` was — including where the sizes actually required differ by eight kilobytes.
///
/// **[MS-OXCROPS] §3.1.5.1.2's remedy therefore cannot be applied**: it has the client resend with
/// the buffer at least `SizeNeeded`, and 65,536 already exceeds 32,767. Asking for fewer bytes is
/// the only way out, so this crate never asks for that many.
///
/// The few bytes between 32,662 and a round 32 KiB are **not** evidence of anything — a server may
/// reserve space, and [MS-OXCROPS] §3.1.5.1.3 appends `RopNotify` and `RopPending` responses to the
/// end of this very buffer. What is evidence is the probe at the documented maximum, which changes
/// nothing.
///
/// 16 KiB rather than the measured 32,662 because the read shares one response buffer with the rest
/// of its batch, and the rest is not fixed: the same chunk that succeeds behind a `RopOpenMessage`
/// is refused behind the `RopOpenMessage` + `RopOpenAttachment` + `RopOpenStream` chain an
/// attachment needs, and a `RopOpenMessage` response grows with the message's recipient count.
///
/// [MS-OXCROPS] §2.2.9.2.2 — `DataSize`
/// [MS-OXCROPS] §3.1.5.1.2 — processing `RopBufferTooSmall`
const CHUNK: usize = 16 * 1024;

/// How many reads one value may take before the loop is called broken.
///
/// A server that answered every read with one byte would otherwise spin forever. At `CHUNK` bytes
/// a piece this allows a value of 32 MiB, which is past any property this client asks for.
const MAX_READS: usize = 2048;

/// A property to read whole, however long it is.
///
/// Nothing is sent until [`read`](Self::read) is called.
#[derive(Debug)]
pub struct StreamRead<'a> {
    connection: &'a mut Connection,
    target: Target,
    tag: PropertyTag,
}

impl<'a> StreamRead<'a> {
    pub(crate) fn new(connection: &'a mut Connection, target: Target, tag: PropertyTag) -> Self {
        Self {
            connection,
            target,
            tag,
        }
    }

    /// The property being read.
    #[must_use]
    pub const fn tag(&self) -> PropertyTag {
        self.tag
    }

    /// Reads the property to its end.
    ///
    /// One round trip opens the object chain and the stream and reads the first chunk; each further
    /// chunk is one more. A property that fits in 32 KiB — which is most of them — therefore costs
    /// exactly one.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused any step. `NotFound` from the open means the object
    /// does not hold that property at all, which for `PidTagAttachDataBinary` on an
    /// `afEmbeddedMessage` attachment is the expected answer rather than a fault.
    ///
    /// [`Error::Unexpected`] if the server keeps answering with data past the read limit, which is
    /// 2,048 chunks — 32 MiB, past any property this client asks for.
    pub async fn read(self) -> Result<StreamValue> {
        let Self {
            connection,
            target,
            tag,
        } = self;

        let mut batch = RopBatch::new();
        let opened = target.open(&mut batch);
        let stream = batch.open_stream(opened.slot, tag);
        batch.read_stream(stream, CHUNK);
        opened.release(&mut batch);

        let execution = connection
            .execute(batch, "opening a property stream")
            .await?;
        let reported = execution
            .responses()
            .iter()
            .find_map(RopResponse::as_stream_size)
            .map(mapi_proto::StreamSizeResponse::size);
        let handle = execution.handle(stream).filter(|h| !h.is_none());

        let mut bytes = first_chunk(&execution);
        let complete = read_rest(connection, handle, &mut bytes).await?;
        release(connection, handle).await;

        Ok(StreamValue {
            tag,
            bytes,
            reported,
            complete,
        })
    }
}

/// Takes the bytes the opening batch already returned.
fn first_chunk(execution: &mapi_proto::Execution) -> Vec<u8> {
    execution
        .responses()
        .iter()
        .find_map(RopResponse::as_stream_data)
        .map(ReadStreamResponse::data)
        .unwrap_or_default()
        .to_vec()
}

/// Keeps reading until the server answers with nothing, which is how a stream ends.
///
/// Reports whether it got there, rather than pretending: hitting the read limit means the value in
/// hand is a prefix, and a caller told it was the whole thing would index a truncated body.
async fn read_rest(
    connection: &mut Connection,
    handle: Option<ObjectHandle>,
    bytes: &mut Vec<u8>,
) -> Result<bool> {
    let Some(handle) = handle else {
        // No stream handle means the open failed, which `execute` has already reported as an
        // error — so this is only reachable for a server that succeeded and produced no handle.
        return Ok(true);
    };

    // The first chunk came back short of what was asked for, so the stream is already exhausted.
    if bytes.len() < CHUNK {
        return Ok(true);
    }

    for _ in 0..MAX_READS {
        let mut batch = RopBatch::new();
        let stream = batch.bind(handle);
        batch.read_stream(stream, CHUNK);

        let execution = connection
            .execute(batch, "reading a property stream")
            .await?;
        let Some(chunk) = execution
            .responses()
            .iter()
            .find_map(RopResponse::as_stream_data)
        else {
            return Ok(true);
        };

        let length = chunk.data().len();
        bytes.extend_from_slice(chunk.data());
        if length < CHUNK {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Gives the stream handle back, ignoring whether the server minded.
///
/// A failure here is not worth reporting over a value that was read successfully: the Session
/// Context times the handle out on its own.
async fn release(connection: &mut Connection, handle: Option<ObjectHandle>) {
    let Some(handle) = handle else { return };
    let mut batch = RopBatch::new();
    let slot = batch.bind(handle);
    batch.release(slot);
    let _ = connection.execute(batch, "releasing a stream").await;
}

/// A property read whole, and what is known about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamValue {
    tag: PropertyTag,
    bytes: Vec<u8>,
    reported: Option<u32>,
    complete: bool,
}

impl StreamValue {
    /// The property this is.
    #[must_use]
    pub const fn tag(&self) -> PropertyTag {
        self.tag
    }

    /// The bytes, as they came off the wire.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How many bytes arrived.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the property held nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// How long the server said the stream was when it was opened.
    ///
    /// A measurement, not a promise. It is worth comparing against [`len`](Self::len) — the two
    /// disagreeing means the property changed under the read — but the read stops when the server
    /// answers with nothing, never at this number.
    #[must_use]
    pub const fn reported_size(&self) -> Option<u32> {
        self.reported
    }

    /// Whether the read reached the end of the stream.
    ///
    /// `false` only when the read limit was hit first, which means these bytes are a prefix.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Takes the bytes out.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The value as text, if the property is one whose bytes are characters.
    ///
    /// Decoded by the **tag's own type**, because a stream carries no encoding of its own:
    /// `PtypString` is UTF-16LE and `PtypString8` is the session's code page, which this crate does
    /// not track — so the second is decoded as Latin-1 and said so here rather than guessed at
    /// silently. `PidTagHtml` is `PtypBinary` and is deliberately **not** decoded: its character
    /// set is named by `PidTagInternetCodepage`, which is a different property.
    ///
    /// # Errors
    ///
    /// [`Error::Unexpected`] if the tag is not a string type, or if a `PtypString` value did not
    /// decode as UTF-16 — an odd byte count, or an unpaired surrogate.
    ///
    /// [MS-OXCDATA] §2.11.1 — `PtypString`, `PtypString8`
    pub fn text(&self) -> Result<String> {
        match self.tag.property_type() {
            PropertyType::String => decode_utf16(&self.bytes),
            // Latin-1 is the identity mapping from bytes to codepoints. It is right for the
            // Windows-1252 lab and wrong for a code page that is not, which is why this is
            // documented rather than presented as a decode.
            PropertyType::String8 => Ok(self.bytes.iter().copied().map(char::from).collect()),
            _ => Err(Error::Unexpected {
                expected: "a string property",
                found: "a property whose type is not PtypString or PtypString8",
            }),
        }
    }
}

/// Decodes UTF-16LE, dropping the terminator the server may or may not have included.
fn decode_utf16(bytes: &[u8]) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Unexpected {
            expected: "a PtypString value, which is UTF-16LE",
            found: "an odd number of bytes, which cannot be UTF-16",
        });
    }

    let mut units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            u16::from_le_bytes([
                pair.first().copied().unwrap_or(0),
                pair.get(1).copied().unwrap_or(0),
            ])
        })
        .collect();
    // A streamed string may or may not carry its terminator; a trailing NUL in the text would be
    // a surprise in a subject line either way.
    while units.last() == Some(&0) {
        units.pop();
    }

    String::from_utf16(&units).map_err(|_| Error::Unexpected {
        expected: "a PtypString value, which is UTF-16LE",
        found: "an unpaired surrogate",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(tag: PropertyTag, bytes: Vec<u8>) -> StreamValue {
        StreamValue {
            tag,
            bytes,
            reported: None,
            complete: true,
        }
    }

    /// The chunk size has to stay under two limits, only one of which is in the specification: the
    /// two-byte `DataSize` field, and the 32,767-byte output buffer the lab server enforces
    /// whatever `MaxRopOut` asks for.
    #[test]
    fn the_chunk_size_stays_under_both_limits() {
        const { assert!(CHUNK <= 0xFFFF, "DataSize is two bytes") }
        const {
            assert!(
                CHUNK <= 32_662,
                "32,662 bytes is the largest read measured to succeed, behind the shortest chain \
                 that reaches a message — and the rest of the batch shares the same buffer"
            );
        }
    }

    #[test]
    fn a_string_property_decodes_as_utf16() {
        let mut bytes: Vec<u8> = "caf\u{E9}"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let text = value(PropertyTag::BODY, bytes.clone());
        assert_eq!(text.text().expect("valid UTF-16"), "caf\u{E9}");

        // With the terminator the server may include.
        bytes.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            value(PropertyTag::BODY, bytes)
                .text()
                .expect("valid UTF-16"),
            "caf\u{E9}"
        );
    }

    /// `PidTagHtml` is `PtypBinary` and carries its own character set in another property, so
    /// handing back a `String` for it would be a guess wearing a decode's clothes.
    #[test]
    fn a_binary_property_refuses_to_pretend_it_is_text() {
        let html = value(PropertyTag::BODY_HTML, b"<html/>".to_vec());
        assert!(html.text().is_err());
        assert_eq!(html.as_bytes(), b"<html/>");
        assert_eq!(html.len(), 7);
        assert!(!html.is_empty());
        assert_eq!(html.tag(), PropertyTag::BODY_HTML);
    }

    #[test]
    fn a_truncated_or_invalid_utf16_value_is_reported_rather_than_patched() {
        assert!(value(PropertyTag::BODY, vec![0x41]).text().is_err());
        // A lone high surrogate.
        assert!(value(PropertyTag::BODY, vec![0x00, 0xD8]).text().is_err());
    }

    /// `PtypString8`'s code page is the session's, which this crate never negotiates — so the
    /// mapping is stated rather than inferred.
    #[test]
    fn an_eight_bit_string_maps_each_byte_to_a_codepoint() {
        let tag = PropertyTag::BODY.with_type(PropertyType::String8);
        assert_eq!(
            value(tag, vec![b'c', b'a', b'f', 0xE9])
                .text()
                .expect("bytes"),
            "caf\u{E9}"
        );
    }

    #[test]
    fn an_empty_value_says_so() {
        let empty = value(PropertyTag::BODY, Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.is_complete());
        assert_eq!(empty.reported_size(), None);
        assert!(empty.into_bytes().is_empty());
    }
}
