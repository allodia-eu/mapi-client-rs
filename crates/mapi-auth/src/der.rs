//! Just enough DER to read and write a SPNEGO token.
//!
//! SPNEGO's tokens are ASN.1 DER ([RFC 4178] §4.2, encoded per [X690]), and so is the X.509
//! certificate a channel binding is computed over. Both need a handful of tags and definite-length
//! encoding and nothing else — no indefinite lengths, no BER, no schema — so this is a reader and
//! a writer rather than a dependency.
//!
//! Every read is bounds-checked and returns [`Error::MalformedToken`] carrying the offset it
//! stopped at, because the whole failure mode of a hand-rolled ASN.1 reader is walking off the end
//! of a buffer somebody else wrote.

use crate::error::{Error, Result};

/// `SEQUENCE`, constructed. [X690] §8.9
pub(crate) const SEQUENCE: u8 = 0x30;
/// `OBJECT IDENTIFIER`. [X690] §8.19
pub(crate) const OID: u8 = 0x06;
/// `OCTET STRING`. [X690] §8.7
pub(crate) const OCTET_STRING: u8 = 0x04;
/// `ENUMERATED`. [X690] §8.4
pub(crate) const ENUMERATED: u8 = 0x0A;

/// A context-specific constructed tag, `[n]`. [X690] §8.1.2.2
pub(crate) const fn context(n: u8) -> u8 {
    0xA0 | n
}

/// An application constructed tag, `[APPLICATION n]`. [X690] §8.1.2.2
pub(crate) const fn application(n: u8) -> u8 {
    0x60 | n
}

/// Walks a DER buffer one tag-length-value at a time.
#[derive(Clone, Debug)]
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    /// Where this reader's buffer starts within the token the caller was handed, so that an offset
    /// in an error points into that token rather than into some interior slice of it.
    base: usize,
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over a whole token.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            base: 0,
            pos: 0,
        }
    }

    /// Whether anything is left.
    pub(crate) const fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// Where the next element starts, counted from the outermost buffer.
    pub(crate) const fn offset(&self) -> usize {
        self.base.saturating_add(self.pos)
    }

    /// The next element's tag, without consuming it.
    pub(crate) fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Reads the next element, returning its tag and its contents.
    pub(crate) fn read(&mut self) -> Result<(u8, &'a [u8])> {
        let start = self.offset();
        let tag = *self.bytes.get(self.pos).ok_or(Error::MalformedToken {
            offset: start,
            reason: "a tag was expected and the buffer ended",
        })?;
        let (len, header) = self.read_length()?;

        let value_start = self.pos.saturating_add(header);
        let value_end = value_start.checked_add(len).ok_or(Error::MalformedToken {
            offset: start,
            reason: "a length that overflows a machine word",
        })?;
        let value = self
            .bytes
            .get(value_start..value_end)
            .ok_or(Error::MalformedToken {
                offset: start,
                reason: "a length that overruns the buffer",
            })?;

        self.pos = value_end;
        Ok((tag, value))
    }

    /// Reads the next element and insists it carries the expected tag.
    pub(crate) fn expect(&mut self, tag: u8, reason: &'static str) -> Result<&'a [u8]> {
        let offset = self.offset();
        let (found, value) = self.read()?;
        if found == tag {
            Ok(value)
        } else {
            Err(Error::MalformedToken { offset, reason })
        }
    }

    /// A reader over the contents of the next element, which must carry `tag`.
    pub(crate) fn expect_nested(&mut self, tag: u8, reason: &'static str) -> Result<Self> {
        let outer = self.offset();
        let (_, header) = self.read_length_at(outer)?;
        let value = self.expect(tag, reason)?;
        Ok(Self {
            bytes: value,
            base: outer.saturating_add(header),
            pos: 0,
        })
    }

    /// Decodes the length that follows the tag, returning it and the size of the header.
    ///
    /// Long form is accepted up to four length bytes, which is four gigabytes and therefore not a
    /// limit any real token meets. Indefinite length (`0x80`) is BER, not DER, and is refused.
    fn read_length(&self) -> Result<(usize, usize)> {
        self.read_length_at(self.offset())
    }

    /// [`Self::read_length`], reporting failures against a caller-chosen offset.
    fn read_length_at(&self, offset: usize) -> Result<(usize, usize)> {
        let short = usize::from(*self.bytes.get(self.pos.saturating_add(1)).ok_or(
            Error::MalformedToken {
                offset,
                reason: "a length was expected and the buffer ended",
            },
        )?);

        if short < 0x80 {
            return Ok((short, 2));
        }
        let count = short.saturating_sub(0x80);
        if count == 0 || count > 4 {
            return Err(Error::MalformedToken {
                offset,
                reason: "an indefinite or oversized length, which DER does not permit",
            });
        }

        let mut len = 0usize;
        for index in 0..count {
            let at = self.pos.saturating_add(2).saturating_add(index);
            let byte = *self.bytes.get(at).ok_or(Error::MalformedToken {
                offset,
                reason: "a long-form length that runs past the buffer",
            })?;
            len = len
                .checked_mul(0x100)
                .and_then(|shifted| shifted.checked_add(usize::from(byte)))
                .ok_or(Error::MalformedToken {
                    offset,
                    reason: "a length that overflows a machine word",
                })?;
        }
        Ok((len, count.saturating_add(2)))
    }
}

/// Wraps `value` in a tag-length-value.
pub(crate) fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len().saturating_add(6));
    out.push(tag);
    encode_length(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

/// Writes a definite length in the shortest form DER allows.
///
/// [X690] §10.1 requires the minimum number of octets, which is why this is not simply always the
/// four-byte form: a receiver that checks canonical encoding rejects the padded version.
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if let Ok(short) = u8::try_from(len)
        && short < 0x80
    {
        out.push(short);
        return;
    }

    let bytes = len.to_be_bytes();
    let significant = bytes.iter().position(|byte| *byte != 0).unwrap_or_default();
    let tail = bytes.get(significant..).unwrap_or_default();
    // `tail` is at most eight bytes, so the count always fits.
    let count = u8::try_from(tail.len()).unwrap_or(0x7F);
    out.push(0x80 | count);
    out.extend_from_slice(tail);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_element_round_trips() {
        let encoded = tlv(SEQUENCE, &[1, 2, 3]);
        assert_eq!(encoded, vec![0x30, 0x03, 1, 2, 3]);

        let mut reader = Reader::new(&encoded);
        let (tag, value) = reader.read().unwrap();
        assert_eq!(tag, SEQUENCE);
        assert_eq!(value, &[1, 2, 3]);
        assert!(reader.is_empty());
    }

    /// The boundary DER's shortest-form rule turns on, from both sides.
    #[test]
    fn lengths_are_written_in_the_shortest_form_and_read_back() {
        for len in [0usize, 1, 127, 128, 255, 256, 65_535, 65_536] {
            let body = vec![0xAB; len];
            let encoded = tlv(OCTET_STRING, &body);
            let mut reader = Reader::new(&encoded);
            let (tag, value) = reader.read().unwrap();
            assert_eq!(tag, OCTET_STRING);
            assert_eq!(value.len(), len, "{len}");
        }

        assert_eq!(tlv(OCTET_STRING, &[0; 127])[1], 0x7F);
        assert_eq!(tlv(OCTET_STRING, &[0; 128])[1..3], [0x81, 0x80]);
        assert_eq!(tlv(OCTET_STRING, &[0; 256])[1..4], [0x82, 0x01, 0x00]);
    }

    #[test]
    fn a_nested_reader_reports_offsets_from_the_outer_buffer() {
        let inner = [tlv(OID, &[0x2B]), tlv(OCTET_STRING, &[9])].concat();
        let outer = tlv(SEQUENCE, &inner);

        let mut reader = Reader::new(&outer);
        let mut nested = reader.expect_nested(SEQUENCE, "a sequence").unwrap();
        assert_eq!(nested.offset(), 2);
        assert_eq!(nested.expect(OID, "an oid").unwrap(), &[0x2B]);
        assert_eq!(nested.offset(), 5);
        assert_eq!(nested.peek_tag(), Some(OCTET_STRING));
    }

    /// Every way a hostile buffer can try to walk the reader off the end.
    #[test]
    fn a_malformed_buffer_is_refused_with_the_offset_it_failed_at() {
        for bytes in [
            vec![],                          // no tag
            vec![0x30],                      // no length
            vec![0x30, 0x05, 1, 2],          // a length past the end
            vec![0x30, 0x80],                // indefinite length: BER, not DER
            vec![0x30, 0x85, 1, 1, 1, 1, 1], // more length bytes than DER permits
            vec![0x30, 0x82, 0x01],          // a long form that is itself truncated
        ] {
            let error = Reader::new(&bytes).read().unwrap_err();
            assert!(
                matches!(error, Error::MalformedToken { offset: 0, .. }),
                "{bytes:?} gave {error}"
            );
        }
    }

    #[test]
    fn the_wrong_tag_is_reported_rather_than_read() {
        let encoded = tlv(OCTET_STRING, &[1]);
        let error = Reader::new(&encoded)
            .expect(SEQUENCE, "a sequence")
            .unwrap_err();
        assert!(matches!(
            error,
            Error::MalformedToken {
                reason: "a sequence",
                ..
            }
        ));

        let error = Reader::new(&encoded)
            .expect_nested(SEQUENCE, "a sequence")
            .unwrap_err();
        assert!(matches!(
            error,
            Error::MalformedToken {
                reason: "a sequence",
                ..
            }
        ));
    }

    #[test]
    fn the_tag_helpers_match_the_encoding_rules() {
        assert_eq!(context(0), 0xA0);
        assert_eq!(context(3), 0xA3);
        assert_eq!(application(0), 0x60);
        assert_eq!(ENUMERATED, 0x0A);
    }
}
