//! The first two of the three NTLM messages: what the client opens with, and what comes back.
//!
//! [MS-NLMP] §2.2.1.1 — `NEGOTIATE_MESSAGE`
//! [MS-NLMP] §2.2.1.2 — `CHALLENGE_MESSAGE`

use crate::error::{Error, Result};
use crate::ntlm::avpair::AvPairs;
use crate::ntlm::flags::NegotiateFlags;

/// The eight bytes every NTLM message opens with.
///
/// [MS-NLMP] §2.2.1.1 — `Signature`
pub(crate) const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// `MessageType` for the `NEGOTIATE_MESSAGE`.
pub(crate) const TYPE_NEGOTIATE: u32 = 1;
/// `MessageType` for the `CHALLENGE_MESSAGE`.
pub(crate) const TYPE_CHALLENGE: u32 = 2;
/// `MessageType` for the `AUTHENTICATE_MESSAGE`.
pub(crate) const TYPE_AUTHENTICATE: u32 = 3;

/// Fixed size of a `NEGOTIATE_MESSAGE` before its payload: signature, type, flags, two field
/// triples and the version.
const NEGOTIATE_HEADER: usize = 40;

/// The `NEGOTIATE_MESSAGE`, which carries no secret and depends on nothing the server has said.
///
/// Neither `DomainName` nor `WorkstationName` is supplied. [MS-NLMP] §2.2.1.1 only permits them
/// alongside `NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED` and its workstation counterpart, both of which
/// mean the OEM character set; and the values are advisory — the domain that matters is the one in
/// the `AUTHENTICATE_MESSAGE`, where it is an input to the response key. So the fields are the
/// empty form the same section defines, with offsets pointing at where the payload would begin.
pub(crate) fn negotiate(flags: NegotiateFlags) -> Vec<u8> {
    let mut out = Vec::with_capacity(NEGOTIATE_HEADER);
    out.extend_from_slice(SIGNATURE);
    out.extend_from_slice(&TYPE_NEGOTIATE.to_le_bytes());
    out.extend_from_slice(&flags.bits().to_le_bytes());
    // DomainNameFields and WorkstationFields: zero lengths, and the offset the payload would be
    // at, which is what §2.2.1.1 says an absent field SHOULD carry.
    for _ in 0..2 {
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        let offset = u32::try_from(NEGOTIATE_HEADER).unwrap_or(u32::MAX);
        out.extend_from_slice(&offset.to_le_bytes());
    }
    // Version, all zero because NTLMSSP_NEGOTIATE_VERSION is not requested.
    out.extend_from_slice(&[0u8; 8]);
    out
}

/// What a server answered a `NEGOTIATE_MESSAGE` with.
#[derive(Clone, Debug)]
pub(crate) struct ChallengeMessage {
    /// The flags the server settled on.
    pub(crate) flags: NegotiateFlags,
    /// The eight bytes the response is computed against.
    pub(crate) server_challenge: [u8; 8],
    /// `TargetInfo`, parsed. Empty when the server sent none.
    pub(crate) target_info: AvPairs,
    /// The message exactly as it arrived.
    ///
    /// Kept because the MIC is `HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE ||
    /// AUTHENTICATE)` ([MS-NLMP] §3.1.5.1.2) — over the bytes, not over a re-encoding of them, so
    /// a challenge that round-tripped imperfectly would produce a MIC the server disagrees with.
    pub(crate) raw: Vec<u8>,
}

impl ChallengeMessage {
    /// Reads a `CHALLENGE_MESSAGE`.
    ///
    /// # Errors
    ///
    /// [`Error::NotAChallenge`] if the signature or the message type is not a challenge's, and
    /// [`Error::Truncated`] if any field runs past the end of the buffer.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let signature = bytes.get(0..8).ok_or(Error::Truncated {
            structure: "CHALLENGE_MESSAGE",
            field: "Signature",
            offset: 0,
            len: bytes.len(),
        })?;
        if signature != SIGNATURE {
            return Err(Error::NotAChallenge {
                expected: "the signature NTLMSSP",
                found: format!("{signature:02X?}"),
            });
        }

        let message_type = read_u32(bytes, 8).ok_or(Error::Truncated {
            structure: "CHALLENGE_MESSAGE",
            field: "MessageType",
            offset: 8,
            len: bytes.len(),
        })?;
        if message_type != TYPE_CHALLENGE {
            return Err(Error::NotAChallenge {
                expected: "message type 2",
                found: format!("message type {message_type}"),
            });
        }

        let flags = NegotiateFlags::from_bits(read_u32(bytes, 20).ok_or(Error::Truncated {
            structure: "CHALLENGE_MESSAGE",
            field: "NegotiateFlags",
            offset: 20,
            len: bytes.len(),
        })?);

        let mut server_challenge = [0u8; 8];
        let source = bytes.get(24..32).ok_or(Error::Truncated {
            structure: "CHALLENGE_MESSAGE",
            field: "ServerChallenge",
            offset: 24,
            len: bytes.len(),
        })?;
        server_challenge.copy_from_slice(source);

        // TargetInfo is only present when the server says so. Its absence is not an error here —
        // it is what makes an NTLM v2 response impossible, which is decided one layer up where the
        // reason can be reported in terms of the credential rather than of a field.
        let target_info = if flags.contains(NegotiateFlags::TARGET_INFO) {
            AvPairs::parse(read_field(bytes, 40, "TargetInfo")?)?
        } else {
            AvPairs::default()
        };

        Ok(Self {
            flags,
            server_challenge,
            target_info,
            raw: bytes.to_vec(),
        })
    }
}

/// Reads the payload a `len`/`maxlen`/`offset` triple at `at` points to.
///
/// [MS-NLMP] §2.2.1.2 — every variable-length field is described by one of these
fn read_field<'a>(bytes: &'a [u8], at: usize, field: &'static str) -> Result<&'a [u8]> {
    let truncated = |offset: usize| Error::Truncated {
        structure: "CHALLENGE_MESSAGE",
        field,
        offset,
        len: bytes.len(),
    };

    let len = usize::from(read_u16(bytes, at).ok_or_else(|| truncated(at))?);
    let offset =
        usize::try_from(read_u32(bytes, at.saturating_add(4)).ok_or_else(|| truncated(at))?)
            .map_err(|_| truncated(at))?;

    bytes
        .get(offset..offset.saturating_add(len))
        .ok_or_else(|| truncated(offset))
}

/// A little-endian `u16` at a byte offset, or `None` if it does not fit.
pub(crate) fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at.saturating_add(2))?;
    Some(u16::from_le_bytes([*slice.first()?, *slice.get(1)?]))
}

/// A little-endian `u32` at a byte offset, or `None` if it does not fit.
pub(crate) fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at.saturating_add(4))?;
    Some(u32::from_le_bytes([
        *slice.first()?,
        *slice.get(1)?,
        *slice.get(2)?,
        *slice.get(3)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntlm::avpair;
    use crate::ntlm::fixtures::documented_challenge;

    #[test]
    fn a_negotiate_message_is_a_forty_byte_header_and_nothing_else() {
        let bytes = negotiate(NegotiateFlags::REQUESTED);
        assert_eq!(bytes.len(), NEGOTIATE_HEADER);
        assert_eq!(bytes.get(0..8), Some(&SIGNATURE[..]));
        assert_eq!(read_u32(&bytes, 8), Some(TYPE_NEGOTIATE));
        assert_eq!(read_u32(&bytes, 12), Some(0x0088_8205));

        // Both absent-field triples: zero lengths, and the offset the payload would start at.
        for at in [16usize, 24] {
            assert_eq!(read_u16(&bytes, at), Some(0));
            assert_eq!(read_u16(&bytes, at + 2), Some(0));
            assert_eq!(read_u32(&bytes, at + 4), Some(40));
        }
        // Version is zero because NTLMSSP_NEGOTIATE_VERSION was not requested.
        assert_eq!(bytes.get(32..40), Some(&[0u8; 8][..]));
    }

    #[test]
    fn the_documented_challenge_parses_into_its_documented_parts() {
        let bytes = documented_challenge();
        let challenge = ChallengeMessage::parse(&bytes).unwrap();

        assert_eq!(challenge.flags.bits(), 0xE28A_8233);
        assert_eq!(
            challenge.server_challenge,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        );
        assert_eq!(
            challenge.target_info.get(avpair::NB_DOMAIN_NAME),
            Some(&b"D\0o\0m\0a\0i\0n\0"[..])
        );
        assert_eq!(
            challenge.target_info.get(avpair::NB_COMPUTER_NAME),
            Some(&b"S\0e\0r\0v\0e\0r\0"[..])
        );
        // The raw bytes are kept because the MIC covers them rather than a re-encoding.
        assert_eq!(challenge.raw, bytes);
    }

    #[test]
    fn a_challenge_without_target_info_parses_with_an_empty_list() {
        let mut bytes = documented_challenge();
        // Clear NTLMSSP_NEGOTIATE_TARGET_INFO, leaving the field triple in place.
        let cleared = 0xE28A_8233u32 & !NegotiateFlags::TARGET_INFO.bits();
        bytes.splice(20..24, cleared.to_le_bytes());

        let challenge = ChallengeMessage::parse(&bytes).unwrap();
        assert_eq!(challenge.target_info, AvPairs::default());
    }

    #[test]
    fn something_that_is_not_a_challenge_says_so_rather_than_being_read() {
        let error = ChallengeMessage::parse(b"HTTP/1.1 401 Unauthorized").unwrap_err();
        assert!(matches!(
            error,
            Error::NotAChallenge {
                expected: "the signature NTLMSSP",
                ..
            }
        ));

        // A well-signed message of the wrong type: what a server that restarted looks like.
        let mut negotiate_bytes = negotiate(NegotiateFlags::REQUESTED);
        negotiate_bytes.splice(8..12, TYPE_NEGOTIATE.to_le_bytes());
        let error = ChallengeMessage::parse(&negotiate_bytes).unwrap_err();
        assert!(matches!(
            error,
            Error::NotAChallenge {
                expected: "message type 2",
                ..
            }
        ));
    }

    #[test]
    fn every_field_that_can_run_off_the_end_is_reported_by_name() {
        let full = documented_challenge();

        for (truncate_to, field) in [
            (4usize, "Signature"),
            (10, "MessageType"),
            (22, "NegotiateFlags"),
            (28, "ServerChallenge"),
            (44, "TargetInfo"),
        ] {
            let error = ChallengeMessage::parse(full.get(..truncate_to).unwrap()).unwrap_err();
            assert!(
                matches!(error, Error::Truncated { field: found, .. } if found == field),
                "truncating to {truncate_to} gave {error}"
            );
        }

        // A field triple whose offset points past the end, with the header itself intact.
        let mut wild = full.clone();
        wild.splice(44..48, 0xFFFF_FF00u32.to_le_bytes());
        assert!(matches!(
            ChallengeMessage::parse(&wild).unwrap_err(),
            Error::Truncated {
                field: "TargetInfo",
                ..
            }
        ));
    }

    #[test]
    fn the_little_endian_readers_stop_at_the_end_of_the_buffer() {
        assert_eq!(read_u16(&[0x34, 0x12], 0), Some(0x1234));
        assert_eq!(read_u16(&[0x34], 0), None);
        assert_eq!(read_u32(&[0x78, 0x56, 0x34, 0x12], 0), Some(0x1234_5678));
        assert_eq!(read_u32(&[0x78, 0x56, 0x34], 0), None);
        assert_eq!(read_u32(&[], usize::MAX), None);
    }
}
