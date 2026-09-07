//! SPNEGO: the wrapper that turns NTLM messages into `Negotiate` tokens.
//!
//! `Negotiate` is not a mechanism. It is a negotiation *about* mechanisms ([RFC 4178], extended by
//! [MS-SPNG]), and what travels inside it here is the same three NTLM messages the [`ntlm`](crate)
//! module builds. That is the whole reason this crate can offer both HTTP schemes: one mechanism,
//! two envelopes.
//!
//! # Only one mechanism is offered, and it is not Kerberos
//!
//! The `mechTypes` list this sends has exactly one entry, `1.3.6.1.4.1.311.2.2.10` ([MS-NLMP]
//! §1.9). A server that would rather use Kerberos is told that Kerberos is not on offer and picks
//! NTLM, which is precisely what SPNEGO is for.
//!
//! Kerberos is absent because it is a different project, not a bigger version of this one: it needs
//! a KDC round trip, a credential cache to read tickets out of, clock skew handling and a great
//! deal of ASN.1 that has nothing to do with NTLM. Offering it badly would be worse than not
//! offering it, because a client that advertises Kerberos and cannot complete it turns a working
//! deployment into a failing one.
//!
//! What this *does* buy is a server with `Negotiate` enabled and `NTLM` switched off — the shape a
//! hardened IIS is usually left in — which the raw `NTLM` scheme cannot talk to at all.
//!
//! # No `mechListMIC`
//!
//! [RFC 4178] §5 requires the `mechListMIC` exchange when the mechanism the server selects is not
//! the initiator's preferred one. With a single-entry list there is no other mechanism to select,
//! so the case cannot arise and the token is not sent. A server that asks for one anyway is
//! reported rather than guessed at.

use crate::der::{self, Reader};
use crate::error::{Error, Result};

/// `iso.org.dod.internet.security.mechanism.snego` — [MS-SPNG] §1.9.1
const SPNEGO_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];

/// `1.3.6.1.4.1.311.2.2.10`, the NTLM mechanism — [MS-NLMP] §1.9
const NTLM_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];

/// `1.2.840.113554.1.2.2`, Kerberos V5 — [RFC 4121] §4.1
const KERBEROS_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];

/// `1.2.840.48018.1.2.2`, the Kerberos OID Microsoft shipped by mistake and still accepts.
const KERBEROS_LEGACY_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02];

/// `negState` — [RFC 4178] §4.2.2
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NegState {
    /// The negotiation finished and the context is established.
    AcceptCompleted,
    /// More tokens are expected.
    AcceptIncomplete,
    /// The server refused.
    Reject,
    /// The server wants a `mechListMIC`, which this crate does not produce.
    RequestMic,
}

impl NegState {
    /// Reads the `ENUMERATED`, treating anything unrecognised as "keep going".
    ///
    /// The values are 0 through 3, and a server sending a fourth would be describing a state this
    /// crate has no reaction to. Continuing is the reaction that lets the exchange be judged by
    /// what actually comes back rather than by a number.
    fn from_bytes(value: &[u8]) -> Self {
        match value.first() {
            Some(0) => Self::AcceptCompleted,
            Some(2) => Self::Reject,
            Some(3) => Self::RequestMic,
            _ => Self::AcceptIncomplete,
        }
    }
}

/// What a server's SPNEGO token said.
#[derive(Clone, Debug, Default)]
pub(crate) struct ServerToken {
    /// The state, when the server gave one. [RFC 4178] §4.2.2 makes it optional.
    pub(crate) state: Option<NegState>,
    /// The mechanism the server selected, by OID.
    pub(crate) supported_mech: Option<Vec<u8>>,
    /// The inner mechanism token — an NTLM `CHALLENGE_MESSAGE`, when there is one.
    pub(crate) response_token: Option<Vec<u8>>,
}

/// The first token: a `NegTokenInit` inside a GSS-API `InitialContextToken`.
///
/// [RFC 2743] §3.1 requires the outer `[APPLICATION 0]` wrapper naming SPNEGO on the *first* token
/// of a context and forbids it on the rest, which is why the second token is built by
/// [`response_token`] and looks nothing like this one.
pub(crate) fn init_token(mech_token: &[u8]) -> Vec<u8> {
    let mech_types = der::tlv(der::SEQUENCE, &der::tlv(der::OID, NTLM_OID));
    let mut inner = der::tlv(der::context(0), &mech_types);
    inner.extend_from_slice(&der::tlv(
        der::context(2),
        &der::tlv(der::OCTET_STRING, mech_token),
    ));

    let neg_token_init = der::tlv(der::context(0), &der::tlv(der::SEQUENCE, &inner));

    let mut body = der::tlv(der::OID, SPNEGO_OID);
    body.extend_from_slice(&neg_token_init);
    der::tlv(der::application(0), &body)
}

/// A continuation token: a bare `NegTokenResp` carrying one mechanism token.
///
/// `negState` is omitted. [RFC 4178] §4.2.2 makes every field optional, and the state of a
/// negotiation with one mechanism in it is not something the initiator has anything to add to.
pub(crate) fn response_token(mech_token: &[u8]) -> Vec<u8> {
    let response = der::tlv(der::context(2), &der::tlv(der::OCTET_STRING, mech_token));
    der::tlv(der::context(1), &der::tlv(der::SEQUENCE, &response))
}

/// Reads whichever of the two token shapes a server sent.
///
/// A server answering a `NegTokenInit` sends a `NegTokenResp`; one that speaks first — [MS-SPNG]
/// §3.2.5.2's server-initiated variation — sends a `NegTokenInit2` in the application wrapper.
/// Both are accepted, because an HTTP server that has been asked for a scheme it also advertises
/// may do either.
///
/// # Errors
///
/// [`Error::MalformedToken`] if the DER does not parse or is not a negotiation token, and
/// [`Error::UnsupportedMechanism`] if the server selected something other than NTLM.
pub(crate) fn parse(bytes: &[u8]) -> Result<ServerToken> {
    let mut outer = Reader::new(bytes);
    let tag = outer.peek_tag().ok_or(Error::MalformedToken {
        offset: 0,
        reason: "an empty token",
    })?;

    let mut fields = if tag == der::application(0) {
        // [APPLICATION 0] { OID, NegotiationToken }
        let mut wrapper = outer.expect_nested(der::application(0), "a GSS-API context token")?;
        let oid = wrapper.expect(der::OID, "the mechanism OID of a GSS-API context token")?;
        if oid != SPNEGO_OID {
            return Err(Error::UnsupportedMechanism {
                mechanism: name_of(oid),
            });
        }
        negotiation_token(&mut wrapper)?
    } else {
        negotiation_token(&mut outer)?
    };

    let mut token = ServerToken::default();
    while !fields.is_empty() {
        let offset = fields.offset();
        let (tag, value) = fields.read()?;
        let mut inner = Reader::new(value);
        match tag {
            tag if tag == der::context(0) => {
                // In a NegTokenResp this is negState; in a NegTokenInit2 it is mechTypes, which
                // this crate has nothing to decide about and ignores.
                if inner.peek_tag() == Some(der::ENUMERATED) {
                    let state = inner.expect(der::ENUMERATED, "a negState")?;
                    token.state = Some(NegState::from_bytes(state));
                }
            }
            tag if tag == der::context(1) => {
                if inner.peek_tag() == Some(der::OID) {
                    token.supported_mech =
                        Some(inner.expect(der::OID, "a supportedMech")?.to_vec());
                }
            }
            tag if tag == der::context(2) => {
                token.response_token =
                    Some(inner.expect(der::OCTET_STRING, "a responseToken")?.to_vec());
            }
            // reqFlags, negHints, mechListMIC: nothing here acts on them.
            _ => {
                let _ = offset;
            }
        }
    }

    if let Some(mech) = &token.supported_mech
        && mech.as_slice() != NTLM_OID
    {
        return Err(Error::UnsupportedMechanism {
            mechanism: name_of(mech),
        });
    }
    Ok(token)
}

/// Unwraps the `NegotiationToken` CHOICE, whichever alternative it is.
fn negotiation_token<'a>(reader: &mut Reader<'a>) -> Result<Reader<'a>> {
    let offset = reader.offset();
    let tag = reader.peek_tag().ok_or(Error::MalformedToken {
        offset,
        reason: "a negotiation token was expected and the buffer ended",
    })?;
    if tag != der::context(0) && tag != der::context(1) {
        return Err(Error::MalformedToken {
            offset,
            reason: "neither a negTokenInit nor a negTokenResp",
        });
    }
    let mut choice = reader.expect_nested(tag, "a negotiation token")?;
    choice.expect_nested(der::SEQUENCE, "the body of a negotiation token")
}

/// Names an OID in an error, so that "the server picked Kerberos" reads as that.
fn name_of(oid: &[u8]) -> String {
    let known = match oid {
        KERBEROS_OID | KERBEROS_LEGACY_OID => Some("Kerberos"),
        NTLM_OID => Some("NTLM"),
        SPNEGO_OID => Some("SPNEGO"),
        _ => None,
    };
    let digits = dotted(oid);
    known.map_or_else(|| digits.clone(), |name| format!("{name} ({digits})"))
}

/// Renders an OID's body in dotted form.
///
/// [X690] §8.19: the first two arcs share a byte, and every arc after that is base-128 with the
/// top bit set on all but the last octet.
fn dotted(oid: &[u8]) -> String {
    let Some(first) = oid.first().copied() else {
        return "an empty OID".to_owned();
    };

    let mut arcs = vec![
        u32::from(first / 40).to_string(),
        u32::from(first % 40).to_string(),
    ];
    let mut arc = 0u32;
    for byte in oid.iter().skip(1) {
        arc = arc
            .checked_mul(128)
            .and_then(|shifted| shifted.checked_add(u32::from(byte & 0x7F)))
            .unwrap_or(u32::MAX);
        if byte & 0x80 == 0 {
            arcs.push(arc.to_string());
            arc = 0;
        }
    }
    arcs.join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_token_is_the_shape_rfc2743_requires() {
        let token = init_token(b"NTLMSSP\0\x01\x00\x00\x00");

        // [APPLICATION 0], then the SPNEGO OID, then a negTokenInit.
        assert_eq!(token.first(), Some(&0x60));
        assert!(token.windows(SPNEGO_OID.len()).any(|w| w == SPNEGO_OID));
        assert!(token.windows(NTLM_OID.len()).any(|w| w == NTLM_OID));
        assert!(token.ends_with(b"NTLMSSP\0\x01\x00\x00\x00"));

        // And it reads back as one, with exactly the mechanism token that went in.
        let parsed = parse(&token).unwrap();
        assert_eq!(
            parsed.response_token.as_deref(),
            Some(&b"NTLMSSP\0\x01\x00\x00\x00"[..])
        );
    }

    #[test]
    fn a_continuation_token_carries_no_wrapper_and_no_state() {
        let token = response_token(b"NTLMSSP\0\x03\x00\x00\x00");
        assert_eq!(token.first(), Some(&0xA1));
        assert!(!token.windows(SPNEGO_OID.len()).any(|w| w == SPNEGO_OID));

        let parsed = parse(&token).unwrap();
        assert_eq!(parsed.state, None);
        assert_eq!(
            parsed.response_token.as_deref(),
            Some(&b"NTLMSSP\0\x03\x00\x00\x00"[..])
        );
    }

    /// What IIS answers a `NegTokenInit` with: accept-incomplete, NTLM selected, and the
    /// `CHALLENGE_MESSAGE` inside.
    fn server_response(state: u8, mech: &[u8], inner: &[u8]) -> Vec<u8> {
        let mut body = der::tlv(der::context(0), &der::tlv(der::ENUMERATED, &[state]));
        body.extend_from_slice(&der::tlv(der::context(1), &der::tlv(der::OID, mech)));
        body.extend_from_slice(&der::tlv(
            der::context(2),
            &der::tlv(der::OCTET_STRING, inner),
        ));
        der::tlv(der::context(1), &der::tlv(der::SEQUENCE, &body))
    }

    #[test]
    fn a_servers_response_yields_its_state_mechanism_and_inner_token() {
        let token = server_response(1, NTLM_OID, b"NTLMSSP\0\x02\x00\x00\x00");
        let parsed = parse(&token).unwrap();

        assert_eq!(parsed.state, Some(NegState::AcceptIncomplete));
        assert_eq!(parsed.supported_mech.as_deref(), Some(NTLM_OID));
        assert_eq!(
            parsed.response_token.as_deref(),
            Some(&b"NTLMSSP\0\x02\x00\x00\x00"[..])
        );

        for (byte, expected) in [
            (0u8, NegState::AcceptCompleted),
            (2, NegState::Reject),
            (3, NegState::RequestMic),
            // A value no version of the protocol defines, read as "keep going".
            (9, NegState::AcceptIncomplete),
        ] {
            let token = server_response(byte, NTLM_OID, b"x");
            assert_eq!(parse(&token).unwrap().state, Some(expected));
        }
    }

    #[test]
    fn a_server_that_selects_kerberos_is_reported_by_name() {
        for oid in [KERBEROS_OID, KERBEROS_LEGACY_OID] {
            let token = server_response(1, oid, b"a ticket");
            let error = parse(&token).unwrap_err();
            assert!(
                matches!(&error, Error::UnsupportedMechanism { mechanism } if mechanism.contains("Kerberos")),
                "{error}"
            );
        }

        // And so is one nobody has a name for.
        let token = server_response(1, &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x7F], b"?");
        let error = parse(&token).unwrap_err();
        assert!(
            matches!(&error, Error::UnsupportedMechanism { mechanism } if mechanism == "1.3.6.1.4.1.127"),
            "{error}"
        );
    }

    /// [MS-SPNG] §3.2.5.2's server-initiated variation, which arrives in the application wrapper
    /// and carries `mechTypes` where a `NegTokenResp` carries `negState`.
    #[test]
    fn a_server_initiated_negtokeninit2_is_accepted_too() {
        let mech_types = der::tlv(der::SEQUENCE, &der::tlv(der::OID, NTLM_OID));
        let mut inner = der::tlv(der::context(0), &mech_types);
        // negHints, which is ignored.
        inner.extend_from_slice(&der::tlv(der::context(3), &der::tlv(der::SEQUENCE, &[])));
        let init = der::tlv(der::context(0), &der::tlv(der::SEQUENCE, &inner));

        let mut body = der::tlv(der::OID, SPNEGO_OID);
        body.extend_from_slice(&init);
        let token = der::tlv(der::application(0), &body);

        let parsed = parse(&token).unwrap();
        assert_eq!(parsed.state, None);
        assert_eq!(parsed.response_token, None);
    }

    #[test]
    fn a_token_that_is_not_a_negotiation_token_is_refused() {
        for bytes in [
            vec![],
            vec![0x30, 0x00],             // a bare SEQUENCE
            vec![0xA1],                   // a tag with no length
            vec![0xA1, 0x02, 0x05, 0x00], // a negTokenResp whose body is not a SEQUENCE
            vec![0x60, 0x02, 0x05, 0x00], // an application wrapper with no OID
        ] {
            assert!(parse(&bytes).is_err(), "{bytes:02X?}");
        }

        // An application wrapper naming something that is not SPNEGO.
        let mut body = der::tlv(der::OID, KERBEROS_OID);
        body.extend_from_slice(&der::tlv(der::context(0), &der::tlv(der::SEQUENCE, &[])));
        let token = der::tlv(der::application(0), &body);
        assert!(matches!(
            parse(&token).unwrap_err(),
            Error::UnsupportedMechanism { .. }
        ));
    }

    #[test]
    fn oids_render_the_way_they_are_written_down() {
        assert_eq!(dotted(SPNEGO_OID), "1.3.6.1.5.5.2");
        assert_eq!(dotted(NTLM_OID), "1.3.6.1.4.1.311.2.2.10");
        assert_eq!(dotted(KERBEROS_OID), "1.2.840.113554.1.2.2");
        assert_eq!(dotted(&[]), "an empty OID");
        assert_eq!(name_of(NTLM_OID), "NTLM (1.3.6.1.4.1.311.2.2.10)");
    }
}
