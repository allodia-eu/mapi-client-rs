//! What can go wrong during a handshake.

/// The result of a handshake step.
pub type Result<T> = core::result::Result<T, Error>;

/// Something this crate could not do.
///
/// Every variant that reads a server-supplied buffer carries where it stopped, because an NTLM
/// message is a header of offsets into a payload: "malformed" without an offset is a byte string
/// to stare at, and the offset is usually the whole diagnosis.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The `WWW-Authenticate` value did not name the scheme this handshake speaks.
    ///
    /// The usual cause is a server that offers `Negotiate` and `NTLM` and a handshake built for
    /// the one it did not pick, but it is also what a proxy inserting its own challenge looks
    /// like.
    #[error(
        "expected a {expected} challenge, the server sent {}",
        describe_offer(.offered.as_deref())
    )]
    WrongScheme {
        /// The scheme this handshake was built for.
        expected: &'static str,
        /// The scheme name the server used, if it used one at all.
        offered: Option<String>,
    },

    /// The server repeated the bare scheme name where a token was due.
    ///
    /// This is the shape a rejection takes: having refused the credentials, IIS answers the
    /// `AUTHENTICATE_MESSAGE` with the same `WWW-Authenticate: NTLM` it opened with, so a
    /// handshake that treated a missing token as a protocol error would report a wrong password
    /// as malformed input.
    #[error(
        "the server restarted the {scheme} handshake instead of completing it, which is how a \
         refused credential is reported"
    )]
    Refused {
        /// The scheme that was refused.
        scheme: &'static str,
    },

    /// The challenge is not valid base64.
    #[error("the {scheme} challenge is not base64: {detail}")]
    NotBase64 {
        /// The scheme whose challenge it was.
        scheme: &'static str,
        /// What the decoder objected to.
        detail: String,
    },

    /// A message ended before a field it declared.
    ///
    /// [MS-NLMP] §2.2.1.2 — every variable-length field is a length and an offset into the payload
    #[error("{structure} is {len} bytes, too short for {field} at offset {offset}")]
    Truncated {
        /// The structure being read.
        structure: &'static str,
        /// The field that ran off the end.
        field: &'static str,
        /// Where the field claimed to start.
        offset: usize,
        /// How long the buffer actually is.
        len: usize,
    },

    /// A message is not the message it was supposed to be.
    ///
    /// [MS-NLMP] §2.2.1.2 — `Signature` is `NTLMSSP\0` and `MessageType` is 2 for a challenge
    #[error("expected {expected} but the buffer says {found}")]
    NotAChallenge {
        /// What was expected, in words.
        expected: &'static str,
        /// What was found, in words.
        found: String,
    },

    /// The server asked for something this crate does not implement.
    ///
    /// The one that occurs in practice is a `Negotiate` server selecting Kerberos: this crate
    /// offers only the NTLM mechanism, so a server that picks another one has picked one that
    /// cannot be answered. See the crate documentation for why Kerberos is absent.
    #[error("the server selected {mechanism}, which this crate does not implement")]
    UnsupportedMechanism {
        /// The mechanism, by OID where one was given.
        mechanism: String,
    },

    /// A SPNEGO token is not well-formed DER.
    ///
    /// [RFC 4178] §4.2 — `NegTokenInit` and `NegTokenResp`
    #[error("malformed SPNEGO token at byte {offset}: {reason}")]
    MalformedToken {
        /// Where the reader stopped.
        offset: usize,
        /// Which rule the encoding broke.
        reason: &'static str,
    },

    /// The handshake was driven out of order.
    ///
    /// A handshake is a value that is consumed in one direction. Feeding it a second challenge
    /// after it has produced its `AUTHENTICATE_MESSAGE` is a caller bug, not a server one, and it
    /// is reported rather than silently restarted because a silent restart would send the
    /// password's response to a challenge nobody checked.
    #[error("this handshake is {state} and cannot {attempted}")]
    OutOfOrder {
        /// Where the handshake had got to.
        state: &'static str,
        /// What was asked of it.
        attempted: &'static str,
    },
}

/// Renders the scheme a server offered, or says that it offered none.
fn describe_offer(name: Option<&str>) -> String {
    name.map_or_else(
        || "a challenge with no scheme name".to_owned(),
        |name| format!("a {name} challenge"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message is the whole value of an error type here, so each one is read once.
    #[test]
    fn every_message_names_what_went_wrong() {
        let wrong = Error::WrongScheme {
            expected: "NTLM",
            offered: Some("Negotiate".to_owned()),
        };
        assert_eq!(
            wrong.to_string(),
            "expected a NTLM challenge, the server sent a Negotiate challenge"
        );

        let anonymous = Error::WrongScheme {
            expected: "Negotiate",
            offered: None,
        };
        assert!(anonymous.to_string().ends_with("with no scheme name"));

        let truncated = Error::Truncated {
            structure: "CHALLENGE_MESSAGE",
            field: "TargetInfo",
            offset: 56,
            len: 48,
        };
        assert_eq!(
            truncated.to_string(),
            "CHALLENGE_MESSAGE is 48 bytes, too short for TargetInfo at offset 56"
        );

        assert!(
            Error::Refused { scheme: "NTLM" }
                .to_string()
                .contains("refused credential")
        );
        assert!(
            Error::MalformedToken {
                offset: 3,
                reason: "a length that overruns the buffer",
            }
            .to_string()
            .contains("byte 3")
        );
        assert!(
            Error::OutOfOrder {
                state: "complete",
                attempted: "answer another challenge",
            }
            .to_string()
            .contains("cannot answer another challenge")
        );
        assert!(
            Error::UnsupportedMechanism {
                mechanism: "1.2.840.113554.1.2.2 (Kerberos)".to_owned(),
            }
            .to_string()
            .contains("does not implement")
        );
        assert!(
            Error::NotAChallenge {
                expected: "message type 2",
                found: "message type 1".to_owned(),
            }
            .to_string()
            .contains("buffer says message type 1")
        );
        assert!(
            Error::NotBase64 {
                scheme: "NTLM",
                detail: "invalid symbol".to_owned(),
            }
            .to_string()
            .contains("not base64")
        );
    }
}
