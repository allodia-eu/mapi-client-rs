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

    /// A `Negotiate` server's `mechListMIC` is not the signature this session would produce.
    ///
    /// [RFC 4178] §5 integrity-protects the mechanism list so that a man in the middle cannot strip
    /// a preferred mechanism out of it unnoticed. A MIC that does not verify means the list the
    /// server signed is not the list this client sent, and the response it arrived on is not to be
    /// trusted even though it succeeded.
    #[error(
        "the server's mechListMIC does not verify: it sent {} bytes {received:02X?}",
        .received.len()
    )]
    MechListMicMismatch {
        /// What the server sent.
        received: Vec<u8>,
    },

    /// Kerberos cryptography failed: a key of the wrong shape, string-to-key parameters this client
    /// will not run, or something encrypted that did not decrypt.
    ///
    /// `usage` is the key usage ([RFC 4120] §7.5.1) when there is one, which says which part of
    /// which message it was. An integrity failure under a key made from a password is what a wrong
    /// password looks like.
    #[error("Kerberos {}: {reason}", describe_usage(*.usage))]
    Crypto {
        /// The key usage the operation was under, if it was under one.
        usage: Option<u32>,
        /// What was wrong.
        reason: &'static str,
    },

    /// A SPNEGO token, a Kerberos message or a certificate is not well-formed DER, or is not the
    /// structure it was supposed to be.
    ///
    /// [RFC 4178] §4.2 for SPNEGO, [RFC 4120] §5 for Kerberos, both encoded per X.690.
    #[error("malformed {structure} at byte {offset}: {reason}")]
    Malformed {
        /// What was being read: "SPNEGO token", "Kerberos message".
        structure: &'static str,
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

/// Names a key usage in an error, or says there was none.
fn describe_usage(usage: Option<u32>) -> String {
    usage.map_or_else(|| "key".to_owned(), |usage| format!("key usage {usage}"))
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
            Error::Malformed {
                structure: "Kerberos message",
                offset: 3,
                reason: "a length that overruns the buffer",
            }
            .to_string()
            .contains("malformed Kerberos message at byte 3")
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
