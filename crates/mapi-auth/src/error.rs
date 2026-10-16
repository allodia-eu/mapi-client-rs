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

    /// A Kerberos KDC refused a request.
    ///
    /// `code` is the [RFC 4120] §7.5.9 error code. `status` is the `NTSTATUS` a Windows KDC adds in
    /// a `KERB-EXT-ERROR` ([MS-KILE] §2.2.1), which is often the more specific of the two: one
    /// `KDC_ERR_CLIENT_REVOKED` covers a disabled, a locked-out and an expired account, and the
    /// status says which.
    #[error(
        "the KDC for {realm} refused the request: {}{}",
        describe_kdc_code(*.code),
        describe_status(*.status)
    )]
    KdcRefused {
        /// The realm whose KDC answered.
        realm: String,
        /// The error code.
        code: i32,
        /// The Windows status, when the KDC sent one.
        status: Option<u32>,
    },

    /// A Kerberos KDC's reply cannot be used: it does not answer the request that was sent, it
    /// fails a check the exchange requires, or a chain of referrals went nowhere.
    ///
    /// [RFC 4120] §3.1.5 and §3.3.4 list the checks; [RFC 6806] §7, §8 and §11 add the referral
    /// limits and the request checksum.
    #[error("the reply from the KDC for {realm} cannot be used: {reason}")]
    KdcReply {
        /// The realm whose KDC sent it.
        realm: String,
        /// Which check it failed.
        reason: &'static str,
    },

    /// The server refused a Kerberos AP-REQ, with a `KRB-ERROR` in its `Negotiate` token.
    ///
    /// This is a refusal of a ticket the KDC issued, so it is not a reason to fall back to NTLM:
    /// the server was offered Kerberos, chose it, and said no. The code is the [RFC 4120] §7.5.9
    /// one; `KRB_AP_ERR_SKEW` (37) is retried once before it is reported ([MS-KILE] §3.2.5.8).
    #[error(
        "the server refused the Kerberos ticket: {}{}",
        describe_kdc_code(*.code),
        describe_status(*.status)
    )]
    ServiceRefused {
        /// The error code.
        code: i32,
        /// The Windows status, when the server sent one.
        status: Option<u32>,
    },

    /// The server's Kerberos reply cannot be used: an AP-REP that does not answer the AP-REQ, or a
    /// token that is not the one the exchange expected.
    ///
    /// [RFC 4120] §3.2.5 and [RFC 4121] §4.1 give the checks. An AP-REP that fails them did not
    /// come from a server holding the service key, which is the one thing mutual authentication
    /// exists to establish.
    #[error("the server's Kerberos reply cannot be used: {reason}")]
    ServiceReply {
        /// Which check it failed.
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

/// Names a KDC error code, with what it usually means where that is not obvious from the name.
fn describe_kdc_code(code: i32) -> String {
    use crate::kerberos::kdc::code;
    let name = match code {
        code::C_PRINCIPAL_UNKNOWN => "KDC_ERR_C_PRINCIPAL_UNKNOWN, no such account in that realm",
        code::S_PRINCIPAL_UNKNOWN => "KDC_ERR_S_PRINCIPAL_UNKNOWN, no account holds that SPN",
        code::ETYPE_NOSUPP => "KDC_ERR_ETYPE_NOSUPP, no AES key for the account",
        code::CLIENT_REVOKED => "KDC_ERR_CLIENT_REVOKED, the account is disabled or locked out",
        code::KEY_EXPIRED => "KDC_ERR_KEY_EXPIRED, the password has expired",
        code::PREAUTH_FAILED => "KDC_ERR_PREAUTH_FAILED, which is what a wrong password earns",
        code::PREAUTH_REQUIRED => "KDC_ERR_PREAUTH_REQUIRED",
        code::SKEW => "KRB_AP_ERR_SKEW, the clocks differ by more than is allowed",
        code::WRONG_REALM => "KDC_ERR_WRONG_REALM",
        _ => "an error",
    };
    format!("{name} (code {code})")
}

/// Renders a Windows status, when there is one.
fn describe_status(status: Option<u32>) -> String {
    status.map_or_else(String::new, |status| format!(", NTSTATUS 0x{status:08X}"))
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

    /// The Kerberos variants, which name the realm or the server that said no and why.
    #[test]
    fn kerberos_errors_name_who_refused_and_why() {
        assert_eq!(
            Error::KdcRefused {
                realm: "EXAMPLE.TEST".to_owned(),
                code: 24,
                status: Some(0xC000_006A),
            }
            .to_string(),
            "the KDC for EXAMPLE.TEST refused the request: KDC_ERR_PREAUTH_FAILED, which is what a \
             wrong password earns (code 24), NTSTATUS 0xC000006A"
        );
        for code in [6, 7, 14, 18, 23, 25, 37, 68, 60] {
            let refused = Error::KdcRefused {
                realm: "EXAMPLE.TEST".to_owned(),
                code,
                status: None,
            };
            assert!(refused.to_string().ends_with(&format!("(code {code})")));
        }
        assert!(
            Error::KdcReply {
                realm: "EXAMPLE.TEST".to_owned(),
                reason: "a nonce that is not the request's",
            }
            .to_string()
            .contains("EXAMPLE.TEST cannot be used: a nonce")
        );
        assert_eq!(
            Error::ServiceRefused {
                code: 37,
                status: None,
            }
            .to_string(),
            "the server refused the Kerberos ticket: KRB_AP_ERR_SKEW, the clocks differ by more \
             than is allowed (code 37)"
        );
        assert!(
            Error::ServiceReply {
                reason: "an AP-REP for another authenticator",
            }
            .to_string()
            .ends_with("cannot be used: an AP-REP for another authenticator")
        );
    }
}
