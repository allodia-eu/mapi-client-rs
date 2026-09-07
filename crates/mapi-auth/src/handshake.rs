//! Driving a handshake from one HTTP header value to the next.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::binding::ChannelBinding;
use crate::entropy::Entropy;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::ntlm::{self, NegotiateFlags};
use crate::spnego::{self, NegState};

/// Which HTTP authentication scheme to speak.
///
/// Both carry the same NTLM messages; they differ only in what is wrapped around them and in the
/// name at the front of the header. See the [`spnego`](crate) module for why `Negotiate` is worth
/// having when `Ntlm` already works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `Authorization: NTLM …`, carrying an NTLM message directly.
    Ntlm,
    /// `Authorization: Negotiate …`, carrying an NTLM message inside a SPNEGO token.
    ///
    /// [RFC 4559] §4 — the HTTP binding for SPNEGO
    Negotiate,
}

impl Scheme {
    /// The name as it appears in `Authorization` and `WWW-Authenticate`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ntlm => "NTLM",
            Self::Negotiate => "Negotiate",
        }
    }

    /// Whether a `WWW-Authenticate` value is a challenge for this scheme.
    ///
    /// A server offering both answers a 401 with one header per scheme, so picking the right one
    /// out of the list is the caller's first job. Matching is ASCII case-insensitive because
    /// [RFC 9110] §11.1 makes the scheme name so, whatever a particular server capitalises it as.
    #[must_use]
    pub fn matches(self, header_value: &str) -> bool {
        header_value
            .split_whitespace()
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(self.name()))
    }
}

/// How far a handshake has got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Nothing has been sent. [`Handshake::initial`] is next.
    Ready,
    /// The first message has been sent. [`Handshake::advance`] is next.
    AwaitingChallenge,
    /// The last message has been produced. There is nothing more to send.
    Complete,
}

impl State {
    /// How to name this state in an error.
    const fn describe(self) -> &'static str {
        match self {
            Self::Ready => "not started",
            Self::AwaitingChallenge => "waiting for a challenge",
            Self::Complete => "complete",
        }
    }
}

/// One NTLM or SPNEGO handshake, from the first header value to the last.
///
/// A handshake is used once and in one direction. It is **not** reusable across a second
/// authentication: the client challenge inside it must be fresh every time ([MS-NLMP] §3.1.5.1.2
/// calls it a nonce), so a client that has to authenticate again builds a new one with new
/// [`Entropy`] rather than resetting this.
///
/// ```
/// use core::time::Duration;
/// use mapi_auth::{ChannelBinding, Entropy, Handshake, Identity, Scheme};
///
/// let mut handshake = Handshake::new(
///     Scheme::Ntlm,
///     Identity::new("DEV\\developer", "Login123"),
///     Entropy::from_unix_time([0x11; 8], Duration::from_secs(1_800_000_000)),
/// )
/// .channel_binding(ChannelBinding::tls_server_end_point(b"the server certificate, in DER"))
/// .target_spn("HTTP/mail.example.test");
///
/// // POST with this, and expect HTTP 401.
/// let first = handshake.initial()?;
/// assert!(first.starts_with("NTLM "));
///
/// // Feed back the WWW-Authenticate value that came with the 401, and POST again with the answer.
/// // This one is [MS-NLMP] §4.2.4.3's own CHALLENGE_MESSAGE.
/// let www_authenticate = "NTLM TlRMTVNTUAACAAAADAAMADgAAAAzgoriASNFZ4mrze8AAAAAAAAAACQAJABE\
///                         AAAABgBwFwAAAA9TAGUAcgB2AGUAcgACAAwARABvAG0AYQBpAG4AAQAMAFMAZQBy\
///                         AHYAZQByAAAAAAA=";
/// let second = handshake.advance(www_authenticate)?;
/// assert!(second.starts_with("NTLM "));
/// # Ok::<(), mapi_auth::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Handshake {
    scheme: Scheme,
    identity: Identity,
    entropy: Entropy,
    binding: ChannelBinding,
    target_spn: Option<String>,
    state: State,
    /// The `NEGOTIATE_MESSAGE` as it was sent, which the MIC in the third message covers.
    negotiate_message: Vec<u8>,
}

impl Handshake {
    /// A handshake for one scheme, one account and one set of impure inputs.
    #[must_use]
    pub fn new(scheme: Scheme, identity: Identity, entropy: Entropy) -> Self {
        Self {
            scheme,
            identity,
            entropy,
            binding: ChannelBinding::unbound(),
            target_spn: None,
            state: State::Ready,
            negotiate_message: Vec::new(),
        }
    }

    /// Binds this handshake to the TLS connection it will run over.
    ///
    /// Without one the handshake sends the all-zero binding, which a server configured for
    /// Extended Protection refuses — and refuses in a way indistinguishable from a wrong password.
    /// See [`ChannelBinding`].
    #[must_use]
    pub const fn channel_binding(mut self, binding: ChannelBinding) -> Self {
        self.binding = binding;
        self
    }

    /// Names the service being authenticated to, as `HTTP/host`.
    ///
    /// [MS-NLMP] §3.1.5.1.2 puts this in the `MsvAvTargetName` pair. A server checking service
    /// binding compares it with its own name, so it is the other half of what Extended Protection
    /// looks at.
    #[must_use]
    pub fn target_spn(mut self, spn: impl Into<String>) -> Self {
        self.target_spn = Some(spn.into());
        self
    }

    /// How far this handshake has got.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// The value for the first `Authorization` header.
    ///
    /// It carries no secret and depends on nothing the server has said, so the request it goes on
    /// can be one with an empty body: the answer will be a 401 whatever was sent.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfOrder`] if the handshake has already been started.
    pub fn initial(&mut self) -> Result<String> {
        if self.state != State::Ready {
            return Err(Error::OutOfOrder {
                state: self.state.describe(),
                attempted: "start again",
            });
        }

        self.negotiate_message = ntlm::negotiate(NegotiateFlags::REQUESTED);
        let token = match self.scheme {
            Scheme::Ntlm => self.negotiate_message.clone(),
            Scheme::Negotiate => spnego::init_token(&self.negotiate_message),
        };

        self.state = State::AwaitingChallenge;
        Ok(self.header(&token))
    }

    /// Answers the challenge in a `WWW-Authenticate` value.
    ///
    /// Pass the whole header value, scheme name and all — `NTLM TlRMTVNTUAAC…`. The result is the
    /// `Authorization` value for the request that completes the handshake, which should be the
    /// real request rather than another empty one: on success the server processes it, and there
    /// is no further leg to carry it on.
    ///
    /// # Errors
    ///
    /// [`Error::WrongScheme`] if the value names a different scheme, [`Error::Refused`] if the
    /// server restarted the handshake instead of challenging — which is how a rejected credential
    /// arrives — [`Error::NotBase64`], [`Error::MalformedToken`], [`Error::NotAChallenge`] or
    /// [`Error::Truncated`] if what came back will not parse, [`Error::UnsupportedMechanism`] if a
    /// `Negotiate` server chose something other than NTLM, and [`Error::OutOfOrder`] if no
    /// challenge was expected.
    pub fn advance(&mut self, www_authenticate: &str) -> Result<String> {
        if self.state != State::AwaitingChallenge {
            return Err(Error::OutOfOrder {
                state: self.state.describe(),
                attempted: "answer a challenge",
            });
        }

        let token = self.decode(www_authenticate)?;
        let challenge_bytes = match self.scheme {
            Scheme::Ntlm => token,
            Scheme::Negotiate => {
                let server = spnego::parse(&token)?;
                if server.state == Some(NegState::Reject) {
                    return Err(Error::Refused {
                        scheme: self.scheme.name(),
                    });
                }
                if server.state == Some(NegState::RequestMic) {
                    return Err(Error::UnsupportedMechanism {
                        mechanism: "a mechListMIC, which a single-mechanism negotiation does not \
                                    produce"
                            .to_owned(),
                    });
                }
                server.response_token.ok_or(Error::Refused {
                    scheme: self.scheme.name(),
                })?
            }
        };

        let challenge = ntlm::ChallengeMessage::parse(&challenge_bytes)?;
        let message = ntlm::authenticate(
            &self.identity,
            &challenge,
            &self.negotiate_message,
            self.entropy,
            self.binding,
            self.target_spn.as_deref(),
        );

        let token = match self.scheme {
            Scheme::Ntlm => message,
            Scheme::Negotiate => spnego::response_token(&message),
        };

        self.state = State::Complete;
        Ok(self.header(&token))
    }

    /// A header value: the scheme name, a space, and the token in base64.
    fn header(&self, token: &[u8]) -> String {
        format!("{} {}", self.scheme.name(), BASE64.encode(token))
    }

    /// Pulls the token out of a `WWW-Authenticate` value.
    fn decode(&self, header_value: &str) -> Result<Vec<u8>> {
        let scheme = self.scheme.name();
        let mut parts = header_value.split_whitespace();
        let name = parts.next();

        if !name.is_some_and(|name| name.eq_ignore_ascii_case(scheme)) {
            return Err(Error::WrongScheme {
                expected: scheme,
                offered: name.map(str::to_owned),
            });
        }

        // A bare scheme name is not a malformed challenge, it is a refusal: having rejected the
        // credential, the server starts over by offering the scheme again.
        let token = parts.next().ok_or(Error::Refused { scheme })?;

        BASE64.decode(token).map_err(|error| Error::NotBase64 {
            scheme,
            detail: error.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntlm::fixtures::{documented_challenge, timestamped_challenge};

    fn identity() -> Identity {
        Identity::with_domain("DEV", "developer", "Login123")
    }

    fn fresh(scheme: Scheme) -> Handshake {
        Handshake::new(scheme, identity(), Entropy::new([0x11; 8], 0))
    }

    fn token_of(header: &str) -> Vec<u8> {
        BASE64
            .decode(header.split_whitespace().nth(1).unwrap())
            .unwrap()
    }

    #[test]
    fn a_raw_ntlm_handshake_produces_the_two_messages_in_order() {
        let mut handshake = fresh(Scheme::Ntlm);
        assert_eq!(handshake.state(), State::Ready);

        let first = handshake.initial().unwrap();
        assert!(first.starts_with("NTLM "));
        assert_eq!(token_of(&first).get(8..12), Some(&[1, 0, 0, 0][..]));
        assert_eq!(handshake.state(), State::AwaitingChallenge);

        let challenge = format!("NTLM {}", BASE64.encode(timestamped_challenge()));
        let second = handshake.advance(&challenge).unwrap();
        assert!(second.starts_with("NTLM "));
        assert_eq!(token_of(&second).get(8..12), Some(&[3, 0, 0, 0][..]));
        assert_eq!(handshake.state(), State::Complete);
    }

    #[test]
    fn a_negotiate_handshake_wraps_the_same_messages_in_spnego() {
        let mut handshake = fresh(Scheme::Negotiate);
        let first = handshake.initial().unwrap();
        assert!(first.starts_with("Negotiate "));

        // The GSS-API wrapper, and the NTLM message still inside it.
        let token = token_of(&first);
        assert_eq!(token.first(), Some(&0x60));
        assert!(token.windows(8).any(|w| w == b"NTLMSSP\0"));

        let inner = spnego::init_token(&documented_challenge());
        let reply = format!("Negotiate {}", BASE64.encode(&inner));
        let second = handshake.advance(&reply).unwrap();
        let token = token_of(&second);
        assert_eq!(token.first(), Some(&0xA1));
        assert!(token.windows(8).any(|w| w == b"NTLMSSP\0"));
    }

    /// The two headers a real 401 carries, and the job of picking the right one.
    #[test]
    fn a_scheme_recognises_its_own_challenge_however_it_is_capitalised() {
        let offered = ["Negotiate", "NTLM TlRMTVNTUAACAAAA", "Basic realm=\"x\""];

        let ntlm: Vec<_> = offered
            .iter()
            .copied()
            .filter(|value| Scheme::Ntlm.matches(value))
            .collect();
        assert_eq!(ntlm, vec!["NTLM TlRMTVNTUAACAAAA"]);

        assert!(Scheme::Negotiate.matches("negotiate abc"));
        assert!(Scheme::Ntlm.matches("ntlm"));
        assert!(!Scheme::Ntlm.matches(""));
        assert!(!Scheme::Ntlm.matches("Negotiate abc"));
        assert_eq!(Scheme::Negotiate.name(), "Negotiate");
    }

    /// A bare scheme name is what a refused credential looks like, and reporting it as malformed
    /// input would send somebody debugging the wrong thing entirely.
    #[test]
    fn a_bare_scheme_name_is_read_as_a_refusal() {
        let mut handshake = fresh(Scheme::Ntlm);
        let _ = handshake.initial().unwrap();
        assert!(matches!(
            handshake.advance("NTLM").unwrap_err(),
            Error::Refused { scheme: "NTLM" }
        ));
    }

    #[test]
    fn a_challenge_for_another_scheme_is_refused_by_name() {
        let mut handshake = fresh(Scheme::Ntlm);
        let _ = handshake.initial().unwrap();

        let error = handshake.advance("Negotiate abcd").unwrap_err();
        assert!(
            matches!(&error, Error::WrongScheme { expected: "NTLM", offered } if offered.as_deref() == Some("Negotiate")),
            "{error}"
        );

        assert!(matches!(
            handshake.advance("   ").unwrap_err(),
            Error::WrongScheme { offered: None, .. }
        ));
    }

    #[test]
    fn a_challenge_that_is_not_base64_says_so() {
        let mut handshake = fresh(Scheme::Ntlm);
        let _ = handshake.initial().unwrap();
        assert!(matches!(
            handshake.advance("NTLM not!base64!").unwrap_err(),
            Error::NotBase64 { scheme: "NTLM", .. }
        ));
    }

    #[test]
    fn a_negotiate_server_that_rejects_or_wants_a_mic_is_reported_rather_than_answered() {
        let body = |state: u8| {
            let inner = crate::der::tlv(
                crate::der::context(0),
                &crate::der::tlv(crate::der::ENUMERATED, &[state]),
            );
            let token = crate::der::tlv(
                crate::der::context(1),
                &crate::der::tlv(crate::der::SEQUENCE, &inner),
            );
            format!("Negotiate {}", BASE64.encode(token))
        };

        let mut handshake = fresh(Scheme::Negotiate);
        let _ = handshake.initial().unwrap();
        assert!(matches!(
            handshake.advance(&body(2)).unwrap_err(),
            Error::Refused { .. }
        ));

        let mut handshake = fresh(Scheme::Negotiate);
        let _ = handshake.initial().unwrap();
        let error = handshake.advance(&body(3)).unwrap_err();
        assert!(
            matches!(&error, Error::UnsupportedMechanism { mechanism } if mechanism.contains("mechListMIC")),
            "{error}"
        );

        // Accepted, but with no token to answer: also a refusal rather than a parse failure.
        let mut handshake = fresh(Scheme::Negotiate);
        let _ = handshake.initial().unwrap();
        assert!(matches!(
            handshake.advance(&body(1)).unwrap_err(),
            Error::Refused { .. }
        ));
    }

    #[test]
    fn a_handshake_cannot_be_driven_out_of_order() {
        let mut handshake = fresh(Scheme::Ntlm);
        assert!(matches!(
            handshake.advance("NTLM abcd").unwrap_err(),
            Error::OutOfOrder {
                state: "not started",
                attempted: "answer a challenge",
            }
        ));

        let _ = handshake.initial().unwrap();
        assert!(matches!(
            handshake.initial().unwrap_err(),
            Error::OutOfOrder {
                state: "waiting for a challenge",
                ..
            }
        ));

        let challenge = format!("NTLM {}", BASE64.encode(timestamped_challenge()));
        let _ = handshake.advance(&challenge).unwrap();
        assert!(matches!(
            handshake.advance(&challenge).unwrap_err(),
            Error::OutOfOrder {
                state: "complete",
                ..
            }
        ));
    }

    /// A handshake carries a password, so it must not print one — and it is a value a caller may
    /// well put inside a struct they derive `Debug` on.
    #[test]
    fn debug_never_prints_the_password() {
        let rendered = format!("{:?}", fresh(Scheme::Ntlm));
        assert!(!rendered.contains("Login123"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn the_channel_binding_and_target_name_reach_the_message() {
        let make = |configure: fn(Handshake) -> Handshake| {
            let mut handshake = configure(fresh(Scheme::Ntlm));
            let _ = handshake.initial().unwrap();
            let challenge = format!("NTLM {}", BASE64.encode(timestamped_challenge()));
            token_of(&handshake.advance(&challenge).unwrap())
        };

        let plain = make(|handshake| handshake);
        let bound = make(|handshake| {
            handshake.channel_binding(ChannelBinding::tls_server_end_point(b"a certificate"))
        });
        let named = make(|handshake| handshake.target_spn("HTTP/mail.example.test"));

        assert_ne!(plain, bound);
        assert_ne!(plain, named);
        assert!(named.windows(2).any(|w| w == [0x48, 0x00]));
    }
}
