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
///     Identity::new("EXAMPLE\\alice", "hunter2"),
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
    /// The flags the third message declared, once it exists: the session's `NegFlg`, which decides
    /// what signature a `mechListMIC` carries in either direction.
    negotiated: Option<NegotiateFlags>,
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
            negotiated: None,
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
    /// arrives — [`Error::NotBase64`], [`Error::Malformed`], [`Error::NotAChallenge`] or
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
        let (challenge_bytes, mic_requested) = match self.scheme {
            Scheme::Ntlm => (token, false),
            Scheme::Negotiate => {
                let server = spnego::parse(&token)?;
                if server.state == Some(NegState::Reject) {
                    return Err(Error::Refused {
                        scheme: self.scheme.name(),
                    });
                }
                let requested = server.state == Some(NegState::RequestMic);
                let inner = server.response_token.ok_or(Error::Refused {
                    scheme: self.scheme.name(),
                })?;
                (inner, requested)
            }
        };

        let challenge = ntlm::ChallengeMessage::parse(&challenge_bytes)?;
        let flags = ntlm::negotiated(&challenge);
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
            Scheme::Negotiate => {
                // Sent whenever the session can sign, not only when asked: [MS-SPNG] note <8>
                // makes it mandatory once the AUTHENTICATE_MESSAGE carries a MIC, and a server
                // that did not need it ignores it.
                let mic = ntlm::signature(flags);
                if mic_requested && mic.is_none() {
                    return Err(Error::UnsupportedMechanism {
                        mechanism: "a mechListMIC, which a session that negotiated neither SIGN \
                                    nor ALWAYS_SIGN has no signature for"
                            .to_owned(),
                    });
                }
                spnego::response_token(&message, mic.as_ref().map(<[u8; 16]>::as_slice))
            }
        };

        self.negotiated = Some(flags);
        self.state = State::Complete;
        Ok(self.header(&token))
    }

    /// Checks the token, if any, on the response that completed the handshake.
    ///
    /// Pass this scheme's `WWW-Authenticate` value from the successful final response, or `None`
    /// when it carried none. Only a `Negotiate` server has anything to say here: [RFC 4178]
    /// §4.2.2's completing `NegTokenResp`, whose `mechListMIC` is the server's signature over the
    /// mechanism list. [RFC 4178] §5 has the initiator verify one when it arrives, because a list a
    /// man in the middle has edited is exactly what it is there to catch. Exchange Server SE
    /// `15.02.2562.045` sends the token with `accept-completed` and no `mechListMIC`.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfOrder`] if the last message has not been produced, [`Error::Refused`] if the
    /// server's last word was `reject`, [`Error::MechListMicMismatch`] if its `mechListMIC` is not
    /// the signature this session would produce, and the parse errors of
    /// [`advance`](Self::advance) if the token will not read.
    pub fn finish(&self, www_authenticate: Option<&str>) -> Result<()> {
        if self.state != State::Complete {
            return Err(Error::OutOfOrder {
                state: self.state.describe(),
                attempted: "check the server's last token",
            });
        }
        let (Scheme::Negotiate, Some(value)) = (self.scheme, www_authenticate) else {
            return Ok(());
        };
        let token = match self.decode(value) {
            // The bare scheme name on a response that succeeded carries nothing to check.
            Err(Error::Refused { .. }) => return Ok(()),
            other => other?,
        };

        let server = spnego::parse(&token)?;
        if server.state == Some(NegState::Reject) {
            return Err(Error::Refused {
                scheme: self.scheme.name(),
            });
        }
        let Some(received) = server.mech_list_mic else {
            return Ok(());
        };
        // §3.4.4.3's signature does not depend on the direction, so the server's is the same
        // sixteen bytes as the one this side sent.
        let expected = self.negotiated.and_then(ntlm::signature);
        if expected.as_ref().map(<[u8; 16]>::as_slice) == Some(received.as_slice()) {
            Ok(())
        } else {
            Err(Error::MechListMicMismatch { received })
        }
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
mod tests;
