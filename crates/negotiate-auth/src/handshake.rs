//! Driving a handshake from one HTTP header value to the next.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::binding::ChannelBinding;
use crate::entropy::Entropy;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::kerberos::client::{KerberosEntropy, ServiceTicket};
use crate::ntlm::{self, NegotiateFlags};
use crate::spnego::{self, NegState, ServerToken};

mod kerberos;

/// Which HTTP authentication scheme to speak.
///
/// `Ntlm` carries NTLM messages bare. `Negotiate` carries them inside SPNEGO — and, for a
/// handshake built with [`Handshake::kerberos`], offers Kerberos first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `Authorization: NTLM …`, carrying an NTLM message directly.
    Ntlm,
    /// `Authorization: Negotiate …`, carrying a Kerberos or an NTLM token inside SPNEGO.
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
    /// The first message has been sent. [`Handshake::advance`] is next on a 401 — or, when a
    /// Kerberos server accepted the first message outright, [`Handshake::finish`] on the success.
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

/// The mechanism a handshake authenticated with, which a `Negotiate` server chooses.
///
/// Worth asking: a server that cannot use Kerberos lets `Negotiate` fall back to NTLM silently, and
/// a deployment that meant to run Kerberos would not otherwise know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mechanism {
    /// Kerberos V5 ([RFC 4121]), with a service ticket.
    Kerberos,
    /// NTLM v2 ([MS-NLMP]).
    Ntlm,
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
/// use negotiate_auth::{ChannelBinding, Entropy, Handshake, Identity, Scheme};
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
/// # Ok::<(), negotiate_auth::Error>(())
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
    /// The Kerberos side, for a handshake that has a service ticket to offer.
    kerberos: Option<Box<kerberos::Side>>,
    /// The mechanism in use, once it is known.
    mechanism: Option<Mechanism>,
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
            kerberos: None,
            mechanism: None,
        }
    }

    /// A `Negotiate` handshake that offers Kerberos first, with `ticket` as its optimistic token,
    /// and NTLM as `identity` second.
    ///
    /// A server that picks Kerberos is done in one round trip: [`initial`](Self::initial)'s header
    /// earns a success whose token [`finish`](Self::finish) checks — the AP-REP that proves the
    /// server holds the service key. A server that picks NTLM goes on through
    /// [`advance`](Self::advance) as an NTLM handshake would. `entropy` is NTLM's, for that case;
    /// `kerberos` is the first AP-REQ's and the one retry a clock-skew error allows
    /// ([MS-KILE] §3.2.5.8).
    #[must_use]
    pub fn kerberos(
        ticket: ServiceTicket,
        identity: Identity,
        entropy: Entropy,
        kerberos: [KerberosEntropy; 2],
    ) -> Self {
        let mut handshake = Self::new(Scheme::Negotiate, identity, entropy);
        handshake.kerberos = Some(Box::new(kerberos::Side::new(ticket, kerberos)));
        handshake
    }

    /// The mechanism in use: known from the start for `NTLM` and for NTLM-only `Negotiate`, and
    /// for a Kerberos-first `Negotiate` once the server has chosen.
    #[must_use]
    pub const fn mechanism(&self) -> Option<Mechanism> {
        self.mechanism
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

        let token = if let Some(side) = self.kerberos.as_deref_mut() {
            let ap_req = side.start(self.binding)?;
            spnego::init_token(&kerberos::OFFERED, &ap_req)
        } else {
            self.mechanism = Some(Mechanism::Ntlm);
            self.negotiate_message = ntlm::negotiate(NegotiateFlags::REQUESTED);
            match self.scheme {
                Scheme::Ntlm => self.negotiate_message.clone(),
                Scheme::Negotiate => {
                    spnego::init_token(&[spnego::NTLM_OID], &self.negotiate_message)
                }
            }
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
    /// `Negotiate` server chose a mechanism this handshake did not offer, [`Error::ServiceRefused`]
    /// and [`Error::ServiceReply`] if a Kerberos server refused the ticket or answered it wrongly,
    /// and [`Error::OutOfOrder`] if no challenge was expected.
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
                if self.select(&server)? == Mechanism::Kerberos {
                    return self.kerberos_answer(&server);
                }
                if server.state == Some(NegState::Reject) {
                    return Err(Error::Refused {
                        scheme: self.scheme.name(),
                    });
                }
                if self.negotiate_message.is_empty() {
                    // [RFC 4178] §3.2: the server chose NTLM over the optimistic Kerberos token,
                    // so the initiator sends NTLM's first token and the negotiation goes on.
                    self.negotiate_message = ntlm::negotiate(NegotiateFlags::REQUESTED);
                    let token = spnego::response_token(Some(&self.negotiate_message), None);
                    return Ok(self.header(&token));
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
                // makes it mandatory once the AUTHENTICATE_MESSAGE carries a MIC, [RFC 4178] §5
                // makes it mandatory when NTLM is not the preferred mechanism — after Kerberos was
                // offered first — and a server that did not need it ignores it.
                let mic = ntlm::signature(flags);
                if (mic_requested || self.kerberos.is_some()) && mic.is_none() {
                    return Err(Error::UnsupportedMechanism {
                        mechanism: "a mechListMIC, which a session that negotiated neither SIGN \
                                    nor ALWAYS_SIGN has no signature for"
                            .to_owned(),
                    });
                }
                spnego::response_token(Some(&message), mic.as_ref().map(<[u8; 16]>::as_slice))
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
    /// For Kerberos the token is required: it carries the AP-REP, without which the server has not
    /// proved it holds the service key, and a success without one is reported as an error rather
    /// than trusted.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfOrder`] if the last message has not been produced, [`Error::Refused`] if the
    /// server's last word was `reject`, [`Error::MechListMicMismatch`] if its `mechListMIC` is not
    /// the signature this session would produce, [`Error::ServiceReply`] if a Kerberos server's
    /// AP-REP is missing or does not answer, and the parse errors of [`advance`](Self::advance) if
    /// the token will not read.
    pub fn finish(&mut self, www_authenticate: Option<&str>) -> Result<()> {
        if self.kerberos.is_some() && self.mechanism != Some(Mechanism::Ntlm) {
            return self.kerberos_finish(www_authenticate);
        }
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

    /// Which offered mechanism the server's token selects — [RFC 4178] §4.2.2: `supportedMech` is
    /// in the first reply only, so a later one without it continues with the mechanism already
    /// chosen, and a first one without it accepted the preferred one.
    fn select(&mut self, server: &ServerToken) -> Result<Mechanism> {
        let selected = match server.supported_mech.as_deref() {
            Some(spnego::NTLM_OID) => Mechanism::Ntlm,
            Some(spnego::KERBEROS_OID | spnego::KERBEROS_LEGACY_OID) if self.kerberos.is_some() => {
                Mechanism::Kerberos
            }
            Some(other) => {
                return Err(Error::UnsupportedMechanism {
                    mechanism: spnego::name_of(other),
                });
            }
            None => self.mechanism.unwrap_or(if self.kerberos.is_some() {
                Mechanism::Kerberos
            } else {
                Mechanism::Ntlm
            }),
        };
        self.mechanism = Some(selected);
        Ok(selected)
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
