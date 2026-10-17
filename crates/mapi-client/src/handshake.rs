//! Driving a `mapi-auth` handshake, for the two places in this crate that have to.
//!
//! Autodiscover and the MAPI session both POST to an Exchange server with the same credentials, so
//! both meet the same 401 and both have to answer it. What they do not share is the request: one
//! sends XML to a candidate URL, the other a ROP buffer to the endpoint. So what lives here is the
//! part that is the same — deciding what goes in `Authorization`, and turning a refusal into this
//! crate's error — and each caller does its own POSTs.
//!
//! The module is feature-gated on `ntlm`, and with the `kerberos` module it is the only place in
//! this crate that names [`mapi_auth`] types other than in the [`Credentials`] variants themselves.

use core::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use mapi_auth::{ChannelBinding, Entropy, Handshake, Identity, Mechanism, Scheme, State};

use crate::credentials::Credentials;
use crate::error::{Error, Result};
#[cfg(feature = "kerberos")]
use crate::kerberos::{self, Acquired};
use crate::transport::scheme_names;

/// The Kerberos side of a client, which [`Negotiation::begin`] asks for a ticket. Without the
/// `kerberos` feature there is none, and this is a type nothing constructs.
#[cfg(feature = "kerberos")]
pub(crate) type Kdcs = kerberos::Kerberos;
/// The Kerberos side of a client, which [`Negotiation::begin`] asks for a ticket. Without the
/// `kerberos` feature there is none, and this is a type nothing constructs.
#[cfg(not(feature = "kerberos"))]
#[derive(Debug)]
pub(crate) enum Kdcs {}

/// How the last handshake authenticated, as [`MapiClient::authentication`] reports it.
///
/// Worth asking for one reason above all: `Negotiate` falls back to NTLM without a word when no
/// Kerberos ticket can be had, and a deployment that meant to run Kerberos would otherwise never
/// find out that it is not.
///
/// [`MapiClient::authentication`]: crate::MapiClient::authentication
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Authentication {
    /// The mechanism that authenticated.
    pub mechanism: Mechanism,
    /// Why Kerberos was not what authenticated, for `Negotiate` credentials when it was not: no
    /// realm in the account name, no KDC to ask, a KDC that would not issue the ticket, or a
    /// server that chose NTLM. `None` when Kerberos authenticated, and for `NTLM` credentials,
    /// which never offer it.
    pub kerberos_unavailable: Option<String>,
}

/// The most legs a handshake runs after its first two: a Kerberos clock-skew retry, a server's
/// choice of NTLM over the ticket — which costs that mechanism's three messages — and a
/// `request-mic`, at most, before a 401 is taken as the answer.
pub(crate) const MAX_LEGS: usize = 4;

/// How many times a handshake is started when the pool keeps moving it to another connection, the
/// last of them taken as the answer. See [`moved`].
pub(crate) const MAX_ATTEMPTS: usize = 3;

/// Whether a 401 came back on a different connection from the one whose challenge it answered —
/// which says nothing about the credential, and everything about the pool.
///
/// `reqwest` cannot be told which connection to use. The pool underneath it, asked for one before
/// the last has been handed back, opens another at the same time and takes whichever is ready
/// first, keeping the other (`hyper-util` 0.1.20, `client/legacy/client.rs`). The new one nearly
/// always loses — measured against Exchange Server SE `15.02.2562.045`, four sessions opened at
/// once over NTLM held five connections rather than four, the fifth the loser — but when it wins,
/// the next leg of a handshake reaches a connection the server never challenged, and its 401 there
/// is the one a wrong password earns. Which connection a reply came on is what tells the two apart.
///
/// The local address is the only name `reqwest` gives a connection, and it names one only while
/// that connection is open: one closed and replaced on the same port within a handshake reads as
/// unmoved. That takes the operating system handing out the port it has just released, and costs
/// what this check's absence would — the refusal reported as it stands.
pub(crate) fn moved(answered: Option<SocketAddr>, refused_on: Option<SocketAddr>) -> bool {
    matches!((answered, refused_on), (Some(answered), Some(refused_on)) if answered != refused_on)
}

/// A handshake in flight, between its first message and its last.
#[derive(Debug)]
pub(crate) struct Negotiation {
    scheme: Scheme,
    /// NTLM's, until a ticket is had — and NTLM's for good when none is.
    handshake: Handshake,
    /// The account and the service a Kerberos ticket is still to be asked for: on the first 401
    /// that offers `Negotiate`, so that a server that never answers, or offers something else,
    /// costs no trip to a KDC.
    pending: Option<(Identity, String)>,
    /// The service the handshake offers a Kerberos ticket for, once it offers one — whose ticket
    /// is forgotten if the server refuses it.
    ticket_for: Option<String>,
    /// Whether the channel binding has been given to the handshake.
    bound: bool,
    /// Why Kerberos is not on offer, when `Negotiate` was asked for and it is not.
    unavailable: Option<String>,
}

impl Negotiation {
    /// Begins a handshake: NTLM's, with a Kerberos ticket to be asked for on the first 401 when
    /// the credentials are `Negotiate` and nothing already known rules one out — see
    /// [`choose`](Self::choose).
    ///
    /// `host` is the server being authenticated to; it becomes the `HTTP/…` service principal name
    /// — the ticket's service, and NTLM's `MsvAvTargetName`.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] if the operating system will not produce randomness.
    pub(crate) fn begin(
        scheme: Scheme,
        identity: &Identity,
        host: Option<&str>,
        kdcs: Option<&Kdcs>,
    ) -> Result<Self> {
        #[cfg_attr(
            not(feature = "kerberos"),
            expect(
                unused_mut,
                reason = "without the kerberos feature it is NTLM's as it stands"
            )
        )]
        let mut negotiation = Self::ntlm(scheme, identity, host)?;
        #[cfg(feature = "kerberos")]
        if scheme == Scheme::Negotiate {
            match (kdcs, host) {
                (Some(kdcs), Some(host)) => {
                    let spn = format!("HTTP/{host}");
                    match kdcs.unavailable(identity, &spn) {
                        Some(reason) => negotiation.unavailable = Some(reason),
                        None => negotiation.pending = Some((identity.clone(), spn)),
                    }
                }
                _ => {
                    negotiation.unavailable = Some("no server name to ask a ticket for".to_owned());
                }
            }
        }
        let _ = kdcs;
        Ok(negotiation)
    }

    /// On the first 401, asks for the Kerberos ticket [`begin`](Self::begin) left pending, and
    /// returns whether the handshake now offers it. If not, NTLM's opening is still to be sent.
    ///
    /// # Errors
    ///
    /// [`Error::Unauthorized`] if the 401 does not offer this scheme — before any KDC is asked —
    /// or if a KDC refused the credential itself: a wrong password, or a disabled, locked or
    /// expired account, which NTLM would only report less clearly. [`Error::Setup`] if the
    /// operating system will not produce randomness.
    #[cfg_attr(
        not(feature = "kerberos"),
        expect(
            clippy::unused_async,
            reason = "with the kerberos feature this is where the KDC exchanges are awaited"
        )
    )]
    pub(crate) async fn choose(
        &mut self,
        kdcs: Option<&Kdcs>,
        challenges: &[String],
        context: Context<'_>,
    ) -> Result<bool> {
        if !challenges.iter().any(|value| self.scheme.matches(value)) {
            return Err(context.unauthorized(scheme_names(challenges)));
        }
        #[cfg(feature = "kerberos")]
        if let (Some(kdcs), Some((identity, spn))) = (kdcs, self.pending.take()) {
            match kdcs.ticket(&identity, &spn, context.kdc_timeout).await? {
                Acquired::Ticket(ticket) => {
                    self.handshake = Handshake::kerberos(
                        ticket,
                        identity,
                        entropy()?,
                        [kerberos::entropy()?, kerberos::entropy()?],
                    )
                    .target_spn(spn.clone());
                    self.ticket_for = Some(spn);
                }
                Acquired::Unavailable(reason) => self.unavailable = Some(reason),
                Acquired::Refused(error) => {
                    return Err(context.unauthorized(vec![error.to_string()]));
                }
            }
        }
        let _ = kdcs;
        Ok(self.ticket_for.is_some())
    }

    /// A handshake that offers NTLM alone, raw or inside SPNEGO.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] if the operating system will not produce randomness for the client
    /// challenge. Continuing with a predictable one would be worse than failing: it is the client's
    /// half of the freshness guarantee, and a guessable challenge makes the exchange replayable.
    pub(crate) fn ntlm(scheme: Scheme, identity: &Identity, host: Option<&str>) -> Result<Self> {
        let mut handshake = Handshake::new(scheme, identity.clone(), entropy()?);
        if let Some(host) = host {
            handshake = handshake.target_spn(format!("HTTP/{host}"));
        }
        Ok(Self {
            scheme,
            handshake,
            pending: None,
            ticket_for: None,
            bound: false,
            unavailable: None,
        })
    }

    /// Whether the first message waits for the first 401: that is when the ticket is asked for,
    /// and the 401 brings the server's certificate, which only a request that has already reached
    /// the server can supply.
    ///
    /// Kerberos's first message needs it: its AP-REQ carries the channel binding, and Extended
    /// Protection refuses one without — measured. NTLM's does not: the binding goes in its third
    /// message, by which time the challenge has arrived on a TLS connection that has one.
    pub(crate) const fn waits_for_a_challenge(&self) -> bool {
        self.pending.is_some()
    }

    /// The value for the first `Authorization` header.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] if the handshake cannot start, which for Kerberos is a ticket whose key
    /// will not encrypt — a fault in this crate rather than in anything the server said.
    pub(crate) fn opening(&mut self, certificate: Option<&[u8]>) -> Result<String> {
        self.bind(certificate);
        self.handshake.initial().map_err(|source| Error::Setup {
            source: Box::new(source),
        })
    }

    /// Answers a 401, returning the value for the next `Authorization` header.
    ///
    /// `challenges` is every `WWW-Authenticate` value the 401 carried, in any order; the one this
    /// scheme can answer is picked out here rather than by the caller. `certificate` is the
    /// server's, in DER, and is what an NTLM channel binding is computed over — it arrives at this
    /// point rather than at the opening because a TLS connection is the first thing that has one.
    ///
    /// # Errors
    ///
    /// [`Error::Unauthorized`] if no challenge for this scheme was offered, if the credential was
    /// refused, or if the server chose a mechanism this handshake did not offer.
    pub(crate) fn answer(
        &mut self,
        challenges: &[String],
        certificate: Option<&[u8]>,
        context: Context<'_>,
    ) -> Result<String> {
        self.bind(certificate);
        let challenge = challenges
            .iter()
            .find(|value| self.scheme.matches(value))
            .ok_or_else(|| context.unauthorized(scheme_names(challenges)))?;
        self.handshake
            .advance(challenge)
            .map_err(|source| context.unauthorized(vec![source.to_string()]))
    }

    /// Answers the first 401: with the opening, when it waited for the certificate this 401
    /// brought, and otherwise as [`answer`](Self::answer) does.
    ///
    /// `opened` is whether the opening already went out with the first request.
    ///
    /// # Errors
    ///
    /// As for [`answer`](Self::answer) — including when the 401 does not offer this scheme, which
    /// is checked before a deferred opening is sent rather than a leg later.
    pub(crate) fn respond(
        &mut self,
        opened: bool,
        challenges: &[String],
        certificate: Option<&[u8]>,
        context: Context<'_>,
    ) -> Result<String> {
        if opened {
            return self.answer(challenges, certificate, context);
        }
        if !challenges.iter().any(|value| self.scheme.matches(value)) {
            return Err(context.unauthorized(scheme_names(challenges)));
        }
        self.opening(certificate)
    }

    /// Forgets the ticket this handshake offered, after the server refused the handshake: a ticket
    /// under a key the service no longer holds would otherwise be offered again, and refused, on
    /// every connection until its end time.
    pub(crate) fn refused(&self, kdcs: Option<&Kdcs>) {
        #[cfg(feature = "kerberos")]
        if let (Some(kdcs), Some(service)) = (kdcs, &self.ticket_for) {
            kdcs.forget(service);
        }
        #[cfg(not(feature = "kerberos"))]
        let _ = (self, kdcs);
    }

    /// Whether the last message has been sent, so that a 401 now is a refusal and not a step.
    pub(crate) fn is_complete(&self) -> bool {
        self.handshake.state() == State::Complete
    }

    /// Checks what the server said on the response that completed the handshake, and reports how
    /// it authenticated.
    ///
    /// `challenges` is every `WWW-Authenticate` value that response carried. A `Negotiate` server
    /// sends a last token there — IIS one with `accept-completed` and, for Kerberos, the AP-REP —
    /// and it has to check out; see [`Handshake::finish`]. Called only for a response that was not
    /// a 401, since a 401 is a refusal and is reported as one before there is anything to verify.
    ///
    /// # Errors
    ///
    /// [`Error::Unauthorized`] if the last token refused, its AP-REP did not prove the server, or
    /// its `mechListMIC` did not verify — the request succeeded, but over a negotiation that
    /// cannot be shown to be the one this client started.
    pub(crate) fn finish(
        &mut self,
        challenges: &[String],
        context: Context<'_>,
    ) -> Result<Authentication> {
        let last = challenges.iter().find(|value| self.scheme.matches(value));
        self.handshake
            .finish(last.map(String::as_str))
            .map_err(|source| context.unauthorized(vec![source.to_string()]))?;
        let mechanism = self.handshake.mechanism().unwrap_or(Mechanism::Ntlm);
        let kerberos_unavailable = match (mechanism, self.scheme) {
            (Mechanism::Kerberos, _) | (_, Scheme::Ntlm) => None,
            _ if self.ticket_for.is_some() => {
                Some("the server chose NTLM over the Kerberos ticket".to_owned())
            }
            _ => Some(self.unavailable.clone().unwrap_or_else(|| {
                "this client was built without the kerberos feature".to_owned()
            })),
        };
        Ok(Authentication {
            mechanism,
            kerberos_unavailable,
        })
    }

    /// Gives the handshake the channel binding, once.
    fn bind(&mut self, certificate: Option<&[u8]>) {
        if let (false, Some(certificate)) = (self.bound, certificate) {
            self.handshake = self
                .handshake
                .clone()
                .channel_binding(ChannelBinding::tls_server_end_point(certificate));
            self.bound = true;
        }
    }
}

/// Where a refusal happened, so that the error can say.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Context<'a> {
    /// The URL being authenticated to.
    pub(crate) url: &'a str,
    /// What was sent, for the "sent" half of the message.
    pub(crate) credentials: &'a Credentials,
    /// How long to wait for each KDC, when a Kerberos ticket has to be fetched: the connect
    /// timeout, since an exchange is a TCP connection and one small reply the KDC produces in
    /// milliseconds. [MS-KILE] §3.2.6 leaves the timer to the implementation, and Windows' starts
    /// at five seconds (its note <44>); the request timeout, ninety by default, would have a
    /// connection wait out a KDC that is down for longer than most requests take.
    #[cfg_attr(
        not(feature = "kerberos"),
        expect(
            dead_code,
            reason = "without the kerberos feature there is no KDC to wait for"
        )
    )]
    pub(crate) kdc_timeout: core::time::Duration,
}

impl Context<'_> {
    /// This crate's error for a handshake that did not complete.
    ///
    /// Every way one fails is a statement about the credential or about what the server would
    /// accept, so they all arrive as [`Error::Unauthorized`] — with the handshake's own account in
    /// `offered`, which is more specific than a bare 401 and is the part worth reading.
    fn unauthorized(self, offered: Vec<String>) -> Error {
        Error::Unauthorized {
            url: self.url.to_owned(),
            offered,
            sent: self.credentials.describe(),
        }
    }
}

/// The client challenge and timestamp a sans-io handshake cannot obtain for itself.
fn entropy() -> Result<Entropy> {
    let mut client_challenge = [0u8; 8];
    getrandom::fill(&mut client_challenge).map_err(|error| Error::Setup {
        source: Box::new(error),
    })?;

    // A clock before 1970 is a broken clock, not a reason to fail: the timestamp is only used when
    // the server sends none of its own, and every server this crate talks to sends one.
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Ok(Entropy::from_unix_time(client_challenge, since_epoch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> Credentials {
        Credentials::ntlm("EXAMPLE\\alice", "hunter2")
    }

    fn context(credentials: &Credentials) -> Context<'_> {
        Context {
            url: "https://exchange-lab-01/mapi/emsmdb/",
            credentials,
            kdc_timeout: core::time::Duration::from_secs(5),
        }
    }

    /// [MS-NLMP] §4.2.4.3's own `CHALLENGE_MESSAGE`, which is the only challenge that can be
    /// written down here without a server to get one from.
    const DOCUMENTED_CHALLENGE: &str = concat!(
        "NTLM TlRMTVNTUAACAAAADAAMADgAAAAzgoriASNFZ4mrze8AAAAAAAAAACQAJABEAAAA",
        "BgBwFwAAAA9TAGUAcgB2AGUAcgACAAwARABvAG0AYQBpAG4AAQAMAFMAZQByAHYAZQByAAAAAAA="
    );

    #[test]
    fn a_handshake_opens_with_the_scheme_it_was_asked_for() {
        let credentials = credentials();
        let mut ntlm = Negotiation::ntlm(
            Scheme::Ntlm,
            &Identity::new("EXAMPLE\\alice", "hunter2"),
            Some("exchange-lab-01"),
        )
        .unwrap();
        assert!(!ntlm.waits_for_a_challenge());
        let opening = ntlm.opening(None).unwrap();
        assert!(opening.starts_with("NTLM "), "{opening}");

        let mut negotiation =
            Negotiation::ntlm(Scheme::Negotiate, &Identity::new("alice", "hunter2"), None).unwrap();
        let opening = negotiation.opening(None).unwrap();
        assert!(opening.starts_with("Negotiate "), "{opening}");

        // And answering it produces the last leg, with or without a certificate to bind to.
        let answered = negotiation.answer(
            &[DOCUMENTED_CHALLENGE.replace("NTLM ", "Negotiate ")],
            None,
            context(&credentials),
        );
        // The documented challenge is a bare NTLM message, not a SPNEGO token, so Negotiate
        // rejects it — which is itself the check that the wrapper is not being skipped.
        assert!(answered.is_err());
    }

    #[test]
    fn the_binding_and_the_challenge_reach_the_last_leg() {
        let credentials = credentials();
        let identity = Identity::new("EXAMPLE\\alice", "hunter2");

        let answer = |certificate: Option<&[u8]>| {
            let mut negotiation =
                Negotiation::ntlm(Scheme::Ntlm, &identity, Some("exchange-lab-01")).unwrap();
            let _ = negotiation.opening(None).unwrap();
            let last = negotiation
                .answer(
                    &["Negotiate".to_owned(), DOCUMENTED_CHALLENGE.to_owned()],
                    certificate,
                    context(&credentials),
                )
                .unwrap();
            assert!(negotiation.is_complete());
            last
        };

        let unbound = answer(None);
        assert!(unbound.starts_with("NTLM "), "{unbound}");
        // A certificate changes the message, which is the whole point of Extended Protection.
        assert_ne!(answer(Some(b"a certificate")), unbound);
    }

    /// A server that offers only schemes this handshake does not speak, which is a different
    /// failure from a refused password and has to read as one.
    #[test]
    fn a_challenge_this_scheme_cannot_answer_names_what_was_offered() {
        let credentials = credentials();
        let mut negotiation =
            Negotiation::ntlm(Scheme::Ntlm, &Identity::new("u", "p"), None).unwrap();
        let _ = negotiation.opening(None).unwrap();

        let error = negotiation
            .answer(
                &["Negotiate".to_owned(), "Basic realm=\"x\"".to_owned()],
                None,
                context(&credentials),
            )
            .unwrap_err();

        assert!(
            matches!(&error, Error::Unauthorized { offered, sent, .. }
                if offered == &["Negotiate", "Basic"] && *sent == "NTLM credentials"),
            "{error}"
        );
    }

    /// A bare scheme name is how IIS reports a refused credential, and it must not be mistaken for
    /// a malformed challenge.
    #[test]
    fn a_refused_credential_arrives_as_unauthorized_with_the_reason() {
        let credentials = credentials();
        let mut negotiation =
            Negotiation::ntlm(Scheme::Ntlm, &Identity::new("u", "p"), None).unwrap();
        let _ = negotiation.opening(None).unwrap();

        let error = negotiation
            .answer(&["NTLM".to_owned()], None, context(&credentials))
            .unwrap_err();
        assert!(
            matches!(&error, Error::Unauthorized { offered, .. }
                if offered.first().is_some_and(|first| first.contains("refused credential"))),
            "{error}"
        );
    }

    /// The client challenge must be unpredictable and fresh per handshake: two handshakes agreeing
    /// would mean one could be replayed as the other.
    #[test]
    fn entropy_is_different_every_time() {
        assert_ne!(entropy().unwrap(), entropy().unwrap());
        assert_ne!(
            entropy().unwrap(),
            Entropy::from_unix_time([0; 8], core::time::Duration::ZERO)
        );
    }
}
