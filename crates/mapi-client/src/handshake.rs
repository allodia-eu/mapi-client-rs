//! Driving a `mapi-auth` handshake, for the two places in this crate that have to.
//!
//! Autodiscover and the MAPI session both POST to an Exchange server with the same credentials, so
//! both meet the same 401 and both have to answer it. What they do not share is the request: one
//! sends XML to a candidate URL, the other a ROP buffer to the endpoint. So what lives here is the
//! part that is the same — deciding what goes in `Authorization`, and turning a refusal into this
//! crate's error — and each caller does its own POSTs.
//!
//! The module is feature-gated on `ntlm` and is the only place in this crate that names
//! [`mapi_auth`] types other than in the [`Credentials`] variants themselves.

use std::time::{SystemTime, UNIX_EPOCH};

use mapi_auth::{ChannelBinding, Entropy, Handshake, Identity, Scheme};

use crate::credentials::Credentials;
use crate::error::{Error, Result};

/// A handshake in flight, between its first message and its last.
#[derive(Debug)]
pub(crate) struct Negotiation {
    scheme: Scheme,
    handshake: Handshake,
}

impl Negotiation {
    /// Begins a handshake, returning it and the value for the first `Authorization` header.
    ///
    /// `host` is the server being authenticated to; it becomes the `HTTP/…` service principal name
    /// a server checking service binding compares against its own.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] if the operating system will not produce randomness for the client
    /// challenge. Continuing with a predictable one would be worse than failing: it is the client's
    /// half of the freshness guarantee, and a guessable challenge makes the exchange replayable.
    pub(crate) fn start(
        scheme: Scheme,
        identity: &Identity,
        host: Option<&str>,
    ) -> Result<(Self, String)> {
        let mut handshake = Handshake::new(scheme, identity.clone(), entropy()?);
        if let Some(host) = host {
            handshake = handshake.target_spn(format!("HTTP/{host}"));
        }

        let opening = handshake.initial().map_err(|source| Error::Setup {
            source: Box::new(source),
        })?;
        Ok((Self { scheme, handshake }, opening))
    }

    /// Answers the server's challenge, returning the value for the last `Authorization` header.
    ///
    /// `challenges` is every `WWW-Authenticate` value the 401 carried, in any order; the one this
    /// scheme can answer is picked out here rather than by the caller. `certificate` is the
    /// server's, in DER, and is what the channel binding is computed over — it arrives at this
    /// point rather than at [`start`](Self::start) because a TLS connection is the first thing that
    /// has one.
    ///
    /// # Errors
    ///
    /// [`Error::Unauthorized`] if no challenge for this scheme was offered, if the credential was
    /// refused, or if the server chose a mechanism this crate does not implement.
    pub(crate) fn answer(
        mut self,
        challenges: &[String],
        certificate: Option<&[u8]>,
        context: Context<'_>,
    ) -> Result<String> {
        if let Some(certificate) = certificate {
            self.handshake = self
                .handshake
                .channel_binding(ChannelBinding::tls_server_end_point(certificate));
        }

        let challenge = challenges
            .iter()
            .find(|value| self.scheme.matches(value))
            .ok_or_else(|| context.unauthorized(scheme_names(challenges)))?;

        self.handshake
            .advance(challenge)
            .map_err(|source| context.unauthorized(vec![source.to_string()]))
    }
}

/// Where a refusal happened, so that the error can say.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Context<'a> {
    /// The URL being authenticated to.
    pub(crate) url: &'a str,
    /// What was sent, for the "sent" half of the message.
    pub(crate) credentials: &'a Credentials,
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

/// The scheme each `WWW-Authenticate` value names.
pub(crate) fn scheme_names(challenges: &[String]) -> Vec<String> {
    challenges
        .iter()
        .filter_map(|value| value.split_whitespace().next())
        .map(str::to_owned)
        .collect()
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
        Credentials::ntlm("DEV\\developer", "Login123")
    }

    fn context(credentials: &Credentials) -> Context<'_> {
        Context {
            url: "https://exchange-lab-01/mapi/emsmdb/",
            credentials,
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
        let (_, opening) = Negotiation::start(
            Scheme::Ntlm,
            &Identity::new("DEV\\developer", "Login123"),
            Some("exchange-lab-01"),
        )
        .unwrap();
        assert!(opening.starts_with("NTLM "), "{opening}");

        let (negotiation, opening) = Negotiation::start(
            Scheme::Negotiate,
            &Identity::new("developer", "Login123"),
            None,
        )
        .unwrap();
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
        let identity = Identity::new("DEV\\developer", "Login123");

        let answer = |certificate: Option<&[u8]>| {
            let (negotiation, _) =
                Negotiation::start(Scheme::Ntlm, &identity, Some("exchange-lab-01")).unwrap();
            negotiation
                .answer(
                    &["Negotiate".to_owned(), DOCUMENTED_CHALLENGE.to_owned()],
                    certificate,
                    context(&credentials),
                )
                .unwrap()
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
        let (negotiation, _) =
            Negotiation::start(Scheme::Ntlm, &Identity::new("u", "p"), None).unwrap();

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
        let (negotiation, _) =
            Negotiation::start(Scheme::Ntlm, &Identity::new("u", "p"), None).unwrap();

        let error = negotiation
            .answer(&["NTLM".to_owned()], None, context(&credentials))
            .unwrap_err();
        assert!(
            matches!(&error, Error::Unauthorized { offered, .. }
                if offered.first().is_some_and(|first| first.contains("refused credential"))),
            "{error}"
        );
    }

    #[test]
    fn scheme_names_are_lifted_out_of_whole_header_values() {
        let offered = [
            "Negotiate TlRMTVNTUAACAAAA".to_owned(),
            "NTLM".to_owned(),
            "   ".to_owned(),
        ];
        assert_eq!(scheme_names(&offered), ["Negotiate", "NTLM"]);
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
