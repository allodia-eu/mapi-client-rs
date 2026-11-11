//! The Autodiscover side of a connection-oriented handshake: NTLM, or `Negotiate` with Kerberos
//! first. The MAPI transport has its own; what they share is in [`crate::handshake`].

use mapi_autodiscover::EmailAddress;
use reqwest::{StatusCode, Url};

use super::search::{Authorization, Reply, Search};
use crate::error::{Error, Result};
use crate::handshake::{Context, MAX_ATTEMPTS, Negotiation, moved};
use crate::transport::{challenges, connection};

/// What one handshake came to.
enum Attempt {
    /// What the candidate came to.
    Answered(Reply),
    /// A leg was refused on another connection than the one it answered: start again.
    Moved,
}

impl Search<'_> {
    /// Sends the request, running a handshake when the credentials need one and the candidate
    /// asks for it.
    ///
    /// Every leg carries the whole Autodiscover request rather than an empty body, which is the
    /// opposite of what the MAPI transport does and for the opposite reason: an Autodiscover
    /// request is a few hundred bytes of XML rather than a ROP buffer, so re-sending it costs less
    /// than a leg of its own would. The first leg carries no `Authorization` at all: the opening
    /// goes only to a candidate whose 401 offers the scheme, for the reason the
    /// [module](super) gives.
    ///
    /// [`Reply::Silent`] and [`Reply::Unasked`] are reasons to try the next candidate.
    pub(super) async fn authenticate(&self, url: &Url, address: &EmailAddress) -> Result<Reply> {
        let Some((scheme, identity)) = self.credentials.handshake() else {
            return Ok(self.challenged(url, address).await);
        };
        let mut attempt = 1;
        loop {
            let last = attempt >= MAX_ATTEMPTS;
            let started = self.attempt(url, address, scheme, identity, last).await?;
            if let Attempt::Answered(reply) = started {
                return Ok(reply);
            }
            attempt = attempt.saturating_add(1);
        }
    }

    /// One handshake, which a `last` attempt never reports as [`Attempt::Moved`].
    async fn attempt(
        &self,
        url: &Url,
        address: &EmailAddress,
        scheme: negotiate_auth::Scheme,
        identity: &negotiate_auth::Identity,
        last: bool,
    ) -> Result<Attempt> {
        let url_text = url.to_string();
        let context = Context {
            url: &url_text,
            credentials: self.credentials,
            kdc_timeout: self.kdc_timeout,
        };
        let mut negotiation = Negotiation::begin(scheme, identity, url.host_str(), self.kerberos)?;

        let Some(challenged) = self.post(url, address, Authorization::Withheld).await else {
            return Ok(Attempt::Answered(Reply::Silent));
        };

        // A candidate that did not challenge has already answered the request — it wants no
        // authentication, or none this client would have to prove. There is no handshake to run,
        // so the reply is the reply; treating it as a refusal would turn a candidate that answered
        // into an error that ends the whole search.
        if challenged.status() != StatusCode::UNAUTHORIZED {
            return Ok(Attempt::Answered(Reply::Answered(challenged)));
        }

        let certificate = crate::transport::peer_certificate(&challenged);
        let offered = challenges(&challenged);

        // Reading the body is what returns the connection to the pool, and a handshake depends on
        // it: NTLM and Negotiate authenticate a connection, so the next leg has to travel on the
        // one that was challenged. Leaving the body unread hands it a fresh connection, on which
        // the server has nothing outstanding — the same trap the MAPI transport documents.
        let _ = challenged.bytes().await;

        // Nothing has been sent yet, so a 401 that does not offer the scheme is a candidate this
        // client cannot use, not a refusal — and no KDC is asked for a ticket to a server that
        // wants none.
        if !offered.iter().any(|value| scheme.matches(value)) {
            return Ok(Attempt::Answered(Reply::Unasked(offered)));
        }

        // The ticket is asked for once the candidate has asked for `Negotiate`, and not before: a
        // search tries several candidates, and one that does not answer, or wants something else,
        // costs no trip to a KDC. Without one, the opening is NTLM's.
        negotiation.choose(self.kerberos, &offered, context).await?;

        let outcome = self
            .legs(
                url,
                address,
                &mut negotiation,
                certificate.as_deref(),
                context,
                last,
            )
            .await;
        let refused = match &outcome {
            Ok(Attempt::Answered(Reply::Answered(reply))) => {
                reply.status() == StatusCode::UNAUTHORIZED
            }
            Ok(_) => false,
            Err(error) => matches!(error, Error::Unauthorized { .. }),
        };
        if refused {
            negotiation.refused(self.kerberos);
        }
        outcome
    }

    /// The opening, sent once the first 401 has offered the scheme, and the legs after it, up to
    /// the reply that ends the handshake — checked with [`Negotiation::finish`] when it is not a
    /// 401.
    ///
    /// The unauthenticated first leg is not part of the handshake, so the connection it was
    /// answered on is not compared with the opening's: a handshake starts on whichever connection
    /// carries the opening, and only its later legs must stay on that one.
    async fn legs(
        &self,
        url: &Url,
        address: &EmailAddress,
        negotiation: &mut Negotiation,
        certificate: Option<&[u8]>,
        context: Context<'_>,
        last: bool,
    ) -> Result<Attempt> {
        let opening = negotiation.opening(certificate)?;
        let mut reply = self.post(url, address, Authorization::Value(opening)).await;
        let mut answered = None;
        for _ in 0..crate::handshake::MAX_LEGS {
            let Some(current) = reply else {
                return Ok(Attempt::Answered(Reply::Silent));
            };
            if current.status() != StatusCode::UNAUTHORIZED || negotiation.is_complete() {
                reply = Some(current);
                break;
            }
            if !last && moved(answered, connection(&current)) {
                let _ = current.bytes().await;
                return Ok(Attempt::Moved);
            }
            answered = connection(&current);
            let offered = challenges(&current);
            let _ = current.bytes().await;
            let next = negotiation.answer(&offered, certificate, context)?;
            reply = self.post(url, address, Authorization::Value(next)).await;
        }

        match reply {
            Some(reply) if reply.status() != StatusCode::UNAUTHORIZED => {
                negotiation.finish(&challenges(&reply), context)?;
                Ok(Attempt::Answered(Reply::Answered(reply)))
            }
            Some(reply) if !last && moved(answered, connection(&reply)) => {
                let _ = reply.bytes().await;
                Ok(Attempt::Moved)
            }
            reply => Ok(Attempt::Answered(
                reply.map_or(Reply::Silent, Reply::Answered),
            )),
        }
    }
}
