//! The Autodiscover side of a connection-oriented handshake: NTLM, or `Negotiate` with Kerberos
//! first. The MAPI transport has its own; what they share is in [`crate::handshake`].

use mapi_autodiscover::EmailAddress;
use reqwest::{Response, StatusCode, Url};

use super::Search;
use crate::error::{Error, Result};
use crate::handshake::{Context, MAX_ATTEMPTS, Negotiation, moved};
use crate::transport::{challenges, connection};

/// What one handshake came to.
enum Attempt {
    /// The candidate's reply, or `None` when it did not answer.
    Answered(Option<Response>),
    /// A leg was refused on another connection than the one it answered: start again.
    Moved,
}

impl Search<'_> {
    /// Sends the request, running a handshake first when the credentials need one.
    ///
    /// The opening leg carries the whole Autodiscover request rather than an empty body, which is
    /// the opposite of what the MAPI transport does and for the opposite reason: an Autodiscover
    /// request is a few hundred bytes of XML rather than a ROP buffer, so re-sending it costs less
    /// than the round trip an empty leg would add.
    ///
    /// `None` means the candidate did not answer, which is a reason to try the next one.
    pub(super) async fn authenticate(
        &self,
        url: &Url,
        address: &EmailAddress,
    ) -> Result<Option<Response>> {
        let Some((scheme, identity)) = self.credentials.handshake() else {
            return Ok(self.post(url, address, None).await);
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

        // Kerberos's first message carries the channel binding, so it waits for the certificate
        // the first response brings; NTLM's goes at once.
        let mut opening = if negotiation.waits_for_a_challenge() {
            None
        } else {
            Some(negotiation.opening(None)?)
        };
        let Some(mut challenged) = self.post(url, address, opening.as_deref()).await else {
            return Ok(Attempt::Answered(None));
        };

        // The ticket is asked for once the candidate has asked for `Negotiate`, and not before: a
        // search tries several candidates, and one that does not answer, or wants something else,
        // costs no trip to a KDC. With no ticket to be had, NTLM's opening goes on a leg of its
        // own.
        if negotiation.waits_for_a_challenge()
            && challenged.status() == StatusCode::UNAUTHORIZED
            && !negotiation
                .choose(self.kerberos, &challenges(&challenged), context)
                .await?
        {
            let _ = challenged.bytes().await;
            let ntlm = negotiation.opening(None)?;
            let Some(next) = self.post(url, address, Some(&ntlm)).await else {
                return Ok(Attempt::Answered(None));
            };
            challenged = next;
            opening = Some(ntlm);
        }

        // A candidate that did not challenge has already answered the request the opening leg
        // carried — it wants no authentication, or none this client would have to prove. There is
        // no handshake to finish, so the reply is the reply; treating it as a refusal would turn a
        // candidate that answered into an error that ends the whole search.
        if challenged.status() != StatusCode::UNAUTHORIZED {
            return Ok(Attempt::Answered(Some(challenged)));
        }

        let certificate = crate::transport::peer_certificate(&challenged);
        let offered = challenges(&challenged);
        let answered = connection(&challenged);

        // Reading the body is what returns the connection to the pool, and a handshake depends on
        // it: NTLM and Negotiate authenticate a connection, so the next leg has to travel on the
        // one that was challenged. Leaving the body unread hands it a fresh connection, on which
        // the server has nothing outstanding — the same trap the MAPI transport documents.
        let _ = challenged.bytes().await;

        let outcome = self
            .legs(
                url,
                address,
                &mut negotiation,
                (&offered, answered),
                certificate.as_deref(),
                opening.is_some(),
                context,
                last,
            )
            .await;
        let refused = match &outcome {
            Ok(Attempt::Answered(Some(reply))) => reply.status() == StatusCode::UNAUTHORIZED,
            Ok(_) => false,
            Err(error) => matches!(error, Error::Unauthorized { .. }),
        };
        if refused {
            negotiation.refused(self.kerberos);
        }
        outcome
    }

    /// The legs after the first 401 — what it `offered`, on the connection it `answered` on — up
    /// to the reply that ends the handshake, checked with [`Negotiation::finish`] when it is not a
    /// 401.
    #[expect(
        clippy::too_many_arguments,
        reason = "each is one piece of the handshake in flight, and bundling them would only name \
                  the bundle"
    )]
    async fn legs(
        &self,
        url: &Url,
        address: &EmailAddress,
        negotiation: &mut Negotiation,
        (offered, mut answered): (&[String], Option<core::net::SocketAddr>),
        certificate: Option<&[u8]>,
        opened: bool,
        context: Context<'_>,
        last: bool,
    ) -> Result<Attempt> {
        let next = negotiation.respond(opened, offered, certificate, context)?;
        let mut reply = self.post(url, address, Some(&next)).await;
        for _ in 0..crate::handshake::MAX_LEGS {
            let Some(current) = reply else {
                return Ok(Attempt::Answered(None));
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
            reply = self.post(url, address, Some(&next)).await;
        }

        match reply {
            Some(reply) if reply.status() != StatusCode::UNAUTHORIZED => {
                negotiation.finish(&challenges(&reply), context)?;
                Ok(Attempt::Answered(Some(reply)))
            }
            Some(reply) if !last && moved(answered, connection(&reply)) => {
                let _ = reply.bytes().await;
                Ok(Attempt::Moved)
            }
            reply => Ok(Attempt::Answered(reply)),
        }
    }
}
