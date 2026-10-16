//! Requests over a connection-oriented scheme: NTLM and Negotiate.
//!
//! # Why this is a different code path and not another header
//!
//! NTLM authenticates a **TCP connection**, not a request. The `NEGOTIATE_MESSAGE`, the
//! `CHALLENGE_MESSAGE` and the `AUTHENTICATE_MESSAGE` all have to travel on the same one, and every
//! request afterwards has to travel on it too, because that connection — and no other — is the one
//! the server has associated with an authenticated identity.
//!
//! `reqwest` offers no way to pin a request to a connection. What it does offer is a pool, and the
//! pool is deterministic under one condition, measured rather than assumed: **with no other request
//! in flight, a sequential request reuses the idle connection**, and with four concurrent requests
//! it opens up to four. So the guarantee is bought with a mutex — one request at a time while these
//! credentials are in use — and with `pool_max_idle_per_host(1)` in the builder, which keeps the
//! idle set to the one connection there is.
//!
//! That costs concurrency, and the trade is unavoidable rather than merely accepted: two concurrent
//! requests would need two authenticated connections, and nothing here could say which handshake
//! had gone to which.
//!
//! # Kerberos
//!
//! `Negotiate` offers Kerberos first when a ticket can be had, and its first message — the AP-REQ —
//! has to carry the channel binding, which needs the server's certificate. So the Kerberos path
//! opens with an unauthenticated request whose 401 brings the certificate, asks for the ticket only
//! then — once the server has said it wants `Negotiate` — and sends the AP-REQ with the real
//! request: one extra round trip, as for NTLM. When no ticket comes of it, NTLM's opening follows
//! on a leg of its own; the client remembers why for a minute, so the next connection opens with
//! NTLM at once. A server can add legs — a clock-skew error to retry, a choice of NTLM after all, a
//! request for the initiator's `mechListMIC` — and each one is answered on the same connection, up
//! to `MAX_LEGS` of them.
//!
//! # What it costs per request
//!
//! One extra round trip on the first request over a connection, and nothing afterwards. IIS answers
//! a completed handshake with `Persistent-Auth: true` and leaves the connection authenticated —
//! measured against Exchange Server SE `15.02.2562.045` — so later requests carry no
//! `Authorization` header at all. If the pool ever hands over a different connection, that request
//! comes back 401 and the handshake runs again, which is why the state below is a hint rather than
//! a fact.

use mapi_auth::{Identity, Scheme};
use mapi_proto::{Headers, Request};
use reqwest::StatusCode;

use crate::error::{Error, Result};
use crate::handshake::{Context, MAX_LEGS, Negotiation};
use crate::transport::Transport;

/// What is known about the connection this transport's pool is holding.
///
/// Guarded by a mutex that is held for the whole of a request, which is what makes the pool's reuse
/// of one connection deterministic. The flag is only ever a hint: nothing can prove the pool handed
/// back the same connection, so a 401 is always treated as "authenticate again" rather than as an
/// error.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ConnectionAuth {
    authenticated: bool,
}

impl Transport {
    /// Sends a request under NTLM or Negotiate, authenticating first if it has to.
    pub(super) async fn send_negotiated(
        &self,
        request: &Request,
        scheme: Scheme,
        identity: &Identity,
    ) -> Result<(Headers, Vec<u8>)> {
        let mut state = self.connection.lock().await;

        // The connection is probably still authenticated, in which case this is an ordinary
        // request and the handshake below never runs.
        if state.authenticated {
            let reply = self.post(Some(request), None).await?;
            if reply.status != StatusCode::UNAUTHORIZED {
                return self.finish(request, reply);
            }
            state.authenticated = false;
        }

        let url = self.endpoint.to_string();
        let context = Context {
            url: &url,
            credentials: &self.credentials,
            kdc_timeout: self.kdc_timeout,
        };
        let mut negotiation = Negotiation::begin(
            scheme,
            identity,
            self.endpoint.host_str(),
            self.kerberos.as_deref(),
        )?;

        // The first leg carries no MAPI request. It cannot be answered with anything but a 401 —
        // an NTLM `NEGOTIATE_MESSAGE` proves nothing, and the Kerberos path's first leg exists to
        // learn that the server wants `Negotiate` and to fetch the certificate — so sending the
        // body with it would upload the ROP buffer an extra time for no gain. The real request
        // rides on a later leg instead.
        let mut opening = if negotiation.waits_for_a_challenge() {
            None
        } else {
            Some(negotiation.opening(None)?)
        };
        let mut challenged = self.post(None, opening.as_deref()).await?;

        // The ticket is asked for once the server has asked for `Negotiate`, and not before: a
        // server that is down, or wants something else, costs no trip to a KDC. With no ticket to
        // be had, NTLM's opening goes on a leg of its own, without the body for the same reason.
        if negotiation.waits_for_a_challenge()
            && challenged.status == StatusCode::UNAUTHORIZED
            && !negotiation
                .choose(self.kerberos.as_deref(), &challenged.challenges, context)
                .await?
        {
            let ntlm = negotiation.opening(None)?;
            challenged = self.post(None, Some(&ntlm)).await?;
            opening = Some(ntlm);
        }

        // Anything but a 401 means there is no challenge to answer, and reading one out of an
        // empty list would report a 411 or a 503 as a refused credential with nothing offered.
        // The real request has not been sent yet, so send it as it is and let its own status
        // speak: a server that does not want authentication answers it, and one that is failing
        // fails it with the error this crate would report for any other request.
        if challenged.status != StatusCode::UNAUTHORIZED {
            let reply = self.post(Some(request), None).await?;
            state.authenticated = reply.status != StatusCode::UNAUTHORIZED;
            return self.finish(request, reply);
        }

        let outcome = self
            .legs(
                request,
                &mut negotiation,
                &challenged,
                opening.is_some(),
                context,
            )
            .await;
        let refused = match &outcome {
            Ok(reply) => reply.status == StatusCode::UNAUTHORIZED,
            Err(error) => matches!(error, Error::Unauthorized { .. }),
        };
        if refused {
            negotiation.refused(self.kerberos.as_deref());
        }
        let reply = outcome?;

        // Marked authenticated only once `finish` has checked the server's last token: a
        // connection whose AP-REP or `mechListMIC` did not verify carries nothing more.
        state.authenticated = reply.status != StatusCode::UNAUTHORIZED;
        self.finish(request, reply)
    }

    /// The legs after the first 401, up to the reply that ends the handshake — checked with
    /// [`Negotiation::finish`] when it is not a 401.
    async fn legs(
        &self,
        request: &Request,
        negotiation: &mut Negotiation,
        challenged: &super::Reply,
        opened: bool,
        context: Context<'_>,
    ) -> Result<super::Reply> {
        let certificate = challenged.certificate.as_deref();
        let next = negotiation.respond(opened, &challenged.challenges, certificate, context)?;
        let mut reply = self.post(Some(request), Some(&next)).await?;
        for _ in 0..MAX_LEGS {
            if reply.status != StatusCode::UNAUTHORIZED || negotiation.is_complete() {
                break;
            }
            let next = negotiation.answer(&reply.challenges, certificate, context)?;
            reply = self.post(Some(request), Some(&next)).await?;
        }
        if reply.status != StatusCode::UNAUTHORIZED {
            self.record(negotiation.finish(&reply.challenges, context)?);
        }
        Ok(reply)
    }

    /// Keeps how the last handshake authenticated, for
    /// [`MapiClient::authentication`](crate::MapiClient::authentication).
    fn record(&self, authentication: crate::Authentication) {
        if let Ok(mut last) = self.authentication.lock() {
            *last = Some(authentication);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_connection_is_not_yet_authenticated() {
        assert!(!ConnectionAuth::default().authenticated);
    }
}
