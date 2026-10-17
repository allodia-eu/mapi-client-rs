//! Requests over a connection-oriented scheme: NTLM and Negotiate.
//!
//! # Why this is a different code path and not another header
//!
//! NTLM authenticates a **TCP connection**, not a request. The `NEGOTIATE_MESSAGE`, the
//! `CHALLENGE_MESSAGE` and the `AUTHENTICATE_MESSAGE` all have to travel on the same one, and every
//! request afterwards has to travel on it too, because that connection — and no other — is the one
//! the server has associated with an authenticated identity.
//!
//! `reqwest` offers no way to pin a request to a connection, so each connection is an HTTP client
//! of its own, lent to one request at a time: see [`pool`](super::pool) for why that is enough, the
//! one case where it is not, and what it costs. A request here borrows one, authenticates it if it
//! has to, and gives it back.
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
//! comes back 401 and the handshake runs again, which is why a lane's authentication is a belief
//! rather than a fact.

use mapi_proto::{Headers, Request};
use negotiate_auth::{Identity, Scheme};
use reqwest::StatusCode;

use crate::error::{Error, Result};
use crate::handshake::{Context, MAX_ATTEMPTS, MAX_LEGS, Negotiation, moved};
use crate::transport::Transport;
use crate::transport::pool::Lease;

impl Transport {
    /// Sends a request under NTLM or Negotiate, authenticating first if it has to.
    pub(super) async fn send_negotiated(
        &self,
        request: &Request,
        scheme: Scheme,
        identity: &Identity,
    ) -> Result<(Headers, Vec<u8>)> {
        let mut lane = self
            .pool
            .lease(self.endpoint.origin().ascii_serialization())
            .await?;
        if let Some(reply) = self.reuse(&mut lane, request).await? {
            return self.finish(request, reply);
        }

        let turn = self.pool.turn(&lane, self.endpoint.as_str()).await?;
        // The turn before this one may have authenticated a connection that is idle by now.
        lane.trade_for_warm();
        if let Some(reply) = self.reuse(&mut lane, request).await? {
            drop(lane);
            turn.settle(true, &Ok(()));
            return self.finish(request, reply);
        }
        let outcome = self
            .authenticate(&mut lane, request, scheme, identity)
            .await;
        // The lane goes back before the turn is given up, so that the request woken by it finds
        // the connection this one authenticated, and trades for it.
        let authenticated = lane.is_authenticated();
        drop(lane);
        turn.settle(authenticated, &outcome);
        outcome
    }

    /// Sends the request as an ordinary one on a lane believed authenticated: the reply, or `None`
    /// when there is a handshake to run first.
    ///
    /// The lane is believed unauthenticated until the answer says otherwise: a request that fails
    /// or is cancelled in flight costs its client the connection, and the next one on this lane
    /// would otherwise send its body to a connection the server has never seen. A 401 makes the
    /// handshakes that follow take turns — see [`Lease::doubt`].
    async fn reuse(&self, lane: &mut Lease<'_>, request: &Request) -> Result<Option<super::Reply>> {
        if !lane.is_authenticated() {
            return Ok(None);
        }
        lane.set_authenticated(false);
        let reply = self.post(lane.http(), Some(request), None).await?;
        if reply.status == StatusCode::UNAUTHORIZED {
            lane.doubt();
            return Ok(None);
        }
        lane.set_authenticated(true);
        Ok(Some(reply))
    }

    /// Runs the handshake on `lane`, with the request riding its last leg — again, when the pool
    /// moved it to another connection part way through.
    async fn authenticate(
        &self,
        lane: &mut Lease<'_>,
        request: &Request,
        scheme: Scheme,
        identity: &Identity,
    ) -> Result<(Headers, Vec<u8>)> {
        let mut attempt = 1;
        loop {
            let last = attempt >= MAX_ATTEMPTS;
            if let Some(answer) = self.attempt(lane, request, scheme, identity, last).await? {
                return Ok(answer);
            }
            attempt = attempt.saturating_add(1);
        }
    }

    /// One handshake: the answer, or `None` when a leg was refused on a connection other than the
    /// one it answered — unless this is the `last` attempt, whose refusal is believed.
    async fn attempt(
        &self,
        lane: &mut Lease<'_>,
        request: &Request,
        scheme: Scheme,
        identity: &Identity,
        last: bool,
    ) -> Result<Option<(Headers, Vec<u8>)>> {
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
        let mut challenged = self.post(lane.http(), None, opening.as_deref()).await?;

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
            challenged = self.post(lane.http(), None, Some(&ntlm)).await?;
            opening = Some(ntlm);
        }

        // Anything but a 401 means there is no challenge to answer, and reading one out of an
        // empty list would report a 411 or a 503 as a refused credential with nothing offered.
        // The real request has not been sent yet, so send it as it is and let its own status
        // speak: a server that does not want authentication answers it, and one that is failing
        // fails it with the error this crate would report for any other request.
        if challenged.status != StatusCode::UNAUTHORIZED {
            let reply = self.post(lane.http(), Some(request), None).await?;
            lane.set_authenticated(reply.status != StatusCode::UNAUTHORIZED);
            return self.finish(request, reply).map(Some);
        }

        let outcome = self
            .legs(
                lane,
                request,
                &mut negotiation,
                &challenged,
                opening.is_some(),
                context,
                last,
            )
            .await;
        let refused = match &outcome {
            Ok(Some(reply)) => reply.status == StatusCode::UNAUTHORIZED,
            Ok(None) => false,
            Err(error) => matches!(error, Error::Unauthorized { .. }),
        };
        if refused {
            negotiation.refused(self.kerberos.as_deref());
        }
        let Some(reply) = outcome? else {
            return Ok(None);
        };

        // Marked authenticated only once `finish` has checked the server's last token: a
        // connection whose AP-REP or `mechListMIC` did not verify carries nothing more.
        lane.set_authenticated(reply.status != StatusCode::UNAUTHORIZED);
        self.finish(request, reply).map(Some)
    }

    /// The legs after the first 401, up to the reply that ends the handshake — checked with
    /// [`Negotiation::finish`] when it is not a 401. `None` when one was refused on another
    /// connection than the one it answered, and this is not the `last` attempt.
    #[expect(
        clippy::too_many_arguments,
        reason = "each is one piece of the handshake in flight, and bundling them would only name \
                  the bundle"
    )]
    async fn legs(
        &self,
        lane: &Lease<'_>,
        request: &Request,
        negotiation: &mut Negotiation,
        challenged: &super::Reply,
        opened: bool,
        context: Context<'_>,
        last: bool,
    ) -> Result<Option<super::Reply>> {
        let certificate = challenged.certificate.as_deref();
        let next = negotiation.respond(opened, &challenged.challenges, certificate, context)?;
        let mut answered = challenged.connection;
        let mut reply = self.post(lane.http(), Some(request), Some(&next)).await?;
        for _ in 0..MAX_LEGS {
            if reply.status != StatusCode::UNAUTHORIZED || negotiation.is_complete() {
                break;
            }
            if !last && moved(answered, reply.connection) {
                return Ok(None);
            }
            answered = reply.connection;
            let next = negotiation.answer(&reply.challenges, certificate, context)?;
            reply = self.post(lane.http(), Some(request), Some(&next)).await?;
        }
        if reply.status != StatusCode::UNAUTHORIZED {
            self.record(negotiation.finish(&reply.challenges, context)?);
        } else if !last && moved(answered, reply.connection) {
            return Ok(None);
        }
        Ok(Some(reply))
    }

    /// Keeps how the last handshake authenticated, for
    /// [`MapiClient::authentication`](crate::MapiClient::authentication).
    fn record(&self, authentication: crate::Authentication) {
        if let Ok(mut last) = self.authentication.lock() {
            *last = Some(authentication);
        }
    }
}
