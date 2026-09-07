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
//! # What it costs per request
//!
//! One extra round trip on the first request over a connection, and nothing afterwards. IIS answers
//! a completed handshake with `Persistent-Auth: true` and leaves the connection authenticated —
//! measured against Exchange Server SE `15.02.2562.045` — so later requests carry no
//! `Authorization` header at all. If the pool ever hands over a different connection, that request
//! comes back 401 and the handshake runs again, which is why the state below is a hint rather than
//! a fact.

use mapi_proto::{Headers, Request};
use reqwest::StatusCode;

use crate::error::Result;
use crate::handshake::{Context, Negotiation};
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
    pub(super) async fn send_negotiated(&self, request: &Request) -> Result<(Headers, Vec<u8>)> {
        let Some((scheme, identity)) = self.credentials.handshake() else {
            // Unreachable from `send`, which only calls this when there is a handshake to run.
            let reply = self.post(Some(request), None).await?;
            return self.finish(request, reply);
        };

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

        // The first leg carries no MAPI request. It cannot be answered with anything but a 401 —
        // the `NEGOTIATE_MESSAGE` proves nothing — so sending the body with it would upload the ROP
        // buffer an extra time for no gain. The real request rides on the last leg instead, which
        // is what makes a successful handshake cost one extra round trip rather than two.
        let url = self.endpoint.to_string();
        let context = Context {
            url: &url,
            credentials: &self.credentials,
        };

        let (negotiation, opening) =
            Negotiation::start(scheme, identity, self.endpoint.host_str())?;
        let challenged = self.post(None, Some(&opening)).await?;
        let answer = negotiation.answer(
            &challenged.challenges,
            challenged.certificate.as_deref(),
            context,
        )?;

        let reply = self.post(Some(request), Some(&answer)).await?;
        state.authenticated = reply.status != StatusCode::UNAUTHORIZED;
        self.finish(request, reply)
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
