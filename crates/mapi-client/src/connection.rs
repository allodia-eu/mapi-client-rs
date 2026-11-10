//! A live Session Context, and the round trip that drives it.
//!
//! MAPI/HTTP allows exactly one request in flight per Session Context, and a server reports the
//! violation as `X-ResponseCode` 15 (Invalid Sequence) — a diagnostic that points nowhere near the
//! cause. That rule is not documented here and hoped for: every method that sends anything takes
//! `&mut self`, so the borrow checker refuses a second request while the first is outstanding.
//!
//! Cancellation is the other half of that rule. A caller that drops a future part way through a
//! request — a deadline, a `select!` that took another branch — never hands the session the answer
//! it is waiting for, and a session waiting for an answer refuses everything else, `Disconnect`
//! included. So the connection is marked poisoned *before* each request goes out and cleared only
//! once the answer is in hand: whichever point a future is dropped at, what is left behind is a
//! connection that says why it stopped, never one that is wedged.
//!
//! [MS-OXCMAPIHTTP] §2.2.3.3.3 — `X-ResponseCode` 15

use std::borrow::Cow;
use std::time::Instant;

use mapi_proto::{
    Connected, Execution, LegacyDn, Outcome, Request, ResponseCode, RopBatch, Session,
};

use crate::describe;
use crate::error::{Delivery, Error, Result};
use crate::logon::Logon;
use crate::transport::Transport;

/// Giving back the handles of objects dropped before they were closed.
mod hygiene;
/// Re-establishing a Session Context the server has lost, and the handles that do not survive it.
mod recover;
/// What a refused ROP means, as an error.
mod refusal;

pub(crate) use hygiene::{Lease, may_have_released};
pub(crate) use recover::Held;
use recover::{LogonState, Lost};
pub(crate) use refusal::refusal;

/// Why a connection stopped, when the future driving its request was dropped before the answer.
///
/// [MS-OXCMAPIHTTP] §3.1.7.2 — a response that never arrived means a new Session Context
const ABANDONED: &str = concat!(
    "a request was abandoned before its response arrived — the future driving it was dropped — ",
    "so whether the server acted on it is unknown",
);

/// One established Session Context — and, when the server loses it, the next one.
///
/// Dropping this leaves the context for the server to time out. [`disconnect`](Self::disconnect)
/// tears it down at once, which is the polite thing to do and the only way to free the server's
/// handles before the timeout.
///
/// # A lost Session Context
///
/// A context expires once it has sat idle for its [lifetime](Self::expires_at), and the server
/// then answers the next request with `X-ResponseCode` 10 without running it. 6 and 13, for a
/// context cookie it cannot read or one that is missing, mean the same: the request named no
/// context the server has. [MS-OXCMAPIHTTP] §3.2.5.6 has the client "reconnect and establish a new
/// Session Context", and this does, by itself, on the request that found out: a `Connect` passing
/// the old cookies (§3.1.5.7), the logon again if there was one, and then the request once more.
///
/// The request is sent again only when nothing in it belonged to the old context but the logon.
/// A table being paged, a stream being read and a message being written each hold a handle the
/// new context never issued, so such a request fails with [`Error::SessionLost`] — after which the
/// object it came from refuses to go on, with [`Error::SessionReplaced`], and the connection
/// re-establishes itself on its next request.
///
/// # Cancellation
///
/// Every method here and on the types that borrow from it can be dropped part way without wedging
/// anything. A future dropped before its request went out, or while the answer was on its way,
/// leaves the connection [poisoned](Error::Poisoned), with a cause that says the request was
/// abandoned: whether the server acted on it cannot be known, so nothing more is sent through
/// this Session Context except a [`disconnect`](Self::disconnect), which still works, or a
/// [`reconnect`](Self::reconnect), which replaces it with one that has no such unknowns.
#[derive(Debug)]
pub struct Connection {
    transport: Transport,
    session: Session,
    connected: Connected,
    user_dn: LegacyDn,
    /// Why this connection stopped being usable, if it did. See [`Error::Poisoned`].
    poison: Option<Cow<'static, str>>,
    /// When the server will time the Session Context out, by the last response that said. See
    /// [`expires_at`](Self::expires_at).
    expires_at: Option<Instant>,
    /// What this Session Context is logged on as, once it is: what a reconnect logs on again as.
    logon: Option<LogonState>,
    /// How many times the Session Context has been replaced. A handle is only good in the one it
    /// came from; see [`Held`].
    epoch: u64,
    /// Why the server is known to have lost the Session Context, until it is re-established.
    lost: Option<Lost>,
    /// Handles of objects dropped before they were closed, for the next request to release.
    releases: hygiene::Releases,
}

impl Connection {
    pub(crate) fn new(
        transport: Transport,
        session: Session,
        connected: Connected,
        user_dn: LegacyDn,
        sent: Instant,
    ) -> Self {
        let expires_at = session
            .expiration()
            .and_then(|lifetime| sent.checked_add(lifetime));
        Self {
            transport,
            session,
            connected,
            user_dn,
            poison: None,
            expires_at,
            logon: None,
            epoch: 0,
            lost: None,
            releases: hygiene::Releases::default(),
        }
    }

    /// What the server reported when the Session Context was established: the mailbox owner's
    /// display name, and the retry advice.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.2 — `Connect` success response body
    #[must_use]
    pub const fn server(&self) -> &Connected {
        &self.connected
    }

    /// When the server will time this Session Context out if nothing more is sent, by the most
    /// recent response that said — or `None` if none has.
    ///
    /// Every request that reaches the Session Context restarts the server's idle-time timer, and
    /// the response says how long the new idle period is ([MS-OXCMAPIHTTP] §2.2.3.3.8). The
    /// deadline is counted from when the request went out rather than from when the answer came
    /// back, so it errs early, by however long the round trip took, and never late.
    ///
    /// **It is not fixed.** Measured against Exchange Server SE `15.02.2562.056`: the `Connect`
    /// response gives five minutes, and every response once the logon has run gives fifteen.
    ///
    /// **It is on this machine's monotonic clock, and the server's timer is not.** A machine
    /// suspended for a while — a laptop closed, a virtual machine paused — resumes with a deadline
    /// that has not moved, for a Session Context the server has long since timed out. Measured on
    /// the same build: a lab whose clock jumped nine hours across a suspend answered the next
    /// `PING`, sent twelve minutes after the last request by the monotonic clock, with
    /// `X-ResponseCode` 10, "Unable to find session context based on cookie".
    ///
    /// [`keep_alive`](Self::keep_alive) moves it without doing anything else.
    ///
    /// [MS-OXCMAPIHTTP] §3.1.2 — the idle-time timer
    #[must_use]
    pub const fn expires_at(&self) -> Option<Instant> {
        self.expires_at
    }

    /// Keeps the Session Context alive: a `PING` carrying its cookies, which restarts the
    /// server's idle-time timer and does nothing else.
    ///
    /// Returns the new [deadline](Self::expires_at). [MS-OXCMAPIHTTP] §3.1.5.3 has the client
    /// "pass all of the session context cookies", and counts the PING as a refresh only when
    /// "a successful PING response containing the X-ExpirationInfo header" comes back — success
    /// alone proves nothing, because a `PING` naming no Session Context succeeds too. So a
    /// response without that header is an error here, not a refresh.
    ///
    /// Send it well before the deadline: §3.1.5.3 says to "allow for network latency". Any other
    /// request refreshes the timer just as well, so a session in use needs none.
    ///
    /// # Cancellation
    ///
    /// Safe to drop part way, like every request here: see [`Connection`].
    ///
    /// A Session Context the server has already lost is [re-established](Self::reconnect)
    /// instead, which starts a timer of its own.
    ///
    /// # Errors
    ///
    /// [`Error::NotRefreshed`] for a successful `PING` that did not say the timer was
    /// refreshed, and whatever the round trip failed with.
    ///
    /// [MS-OXCMAPIHTTP] §3.1.5.3 — keeping a Session Context alive
    /// [MS-OXCMAPIHTTP] §2.2.6 — `PING`
    pub async fn keep_alive(&mut self) -> Result<Instant> {
        if self.lost.is_none() {
            self.usable()?;
            let request = self.session.begin_ping()?;
            match self.round_trip(request).await {
                Ok(Outcome::Pong) => {
                    return match (self.session.expiration(), self.expires_at) {
                        (Some(_), Some(deadline)) => Ok(deadline),
                        _ => Err(Error::NotRefreshed),
                    };
                }
                Ok(other) => {
                    return Err(Error::Unexpected {
                        expected: "a PING response",
                        found: describe(&other),
                    });
                }
                Err(Error::SessionLost { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        // Gone already: a new Session Context starts its own timer, which is what was asked for.
        self.reconnect().await?;
        self.expires_at.ok_or(Error::NotRefreshed)
    }

    /// Logs on to the mailbox, which is what every later ROP hangs off.
    ///
    /// One round trip. The [`Logon`] takes ownership of this connection: there is one logon per
    /// Session Context, so nothing is lost, and it means the logon handle cannot outlive the
    /// session it belongs to.
    ///
    /// # Cancellation
    ///
    /// Safe to drop at any await. The connection goes with the future, and the Session Context the
    /// server holds times out on its own.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the logon — `LoginPermission` for an account without
    /// rights to the mailbox, `UnknownUser` for a distinguished name it cannot map — or
    /// [`Error::WrongServer`] if the mailbox has moved. Whatever the reason, this connection's
    /// Session Context is torn down on the way out rather than left for the server to time out.
    ///
    /// [MS-OXCROPS] §2.2.3.1 — `RopLogon`
    pub async fn logon(mut self) -> Result<Logon> {
        let mut batch = RopBatch::new();
        let slot = batch.logon(&self.user_dn.clone());

        let execution = match self.execute(batch, "the logon").await {
            Ok(execution) => execution,
            Err(error) => {
                self.close_quietly().await;
                return Err(error);
            }
        };

        let (Some(response), Some(handle)) = (execution.logon(), execution.handle(slot)) else {
            self.close_quietly().await;
            return Err(Error::Unexpected {
                expected: "a RopLogon response",
                found: "no logon in the batch's responses",
            });
        };

        self.logon = Some(LogonState::new(handle, response.clone()));
        Ok(Logon::new(self, handle, response.clone()))
    }

    /// Tears the Session Context down.
    ///
    /// **Allowed on a poisoned connection**, which is when it matters most: a request that failed
    /// or was abandoned still left a Session Context on the server, holding whatever handles it
    /// had, and disconnecting frees it now rather than when it times out.
    ///
    /// That takes a second step when the server finished the request the client gave up on.
    /// Exchange advances a sequence cookie on every response, so the `Disconnect` carries the
    /// value from before the response nobody read and is refused as `X-ResponseCode` 15 —
    /// measured against Exchange Server SE `15.02.2562.056`, for a contents-table read abandoned
    /// 13 ms in. [MS-OXCMAPIHTTP] §3.1.5.7's reconnect is then the way to free the old context: a
    /// `Connect` passing its cookies "allows the server to clean up the previous context", and the
    /// new context it creates is disconnected in turn. Measured on the same build by the server's
    /// own `MSExchange MapiHttp Emsmdb\Connection Count`: back to zero after three refused
    /// disconnects with the reconnect, and left at three without it.
    ///
    /// # Cancellation
    ///
    /// Safe to drop at any await. A Session Context left behind times out on its own.
    ///
    /// # Errors
    ///
    /// Whatever the round trip failed with. A failure here has already cost nothing: the server
    /// times an abandoned Session Context out on its own.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.3 — `Disconnect`
    /// [MS-OXCMAPIHTTP] §3.1.5.7 — reconnecting, passing the old context's cookies
    pub async fn disconnect(mut self) -> Result<()> {
        // A lost or dropped request leaves the session waiting on an answer nobody will hand it,
        // and a session that is waiting refuses to send anything else.
        self.session.abandon();
        self.poison = None;
        let abandoned = self.session.is_abandoned();

        match self.disconnect_once().await {
            Err(Error::Protocol(mapi_proto::Error::Transport { code, .. }))
                if abandoned && code == ResponseCode::INVALID_SEQUENCE =>
            {
                let request = self.session.begin_reconnect(&self.user_dn)?;
                match self.round_trip(request).await? {
                    Outcome::Connected(_) => self.disconnect_once().await,
                    other => Err(Error::Unexpected {
                        expected: "a Connect response",
                        found: describe(&other),
                    }),
                }
            }
            // Nothing to tear down: the server has no Session Context for these cookies, which is
            // what a successful Disconnect would have left.
            Err(Error::SessionLost { .. }) => Ok(()),
            other => other,
        }
    }

    /// One `Disconnect` round trip.
    async fn disconnect_once(&mut self) -> Result<()> {
        let request = self.session.begin_disconnect()?;
        match self.round_trip(request).await? {
            Outcome::Disconnected => Ok(()),
            other => Err(Error::Unexpected {
                expected: "a Disconnect response",
                found: describe(&other),
            }),
        }
    }

    /// Tears the Session Context down without reporting whether it worked.
    ///
    /// For the error paths, where the caller already has a more informative failure in hand and a
    /// second one would only bury it. Skipped entirely when the connection is poisoned, because
    /// then the round trip is known to be pointless.
    async fn close_quietly(&mut self) {
        if self.poison.is_some() {
            return;
        }
        if let Ok(request) = self.session.begin_disconnect() {
            let _ = self.round_trip(request).await;
        }
    }

    /// Runs a batch of ROPs and reports the first refusal in it as an error.
    ///
    /// A failing ROP does not fail the `Execute` — the server runs what it can and reports each
    /// result — so a caller that only checked the transport would read a plausible-looking empty
    /// answer instead of a refusal.
    pub(crate) async fn execute(
        &mut self,
        batch: RopBatch,
        during: &'static str,
    ) -> Result<Execution> {
        let execution = self.execute_allowing_refusals(batch).await?;

        for response in execution.responses() {
            if let Some(error) = refusal(response, during) {
                return Err(error);
            }
        }
        Ok(execution)
    }

    /// Runs a batch and hands back every response, refusals included.
    ///
    /// For the case where a refusal is an answer rather than a failure. Resolving the special
    /// folders asks the server to convert up to eight entry ids in one batch, and a mailbox whose
    /// Archive folder has been removed answers for that one and not the others — failing the whole
    /// enumeration over it would report seven folders that exist as none at all.
    ///
    /// Everything below the ROP layer is still an error here: a refused `Execute`, a poisoned
    /// connection and a response that is not an `Execute` at all all come back as one.
    pub(crate) async fn execute_allowing_refusals(
        &mut self,
        mut batch: RopBatch,
    ) -> Result<Execution> {
        // A connection already known to be lost is replaced rather than refused, poisoned or not:
        // the reconnect is what clears the poison, and a failed one leaves it to try again here.
        if self.lost.is_none() {
            self.usable()?;
        }
        let carries_over = batch.binds_only_the_logon();
        let lost = if let Some(lost) = self.lost.clone() {
            lost
        } else {
            // A copy only of a batch that could be sent again: one holding any other handle never
            // is, and copying every page read and attachment chunk to throw it away costs for
            // nothing.
            let spare = carries_over.then(|| batch.clone());
            match self.send(batch).await {
                Err(Error::SessionLost { code, diagnostic }) => {
                    let Some(spare) = spare else {
                        self.reconnect().await?;
                        return Err(Error::SessionLost { code, diagnostic });
                    };
                    batch = spare;
                    Lost::new(code, diagnostic)
                }
                other => return other,
            }
        };

        // The server ran none of it — every code that means "lost" refuses a request before it is
        // processed — so it is safe to send again, a write included, if it still means anything.
        self.reconnect().await?;
        if !carries_over {
            return Err(lost.into_error());
        }
        self.send(batch).await
    }

    /// One `Execute`, aimed at the current Session Context's logon.
    async fn send(&mut self, mut batch: RopBatch) -> Result<Execution> {
        if let Some(logon) = &self.logon {
            batch.rebind_logon(logon.handle());
        }
        let riding = self.add_releases(&mut batch);
        let request = self.session.execute(batch)?;
        let outcome = self.round_trip(request).await;
        // Kept for the next request only when the server never saw this one. Otherwise it may have
        // released them, and releasing a value twice could free whatever it was handed to next.
        if !outcome
            .as_ref()
            .is_err_and(|error| matches!(error.delivery(), Delivery::NotSent | Delivery::Refused))
        {
            self.released(&riding);
        }
        let outcome = outcome?;

        let Outcome::Executed(execution) = outcome else {
            return Err(Error::Unexpected {
                expected: "an Execute response",
                found: describe(&outcome),
            });
        };
        Ok(execution)
    }

    /// Sends one request and interprets the answer, poisoning the connection if it never arrived.
    ///
    /// Poisoned *before* the await and cleared after it. A future dropped mid-request never runs
    /// the second half, so what it leaves is a connection that says the request was abandoned —
    /// not one whose session is still waiting for an answer, which would refuse even the
    /// disconnect that frees the server's context.
    async fn round_trip(&mut self, request: Request) -> Result<Outcome> {
        self.poison = Some(Cow::Borrowed(ABANDONED));
        let sent = Instant::now();
        let mut reply = self.transport.send(&request).await;
        if reply
            .as_ref()
            .is_err_and(|error| error.delivery() == Delivery::NotSent)
        {
            // [MS-OXCMAPIHTTP] §3.1.7.1: nothing reached the server, so the client "establishes a
            // new HTTP connection, passing all existing cookies for the Session Context, and then
            // resubmits the request as-is". The failed connection is not reused; the request is.
            reply = self.transport.send(&request).await;
        }
        match reply {
            Ok((headers, body)) => {
                self.poison = None;
                let outcome = self.session.on_response(&headers, &body);
                // Kept from the last response that said, rather than cleared by one that did not:
                // a refusal carries no expiration, and says nothing about the deadline it lacks.
                if let Some(lifetime) = self.session.expiration() {
                    self.expires_at = sent.checked_add(lifetime);
                }
                outcome.map_err(|error| {
                    let error = self.lose(error);
                    // Accepted and then failed: what ran is unknown, and the session no longer
                    // knows its own handle table, so nothing more goes into this Session Context.
                    if error.delivery() == Delivery::Unknown {
                        self.poison = Some(Cow::Owned(error.to_string()));
                    }
                    error
                })
            }
            Err(error) => {
                match error.delivery() {
                    // The server never had it, or refused it unread: the Session Context is as it
                    // was, and the request is taken back so that sending it again is the same
                    // request rather than the next one.
                    Delivery::NotSent | Delivery::Refused => {
                        self.session.retract();
                        self.poison = None;
                    }
                    // The request went out and no answer came back, so whether the server acted on
                    // it is unknowable ([MS-OXCMAPIHTTP] §3.1.7.2). Sending the next request
                    // regardless is how a client ends up reading the answer to the previous one.
                    _ => self.poison = Some(Cow::Owned(error.to_string())),
                }
                Err(error)
            }
        }
    }

    fn usable(&self) -> Result<()> {
        match &self.poison {
            Some(cause) => Err(Error::Poisoned {
                cause: cause.clone().into_owned(),
            }),
            None => Ok(()),
        }
    }
}
