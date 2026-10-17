//! The connections NTLM and `Negotiate` authenticate, each a client of its own.
//!
//! # Why one HTTP client per connection
//!
//! Both schemes authenticate a TCP connection, and `reqwest` offers no way to pin a request to
//! one. What it does offer is close to deterministic under one condition, measured rather than
//! assumed: **a client with one request in flight at a time reuses its one idle connection**, and
//! the same client given four concurrent requests opens up to four. So each connection here is a
//! client of its own — a *lane* — built with `pool_max_idle_per_host(1)` and lent to one request at
//! a time.
//!
//! Close to, not quite: a request sent before the last one's connection is back in the pool starts
//! a second connection alongside, and takes whichever is ready first. Where that matters — a
//! handshake leg landing on a connection the server never challenged — each reply's connection
//! says so, and the handshake starts again; see [`moved`](crate::handshake::moved).
//!
//! A request borrows a lane, preferring one already authenticated to its origin; with none idle it
//! builds another, up to
//! [`max_authenticated_connections`](crate::MapiClientBuilder::max_authenticated_connections), and
//! past that it waits for one to come back. A request that had to wait for its turn to authenticate
//! trades its lane for one the turn before it authenticated, when that one is idle by then: a
//! handshake saved is a logon the domain controller does not see.
//!
//! # One password at a time until one has worked
//!
//! Each new lane runs a handshake of its own, and a handshake carrying a wrong password is a failed
//! logon to the domain controller. Concurrent requests on a fresh client would each run one, and an
//! account lockout policy counts every one of them. So until a handshake has succeeded, they take
//! turns, and a handshake refused while others waited for their turn refuses those too: they would
//! have sent the same credential. A request that arrives afterwards tries again — the caller's
//! decision, not this pool's.
//!
//! The same holds once a connection believed authenticated is refused: the password may have
//! changed, so the handshakes that follow take turns again until one works. And all of it is per
//! origin — what one server refused says nothing certain about another, which may not even offer
//! the same scheme.

use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use reqwest::Client;
use tokio::sync::{OwnedMutexGuard, Semaphore, SemaphorePermit};

use crate::error::{Error, Result};
use crate::transport::HttpSettings;

/// How many connections a client authenticates at once unless told otherwise.
pub(crate) const DEFAULT_CONNECTIONS: NonZeroUsize = match NonZeroUsize::new(4) {
    Some(connections) => connections,
    None => NonZeroUsize::MIN,
};

impl crate::MapiClientBuilder {
    /// The most connections NTLM or `Negotiate` authenticate at once — and so the most requests
    /// such a client and its clones run concurrently, with every client
    #[cfg_attr(
        feature = "autodiscover",
        doc = " [`for_mailbox`](crate::MapiClient::for_mailbox)"
    )]
    #[cfg_attr(not(feature = "autodiscover"), doc = " `for_mailbox`")]
    /// makes from it. Defaults to 4.
    ///
    /// Each connection costs one handshake, the first time it is used. A request that finds every
    /// connection busy opens another, up to this many, and past it waits for one to come back.
    /// [`Credentials::Basic`](crate::Credentials::Basic) and
    /// [`Credentials::Bearer`](crate::Credentials::Bearer) authenticate each request rather than a
    /// connection, so any connection serves them and this does not apply.
    #[must_use]
    pub const fn max_authenticated_connections(mut self, connections: NonZeroUsize) -> Self {
        self.connections = connections;
        self
    }
}

/// The lanes of one client and its clones.
#[derive(Debug)]
pub(crate) struct Pool {
    settings: HttpSettings,
    /// One permit per lane there may be: a request holds one for as long as it holds a lane.
    permits: Semaphore,
    /// The lanes no request holds, the most recently returned last.
    idle: Mutex<Vec<Lane>>,
    /// Each origin's [`Gate`].
    gates: Mutex<Vec<(String, Arc<Gate>)>>,
}

/// One connection's client, and the origins it is believed to be authenticated to.
///
/// A belief rather than a fact: nothing proves the server kept the connection, so a 401 on one of
/// them means "authenticate again" rather than an error.
#[derive(Debug)]
struct Lane {
    http: Client,
    authenticated: Vec<String>,
}

/// A lane lent to one request, returned to the pool when dropped — also when the request is
/// cancelled part way through, since its client discards a connection it did not finish with.
#[derive(Debug)]
pub(crate) struct Lease<'a> {
    pool: &'a Pool,
    lane: Lane,
    origin: String,
    _permit: SemaphorePermit<'a>,
}

/// Whether a handshake to one origin has succeeded since the last refusal, and the turns the
/// handshakes take until one has.
#[derive(Debug, Default)]
struct Gate {
    proven: AtomicBool,
    turn: Arc<tokio::sync::Mutex<()>>,
    refusals: Mutex<Refusals>,
}

/// How many handshakes have been refused, and what the server offered and was sent the last time.
#[derive(Debug, Default)]
struct Refusals {
    count: u64,
    last: Option<(Vec<String>, &'static str)>,
}

/// A request's turn to run a handshake: held until [`settle`](Self::settle) while no handshake
/// has succeeded, and nothing at all once one has.
#[derive(Debug)]
pub(crate) struct Turn {
    gate: Arc<Gate>,
    _held: Option<OwnedMutexGuard<()>>,
}

impl Pool {
    /// A pool of up to `settings.connections` lanes, the first of them `first` — the client the
    /// builder made.
    pub(crate) fn new(first: Client, settings: HttpSettings) -> Self {
        Self {
            permits: Semaphore::new(settings.connections.get()),
            settings,
            idle: Mutex::new(vec![Lane {
                http: first,
                authenticated: Vec::new(),
            }]),
            gates: Mutex::default(),
        }
    }

    /// Lends a lane for a request to `origin`, waiting while every lane is lent.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] if a new lane's client cannot be built — which the first one was, from the
    /// same settings.
    pub(crate) async fn lease(&self, origin: String) -> Result<Lease<'_>> {
        let permit = self.permits.acquire().await.map_err(|error| Error::Setup {
            source: Box::new(error),
        })?;
        let idle = {
            let mut idle = self.idle();
            let warm = idle
                .iter()
                .rposition(|lane| lane.authenticated.contains(&origin));
            match warm {
                Some(index) => Some(idle.remove(index)),
                None => idle.pop(),
            }
        };
        let lane = match idle {
            Some(lane) => lane,
            None => Lane {
                http: self.settings.client()?,
                authenticated: Vec::new(),
            },
        };
        Ok(Lease {
            pool: self,
            lane,
            origin,
            _permit: permit,
        })
    }

    /// Waits for the turn of `lease`'s request — to `url` — to run a handshake.
    ///
    /// # Errors
    ///
    /// [`Error::Unauthorized`], naming `url`, if a handshake to the same origin was refused while
    /// this one waited: it would have sent the same credential to the same server.
    pub(crate) async fn turn(&self, lease: &Lease<'_>, url: &str) -> Result<Turn> {
        let gate = self.gate(&lease.origin);
        if gate.proven.load(Ordering::Acquire) {
            return Ok(Turn { gate, _held: None });
        }
        let seen = gate.refusals().count;
        let held = Arc::clone(&gate.turn).lock_owned().await;
        let refused = {
            let refusals = gate.refusals();
            (refusals.count != seen)
                .then(|| refusals.last.clone())
                .flatten()
        };
        if let Some((offered, sent)) = refused {
            return Err(Error::Unauthorized {
                url: url.to_owned(),
                offered,
                sent,
            });
        }
        let held = (!gate.proven.load(Ordering::Acquire)).then_some(held);
        Ok(Turn { gate, _held: held })
    }

    /// `origin`'s gate, made on first use.
    fn gate(&self, origin: &str) -> Arc<Gate> {
        let mut gates = self
            .gates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((_, gate)) = gates.iter().find(|(known, _)| known == origin) {
            return Arc::clone(gate);
        }
        let gate = Arc::<Gate>::default();
        gates.push((origin.to_owned(), Arc::clone(&gate)));
        gate
    }

    fn idle(&self) -> std::sync::MutexGuard<'_, Vec<Lane>> {
        self.idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Lease<'_> {
    /// The lane's client.
    pub(crate) const fn http(&self) -> &Client {
        &self.lane.http
    }

    /// Whether the lane is believed authenticated to this request's origin.
    pub(crate) fn is_authenticated(&self) -> bool {
        self.lane.authenticated.contains(&self.origin)
    }

    /// Records whether the lane is authenticated to this request's origin.
    pub(crate) fn set_authenticated(&mut self, authenticated: bool) {
        let origin = &self.origin;
        self.lane.authenticated.retain(|known| known != origin);
        if authenticated {
            self.lane.authenticated.push(origin.clone());
        }
    }

    /// Records that a connection believed authenticated to this origin was refused, so that the
    /// handshakes that follow take turns until one works: the password may have changed.
    pub(crate) fn doubt(&self) {
        self.pool
            .gate(&self.origin)
            .proven
            .store(false, Ordering::Release);
    }

    /// Trades a lane not authenticated to this origin for an idle one that is, if there is one.
    pub(crate) fn trade_for_warm(&mut self) {
        if self.is_authenticated() {
            return;
        }
        let pool = self.pool;
        let mut idle = pool.idle();
        if let Some(index) = idle
            .iter()
            .rposition(|lane| lane.authenticated.contains(&self.origin))
        {
            let warm = idle.remove(index);
            idle.push(core::mem::replace(&mut self.lane, warm));
        }
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let lane = Lane {
            http: self.lane.http.clone(),
            authenticated: core::mem::take(&mut self.lane.authenticated),
        };
        self.pool.idle().push(lane);
    }
}

impl Gate {
    fn refusals(&self) -> std::sync::MutexGuard<'_, Refusals> {
        self.refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Turn {
    /// Records what the handshake came to — whether it left the connection `authenticated`, and
    /// the request's `outcome` — and gives up the turn.
    ///
    /// A refusal is remembered for whoever was waiting, and makes handshakes take turns again —
    /// a password changed or an account locked since the last success refuses every connection
    /// alike. Any other failure is neither: the next request in line tries for itself.
    pub(crate) fn settle<T>(self, authenticated: bool, outcome: &Result<T>) {
        match outcome {
            _ if authenticated => self.gate.proven.store(true, Ordering::Release),
            Err(Error::Unauthorized { offered, sent, .. }) => {
                self.gate.proven.store(false, Ordering::Release);
                let mut refusals = self.gate.refusals();
                refusals.count = refusals.count.wrapping_add(1);
                refusals.last = Some((offered.clone(), *sent));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
