//! Kerberos for `Negotiate`: where a realm's KDCs are, talking to them, and keeping the tickets.
//!
//! `mapi-auth` writes and reads every Kerberos message; this module carries them. It finds a
//! realm's KDCs — an address the caller gave, or DNS SRV `_kerberos._tcp.<realm>` ([RFC 4120]
//! §7.2.3.2, [MS-KILE] §3.2.3) answered by a resolver the host supplies — sends each message over
//! TCP, and keeps the tickets it gets so that a second connection costs an AP-REQ and not another
//! trip to the KDC. It remembers what came to nothing, too — a realm whose KDCs did not answer, a
//! service the KDC would not issue a ticket for — for a minute, so that every new connection does
//! not wait for the same failure before falling back to NTLM.
//!
//! # Why the resolver is the host's
//!
//! The DNS a device actually uses — its VPN's split DNS, a corporate resolver, an Android private
//! DNS setting — is the operating system's, and the platform's own resolver is the one that knows
//! it. So the lookup is a trait, [`SrvResolver`], which a host implements with that resolver. The
//! `hickory-dns` feature supplies an implementation for a caller who has none, reading the system's
//! resolver configuration; and [`KdcLocator::kdc`] names a KDC outright, which overrides both.
//!
//! Without a resolver and without a named KDC there is no KDC to ask, and `Negotiate` uses NTLM —
//! which [`MapiClient::authentication`](crate::MapiClient::authentication) reports, with the
//! reason, so that a deployment meant to run Kerberos can tell that it is not.

mod kdc;

#[cfg(feature = "hickory-dns")]
mod hickory;

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use mapi_auth::{
    Identity, KerberosEntropy, ServiceTicket, TicketGrantingTicket, TicketRequest, TicketStep,
};

use crate::error::{Error, Result};

/// One SRV record — [RFC 2782]'s target, port, priority and weight.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SrvRecord {
    /// Lower is tried first.
    pub priority: u16,
    /// Among records of one priority, the share of clients that should try this one first.
    pub weight: u16,
    /// The port.
    pub port: u16,
    /// The host. `.` alone means the service is decidedly not available ([RFC 2782]).
    pub target: String,
}

impl SrvRecord {
    /// A record, as a resolver read it.
    #[must_use]
    pub fn new(priority: u16, weight: u16, port: u16, target: impl Into<String>) -> Self {
        Self {
            priority,
            weight,
            port,
            target: target.into(),
        }
    }
}

/// What a resolver hands back: the records, or the reason there are none.
pub type SrvLookup<'a> = Pin<Box<dyn Future<Output = std::io::Result<Vec<SrvRecord>>> + Send + 'a>>;

/// Looks up DNS SRV records, the way the host's own resolver does.
///
/// Return an empty list for a name with no records, and an error only when the lookup itself
/// failed. Either way `Negotiate` goes on with NTLM, and says why.
pub trait SrvResolver: Send + Sync + core::fmt::Debug {
    /// The SRV records for `name` — `_kerberos._tcp.EXAMPLE.TEST`, say.
    fn resolve<'a>(&'a self, name: &'a str) -> SrvLookup<'a>;
}

/// Where `Negotiate` finds a realm's KDCs.
///
/// Explicit addresses come first and are used alone for their realm; every other realm is looked
/// up through the resolver. A referral can take an exchange through more than one realm, so the
/// resolver is the usual answer and an explicit KDC the exception — a lab, a test, a realm the
/// host's DNS does not publish.
#[derive(Clone, Debug, Default)]
pub struct KdcLocator {
    resolver: Option<Arc<dyn SrvResolver>>,
    kdcs: Vec<(String, String)>,
}

impl KdcLocator {
    /// A locator with no resolver and no KDCs — which, without the `hickory-dns` feature, finds
    /// nothing until one of the two is added.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks KDCs up through `resolver`.
    #[must_use]
    pub fn resolver(mut self, resolver: Arc<dyn SrvResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Uses `address` — `host` or `host:port`, port 88 if none ([RFC 4120] §7.2.2) — as a KDC
    /// for `realm`. Call it more than once to name more than one, tried in order.
    #[must_use]
    pub fn kdc(mut self, realm: impl Into<String>, address: impl Into<String>) -> Self {
        self.kdcs.push((realm.into(), address.into()));
        self
    }
}

/// What looking for a service ticket came to.
#[derive(Clone, Debug)]
pub(crate) enum Acquired {
    /// A ticket, for `Negotiate` to offer.
    Ticket(ServiceTicket),
    /// No ticket, for this reason; `Negotiate` goes on with NTLM.
    Unavailable(String),
    /// A KDC refused the credential itself — a wrong password, a disabled, locked or expired
    /// account — which NTLM would only report less clearly, so it is reported instead.
    Refused(mapi_auth::Error),
}

/// The Kerberos side of one client: its locator, what is known of the realms it found, and the
/// tickets it has got.
///
/// Shared by a client's clones and by [`for_mailbox`](crate::MapiClient::for_mailbox), so that the
/// tickets are too.
#[derive(Debug, Default)]
pub(crate) struct Kerberos {
    locator: KdcLocator,
    /// Which KDCs answered, and which realms had none that did — about the KDCs rather than the
    /// account, so a client that authenticates as someone else keeps it.
    realms: Arc<kdc::Realms>,
    cache: Mutex<Cache>,
    /// Held while the KDCs are asked, so that connections authenticating at once ask once: the
    /// rest wait, and find the ticket — or the reason there is none — in the cache.
    asking: tokio::sync::Mutex<()>,
}

/// Tickets kept for reuse, all for the one account a client authenticates as.
#[derive(Debug, Default)]
struct Cache {
    tgt: Option<TicketGrantingTicket>,
    services: Vec<(String, ServiceTicket)>,
    /// Services whose last request came to no ticket, until when that is believed, and why: a
    /// service the KDC does not know, say, is not asked about again by every new connection.
    unavailable: Vec<(String, Instant, String)>,
}

/// How long before its end a ticket stops being reused: [RFC 4120] §1.6's customary five minutes
/// of clock skew, so that a ticket is not presented to a server whose clock has already passed it.
const MARGIN: Duration = Duration::from_mins(5);

impl crate::MapiClientBuilder {
    /// Where `Negotiate` finds Kerberos KDCs. See [`KdcLocator`].
    ///
    /// Without it — or with a locator that finds none for a realm — `Negotiate` uses NTLM, and
    /// [`MapiClient::authentication`](crate::MapiClient::authentication) says why. With the
    /// `hickory-dns` feature, a locator with no resolver uses the system's DNS.
    #[must_use]
    pub fn kdc_locator(mut self, locator: KdcLocator) -> Self {
        self.kerberos = Arc::new(Kerberos::new(locator));
        self
    }
}

impl Kerberos {
    pub(crate) fn new(locator: KdcLocator) -> Self {
        Self {
            locator,
            realms: Arc::default(),
            cache: Mutex::default(),
            asking: tokio::sync::Mutex::default(),
        }
    }

    /// Why a ticket for `service` is not worth asking the KDCs for, when that is known without
    /// asking them: an account that names no realm, a realm with no KDC named and no resolver to
    /// find one, a service whose last request came to nothing less than
    /// [`RETRY_AFTER`](kdc::RETRY_AFTER) ago, or a realm none of whose KDCs answered.
    ///
    /// `None` means a ticket may be had — cached already, or worth the trip.
    pub(crate) fn unavailable(&self, identity: &Identity, service: &str) -> Option<String> {
        let Some(realm) = identity.kerberos_realm() else {
            return Some(format!(
                "{:?} names no realm: give user@realm, or a realm with Identity::realm",
                identity.username()
            ));
        };
        if let Some(reason) = kdc::unlocatable(&self.locator, &realm) {
            return Some(reason);
        }
        let (wall, now) = (now(), Instant::now());
        {
            let cache = self.lock();
            if cache
                .services
                .iter()
                .any(|(name, ticket)| name == service && fresh(ticket.expires(), wall))
            {
                return None;
            }
            if let Some((_, _, reason)) = cache
                .unavailable
                .iter()
                .find(|(name, until, _)| name == service && *until > now)
            {
                return Some(reason.clone());
            }
        }
        self.realms.unreachable(&realm, now)
    }

    /// A ticket for `service` (`HTTP/host`), from the cache or from the KDCs, waiting at most
    /// `timeout` for each KDC — and, when there is none to be had, remembering why for
    /// [`unavailable`](Self::unavailable) to say.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] if the operating system will not produce randomness. Everything the KDCs
    /// say is an [`Acquired`].
    pub(crate) async fn ticket(
        &self,
        identity: &Identity,
        service: &str,
        timeout: Duration,
    ) -> Result<Acquired> {
        // A ticket already held needs no turn: the lock is for asking the KDCs, and a connection
        // with a ticket to hand would otherwise wait out another service's KDC exchange for it.
        if let Some(ticket) = self.cached(service, now()) {
            return Ok(Acquired::Ticket(ticket));
        }
        let _asking = self.asking.lock().await;
        // Another connection may have asked while this one waited, and come to nothing: a KDC
        // that did not answer it would not answer this one either.
        if let Some(reason) = self.unavailable(identity, service) {
            return Ok(Acquired::Unavailable(reason));
        }
        let acquired = self.acquire(identity, service, timeout).await?;
        if let Acquired::Unavailable(reason) = &acquired {
            let now = Instant::now();
            let until = now.checked_add(kdc::RETRY_AFTER).unwrap_or(now);
            let mut cache = self.lock();
            cache
                .unavailable
                .retain(|(name, until, _)| name != service && *until > now);
            cache
                .unavailable
                .push((service.to_owned(), until, reason.clone()));
        }
        Ok(acquired)
    }

    async fn acquire(
        &self,
        identity: &Identity,
        service: &str,
        timeout: Duration,
    ) -> Result<Acquired> {
        let now = now();
        if let Some(ticket) = self.cached(service, now) {
            return Ok(Acquired::Ticket(ticket));
        }
        let mut tgt = self
            .lock()
            .tgt
            .clone()
            .filter(|tgt| fresh(tgt.expires(), now));

        let tickets = loop {
            let started = match &tgt {
                Some(tgt) => TicketRequest::with_tgt(tgt, service, &entropy()?),
                None => TicketRequest::new(identity, service, &entropy()?),
            };
            let (request, message) = match started {
                Ok(started) => started,
                Err(error) => return Ok(Acquired::Unavailable(error.to_string())),
            };
            match self.run(request, message, timeout).await? {
                Ok(tickets) => break tickets,
                // A TGT the KDC will no longer honour — revoked, expired by the KDC's clock, or
                // under a key since rolled over — is dropped and the password asked instead,
                // rather than kept until its end time while every handshake falls back to NTLM.
                Err(Failure::StaleTgt(_)) if tgt.is_some() => {
                    self.lock().tgt = None;
                    tgt = None;
                }
                Err(Failure::StaleTgt(reason)) => return Ok(Acquired::Unavailable(reason)),
                Err(Failure::Acquired(acquired)) => return Ok(acquired),
            }
        };

        let (ticket, tgt) = tickets.into_parts();
        let mut cache = self.lock();
        cache.tgt = Some(tgt);
        // Expired tickets go too, so that a client that has asked for many services — one per
        // Autodiscover candidate, say — does not keep every ticket it ever held.
        cache
            .services
            .retain(|(name, held)| name != service && fresh(held.expires(), now));
        cache.services.push((service.to_owned(), ticket.clone()));
        Ok(Acquired::Ticket(ticket))
    }

    /// The cached ticket for `service`, if it is still fresh at `now`.
    fn cached(&self, service: &str, now: Duration) -> Option<ServiceTicket> {
        self.lock()
            .services
            .iter()
            .find(|(name, ticket)| name == service && fresh(ticket.expires(), now))
            .map(|(_, ticket)| ticket.clone())
    }

    /// Drops the cached ticket for `service`, which the server refused: a ticket under a key the
    /// service no longer has would otherwise be offered, and refused, until its end time.
    pub(crate) fn forget(&self, service: &str) {
        self.lock().services.retain(|(name, _)| name != service);
    }

    /// The same locator and realms with no tickets, for a client that authenticates as someone
    /// else.
    pub(crate) fn without_tickets(&self) -> Self {
        Self {
            locator: self.locator.clone(),
            realms: Arc::clone(&self.realms),
            cache: Mutex::default(),
            asking: tokio::sync::Mutex::default(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Carries a request's messages to the KDCs of whichever realms it names.
    async fn run(
        &self,
        mut request: TicketRequest,
        mut message: mapi_auth::KdcMessage,
        timeout: Duration,
    ) -> Result<core::result::Result<mapi_auth::Tickets, Failure>> {
        let unavailable =
            |reason: String| Ok(Err(Failure::Acquired(Acquired::Unavailable(reason))));
        loop {
            let reply = match kdc::send(&self.locator, &self.realms, &message, timeout).await {
                Ok(reply) => reply,
                Err(reason) => return unavailable(reason),
            };
            match request.receive(&reply, &entropy()?) {
                Ok(TicketStep::Send(next)) => message = next,
                Ok(TicketStep::Done(tickets)) => return Ok(Ok(tickets)),
                Ok(_) => return unavailable("an unknown step".to_owned()),
                Err(error) if about_the_credential(&error) => {
                    return Ok(Err(Failure::Acquired(Acquired::Refused(error))));
                }
                Err(error) if about_the_tgt(&error) => {
                    return Ok(Err(Failure::StaleTgt(error.to_string())));
                }
                Err(error) => return unavailable(error.to_string()),
            }
        }
    }
}

/// Why [`Kerberos::run`] came back without tickets.
enum Failure {
    /// What to report.
    Acquired(Acquired),
    /// The TGT a request started from was refused, which the password may yet get past.
    StaleTgt(String),
}

/// Whether a KDC's refusal is about the ticket-granting ticket presented — [RFC 4120] §7.5.9's
/// `KDC_ERR_TGT_REVOKED` (20), `KRB_AP_ERR_TKT_EXPIRED` (32) and `KRB_AP_ERR_MODIFIED` (41).
fn about_the_tgt(error: &mapi_auth::Error) -> bool {
    matches!(
        error,
        mapi_auth::Error::KdcRefused {
            code: 20 | 32 | 41,
            ..
        }
    )
}

/// Whether a KDC's refusal is about the password or the account — [RFC 4120] §7.5.9's
/// `KDC_ERR_CLIENT_REVOKED` (18), `KDC_ERR_KEY_EXPIRED` (23) and `KDC_ERR_PREAUTH_FAILED` (24) —
/// which no other mechanism would fare better with.
fn about_the_credential(error: &mapi_auth::Error) -> bool {
    matches!(
        error,
        mapi_auth::Error::KdcRefused {
            code: 18 | 23 | 24,
            ..
        }
    )
}

/// Whether a ticket ending at `expires` is still worth presenting at `now`.
fn fresh(expires: Duration, now: Duration) -> bool {
    expires > now.saturating_add(MARGIN)
}

fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Sixty-four bytes from the operating system and the time, for one Kerberos message.
///
/// # Errors
///
/// [`Error::Setup`] if the operating system will not produce randomness, as for NTLM's challenge.
pub(crate) fn entropy() -> Result<KerberosEntropy> {
    let mut random = [0u8; 64];
    getrandom::fill(&mut random).map_err(|error| Error::Setup {
        source: Box::new(error),
    })?;
    Ok(KerberosEntropy::new(random, stamp()))
}

/// The time for one Kerberos message: the clock's, but never the same twice in this process.
///
/// A server keeps the authenticators it has seen and rejects a second with the same time as a
/// replay, so "Client implementations SHOULD ensure that the timestamps are not reused, possibly by
/// incrementing the microseconds field in the time stamp when the clock returns the same time for
/// multiple requests" ([RFC 4120] §3.2.3). Connections authenticating at once can build their
/// AP-REQs within one tick of the clock; one after another, they could not.
fn stamp() -> Duration {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let clock = u64::try_from(now().as_micros()).unwrap_or(u64::MAX);
    let next = |last: u64| clock.max(last.saturating_add(1));
    let last = LAST
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
            Some(next(last))
        })
        .unwrap_or_else(|last| last);
    Duration::from_micros(next(last))
}

#[cfg(test)]
mod tests;
