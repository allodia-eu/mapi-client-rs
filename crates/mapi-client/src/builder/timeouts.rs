//! How long a request may take, and how long it may go quiet.
//!
//! Two different questions, and a long request needs them kept apart. A server working on a request
//! holds the connection open and says so with a `PENDING` keep-alive, so a request that is slow and
//! one that is dead differ in whether anything arrives, not in how long they take. A bound on the
//! whole exchange cannot tell them apart; a bound on silence can.
//!
//! [MS-OXCMAPIHTTP] §3.1.5.6 — handling a chunked response

use core::time::Duration;

use super::MapiClientBuilder;

/// How long to wait for a whole request/response exchange.
///
/// A server working on a request holds the connection open and emits a `PENDING` keep-alive every
/// 30 seconds by default, so a timeout has to be a multiple of that to mean anything: this one
/// allows three. Anything shorter measures the keep-alive interval rather than the server.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.5 — `X-PendingPeriod`, default 30000 ms
pub(super) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);

/// How long to wait for the TCP connection and TLS handshake alone.
pub(super) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a response may go without a byte arriving.
///
/// Twice the keep-alive interval [MS-OXCMAPIHTTP] §2.2.3.3.5 gives as `X-PendingPeriod`'s default,
/// so one keep-alive lost or late is not called a dead server. Exchange is quicker than it says:
/// measured against Exchange Server SE `15.02.2562.056`, a request the server held open for five
/// and a half minutes announced `X-PendingPeriod: 30000` and sent `PENDING` every 18 seconds, the
/// first after 16.5.
pub(super) const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_mins(1);

impl MapiClientBuilder {
    /// How long a response may go without a byte arriving — the first byte included — before the
    /// request is called a failure. Defaults to a minute.
    ///
    /// The bound a long request needs. The server sends `PROCESSING` as soon as it has queued a
    /// request and `PENDING` while it works on it ([MS-OXCMAPIHTTP] §3.2.5.2), each of which
    /// restarts this clock, so a request that is slow and still alive never trips it, and one
    /// that has gone quiet does. **The bound on the whole exchange still applies alongside it** —
    /// 90 seconds unless [`timeout`](Self::timeout) says otherwise — so a request allowed to take
    /// as long as it stays alive needs [`no_timeout`](Self::no_timeout) as well. [MS-OXCMAPIHTTP]
    /// §3.1.5.6 has the client "abandon a request if no periodic keep-alive response is
    /// received within a reasonable amount of time", which is what this is.
    ///
    /// A request that trips it was sent and never answered, so it fails as [`Error::Timeout`]
    /// with [`Delivery::Unknown`] and poisons its connection.
    ///
    /// [`Error::Timeout`]: crate::Error::Timeout
    /// [`Delivery::Unknown`]: crate::Delivery::Unknown
    #[must_use]
    pub const fn stall_timeout(mut self, timeout: Duration) -> Self {
        self.stall_timeout = timeout;
        self
    }

    /// Takes away the bound on a whole exchange, leaving [`stall_timeout`](Self::stall_timeout)
    /// as the only one — for a caller that would rather bound silence than time.
    #[must_use]
    pub const fn no_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }
}
