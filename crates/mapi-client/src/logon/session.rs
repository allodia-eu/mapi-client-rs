//! The Session Context under a logon: when it expires, keeping it alive, and replacing it.
//!
//! Each of these is the [`Connection`](crate::Connection)'s, which the logon owns; see it for what
//! they do.

use std::time::Instant;

use super::Logon;
use crate::error::Result;

impl Logon {
    /// Replaces the Session Context with a new one and logs on again. See
    /// [`Connection::reconnect`](crate::Connection::reconnect).
    ///
    /// Not needed when the server loses the context, which is re-established on the request that
    /// finds out. Named properties stay resolved unless the new logon names another mailbox — a
    /// restored or moved one — in which case they are asked for afresh.
    ///
    /// # Cancellation
    ///
    /// Safe to drop at any await. The connection stays marked as lost, and its next request
    /// re-establishes it.
    ///
    /// # Errors
    ///
    /// As [`Connection::reconnect`](crate::Connection::reconnect).
    pub async fn reconnect(&mut self) -> Result<()> {
        self.connection.reconnect().await
    }

    /// How many times this logon's Session Context has been replaced, by a [`reconnect`] or by
    /// recovering from a lost one.
    ///
    /// [`reconnect`]: Self::reconnect
    #[must_use]
    pub const fn reconnects(&self) -> u64 {
        self.connection.reconnects()
    }

    /// When the server will time this logon's Session Context out if nothing more is sent. See
    /// [`Connection::expires_at`](crate::Connection::expires_at).
    #[must_use]
    pub const fn expires_at(&self) -> Option<Instant> {
        self.connection.expires_at()
    }

    /// Keeps the Session Context alive, and returns its new deadline. See
    /// [`Connection::keep_alive`](crate::Connection::keep_alive).
    ///
    /// # Cancellation
    ///
    /// Safe to drop at any await. A future dropped while its request is in flight leaves the
    /// connection [poisoned](crate::Connection#cancellation), never wedged, and
    /// [`reconnect`](crate::Connection::reconnect) makes it usable again. Nothing was changed, so
    /// the call can simply be made again.
    ///
    /// # Errors
    ///
    /// As [`Connection::keep_alive`](crate::Connection::keep_alive).
    pub async fn keep_alive(&mut self) -> Result<Instant> {
        self.connection.keep_alive().await
    }
}
