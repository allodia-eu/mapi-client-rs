//! Giving up on a request, taking one back, and replacing the Session Context.
//!
//! The three things a caller does when a request goes wrong in transit, kept together because each
//! is defined by how it differs from the other two.
//!
//! [MS-OXCMAPIHTTP] §3.1.7 — handling communication failures

use super::{Pending, Session};
use crate::error::{Error, Result};
use crate::http::{Request, RequestType, connect_body};
use crate::oxcdata::LegacyDn;

impl Session {
    /// Treats an `Execute` that was accepted and then failed as one that was abandoned.
    ///
    /// Failed after `DONE`, or failed as a whole with a non-zero `StatusCode`: either way the
    /// server had the ROPs, and nothing in the response says which of them ran. So what the
    /// session knows of the handle table may be wrong — a table opened, a handle released — and it
    /// is in the state [`abandon`](Self::abandon) leaves: column sets forgotten, and nothing but a
    /// `Disconnect` or a reconnect allowed.
    pub(super) fn lose_track(&mut self) {
        self.abandoned = true;
        self.table_columns.clear();
    }

    /// Forgets the request in flight, for a caller that will never hand its response back.
    ///
    /// The caller's side of cancellation: a transport that dropped a request part way — a
    /// deadline, a `select!` that chose another branch, a connection that failed — calls this
    /// rather than leaving the session waiting for an answer that is not coming, which would refuse
    /// every later request, `Disconnect` included.
    ///
    /// **What the server did with the request is unknowable**, so the session stops there. Once a
    /// request in a Session Context is abandoned, [`execute`](Self::execute) and
    /// [`begin_ping`](Self::begin_ping) are refused and only
    /// [`begin_disconnect`](Self::begin_disconnect) is allowed:
    ///
    /// * An abandoned `Execute` may have opened handles this session never learnt of, or released
    ///   ones whose column sets it still holds — so the handle table is no longer known, and a
    ///   table read against it could decode rows by another table's columns.
    /// * [MS-OXCMAPIHTTP] §3.2.5.1 has the server "fail every subsequent request" with
    ///   `X-ResponseCode` 15 once it sees two at once in a Session Context, and a request the
    ///   client gave up on may still be running there. Disconnecting risks that once, to free the
    ///   server's context now rather than when it times out; anything more would risk it again.
    ///
    /// The remedy [MS-OXCMAPIHTTP] §3.1.7.2 gives for a response that never arrived is a new
    /// Session Context, passing this one's [`cookies`](Self::cookies) so the server can clean the
    /// old one up (§3.1.5.7).
    ///
    /// Before a Session Context exists there is nothing to lose: an abandoned `Connect` or `PING`
    /// leaves the session as it was, free to try again.
    ///
    /// Returns whether a request was in flight. With none, nothing changes.
    pub fn abandon(&mut self) -> bool {
        let abandoned = self.pending.take().is_some();
        if abandoned && self.connected {
            self.abandoned = true;
            self.table_columns.clear();
        }
        abandoned
    }

    /// Takes back the request in flight, for a caller whose transport failed before any of it
    /// reached the server.
    ///
    /// [MS-OXCMAPIHTTP] §3.1.7.1: when a failure occurs "before streaming the request body or
    /// while streaming the request body", the client "resubmits the request as-is" on a new HTTP
    /// connection, and "does not need to re-establish a new Session Context". The server never saw
    /// it, so nothing about the Session Context has changed — unlike [`abandon`](Self::abandon),
    /// which is for a request that may have been acted on and leaves only `Disconnect`. The
    /// request counter is put back as well, so that the same request built again is the same
    /// bytes.
    ///
    /// Whether the server saw any of it is the caller's to know, and a caller that is not sure
    /// must abandon instead: a request retracted after the server acted on it would be sent twice.
    ///
    /// Returns whether a request was in flight. With none, nothing changes.
    pub fn retract(&mut self) -> bool {
        let retracted = self.pending.take().is_some();
        if retracted {
            self.counter = self.counter.saturating_sub(1);
        }
        retracted
    }

    /// Builds a `Connect` that re-establishes this session's Session Context, passing the cookies
    /// of the one it replaces.
    ///
    /// [MS-OXCMAPIHTTP] §3.1.5.7: "the only difference between reconnecting and an initial
    /// connection is that the client passes all existing cookies that are associated with the
    /// previous Session Context", which "allows the server to clean up the previous context in a
    /// timely fashion to prevent session limits from being reached". It is §3.1.7.2's remedy for a
    /// response that never arrived, and the only way to free a context whose `Disconnect` the
    /// server refuses — which is what an [abandoned](Self::abandon) request leaves behind when the
    /// server finished it: Exchange advances a sequence cookie on every response, so the next
    /// request carries the value from before the one the client never read, and is refused as
    /// `X-ResponseCode` 15.
    ///
    /// **Everything the old context held is gone**: its handles, and with them every table's
    /// column set, which this session forgets once the answer arrives. A successful reconnect also
    /// clears an abandonment, since the new context has none of the old one's unknowns.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidState`] if a request is in flight or there is no Session Context to
    /// re-establish — a session that never connected sends [`begin_connect`](Self::begin_connect).
    ///
    /// [MS-OXCMAPIHTTP] §3.1.5.7 — reconnecting and establishing a new Session Context
    pub fn begin_reconnect(&mut self, user_dn: &LegacyDn) -> Result<Request> {
        self.check_idle("send a reconnecting Connect")?;
        if !self.connected {
            return Err(Error::InvalidState {
                attempted: "send a reconnecting Connect",
                reason: "there is no Session Context to re-establish; send Connect first",
            });
        }

        let body = connect_body(user_dn, self.lcid_sort, self.lcid_string);
        let request = self.request(RequestType::Connect, body);
        self.pending = Some(Pending::Connect(user_dn.clone()));
        Ok(request)
    }
}
