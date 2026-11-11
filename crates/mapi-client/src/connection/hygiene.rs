//! Giving back the handles of objects dropped before they were closed.
//!
//! A [`Rows`](crate::Rows) or a [`Download`](crate::Download) holds a Server object open across
//! round trips, and a caller is free to drop one part way — a `select!` that took another branch,
//! a loop that found what it wanted. `Drop` cannot send a request, so the handle is queued here
//! instead, and the next request the connection sends releases it on the way.
//!
//! **It matters for a session that lasts.** Measured against Exchange Server SE `15.02.2562.056`,
//! one Session Context may hold 500 objects. With 500 folders open, or 500 contents tables open
//! and their folders released, the next `RopOpenFolder` was refused with `ecMaxObjsExceeded`
//! (`0x000004DE`). A caller that read the first page of each table and dropped the rest therefore
//! stopped being able to open anything after its 500th read.
//!
//! The queue is shared with a [`Lease`] rather than reached through the borrowed connection, so
//! that the objects holding one need no `Drop` of their own: a `Drop` on a type that borrows the
//! connection would keep the borrow alive to the end of the caller's scope, and turn every
//! `rows` used before a `logon.disconnect()` into a compile error.
//!
//! [MS-OXCROPS] §2.2.15.3 — `RopRelease`
//! [MS-OXCDATA] §2.4.2 — `TooManyOpenObjects`, `ecMaxObjsExceeded`

use std::sync::{Arc, Mutex};

use mapi_proto::RopBatch;

use super::{Connection, Held};
use crate::error::{Delivery, Error, Result};

/// How many queued releases ride along with one request, so that a long queue cannot crowd the
/// caller's own ROPs out of the one-byte handle table.
const PER_REQUEST: usize = 32;

/// A handle table has this many slots, of which the caller's batch has already used some.
const SLOTS: usize = 256;

/// What one release adds to a batch: `RopRelease` is three bytes ([MS-OXCROPS] §2.2.15.3.1), and
/// the handle it names four more in the handle table.
const RELEASE_BYTES: usize = 7;

/// Handles of objects dropped before they were closed, for the next request to release.
pub(crate) type Releases = Arc<Mutex<Vec<Held>>>;

/// A handle an object holds across round trips, given back to the connection if the object is
/// dropped still holding it.
#[derive(Debug)]
pub(crate) struct Lease {
    queue: Releases,
    held: Option<Held>,
}

impl Lease {
    /// The handle, while one is held.
    pub(crate) const fn held(&self) -> Option<Held> {
        self.held
    }

    /// Starts holding `held`, or nothing.
    pub(crate) const fn hold(&mut self, held: Option<Held>) {
        self.held = held;
    }

    /// Stops holding the handle and hands it over, for an object that releases it itself.
    pub(crate) const fn take(&mut self) -> Option<Held> {
        self.held.take()
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let (Some(held), Ok(mut queue)) = (self.held.take(), self.queue.lock())
            && !queue.contains(&held)
        {
            queue.push(held);
        }
    }
}

/// Whether a request that failed with `error` can have released anything.
///
/// Not when the server never saw it, or refused it unread. A lost or replaced Session Context is
/// the exception that proves it: the request was refused, or never sent, but the context took
/// every handle along with it. [`Error::SessionReplaced`] is what a request holding a handle gets
/// once a reconnect has run — after one that failed or was dropped, the next request's — so it
/// says the same thing as [`Error::SessionLost`] about the handles.
pub(crate) fn may_have_released(error: &Error) -> bool {
    matches!(
        error,
        Error::SessionLost { .. } | Error::SessionReplaced { .. }
    ) || !matches!(error.delivery(), Delivery::NotSent | Delivery::Refused)
}

/// How many releases fit in `batch`: in handle slots, in bytes, and within [`PER_REQUEST`].
fn room(batch: &RopBatch) -> usize {
    let bytes = RopBatch::MAX_SIZE.saturating_sub(batch.size()) / RELEASE_BYTES;
    SLOTS
        .saturating_sub(batch.slots())
        .min(PER_REQUEST)
        .min(bytes)
}

impl Connection {
    /// Releases what `leases` hold, now, and lets each go once that is settled.
    ///
    /// A lease is let go of when the release ran, or may have: a handle released twice may free
    /// whatever the server handed its value to in between. One whose release never reached the
    /// server is kept, so the object dropped afterwards queues it after all. A Session Context the
    /// server has lost, or that has been replaced, took the handles with it, which leaves nothing
    /// to release, and is success — so a [`Download::close`](crate::Download::close) on a
    /// connection still recovering from a failed reconnect hands back its state rather than
    /// losing it.
    ///
    /// # Errors
    ///
    /// Whatever the release failed with, but [`Error::SessionLost`] and
    /// [`Error::SessionReplaced`].
    pub(crate) async fn release_now(
        &mut self,
        leases: &mut [&mut Lease],
        during: &'static str,
    ) -> Result<()> {
        let mut batch = RopBatch::new();
        for lease in leases.iter_mut() {
            match lease.held() {
                Some(held) if self.holds(held) => {
                    let slot = batch.bind(held.handle());
                    batch.release(slot);
                }
                // From a Session Context since replaced, which took it along.
                Some(_) => {
                    let _ = lease.take();
                }
                None => {}
            }
        }
        if batch.is_empty() {
            return Ok(());
        }
        let outcome = self.execute(batch, during).await;
        if outcome
            .as_ref()
            .is_err_and(|error| !may_have_released(error))
        {
            return outcome.map(drop);
        }
        for lease in leases.iter_mut() {
            let _ = lease.take();
        }
        match outcome {
            Ok(_) | Err(Error::SessionLost { .. } | Error::SessionReplaced { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// An empty lease on this connection's release queue.
    pub(crate) fn lease(&self) -> Lease {
        Lease {
            queue: Arc::clone(&self.releases),
            held: None,
        }
    }

    /// Queues a handle to be released by the next request this connection sends.
    pub(crate) fn release_later(&self, held: Held) {
        let mut lease = self.lease();
        lease.hold(Some(held));
    }

    /// Adds as many queued releases to `batch` as fit, and says which.
    ///
    /// They go last. A `RopRelease` has no response, so the caller's responses are unchanged, and
    /// a handle released after the caller's ROPs have run cannot be handed out again to one of
    /// them in the same buffer. A handle from a Session Context since replaced is never sent: it
    /// went with that context, and the same value in the new one names something else.
    ///
    /// Only as many as fit, in handle slots and in bytes: a release costs a slot and seven bytes
    /// (three of `RopRelease`, four in the handle table), and a caller's batch near
    /// [`RopBatch::MAX_SIZE`] would otherwise be pushed past it — failing with
    /// `RopBufferTooLarge` though it fits on its own, and again on every later request that came as
    /// close, since a release that never left stays queued. What does not fit waits for a request
    /// with room.
    pub(super) fn add_releases(&self, batch: &mut RopBatch) -> Vec<Held> {
        let room = room(batch);
        let riding: Vec<Held> = self.releases.lock().map_or_else(
            |_| Vec::new(),
            |queue| {
                queue
                    .iter()
                    .copied()
                    .filter(|held| self.holds(*held))
                    .take(room)
                    .collect()
            },
        );
        for held in &riding {
            let slot = batch.bind(held.handle());
            batch.release(slot);
        }
        riding
    }

    /// Forgets the releases a request carried, and every queued handle of a Session Context since
    /// replaced. Called unless the server never saw the request.
    ///
    /// A request that never reached the server released nothing, and the queue keeps them for the
    /// next one. Any other outcome may have released them, and a handle value released twice may
    /// free whatever the server handed it to in between; leaking one is the lesser fault, and the
    /// Session Context frees it when it ends.
    pub(super) fn released(&self, riding: &[Held]) {
        let epoch = self.reconnects();
        if let Ok(mut queue) = self.releases.lock() {
            queue.retain(|held| !riding.contains(held) && held.epoch() == epoch);
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use mapi_proto::ResponseCode;

    use super::*;

    /// A caller's batch a few bytes short of the limit has room for as many releases as fit in
    /// those bytes, and the batch they make still builds; one with fewer than a release's bytes
    /// left has room for none, rather than being pushed past the limit.
    #[test]
    fn releases_ride_only_in_the_bytes_a_batch_has_left() {
        use mapi_proto::ObjectHandle;

        let near = |left: usize| {
            let mut batch = RopBatch::new();
            let stream = batch.bind(ObjectHandle::new(0x2A));
            batch.write_stream(stream, &[]);
            let fill = RopBatch::MAX_SIZE - batch.size() - left;
            let mut batch = RopBatch::new();
            let stream = batch.bind(ObjectHandle::new(0x2A));
            batch.write_stream(stream, &vec![0; fill]);
            batch
        };

        let mut batch = near(2 * RELEASE_BYTES + 3);
        assert_eq!(room(&batch), 2);
        for handle in [0x30, 0x31] {
            let slot = batch.bind(ObjectHandle::new(handle));
            batch.release(slot);
        }
        assert!(
            batch.size() <= RopBatch::MAX_SIZE,
            "the releases that fit leave a batch that still fits: {}",
            batch.size()
        );

        let slot = batch.bind(ObjectHandle::new(0x32));
        batch.release(slot);
        assert!(
            batch.size() > RopBatch::MAX_SIZE,
            "and one more would not have"
        );

        assert_eq!(room(&near(RELEASE_BYTES - 1)), 0);
        assert_eq!(
            room(&RopBatch::new()),
            PER_REQUEST,
            "a small batch takes the usual number"
        );
    }

    /// A context lost or replaced took its handles along, so nothing is left to release — while a
    /// request refused unread released nothing, and one that went unanswered may have.
    #[test]
    fn a_lost_or_replaced_context_took_its_handles_along() {
        let lost = Error::SessionLost {
            code: ResponseCode::CONTEXT_NOT_FOUND,
            diagnostic: None,
        };
        assert!(may_have_released(&lost));
        let replaced = Error::SessionReplaced { during: "reading" };
        assert!(may_have_released(&replaced));

        let refused = Error::Http {
            status: 400,
            url: String::new(),
            detail: None,
        };
        assert!(!may_have_released(&refused));
        let unanswered = Error::Timeout {
            url: String::new(),
            after: Duration::from_secs(1),
        };
        assert!(may_have_released(&unanswered));
    }
}
