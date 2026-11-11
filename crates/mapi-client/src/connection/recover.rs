//! Re-establishing a Session Context the server has lost, and the handles that do not survive it.
//!
//! [MS-OXCMAPIHTTP] §3.1.5.7 — reconnecting and establishing a new Session Context
//! [MS-OXCMAPIHTTP] §3.2.5.6 — what the server does with the old one

use mapi_proto::{HandleSlot, LogonResponse, ObjectHandle, Outcome, ResponseCode, RopBatch};

use super::{Connection, refusal};
use crate::describe;
use crate::error::{Error, Result};

/// What a Session Context is logged on as: the handle every ROP hangs off, and what the logon
/// reported.
#[derive(Clone, Debug)]
pub(crate) struct LogonState {
    handle: ObjectHandle,
    response: LogonResponse,
}

impl LogonState {
    pub(crate) const fn new(handle: ObjectHandle, response: LogonResponse) -> Self {
        Self { handle, response }
    }

    pub(crate) const fn handle(&self) -> ObjectHandle {
        self.handle
    }
}

/// Why the Session Context is known to be gone.
#[derive(Clone, Debug)]
pub(crate) struct Lost {
    /// What the server said, or `None` for a context being replaced on the caller's say-so — the
    /// server may already have destroyed it, so it is gone either way.
    code: Option<ResponseCode>,
    diagnostic: Option<String>,
}

impl Lost {
    pub(crate) const fn new(code: ResponseCode, diagnostic: Option<String>) -> Self {
        Self {
            code: Some(code),
            diagnostic,
        }
    }

    /// The error for a request this cannot carry over to the new Session Context.
    pub(crate) fn into_error(self) -> Error {
        match self.code {
            Some(code) => Error::SessionLost {
                code,
                diagnostic: self.diagnostic,
            },
            None => Error::SessionReplaced {
                during: "a request held over from a Session Context that was being replaced",
            },
        }
    }
}

/// Whether an `X-ResponseCode` says the request named no Session Context the server has.
///
/// 10, "Context Not Found", is the one [MS-OXCMAPIHTTP] §3.2.5.6 gives for a context that "has
/// expired, is no longer valid, or is not valid for the server in which the mailbox currently
/// resides", and §3.2.5.1 for a request whose authentication context differs from the one the
/// context was created with. 6, "Invalid Context Cookie", and 13, "Missing Cookie", name no context
/// either. Measured against Exchange Server SE `15.02.2562.056`, which answers each without running
/// the request: 10 for a context replaced by a reconnect, for one disconnected, and for the right
/// cookies sent with another account's credentials ("Unable to find user context based on user
/// authentication identifier"); 13 with the context or sequence cookie left out; 6 with a context
/// cookie that is not base64.
///
/// 15, "Invalid Sequence", is deliberately not one: the context is there, and a sequence cookie
/// out of step is what an abandoned request leaves, which is [`Connection::disconnect`]'s to
/// handle.
const fn names_no_context(code: ResponseCode) -> bool {
    matches!(code.as_u32(), 6 | 10 | 13)
}

/// A handle, and the Session Context it came from.
///
/// Every handle but the logon's is only good in the Session Context that issued it: a reconnect
/// creates a new server object table, in which the same value names something else or nothing
/// ([MS-OXCROPS] §2.2.1). The logon is the one handle a reconnect re-creates, which is why it is
/// bound with [`RopBatch::bind_logon`] and repointed rather than held. Everything else an object
/// keeps across round trips — a table being paged, a stream, a message being written — is held
/// as one of these, and [`Connection::bind`] refuses one from a context since replaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Held {
    handle: ObjectHandle,
    epoch: u64,
}

impl Held {
    pub(super) const fn handle(self) -> ObjectHandle {
        self.handle
    }

    pub(super) const fn epoch(self) -> u64 {
        self.epoch
    }
}

impl Connection {
    /// Replaces the Session Context with a new one, and logs on again if this one was.
    ///
    /// A `Connect` passing every cookie of the context it replaces: [MS-OXCMAPIHTTP] §3.1.5.7
    /// makes that the "only difference between reconnecting and an initial connection", and it is
    /// what lets the server "clean up the previous context in a timely fashion to prevent session
    /// limits from being reached" — §3.2.5.6 has it destroy the old one before creating the new.
    /// The cookies the response sets replace the old ones rather than joining them, as §3.2.5.6
    /// requires.
    ///
    /// **Every handle but the logon's is gone afterwards.** A [`Rows`](crate::Rows) or a
    /// [`Download`](crate::Download) part way through refuses to go on with
    /// [`Error::SessionReplaced`]. Named-property ids are not handles: they belong to the store,
    /// and stay valid while the logon names the same mailbox.
    ///
    /// Not needed for a context the server lost, which is re-established on the request that
    /// finds out. This is for one the caller wants replaced: a poisoned connection, which this
    /// makes usable again, or a mailbox suspected of having moved.
    ///
    /// # Cancellation
    ///
    /// Safe to drop at any await. The connection stays marked as lost, and its next request
    /// re-establishes it.
    ///
    /// # Errors
    ///
    /// Whatever the `Connect` or the logon failed with. The connection is then left as lost, and
    /// its next request tries again.
    ///
    /// [MS-OXCMAPIHTTP] §3.1.5.7 — reconnecting and establishing a new Session Context
    pub async fn reconnect(&mut self) -> Result<()> {
        // Whatever was in flight is given up on: the new context has none of the old one's
        // unknowns, and a session still waiting for an answer would refuse to send the Connect.
        self.session.abandon();
        // Marked before anything is sent, so that a reconnect that fails — or is dropped — leaves a
        // connection that tries again rather than one that talks to a context the Connect may
        // already have destroyed.
        if self.lost.is_none() {
            self.lost = Some(Lost {
                code: None,
                diagnostic: None,
            });
        }

        let request = self.session.begin_reconnect(&self.user_dn)?;
        match self.round_trip(request).await? {
            Outcome::Connected(connected) => self.connected = connected,
            other => {
                return Err(Error::Unexpected {
                    expected: "a Connect response",
                    found: describe(&other),
                });
            }
        }
        self.epoch = self.epoch.saturating_add(1);
        // Every queued release named a handle of the context just replaced, which took them along.
        if let Ok(mut queue) = self.releases.lock() {
            queue.clear();
        }

        if self.logon.is_some() {
            let mut batch = RopBatch::new();
            let slot = batch.logon(&self.user_dn.clone());
            let request = self.session.execute(batch)?;
            let Outcome::Executed(execution) = self.round_trip(request).await? else {
                return Err(Error::Unexpected {
                    expected: "an Execute response",
                    found: "something else, to the logon after a reconnect",
                });
            };
            if let Some(error) = execution
                .responses()
                .iter()
                .find_map(|response| refusal(response, "the logon after a reconnect"))
            {
                return Err(error);
            }
            let (Some(response), Some(handle)) = (execution.logon(), execution.handle(slot)) else {
                return Err(Error::Unexpected {
                    expected: "a RopLogon response",
                    found: "no logon in the batch's responses",
                });
            };
            self.logon = Some(LogonState::new(handle, response.clone()));
        }

        self.lost = None;
        self.poison = None;
        Ok(())
    }

    /// How many times the Session Context has been replaced.
    #[must_use]
    pub const fn reconnects(&self) -> u64 {
        self.epoch
    }

    /// The logon's handle in the current Session Context, once there is one.
    pub(crate) fn logon_handle(&self) -> Option<ObjectHandle> {
        self.logon.as_ref().map(LogonState::handle)
    }

    /// What the logon reported in the current Session Context, once there is one.
    pub(crate) fn logon_response(&self) -> Option<&LogonResponse> {
        self.logon.as_ref().map(|logon| &logon.response)
    }

    /// Notes that the server has no Session Context for these cookies, and says so in the error.
    ///
    /// A context lost *after* `DONE` is lost all the same, and the next request re-establishes it.
    /// But that request was accepted before it failed, so how much of it ran is not known, and it
    /// is reported as it came rather than as [`Error::SessionLost`] — which says the server ran
    /// nothing, and is what lets a request be sent again.
    pub(super) fn lose(&mut self, error: mapi_proto::Error) -> Error {
        match error {
            mapi_proto::Error::Transport { code, diagnostic } if names_no_context(code) => {
                self.lost = Some(Lost::new(code, diagnostic.clone()));
                Error::SessionLost { code, diagnostic }
            }
            mapi_proto::Error::FailedAfterDone { code, diagnostic } if names_no_context(code) => {
                self.lost = Some(Lost::new(code, diagnostic.clone()));
                Error::Protocol(mapi_proto::Error::FailedAfterDone { code, diagnostic })
            }
            other => Error::Protocol(other),
        }
    }

    /// A handle this Session Context just issued, to be used in a later round trip.
    pub(crate) const fn hold(&self, handle: ObjectHandle) -> Held {
        Held {
            handle,
            epoch: self.epoch,
        }
    }

    /// Whether a held handle is from the current Session Context.
    pub(crate) const fn holds(&self, held: Held) -> bool {
        held.epoch == self.epoch
    }

    /// Places a held handle into `batch`, or refuses one from a Session Context since replaced.
    ///
    /// # Errors
    ///
    /// [`Error::SessionReplaced`], naming `during`.
    pub(crate) fn bind(
        &self,
        batch: &mut RopBatch,
        held: Held,
        during: &'static str,
    ) -> Result<HandleSlot> {
        if self.holds(held) {
            Ok(batch.bind(held.handle))
        } else {
            Err(Error::SessionReplaced { during })
        }
    }
}
