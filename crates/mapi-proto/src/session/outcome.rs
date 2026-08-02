//! What a response turned out to be.

use crate::error::ErrorCode;
use crate::oxcdata::PropertySet;
use crate::rop::{
    HandleSlot, LogonResponse, ObjectHandle, PropertyProblemsResponse, QueryRowsResponse,
    RopResponse,
};

/// What a response turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// A Session Context now exists; every later request carries its cookies.
    Connected(Connected),
    /// A ROP batch ran. Individual ROPs inside it may still have failed.
    Executed(Execution),
    /// The Session Context has been torn down.
    Disconnected,
    /// The endpoint answered a `PING`.
    Pong,
}

/// What the server reported when the Session Context was established.
///
/// [MS-OXCMAPIHTTP] §2.2.4.1.2 — `Connect` success response body
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connected {
    pub(super) display_name: String,
    pub(super) dn_prefix: String,
    pub(super) polls_max: u32,
    pub(super) retry_count: u32,
    pub(super) retry_delay: u32,
}

impl Connected {
    /// The mailbox owner's display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The distinguished-name prefix to use for the session.
    #[must_use]
    pub fn dn_prefix(&self) -> &str {
        &self.dn_prefix
    }

    /// The longest a `NotificationWait` may block, in milliseconds.
    #[must_use]
    pub const fn polls_max(&self) -> u32 {
        self.polls_max
    }

    /// How many times to retry a failed request.
    #[must_use]
    pub const fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// How long to wait between retries, in milliseconds.
    ///
    /// Advice for *this* connection, not a property of the server: three consecutive `Connect`s to
    /// one Exchange Server SE `15.02.2562.045` answered 13314, 13687 and 13835 ms. Treat it as the
    /// number to wait, not as a value worth remembering or comparing between sessions.
    #[must_use]
    pub const fn retry_delay(&self) -> u32 {
        self.retry_delay
    }
}

/// The result of one `Execute`: every ROP response, and the handle table as it now stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    pub(super) responses: Vec<RopResponse>,
    pub(super) handles: Vec<ObjectHandle>,
}

impl Execution {
    /// Every response, in the order the server produced them.
    ///
    /// Note that `RopRelease` produces no response when it succeeds, so this does not line up
    /// one-for-one with the ROPs that were issued.
    #[must_use]
    pub fn responses(&self) -> &[RopResponse] {
        &self.responses
    }

    /// The handle table the server sent back.
    #[must_use]
    pub fn handles(&self) -> &[ObjectHandle] {
        &self.handles
    }

    /// The handle now sitting in one of the batch's slots.
    ///
    /// This is how a handle produced by one round trip reaches the next, through
    /// [`RopBatch::bind`](crate::RopBatch::bind).
    #[must_use]
    pub fn handle(&self, slot: HandleSlot) -> Option<ObjectHandle> {
        self.handles.get(usize::from(slot.index())).copied()
    }

    /// The logon response, if the batch contained a `RopLogon`.
    #[must_use]
    pub fn logon(&self) -> Option<&LogonResponse> {
        self.responses.iter().find_map(RopResponse::as_logon)
    }

    /// The first batch of rows, if the batch contained a `RopQueryRows`.
    #[must_use]
    pub fn rows(&self) -> Option<&QueryRowsResponse> {
        self.responses.iter().find_map(RopResponse::as_query_rows)
    }

    /// The first set of properties, if the batch read any.
    #[must_use]
    pub fn properties(&self) -> Option<&PropertySet> {
        self.responses.iter().find_map(RopResponse::as_properties)
    }

    /// The first per-property report, if the batch wrote or deleted any properties.
    ///
    /// Worth looking at even when the `Execute` and every ROP in it succeeded: a property that was
    /// refused is reported here and nowhere else.
    ///
    /// [MS-OXCDATA] §2.7 — `PropertyProblem` structure
    #[must_use]
    pub fn property_problems(&self) -> Option<&PropertyProblemsResponse> {
        self.responses
            .iter()
            .find_map(RopResponse::as_property_problems)
    }

    /// The first ROP the server refused, if any did.
    ///
    /// A failing ROP does not fail the `Execute`: the server runs what it can and reports each
    /// result, so this has to be looked at rather than inferred from the absence of an error.
    #[must_use]
    pub fn failure(&self) -> Option<ErrorCode> {
        self.responses.iter().find_map(RopResponse::failure)
    }
}
