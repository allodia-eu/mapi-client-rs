//! Async client for **MAPI over HTTP**, built on the sans-io [`mapi-proto`](mapi_proto) codec.
//!
//! Everything that touches the outside world lives here: HTTP, TLS and authentication.
//! [`mapi-proto`](mapi_proto) stays free of all of it, and nothing in this workspace depends on
//! this crate — so a caller who wants a different transport can use the codec directly and skip
//! this layer entirely.
//!
//! ```no_run
//! use mapi_client::{Credentials, LegacyDn, MapiClient, PropertyTag, WellKnownFolder};
//!
//! # async fn example() -> Result<(), mapi_client::Error> {
//! // Both of these come from Autodiscover, and are used exactly as it gave them.
//! let endpoint = "https://mail.example.test/mapi/emsmdb/\
//!                 ?MailboxId=00000000-0000-0000-0000-000000000000@example.test";
//! let user_dn = "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=alice";
//!
//! let client = MapiClient::builder()
//!     .endpoint(endpoint)
//!     .user_dn(LegacyDn::new(user_dn)?)
//!     .credentials(Credentials::basic("alice@example.test", "hunter2"))
//!     .build()?;
//!
//! let mut logon = client.connect().await?.logon().await?;
//! let mut rows = logon
//!     .well_known(WellKnownFolder::Inbox)?
//!     .contents()
//!     .columns([PropertyTag::SUBJECT, PropertyTag::MESSAGE_DELIVERY_TIME])
//!     .rows();
//!
//! while let Some(row) = rows.try_next().await? {
//!     println!("{:?}", row.string(PropertyTag::SUBJECT));
//! }
//!
//! logon.disconnect().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Three round trips to the first row
//!
//! `Connect` establishes the Session Context, `RopLogon` returns thirteen folder ids, and one more
//! `Execute` opens the folder, opens its table, sets the columns and reads the first page — because
//! ROPs chained in a single buffer consume the handles that earlier ROPs in the same buffer
//! produced. Later pages are one round trip each.
//!
//! **The Calendar is two more.** `RopLogon` does not name it, or Contacts, or Drafts, or Tasks, or
//! Notes, or Journal: those live behind binary entry-id properties on the Inbox, and an entry id is
//! long-term while `RopOpenFolder` takes a short-term id. [`Logon::special_folders`] reads all
//! eight properties in one `Execute` and converts all eight in the next, so finding every one of
//! them costs what finding one would.
//!
//! # What the types enforce
//!
//! * **One request in flight.** MAPI/HTTP allows exactly one per Session Context, and a violation
//!   comes back as `X-ResponseCode` 15 (Invalid Sequence), pointing nowhere near the cause. Every
//!   method that sends anything takes `&mut self`, so the borrow checker refuses the second one.
//! * **A logon cannot outlive its session.** [`Connection::logon`] takes the connection by value,
//!   and every folder read borrows from the [`Logon`].
//! * **A failed round trip ends the connection.** When a request fails in transit there is no way
//!   to know whether the server acted on it, so the connection reports [`Error::Poisoned`] rather
//!   than sending the next request into an unknown state.
//! * **No secret reaches a log.** [`Credentials`] implements [`Debug`] by hand and redacts.
//!
//! # Transport
//!
//! HTTP is [`reqwest`] with rustls, verifying certificates against the operating system's own
//! trust store — which is what an on-premises Exchange behind an organisation's internal CA needs.
//! None of that appears in this crate's public API: the HTTP client is an implementation detail,
//! its errors are boxed as [`source`](core::error::Error::source), and endpoints are given as
//! strings.
//!
//! Authentication is Basic or Bearer. **`Negotiate` and `NTLM` are not implemented**, which
//! matters because a default-configured Exchange offers only those two — see [`Credentials`] for
//! what to do about it.
//!
//! # Seeing the bytes
//!
//! A wrong ROP buffer is not readable by inspection, so [`MapiClientBuilder::observer`] hands every
//! request and the response it produced to an [`Observer`] verbatim. That is what `mapi-cli`
//! captures the repository's fixture corpus with — the capture path and the diagnostic path are
//! deliberately the same path.
//!
//! # Specification authority
//!
//! Every protocol behaviour cites the Microsoft Open Specification document it comes from, by
//! section. Where a real server is observed to deviate, both facts are recorded: the citation and
//! the deviation, with the server version that produced it. The pinned document versions live in
//! `SPEC.md` at the repository root.

mod builder;
mod client;
mod connection;
mod credentials;
mod logon;
mod observer;
mod properties;
mod special;
mod table;
mod transport;

#[cfg(feature = "autodiscover")]
mod discovery;

pub mod error;

#[cfg(feature = "autodiscover")]
/// The Autodiscover client this crate drives, for the types it does not re-export.
pub use mapi_autodiscover;
#[cfg(feature = "autodiscover")]
pub use mapi_autodiscover::{EmailAddress, MapiHttpEndpoint};
/// The sans-io codec every byte on the wire comes from, for the types this crate does not
/// re-export.
pub use mapi_proto;
/// The types from [`mapi-proto`](mapi_proto) that appear in this crate's own API, re-exported
/// so that the common path needs one dependency rather than two.
pub use mapi_proto::{
    Bookmark, CONTENTS_COLUMNS, Cell, Connected, ContainerClass, ErrorCode, FOLDER_PROPERTIES,
    FileTime, Floating64, FolderDepth, FolderEntryId, FolderId, Guid, HIERARCHY_COLUMNS, Headers,
    Lcid, LegacyDn, LogonResponse, LongTermId, MAILBOX_PROPERTIES, MessageId, PropertyProblem,
    PropertyRow, PropertySet, PropertySetIter, PropertyTag, PropertyType, PropertyValue, ReplicaId,
    RequestType, RowForm, ShortTermId, SpecialFolder, StoreObjectType, TableString, TaggedValue,
    WellKnownFolder,
};

pub use crate::builder::MapiClientBuilder;
pub use crate::client::MapiClient;
pub use crate::connection::Connection;
pub use crate::credentials::Credentials;
pub use crate::error::{Error, Result};
pub use crate::logon::{Folder, Logon};
pub use crate::observer::{Exchange, Observer};
pub use crate::properties::Properties;
pub use crate::special::{
    SpecialFolderEntry, SpecialFolderState, SpecialFolders, SpecialFoldersIter,
};
pub use crate::table::{Rows, TableRead};

/// Names an outcome for an error message, when the one that arrived is not the one expected.
pub(crate) const fn describe(outcome: &mapi_proto::Outcome) -> &'static str {
    match outcome {
        mapi_proto::Outcome::Connected(_) => "a Connect response",
        mapi_proto::Outcome::Executed(_) => "an Execute response",
        mapi_proto::Outcome::Disconnected => "a Disconnect response",
        mapi_proto::Outcome::Pong => "a PING response",
        _ => "a response this crate does not recognise",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every public type crosses a `.await`, so every one of them has to be sendable to another
    /// task. A stray `Rc` in any of them would break that silently; this is the test that says so
    /// at compile time. C-SEND-SYNC.
    #[test]
    const fn public_types_are_send_and_sync() {
        const fn assert<T: Send + Sync>() {}

        assert::<MapiClient>();
        assert::<MapiClientBuilder>();
        assert::<Connection>();
        assert::<Credentials>();
        assert::<Logon>();
        assert::<Error>();
        assert::<Folder<'_>>();
        assert::<Properties<'_>>();
        assert::<TableRead<'_>>();
        assert::<Rows<'_>>();
        assert::<Exchange<'_>>();
        assert::<SpecialFolders>();
        assert::<SpecialFolderEntry>();
        assert::<SpecialFolderState>();
        assert::<SpecialFoldersIter<'_>>();
    }

    #[test]
    fn every_outcome_is_named_for_a_message() {
        assert_eq!(
            describe(&mapi_proto::Outcome::Disconnected),
            "a Disconnect response"
        );
        assert_eq!(describe(&mapi_proto::Outcome::Pong), "a PING response");
    }
}
