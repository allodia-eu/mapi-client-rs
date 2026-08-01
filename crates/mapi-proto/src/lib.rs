//! Sans-io codec for **MAPI over HTTP** — the protocol Outlook speaks to Exchange.
//!
//! This crate owns all bytes and all protocol state, and performs no I/O whatsoever: no network,
//! no async runtime, not even a filesystem read. The caller decides how a request reaches the
//! server and hands the response back.
//!
//! ```
//! use mapi_proto::{HIERARCHY_COLUMNS, LegacyDn, RopBatch, Session, WellKnownFolder};
//!
//! let mut session = Session::new();
//! let user_dn = LegacyDn::new("/o=First/ou=Exchange Administrative Group/cn=alice")?;
//!
//! // 1. Establish a Session Context.
//! let request = session.begin_connect(&user_dn)?;
//! //    ... POST request.body() with request.headers(), then:
//! //    session.on_response(&response_headers, &response_payload)?;
//! # let _ = request;
//! # Ok::<(), mapi_proto::Error>(())
//! ```
//!
//! Four ROPs chain through one `Execute`, so reading a folder's contents is a single round trip.
//! Handle indices are never written by hand: issuing a ROP hands back a token that later ROPs
//! consume.
//!
//! ```
//! use mapi_proto::{FolderId, HIERARCHY_COLUMNS, ObjectHandle, RopBatch};
//!
//! let mut batch = RopBatch::new();
//! let logon = batch.bind(ObjectHandle::new(0x0000_002A)); // from the previous round trip
//! let folder = batch.open_folder(logon, FolderId::new(0x0D00_0000_0000_0001));
//! let table = batch.hierarchy_table(folder);
//! batch.set_columns(table, &HIERARCHY_COLUMNS).query_rows(table, 50);
//! assert_eq!(batch.len(), 4);
//! ```
//!
//! That boundary is what makes the test suite meaningful. Captured request/response pairs from a
//! real Exchange Server replay straight through the codec with nothing stubbed, so a passing test
//! is a statement about bytes the server actually sent.
//!
//! For an async client that does the I/O for you, see [`mapi-client`]; to locate an endpoint in
//! the first place, see [`mapi-autodiscover`].
//!
//! # Specification authority
//!
//! Every protocol constant, structure and behaviour in this crate cites the Microsoft Open
//! Specification document it comes from, by section — `[MS-OXCROPS] §2.2.4.1.1`, never just "the
//! spec". Those documents are authoritative over this crate's own documentation, over any
//! observed transcript, and over any other implementation. Where a real server is observed to
//! deviate, both facts are recorded: the citation *and* the deviation, with the server version
//! that produced it.
//!
//! The pinned document versions and their download URLs live in `SPEC.md` at the repository root.
//!
//! # What this crate does not do
//!
//! No compression (LZ77+DIRECT2), no `0xA5` obfuscation and no auxiliary buffers: every request
//! asks the server to skip all three, and a server that ignores that is reported rather than
//! guessed at. No Address Book endpoint, no notifications, no ICS. Basic table reads and folder
//! walks are what v0.1 covers.
//!
//! [`mapi-client`]: https://docs.rs/mapi-client
//! [`mapi-autodiscover`]: https://docs.rs/mapi-autodiscover

pub mod error;
pub mod http;
pub mod oxcdata;
pub mod rop;
pub mod session;

mod wire;

#[cfg(test)]
mod testing;

pub use crate::error::{Error, ErrorCode, Result};
pub use crate::http::{CookieJar, Headers, MetaTag, Payload, Request, RequestType, ResponseCode};
pub use crate::oxcdata::{
    CONTENTS_COLUMNS, Cell, FileTime, FolderId, Guid, HIERARCHY_COLUMNS, LegacyDn, MessageId,
    PropertyRow, PropertyTag, PropertyType, PropertyValue, ReplicaId, RowForm, TableString,
};
pub use crate::rop::{
    Bookmark, HandleSlot, LogonResponse, ObjectHandle, QueryRowsResponse, RopBatch, RopId,
    RopResponse, TableStatus, WellKnownFolder,
};
pub use crate::session::{Connected, Execution, Outcome, Session, SessionBuilder};
