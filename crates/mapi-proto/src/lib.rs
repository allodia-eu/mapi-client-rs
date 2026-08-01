//! Sans-io codec for **MAPI over HTTP** — the protocol Outlook speaks to Exchange.
//!
//! This crate owns all bytes and all protocol state, and performs no I/O whatsoever: no network,
//! no async runtime, not even a filesystem read. The caller decides how a request reaches the
//! server and hands the response back:
//!
//! ```text
//! let req      = session.begin_connect(&user_dn)?;   // -> request type + body bytes
//! //  ... caller POSTs req.body() however it likes ...
//! let outcome  = session.on_response(&headers, &body)?;
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
//! # Status
//!
//! Pre-release scaffolding. The protocol layers described in `SCAFFOLD-PLAN.md` §2 land next; this
//! crate currently exposes no public API.
//!
//! [`mapi-client`]: https://docs.rs/mapi-client
//! [`mapi-autodiscover`]: https://docs.rs/mapi-autodiscover
