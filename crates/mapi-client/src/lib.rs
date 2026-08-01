//! Async client for **MAPI over HTTP**, built on the sans-io [`mapi-proto`] codec.
//!
//! Everything that touches the outside world lives here: HTTP, TLS, authentication and retry.
//! [`mapi-proto`] stays free of all of it, and nothing in this workspace depends on this crate —
//! so a caller who wants a different transport can use the codec directly and skip this layer
//! entirely.
//!
//! ```text
//! let client = MapiClient::builder()
//!     .endpoint(url)                       // from mapi-autodiscover
//!     .credentials(Credentials::basic(user, pass))
//!     .build()?;
//!
//! let logon    = client.connect().await?.logon().await?;
//! let mut rows = logon.folder(WellKnown::Inbox)
//!     .contents()
//!     .columns([PropTag::SUBJECT, PropTag::MESSAGE_DELIVERY_TIME])
//!     .rows();
//! ```
//!
//! # Status
//!
//! Pre-release scaffolding; this crate currently exposes no public API.
//!
//! [`mapi-proto`]: https://docs.rs/mapi-proto
