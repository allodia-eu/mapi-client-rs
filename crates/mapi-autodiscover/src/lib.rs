//! Exchange **Autodiscover** — finding the MAPI over HTTP endpoint for a mailbox.
//!
//! Autodiscover is a genuinely separate protocol from the one [`mapi-proto`] implements: XML over
//! HTTPS, with nothing to do with ROPs. It lives in its own crate because it is separately useful
//! — anyone who needs to locate an Exchange endpoint can depend on this without pulling in a ROP
//! codec — and because the `X-MapiHttpCapability` request header, without which a server will not
//! advertise its MAPI/HTTP URL at all, is a quirk that belongs in exactly one place.
//!
//! Like [`mapi-proto`], this crate performs no I/O. It says where to look, what to send and what
//! came back; the caller does the sending.
//!
//! ```
//! use mapi_autodiscover::{AutodiscoverRequest, EmailAddress, candidate_urls};
//!
//! let address = EmailAddress::new("developer@dev.local")?;
//! let request = AutodiscoverRequest::new(&address);
//!
//! for url in candidate_urls(&address) {
//!     // POST request.body() to `url` with request.headers(), then hand the answer to
//!     // AutodiscoverResponse::parse.
//!     assert!(url.starts_with("https://"));
//! }
//! # Ok::<(), mapi_autodiscover::Error>(())
//! ```
//!
//! A response that carries settings hands over everything a MAPI session needs, in one step:
//!
//! ```
//! # use mapi_autodiscover::AutodiscoverResponse;
//! # let xml = include_str!("../tests/exchange-se-mapihttp.xml");
//! let response = AutodiscoverResponse::parse(xml)?;
//! let endpoint = response
//!     .settings()
//!     .and_then(|settings| settings.mapi_http())
//!     .expect("this deployment offers MAPI/HTTP");
//!
//! assert!(endpoint.mail_store_url().unwrap().contains("/mapi/emsmdb/"));
//! assert!(endpoint.legacy_dn().starts_with("/o="));
//! # Ok::<(), mapi_autodiscover::Error>(())
//! ```
//!
//! # Specification authority
//!
//! Every element and header cites the Microsoft Open Specification document it comes from, by
//! section. Two documents cover this protocol: [MS-OXDISCO] says *where to look* for the service,
//! and [MS-OXDSCLI] defines the XML and the `mapiHttp` block. Where a real server is observed to
//! deviate, both facts are recorded — the citation and the deviation, with the server version that
//! produced it.
//!
//! The pinned document versions and their download URLs live in `SPEC.md` at the repository root.
//!
//! # On XML
//!
//! Parsing uses `roxmltree`, which builds a read-only tree and does not expand external entities.
//! That closes XXE — the failure mode that turns "parse this response" into "read this file off my
//! disk" — and the response comes from whatever host a mailbox's own domain points at, which is
//! not always a host anybody chose.
//!
//! [`mapi-proto`]: https://docs.rs/mapi-proto

mod discovery;
mod email;
mod request;
mod response;
mod settings;

pub mod error;

pub use crate::discovery::{
    CandidateUrls, candidate_urls, redirect_probe_url, srv_query, url_for_host,
};
pub use crate::email::EmailAddress;
pub use crate::error::{Error, Result};
pub use crate::request::AutodiscoverRequest;
pub use crate::response::AutodiscoverResponse;
pub use crate::settings::{
    MapiHttpEndpoint, Protocol, ProtocolType, ServerError, Settings, Urls, User,
};
