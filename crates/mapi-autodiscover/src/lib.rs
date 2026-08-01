//! Exchange **Autodiscover** — finding the MAPI over HTTP endpoint for a mailbox.
//!
//! Autodiscover is a genuinely separate protocol from the one [`mapi-proto`] implements: XML over
//! HTTPS, with nothing to do with ROPs. It lives in its own crate because it is separately useful
//! — anyone who needs to locate an Exchange endpoint can depend on this without pulling in a ROP
//! codec — and because the `X-MapiHttpCapability: 1` request header, without which a server will
//! not advertise its MAPI/HTTP URL at all, is a quirk that belongs in exactly one place.
//!
//! # Status
//!
//! Pre-release scaffolding; this crate currently exposes no public API.
//!
//! [`mapi-proto`]: https://docs.rs/mapi-proto
