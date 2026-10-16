//! Kerberos V5 as a client, profiled by [MS-KILE], and sans-io like the rest of this crate.
//!
//! [MS-KILE] is written as a set of differences from [RFC 4120]: what a Windows KDC adds, requires
//! and ignores. Each module here cites both, and where they differ the Microsoft document wins,
//! because the server on the other end is a Windows KDC.

pub(crate) mod crypto;
