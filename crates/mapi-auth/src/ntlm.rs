//! NTLM v2: the three messages, and nothing above them.
//!
//! This module produces and consumes the bytes [MS-NLMP] defines. Wrapping them in an
//! `Authorization` header, or in a SPNEGO token, happens above it — which is what lets the same
//! code serve both the `NTLM` and the `Negotiate` HTTP schemes.
//!
//! # NTLM v2 only
//!
//! NTLM v1 and LM are not implemented, and their absence is a feature rather than a gap. Both are
//! broken well past the point of being a fallback: LM in particular reduces to two independent
//! seven-character DES keys over an upper-cased password. [MS-NLMP] §3.3.2 notes that the version
//! "is not negotiated by the protocol" but configured at both ends, so a client that only speaks
//! v2 is a client that cannot be talked down to v1 — and every server that matters has had v2
//! since Windows 2000.
//!
//! What that removes is DES and RC4 entirely. The one place NTLM v2 would still need RC4 is the
//! key exchange, and [`NegotiateFlags::REQUESTED`] does not ask for it: see that constant for why.

mod authenticate;
mod avpair;
mod flags;
mod message;
mod response;

#[cfg(test)]
pub(crate) mod fixtures;

pub(crate) use authenticate::authenticate;
pub(crate) use flags::NegotiateFlags;
pub(crate) use message::{ChallengeMessage, negotiate};
