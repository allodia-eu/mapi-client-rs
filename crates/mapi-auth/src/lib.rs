//! **NTLM and Negotiate (SPNEGO)** authentication, as a state machine that does no I/O.
//!
//! A default-configured Exchange offers exactly two authentication schemes on its MAPI virtual
//! directory, `Negotiate` and `NTLM`, and neither is a header a client can compute on its own: both
//! are multi-leg challenge/response exchanges bound to a TCP connection. This crate produces the
//! `Authorization` values for those legs and consumes the `WWW-Authenticate` values that come back.
//! It never opens a socket, reads a clock or generates a random number.
//!
//! ```
//! use core::time::Duration;
//!
//! use mapi_auth::{Entropy, Handshake, Identity, Scheme};
//!
//! let mut handshake = Handshake::new(
//!     Scheme::Ntlm,
//!     Identity::new("DEV\\developer", "Login123"),
//!     // Eight bytes from a secure random source, and the current time.
//!     Entropy::from_unix_time([0x11; 8], Duration::from_secs(1_800_000_000)),
//! );
//!
//! let first = handshake.initial()?;
//! assert!(first.starts_with("NTLM "));
//! // POST with `Authorization: {first}`, expect 401, feed the WWW-Authenticate value to
//! // `handshake.advance(…)`, and POST the real request with what that returns.
//! # Ok::<(), mapi_auth::Error>(())
//! ```
//!
//! Most callers do not use this crate directly: `mapi-client` drives it, supplies the entropy from
//! the operating system and takes the channel binding off the TLS connection it already has. It is
//! a separate crate because the same handshake is needed by anyone using [`mapi-proto`] with an
//! HTTP client of their own, which is the escape hatch that sans-io exists to provide.
//!
//! # What is implemented
//!
//! * **NTLM v2**, as [MS-NLMP] §3.3.2 defines it, with the message integrity code of §3.1.5.1.2.
//! * **SPNEGO**, offering NTLM as its only mechanism, so that a server with `Negotiate` enabled and
//!   `NTLM` switched off can still be authenticated to.
//! * **Channel binding** (`tls-server-end-point`, [RFC 5929] §4.1), without which a server
//!   configured for Extended Protection refuses the credential.
//!
//! # What is not, and why
//!
//! * **Kerberos.** SPNEGO here negotiates NTLM and nothing else. Kerberos needs a KDC round trip, a
//!   credential cache and a great deal of unrelated ASN.1; advertising it and failing to complete
//!   it would break deployments that work today.
//! * **NTLM v1 and LM.** Both are broken past the point of being a fallback, and [MS-NLMP] §3.3.2
//!   notes the version is configured rather than negotiated — so speaking only v2 is what makes
//!   this client impossible to talk down.
//! * **Signing and sealing.** NTLM's own message protection, which HTTP does not carry and TLS
//!   already provides. Leaving it out removes RC4 and DES from this crate entirely.
//!
//! # This crate cannot make the connection stick, and that matters
//!
//! NTLM and Negotiate authenticate a **TCP connection**, not a request. Every leg of a handshake,
//! and every request that relies on it afterwards, has to travel on the same connection — which is
//! a property of whatever HTTP client is underneath, and therefore not something a sans-io crate
//! can promise. `mapi-client` meets it by pinning its connection pool to one connection per host
//! and serialising requests while a handshake is in flight; a caller wiring this up themselves has
//! to do the equivalent, or the third message arrives on a connection that never saw the second.
//!
//! # Specification authority
//!
//! Every message field, flag and derivation cites its section. Two documents cover this: [MS-NLMP]
//! for NTLM, and [MS-SPNG] with [RFC 4178] for SPNEGO. The pinned versions and their download URLs
//! live in `SPEC.md` at the repository root.
//!
//! [`mapi-proto`]: https://docs.rs/mapi-proto

mod binding;
mod crypto;
mod der;
mod entropy;
mod error;
mod handshake;
mod identity;
mod ntlm;
mod spnego;

pub use binding::ChannelBinding;
pub use entropy::Entropy;
pub use error::{Error, Result};
pub use handshake::{Handshake, Scheme, State};
pub use identity::Identity;

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound `mapi-client` needs in order to hold one of these in a client that is shared
    /// across tasks. Asserted rather than hoped for, so that a stray `Rc` cannot regress it.
    #[test]
    fn the_public_types_are_send_and_sync() {
        const fn assert<T: Send + Sync>() {}
        assert::<Handshake>();
        assert::<Identity>();
        assert::<Entropy>();
        assert::<ChannelBinding>();
        assert::<Scheme>();
        assert::<Error>();
    }
}
