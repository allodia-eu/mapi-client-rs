//! **Kerberos, NTLM and Negotiate (SPNEGO)** authentication, as state machines that do no I/O.
//!
//! A default-configured Exchange offers exactly two authentication schemes on its MAPI virtual
//! directory, `Negotiate` and `NTLM`, and neither is a header a client can compute on its own: both
//! are challenge/response exchanges bound to a TCP connection, and `Negotiate`'s preferred
//! mechanism, Kerberos, first needs a ticket from a KDC. This crate produces the messages for the
//! KDC and the `Authorization` values for the server, and consumes what comes back. It never opens
//! a socket, reads a clock or generates a random number.
//!
//! ```
//! use core::time::Duration;
//!
//! use mapi_auth::{Entropy, Handshake, Identity, Scheme};
//!
//! let mut handshake = Handshake::new(
//!     Scheme::Ntlm,
//!     Identity::new("EXAMPLE\\alice", "hunter2"),
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
//! # Kerberos
//!
//! A [`TicketRequest`] turns a password into a service ticket, one KDC message at a time: the AS
//! exchange, the TGS exchange, and referrals across realms in both directions ([RFC 6806] §7 and
//! §8), as [MS-KILE] profiles them. [`Handshake::kerberos`] then offers the ticket to the server
//! inside SPNEGO, with NTLM behind it.
//!
//! ```no_run
//! use core::time::Duration;
//!
//! use mapi_auth::{Entropy, Handshake, Identity, KerberosEntropy, TicketRequest, TicketStep};
//!
//! # fn kdc(realm: &str, message: &[u8]) -> Vec<u8> { unimplemented!() }
//! # fn entropy() -> KerberosEntropy { KerberosEntropy::new([0; 64], Duration::ZERO) }
//! let identity = Identity::new("alice@example.test", "hunter2");
//! let (mut request, mut message) =
//!     TicketRequest::new(&identity, "HTTP/mail.example.test", &entropy())?;
//! let tickets = loop {
//!     // Find the realm's KDC (DNS SRV `_kerberos._tcp.<realm>`) and exchange over TCP.
//!     match request.receive(&kdc(message.realm(), message.bytes()), &entropy())? {
//!         TicketStep::Send(next) => message = next,
//!         TicketStep::Done(tickets) => break tickets,
//!         _ => unreachable!(),
//!     }
//! };
//! let mut handshake = Handshake::kerberos(
//!     tickets.service().clone(),
//!     identity,
//!     Entropy::from_unix_time([0x11; 8], Duration::from_secs(1_800_000_000)),
//!     [entropy(), entropy()],
//! );
//! let first = handshake.initial()?;
//! // Send it; on success, `handshake.finish(Some(www_authenticate))` checks the AP-REP.
//! # Ok::<(), mapi_auth::Error>(())
//! ```
//!
//! # What is implemented
//!
//! * **Kerberos V5** with the four AES encryption types [MS-KILE] §3.1.5.2 requires, password
//!   pre-authentication, `PA-REQ-ENC-PA-REP` ([RFC 6806] §11), referrals, clock-skew recovery, and
//!   mutual authentication: the server's AP-REP is checked, not assumed.
//! * **NTLM v2**, as [MS-NLMP] §3.3.2 defines it, with the message integrity code of §3.1.5.1.2.
//! * **SPNEGO**, offering Kerberos then NTLM when there is a ticket and NTLM alone when there is
//!   not — with the `mechListMIC`s [RFC 4178] §5 and [MS-SPNG] §3.1.5.1 note `<8>` call for, and a
//!   check of the server's.
//! * **Channel binding** (`tls-server-end-point`, [RFC 5929] §4.1), without which a server
//!   configured for Extended Protection refuses the credential — NTLM's and Kerberos's alike.
//!
//! # What is not, and why
//!
//! * **RC4 and DES Kerberos.** [RFC 8429] deprecates RC4 in Kerberos, and DES is gone from every
//!   supported Windows. An account with no AES keys is reported as such, and `Negotiate` falls back
//!   to NTLM.
//! * **Kerberos FAST.** [MS-KILE] §3.2.5.4 armors requests with a machine's ticket-granting ticket,
//!   which a client that is not joined to the domain does not have, and its own default
//!   (`EnableCBACandArmor`) is off.
//! * **`DOMAIN\user` for Kerberos.** A NetBIOS domain is not a realm, and mapping one to the other
//!   is domain-controller locator work. Kerberos needs `user@realm`, or a realm given with
//!   [`Identity::realm`]; without one, `Negotiate` is NTLM.
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
//! Every message field, flag and derivation cites its section: [MS-NLMP] for NTLM, [MS-KILE] and
//! the RFCs it rests on for Kerberos, and [MS-SPNG] with [RFC 4178] for SPNEGO. The pinned versions
//! and their download URLs live in `SPEC.md` at the repository root.
//!
//! [`mapi-proto`]: https://docs.rs/mapi-proto

mod binding;
mod crypto;
mod der;
mod entropy;
mod error;
mod handshake;
mod identity;
mod kerberos;
mod ntlm;
mod spnego;
#[cfg(feature = "testing")]
pub mod testing;

pub use binding::ChannelBinding;
pub use entropy::Entropy;
pub use error::{Error, Result};
pub use handshake::{Handshake, Mechanism, Scheme, State};
pub use identity::Identity;
pub use kerberos::client::{
    KdcMessage, KerberosEntropy, ServiceTicket, TicketGrantingTicket, TicketRequest, TicketStep,
    Tickets,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound `mapi-client` needs in order to hold one of these in a client that is shared
    /// across tasks. Asserted rather than hoped for, so that a stray `Rc` cannot regress it.
    #[test]
    fn the_public_types_are_send_and_sync() {
        const fn assert<T: Send + Sync>() {}
        assert::<Handshake>();
        assert::<TicketRequest>();
        assert::<KerberosEntropy>();
        assert::<KdcMessage>();
        assert::<TicketStep>();
        assert::<Tickets>();
        assert::<ServiceTicket>();
        assert::<TicketGrantingTicket>();
        assert::<Mechanism>();
        assert::<Identity>();
        assert::<Entropy>();
        assert::<ChannelBinding>();
        assert::<Scheme>();
        assert::<Error>();
    }
}
