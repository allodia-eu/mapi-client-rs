# `mapi-auth`

**Kerberos**, **NTLM** and **Negotiate** (SPNEGO) authentication, as state machines that do no I/O.

A default-configured Exchange offers exactly two authentication schemes on its MAPI virtual
directory, `Negotiate` and `NTLM`, and neither is a header a client can compute on its own: both are
challenge/response exchanges bound to a TCP connection, and `Negotiate`'s preferred mechanism,
Kerberos, first needs a ticket from a KDC. This crate produces the messages for the KDC and the
`Authorization` values for the server, and consumes what comes back. It never opens a socket, reads
a clock or generates a random number.

Sans-io, like [`mapi-proto`](https://crates.io/crates/mapi-proto) — and here the boundary pays for
itself immediately. [MS-NLMP] §4.2.4 publishes worked NTLM v2 values, and they are only reproducible
with the document's own client challenge and timestamp. A handshake that took its entropy from the
environment could not be checked against the specification at all; because these are inputs, the
test that pins `NTProofStr` to the published bytes is possible.

```rust
use core::time::Duration;
use mapi_auth::{ChannelBinding, Entropy, Handshake, Identity, Scheme};

let mut handshake = Handshake::new(
    Scheme::Ntlm,
    Identity::new(r"EXAMPLE\alice", "…"),
    // Eight bytes from a secure random source, and the current time.
    Entropy::from_unix_time(client_challenge, since_epoch),
)
.channel_binding(ChannelBinding::tls_server_end_point(server_certificate_der))
.target_spn("HTTP/mail.example.test");

// POST with this and expect HTTP 401 …
let first = handshake.initial()?;
// … then feed back the WWW-Authenticate value it came with, and POST the real request with this.
let second = handshake.advance(www_authenticate)?;
```

Most callers do not use this crate directly:
[`mapi-client`](https://crates.io/crates/mapi-client) drives it, supplies the entropy from the
operating system and takes the channel binding off the TLS connection it already has. It is separate
because the same handshake is needed by anyone using `mapi-proto` with an HTTP client of their own.

## What is implemented

- **Kerberos V5** ([RFC4120], profiled by [MS-KILE]): `TicketRequest` gets a service ticket one KDC
  message at a time — the AS exchange, the TGS exchange, referrals across realms in both directions
  ([RFC6806]), clock-skew recovery — and `Handshake::kerberos` offers it, checking the server's
  AP-REP. The four AES encryption types, pinned to the published vectors.
- **NTLM v2** ([MS-NLMP] §3.3.2), with the message integrity code of §3.1.5.1.2.
- **SPNEGO** ([RFC4178], extended by [MS-SPNG]), offering Kerberos then NTLM with a ticket and NTLM
  alone without — so a server with `Negotiate` enabled and `NTLM` switched off can still be
  authenticated to. The `mechListMIC`s [RFC4178] §5 and [MS-SPNG] §3.1.5.1 note `<8>` call for are
  sent, and a server's is verified when it sends one.
- **Channel binding** (`tls-server-end-point`, [RFC5929] §4.1). Not optional in practice:
  Exchange Server SE `15.02.2562.045` ships with `ExtendedProtectionTokenChecking: Require`, and an
  `AUTHENTICATE_MESSAGE` without an `MsvAvChannelBindings` pair is refused with a 401 that is byte
  for byte what a wrong password looks like.

## What is not, and why

- **RC4 and DES Kerberos.** [RFC8429] deprecates RC4 in Kerberos, and DES is gone from every
  supported Windows.
- **Kerberos FAST.** It armors requests with a machine account's ticket, which a client outside the
  domain does not have, and [MS-KILE]'s own default is off.
- **Kerberos for `DOMAIN\user`.** A NetBIOS domain is not a realm; give `user@realm`, or a realm with
  `Identity::realm`. Without one, `Negotiate` is NTLM.
- **NTLM v1 and LM.** Both are broken past the point of being a fallback, and [MS-NLMP] §3.3.2 notes
  the version is configured at both ends rather than negotiated — so speaking only v2 is what makes
  a client impossible to talk down.
- **Signing and sealing.** NTLM's own message protection, which HTTP does not carry and TLS already
  provides. Leaving it out removes DES and RC4 from this crate entirely.

## This crate cannot make the connection stick

NTLM and Negotiate authenticate a **TCP connection**, not a request. Every leg of a handshake, and
every request that relies on it afterwards, has to travel on the same connection — which is a
property of whatever HTTP client is underneath, and therefore not something a sans-io crate can
promise. `mapi-client` meets it by giving each connection an HTTP client of its own and lending
it to one request at a time; a caller wiring this up themselves has to do the equivalent, or the
third message arrives on a connection that never saw the second.

## Licence

MIT OR Apache-2.0, at your option.
