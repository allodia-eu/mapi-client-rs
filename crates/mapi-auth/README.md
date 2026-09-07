# `mapi-auth`

**NTLM** and **Negotiate** (SPNEGO) authentication, as a state machine that does no I/O.

A default-configured Exchange offers exactly two authentication schemes on its MAPI virtual
directory, `Negotiate` and `NTLM`, and neither is a header a client can compute on its own: both are
multi-leg challenge/response exchanges bound to a TCP connection. This crate produces the
`Authorization` values for those legs and consumes the `WWW-Authenticate` values that come back. It
never opens a socket, reads a clock or generates a random number.

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
    Identity::new(r"DEV\developer", "…"),
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

- **NTLM v2** ([MS-NLMP] §3.3.2), with the message integrity code of §3.1.5.1.2.
- **SPNEGO** ([RFC4178], extended by [MS-SPNG]), offering NTLM as its only mechanism — so a server
  with `Negotiate` enabled and `NTLM` switched off can still be authenticated to.
- **Channel binding** (`tls-server-end-point`, [RFC5929] §4.1). Not optional in practice:
  Exchange Server SE `15.02.2562.045` ships with `ExtendedProtectionTokenChecking: Require`, and an
  `AUTHENTICATE_MESSAGE` without an `MsvAvChannelBindings` pair is refused with a 401 that is byte
  for byte what a wrong password looks like.

## What is not, and why

- **Kerberos.** It needs a KDC round trip, a credential cache and a great deal of unrelated ASN.1.
  Advertising it and failing to complete it would break deployments that work today, so a server
  that selects it is reported by name instead.
- **NTLM v1 and LM.** Both are broken past the point of being a fallback, and [MS-NLMP] §3.3.2 notes
  the version is configured at both ends rather than negotiated — so speaking only v2 is what makes
  a client impossible to talk down.
- **Signing and sealing.** NTLM's own message protection, which HTTP does not carry and TLS already
  provides. Leaving it out removes DES and RC4 from this crate entirely.

## This crate cannot make the connection stick

NTLM and Negotiate authenticate a **TCP connection**, not a request. Every leg of a handshake, and
every request that relies on it afterwards, has to travel on the same connection — which is a
property of whatever HTTP client is underneath, and therefore not something a sans-io crate can
promise. `mapi-client` meets it by pinning its connection pool to one connection per host and
serialising requests while a handshake is in flight; a caller wiring this up themselves has to do
the equivalent, or the third message arrives on a connection that never saw the second.

## Status

**`0.4.0`, and the first release of this crate.** NTLM v2, SPNEGO carrying it, the message integrity
code and `tls-server-end-point` channel binding are implemented and checked against [MS-NLMP]'s
published values; the whole of `mapi-client`'s live suite runs over both schemes against Exchange
Server SE `15.02.2562.045`. No Kerberos, no NTLM v1 or LM, no signing or sealing — each for a reason
given above rather than as an omission to be discovered.

## Licence

MIT OR Apache-2.0, at your option.
