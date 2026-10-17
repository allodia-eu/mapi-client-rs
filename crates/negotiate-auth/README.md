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

## What else it is for

Nothing in the handshake is MAPI's. It answers any server that sends `WWW-Authenticate: Negotiate`
or `NTLM` — which is what Windows Authentication is, wherever IIS or a Kerberos-aware web server
does it — given a password and an HTTP client to carry the headers:

- **The rest of an on-premises Exchange**: EWS, Autodiscover, the offline address book, Outlook
  Anywhere.
- **Anything behind IIS Windows Authentication**: SharePoint Server, SQL Server Reporting Services,
  Azure DevOps Server, Dynamics on-premises, AD FS's Windows Integrated Authentication, and the
  intranet services an organisation writes for itself.
- **WinRM over HTTPS**, port 5986. Over plain HTTP WinRM encrypts each message with the session
  key, which is the session security this crate leaves out.
- **An authenticating proxy**: `Proxy-Authenticate: Negotiate` on a 407 is the same exchange as a
  401's.
- **Kerberos-protected HTTP away from Windows** — Hadoop's web interfaces, Apache's
  `mod_auth_gssapi`, the FreeIPA web UI — wherever the KDC offers AES and is found by DNS SRV. Only
  Windows Server 2025 KDCs have been measured.

What it does not reach, as the API stands, is Negotiate outside HTTP. The values in and out are
header values rather than raw tokens, so LDAP's `GSS-SPNEGO` bind and SQL Server's integrated
login are an additive API away; SMB, LDAP signing on port 389, DCE/RPC, CredSSP and SASL `GSSAPI`
also need the session key and message protection, which are outside this crate by the rules below.

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

## How much of each protocol this is

This is the **client half of HTTP `Negotiate` and `NTLM`, with a password**, and very little else.
Taking that slice whole is deliberate; so is everything outside it.

| | What a client authenticating over HTTP needs | The protocol as a whole |
|---|---|---|
| **NTLM** ([MS-NLMP]) | All of it: the three messages, NTLM v2, the AV pairs, the MIC, the channel binding | About 40% of the normative text. No server role, no connectionless mode, no NTLM v1 or LM, no session security — the signing, sealing and key exchange of §3.4, which HTTP never uses |
| **Kerberos** ([RFC4120], [MS-KILE]) | Nearly all of it: AS and TGS with a password, referrals, the AP exchange with mutual authentication and channel binding, MIC tokens | Perhaps 10–15% of what a general Kerberos library carries. No KDC or acceptor role, no RC4, DES or 3DES, no PKINIT or smart cards, no FAST, no S4U or delegation, no user-to-user, no ticket renewal or forwarding, no `KRB-SAFE`/`KRB-PRIV`, no GSS wrap and unwrap, no password change, no keytab or credential cache, no UDP or KDC proxy |
| **SPNEGO** ([RFC4178], [MS-SPNG]) | The initiator, with Kerberos and NTLM and both `mechListMIC`s | No acceptor, no NegoEx |

Those percentages are rough, measured by section rather than by line, but the shape is not: the
client slice is closed, and the rest is a different product. Requests for it are declined by the
same rules the list above states — this crate is not on its way to being a general Kerberos library.

## Why not an existing crate

Measured against what an Exchange deployment demands, on the versions current in October 2026:

- **Extended Protection is the dividing line.** Exchange refuses a handshake that does not carry
  the channel binding, with the same 401 a wrong password earns. Of the pure-Rust NTLM crates,
  `ntlmclient` 0.2.0 names the `MsvAvChannelBindings` AV pair but never computes it and sends no
  MIC, and `ntlmssp` 0.1.1 sends a MIC without the `MsvAvFlags` bit that announces it and no
  binding at all. Neither Kerberos-only crate builds the `0x8003` checksum's binding field or
  [MS-KILE]'s `KERB_AP_OPTIONS_CBT`: `kerbcore` 0.3.0 has nowhere to put the latter, and `krb5-rs`
  0.1.0 is a placeholder. `rasn-kerberos` is the RFC 4120 message types and no client.
- **`sspi`** (Devolutions, and the engine behind IronRDP) does carry both bindings, and is the
  serious alternative. It is a different shape: it mirrors the Windows SSPI API, reads the clock
  and the operating system's random source itself with no way to supply either, and, unless named
  a KDC, finds one itself — environment variables, `krb5.conf`, the platform's DNS. So no
  published test vector can be replayed through it, and a host's own resolver, which knows its VPN
  and its split DNS, cannot be the one that answers.
  Kerberos there is AES-SHA1 and 3DES, without the RFC 8009 types [MS-KILE] §3.1.5.2 makes a MUST
  or the `PA-REQ-ENC-PA-REP` that makes the first KDC exchange tamper-evident. It brings around
  thirty dependencies, some pinned to pre-release versions, ships `unsafe` in the crate itself, and
  has made five breaking releases in 2026. None of that makes it wrong — it does far more
  than this crate — but each is a property `mapi-client` gives its own callers, and would lose.
- **`picky-krb`**, the message layer under `sspi`, is free of I/O and could have carried these
  messages, but its encryption draws its confounder from the operating system's random source with
  no way to supply one, and it has neither RFC 8009 nor the structure `KERB_AP_OPTIONS_CBT` rides
  in.
- **`libgssapi` and `cross-krb5`** bind the system's GSSAPI or SSPI: a C toolchain and system
  libraries off Windows, and whatever the machine's own stack does on it. `kerbeiros` is
  AGPL-3.0, which this MIT-or-Apache workspace cannot take.

What writing it here bought is what the rest of the workspace already has: every field cites the
section that defines it, every primitive is pinned to the specification's own vectors — [MS-NLMP]
§4.2.4 and RFC 3961, 3962 and 8009 — because time and entropy are inputs, no parser can panic on
hostile input, and the crate's tests cover 99% of its lines.

## This crate cannot make the connection stick

NTLM and Negotiate authenticate a **TCP connection**, not a request. Every leg of a handshake, and
every request that relies on it afterwards, has to travel on the same connection — which is a
property of whatever HTTP client is underneath, and therefore not something a sans-io crate can
promise. `mapi-client` meets it by giving each connection an HTTP client of its own and lending
it to one request at a time; a caller wiring this up themselves has to do the equivalent, or the
third message arrives on a connection that never saw the second.

## Status

**`0.4.0`, and the first release of this crate.** NTLM v2, Kerberos V5 with the four AES encryption
types, SPNEGO carrying either, the message integrity codes and `tls-server-end-point` channel binding
are implemented, and checked against [MS-NLMP]'s published values and the RFC 3961, 3962 and 8009
vectors. The whole of `mapi-client`'s live suite runs over NTLM, and over `Negotiate` authenticated
with Kerberos — a user of a second realm included, reached by referral — against Exchange Server SE
`15.02.2562.045`. No RC4 or DES, no FAST, no NTLM v1 or LM, no signing or sealing — each for a reason
given above rather than as an omission to be discovered.

## Licence

MIT OR Apache-2.0, at your option.
