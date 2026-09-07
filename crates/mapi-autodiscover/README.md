# `mapi-autodiscover`

Exchange **Autodiscover** client: locates the MAPI over HTTP endpoint for a mailbox.

A separate protocol from the ROP layer — XML over HTTPS — and separately useful, so it is a
separate crate. It is also the one place the `X-MapiHttpCapability` request header lives, without
which a server will not advertise its MAPI/HTTP URL at all: the `mapiHttp` block is simply absent,
and the answer looks like a deployment that does not support the protocol rather than one that was
never asked.

Sans-io, like [`mapi-proto`](https://crates.io/crates/mapi-proto). This crate says where to look,
what to send and what came back; the caller does the sending.

```rust
use mapi_autodiscover::{AutodiscoverRequest, AutodiscoverResponse, EmailAddress, candidate_urls};

let address = EmailAddress::new("user@contoso.com")?;
let request = AutodiscoverRequest::new(&address);

for url in candidate_urls(&address) {
    // POST request.body() to `url` with request.headers().
    let response = AutodiscoverResponse::parse(&body)?;

    if let Some(endpoint) = response.settings().and_then(|s| s.mapi_http()) {
        // Everything a MAPI session needs, from one round trip.
        let url = endpoint.mail_store_url();
        let dn = endpoint.legacy_dn();
        break;
    }
}
```

Two shapes in a real response defeat a first attempt at reading it, and both are pinned by a test
against a capture from a live Exchange Server:

- `Autodiscover` and `Response` are in **different XML namespaces**.
- `mapiHttp` names itself with a `Type` **attribute** while every other protocol uses a `Type`
  **child element** — so a reader that only looks at one of the two never finds MAPI/HTTP.

Part of [`mapi-client-rs`](https://github.com/allodia-eu/mapi-client-rs). Every element and header
cites its Microsoft Open Specification section; see `SPEC.md` in the repository root for the pinned
document versions.

**Status:** `0.4.0`, carrying the first change to this crate since `0.1.0`. Request building, the
candidate-URL sequence, response parsing, redirects and server errors are implemented. SRV lookup
and HTTP redirect probing need DNS and HTTP, so this crate names them and the caller performs them.

`AlternativeMailbox` elements are now parsed, which is the whole of *list mailboxes*: MAPI/HTTP has
no enumeration verb, so this is the only place in the protocol family a shared, delegated or archive
mailbox is ever named. Measured against Exchange Server SE `15.02.2562.045`, and the measurement
shapes the API: Exchange names such a mailbox by **SMTP address** and never by the distinguished
name [MS-OXDSCLI] §2.2.4.1.1.2.5.2 offers, so opening one costs a second lookup. `MailboxAddress`
is an enum rather than a struct of options because the two forms are mutually exclusive in four
`MUST`s, and a caller has to handle whichever arrives.

## Licence

`MIT OR Apache-2.0`, at your option.
