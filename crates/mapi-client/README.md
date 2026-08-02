# `mapi-client`

Async client for **MAPI over HTTP**, built on the sans-io
[`mapi-proto`](https://crates.io/crates/mapi-proto) codec. HTTP, TLS and authentication live here
so that the codec stays free of them.

Nothing in the workspace depends on this crate, so a caller who wants a different transport can use
`mapi-proto` directly and skip this layer entirely.

```rust
use mapi_client::{Credentials, EmailAddress, MapiClient, PropertyTag, WellKnownFolder};

let client = MapiClient::builder()
    .credentials(Credentials::basic("alice@example.test", "hunter2"))
    .discover(&EmailAddress::new("alice@example.test")?)
    .await?;

let mut logon = client.connect().await?.logon().await?;
let mut rows  = logon.well_known(WellKnownFolder::Inbox)?.contents().rows();

while let Some(row) = rows.try_next().await? {
    println!("{:?}", row.string(PropertyTag::SUBJECT));
}
logon.disconnect().await?;
```

Three round trips reach the first row: `Connect` establishes the Session Context, `RopLogon`
returns every special folder's id, and one more `Execute` opens the folder, opens its table, sets
the columns and reads the first page — because ROPs chained in a single buffer consume the handles
that earlier ROPs in the same buffer produced. Later pages are one round trip each, and do not
re-send the column set.

## What the types enforce

- **One request in flight.** MAPI/HTTP allows exactly one per Session Context, and a violation
  comes back as `X-ResponseCode` 15 (Invalid Sequence), pointing nowhere near the cause. Every
  method that sends anything takes `&mut self`, so the borrow checker refuses the second.
- **A logon cannot outlive its session.** `Connection::logon` takes the connection by value.
- **A failed round trip ends the connection.** When a request fails in transit there is no way to
  know whether the server acted on it, so the connection refuses further use rather than sending
  the next request into an unknown state.
- **No secret reaches a log.** `Credentials` implements `Debug` by hand and redacts.

## Transport and authentication

TLS is rustls verifying against the **operating system's** trust store, which is what an
on-premises Exchange behind an organisation's internal CA needs; a bundled root list would reject
exactly the deployments this crate exists for. The HTTP client itself is an implementation detail
and appears nowhere in the public API.

Authentication is **Basic** or **Bearer**. `Negotiate` and `NTLM` are **not** implemented, which
matters because a default-configured Exchange offers only those two: both are multi-leg
challenge/response handshakes bound to the connection, which a "compute one header" credential
cannot express. Enable Basic on the MAPI virtual directory (over TLS), terminate Negotiate at a
reverse proxy, or drive `mapi-proto` with an HTTP client of your own.

## Testing

`cargo test` runs against a fake MAPI/HTTP server that answers with hand-built responses in the
layouts the specification defines. It never contacts Exchange, and neither does CI — so a green
badge means "the bytes still decode", never "verified against a real server". That second claim is
`scripts/Test-Live.ps1`, run deliberately against a lab.

Part of [`mapi-client-rs`](https://github.com/allodia-eu/mapi-client-rs). Every protocol behaviour
cites its Microsoft Open Specification section; see `SPEC.md` in the repository root for the pinned
document versions.

**Status:** pre-release. Connect, logon, folder and table reads with paging, and disconnect are
implemented, along with Autodiscover lookup. No message bodies, no notifications, no ICS, no
address book.

## Licence

`MIT OR Apache-2.0`, at your option.
