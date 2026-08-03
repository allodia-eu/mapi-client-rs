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

Three round trips reach the first row: `Connect` establishes the Session Context, `RopLogon` returns
thirteen folder ids, and one more `Execute` opens the folder, opens its table, sets the columns and
reads the first page — because ROPs chained in a single buffer consume the handles that earlier ROPs
in the same buffer produced. Later pages are one round trip each, and do not re-send the column set.

The Calendar costs two more, and so does everything else `RopLogon` does not name — Contacts,
Drafts, Tasks, Notes, Journal. Those live behind binary entry-id properties on the Inbox, and an
entry id is long-term while `RopOpenFolder` takes a short-term id, so `Logon::special_folders()`
reads all eight properties in one `Execute` and converts all eight in the next:

```rust
use mapi_client::{FOLDER_PROPERTIES, SpecialFolder};

let special = logon.special_folders().await?;
let calendar = special.get(SpecialFolder::Calendar).expect("a Calendar");

// "Get calendar details" — a calendar is a folder, so the two are one question.
let details = logon.folder(calendar).properties().read(FOLDER_PROPERTIES).await?;
```

What is *in* a calendar entry costs one more round trip, and only once per session. A start time, an
end time and a location are named properties with no fixed ids: each store allocates its own, so they
have to be asked for. `Logon::resolve_names()` asks for them all in one `Execute` and caches the
answer, and asking again for names already known sends nothing at all.

```rust
use mapi_client::NamedProperty;

// Or `NamedProperty::ALL`, the ten a calendar or contact read is made of.
let names = logon.resolve_names([NamedProperty::Location, NamedProperty::BusyStatus]).await?;
let location = names.get(&NamedProperty::Location.name());   // None if this store would not map it
```

## What the types enforce

- **One request in flight.** MAPI/HTTP allows exactly one per Session Context, and a violation
  comes back as `X-ResponseCode` 15 (Invalid Sequence), pointing nowhere near the cause. Every
  method that sends anything takes `&mut self`, so the borrow checker refuses the second.
- **A logon cannot outlive its session.** `Connection::logon` takes the connection by value.
- **A failed round trip ends the connection.** When a request fails in transit there is no way to
  know whether the server acted on it, so the connection refuses further use rather than sending
  the next request into an unknown state.
- **No secret reaches a log.** `Credentials` implements `Debug` by hand and redacts.
- **A folder id does not travel between mailboxes.** Measured: the two lab mailboxes report the
  *same* id for each of six special folders, so an id cached from one and used against the other
  opens a real folder and reports nothing wrong. The entry ids that resolve to them carry the
  mailbox GUID that issued them, and `FolderEntryId::belongs_to` answers before a conversion is
  asked for.
- **Nor does a named-property id.** Ids are allocated per store, and in the lab every one of one
  mailbox's ten ids names a real, *different*, registered property in the other — so the mistake is
  answered with a plausible value rather than an error. A `NamedProperties` map carries the store
  that issued its ids and cannot be given a foreign one.

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

**Status:** `0.2.0`. Connect, logon, hierarchy and contents reads with paging — the hierarchy
recursively, tagged by container class — the folders a logon does not name, property reads and
writes on Store and Folder objects, named-property resolution cached per session, disconnect, and
Autodiscover lookup are implemented. No messages, no attachments, no streams, no notifications, no
ICS, no address book.

## Licence

`MIT OR Apache-2.0`, at your option.
