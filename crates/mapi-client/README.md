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

// Or `NamedProperty::ALL`, the sixteen a calendar or contact is read and written with.
let names = logon.resolve_names([NamedProperty::Location, NamedProperty::BusyStatus]).await?;
let location = names.get(&NamedProperty::Location.name());   // None if this store would not map it
```

A message is opened by its folder and its id together, because `RopOpenMessage` takes both. Its
body goes through a stream rather than a property fetch, which is not a preference: a value too
large for the response buffer comes back as `NotEnoughMemory` instead of as a value, and any real
body clears that bar.

```rust
use mapi_client::{ATTACHMENT_COLUMNS, AttachMethod, PropertyTag, PropertyValue};

let body = logon.message(inbox, id).stream(PropertyTag::BODY).read().await?;
println!("{} characters", body.text()?.chars().count());

for row in logon.message(inbox, id).attachments().collect().await? {
    let method = row.get(PropertyTag::ATTACH_METHOD)
        .and_then(PropertyValue::as_u32)
        .map(AttachMethod::new);

    // An afEmbeddedMessage attachment has no PidTagAttachDataBinary at all: its content is
    // another Message object. A client that only ever streamed the bytes reports a forwarded
    // mail as an empty file.
    match method {
        Some(m) if m.is_embedded_message() => { /* attachment(n).embedded().open() */ }
        Some(m) if m.has_binary_content()  => { /* attachment(n).content().read()   */ }
        _ => {}
    }
}
```

Sorting and filtering happen on the server, so a folder of any size costs the rows you asked for
rather than all of them:

```rust
use mapi_client::{PropertyTag, SortOrder, SortOrderSet};

let newest = logon.folder(inbox)
    .contents()
    .sort(SortOrderSet::new([SortOrder::descending(PropertyTag::MESSAGE_DELIVERY_TIME)]))
    .page_size(10)
    .rows();
```

Writing an item is the other direction, and its shape is fixed rather than chosen: an attachment's
content goes through a stream, a stream write is bounded by a two-byte length field, and a message
must be saved *after* every attachment it holds. So it is create, fill, attach, save — two round
trips to a saved draft, one more per attachment and one more per 16 KiB of attachment content.

**Nothing exists until the save.** [MS-OXCMSG] §3.2.5.2 has the server hold a new Message object
until `RopSaveChangesMessage` arrives, so every failure before that point leaves the mailbox exactly
as it was — which is what makes this safe to run against a real one.

```rust
use mapi_client::{MessageClass, NewAttachment, PropertyTag, PropertyValue, Recipient,
                  SpecialFolder, TaggedValue};

let drafts = logon.special_folder(SpecialFolder::Drafts).await?;
let saved = logon.folder(drafts)
    .create_message(MessageClass::Note)
    .set([TaggedValue::new(PropertyTag::SUBJECT, PropertyValue::String("Notes".into()))?])
    .to([Recipient::to("Ada Lovelace", "ada@example.test")?])   // one-off: nothing is looked up
    .attach([NewAttachment::by_value("notes.txt", *b"one line\n")?])
    .save()
    .await?;

// Changing one is a single round trip: opened read/write, written, saved and released in one
// `Execute`. Taking it out again is a soft delete.
logon.message(drafts, saved.id()).update()
    .set([TaggedValue::new(PropertyTag::SUBJECT, PropertyValue::String("Revised".into()))?])
    .save()
    .await?;
logon.folder(drafts).delete_messages(&[saved.id()]).await?;
```

A contact and a single-instance appointment are the same call with a different `MessageClass` and
the named properties that make them what they are — `NEW_CONTACT_PROPERTIES` and
`NEW_APPOINTMENT_PROPERTIES` name them. A recipient is addressed **one-off**: the address travels
in the message rather than being resolved, because the address book is NSPI, a separate endpoint
this workspace does not implement.

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
  mailbox's sixteen ids names a real, *different*, registered property in the other — so the
  mistake is answered with a plausible value rather than an error. A `NamedProperties` map carries
  the store that issued its ids and cannot be given a foreign one.

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

**Status:** `0.3.0` released, and the tree is ahead of it. Connect, logon, hierarchy and contents
reads with paging — the hierarchy recursively, tagged by container class, the contents sorted and
filtered by the server — the folders a logon does not name, property reads and writes on Store and
Folder objects, named-property resolution cached per session, messages with their properties,
attachments, embedded messages and streamed bodies, disconnect, and Autodiscover lookup are
implemented. Then creating a message, a contact or a single-instance appointment, with recipients
and attachments, changing one and deleting it. Unreleased on top of that: **sending** a message,
moving one between folders, marking one read or unread, replacing a recipient list, and registering
a named property a store has never held. No notifications, no ICS, no address book, and no way to
enumerate more than the one mailbox a logon names.

## Licence

`MIT OR Apache-2.0`, at your option.
