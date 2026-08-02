# Plan: mailbox, calendar and contact operations

A plan for eighteen requested operations, sequenced by what they depend on rather than by the order
they were asked in. Written against the v0.1.0 tree, whose one capability is reading folder
hierarchies and contents tables.

Like `SCAFFOLD-PLAN.md` before it, this file is spent when the work is done and should be retired
into the standing brief at that point, not left to rot.

## Scope decisions taken

Two questions were open when this was drafted and are now settled:

- **Attachments are in scope**, though they were not among the eighteen. Drafting a message without
  them is a half-feature, and the stream machinery they need is already required for large bodies.
  They land in Phases 4 and 5 alongside the message object itself.
- **Recurrence is read, not expanded.** `PidLidAppointmentRecur` is decoded into its documented
  structure and exposed as such; turning a pattern into a list of occurrences is deliberately not
  attempted here. See [Deferred](#deferred-and-said-so-plainly) for why that line is where it is.

## What MAPI actually offers

Fifteen of the eighteen are native operations. Three are not, and saying so early is cheaper than
discovering it in Phase 6.

| Requested | Mechanism | Verdict |
|---|---|---|
| List mailboxes the user can access | **No such operation.** Autodiscover's `AlternativeMailbox` elements, plus a second `Connect` per mailbox | Not MAPI — see Phase 7 |
| Get mailbox metadata | `RopLogon` response (have it) + `RopGetPropertiesSpecific` on the Store object | Phase 1 |
| List folders in mailbox | `RopGetHierarchyTable` with the `Depth` flag + `PidTagContainerClass` | Phase 2 |
| List messages in folder | `RopGetContentsTable` | **Done in v0.1.0**; sorting and filtering in Phase 4 |
| Draft a new message | `RopCreateMessage` → `RopSetProperties` → `RopModifyRecipients` → `RopSaveChangesMessage` | Phase 5 |
| Send a message | `RopSubmitMessage` | Phase 6 |
| Archive / delete a message | `RopMoveCopyMessages` / `RopDeleteMessages` | Phase 6 |
| Flag a message | Two different things — read state is `RopSetReadFlags`, follow-up is `RopSetProperties` | Phase 6 |
| List calendars | Folder hierarchy filtered on `PidTagContainerClass = "IPF.Appointment"` | Phase 2 |
| Get calendar details | `RopGetPropertiesSpecific` on the folder | Phase 2 |
| List calendar events | Contents table, but the useful columns are **named properties** | Phase 4 |
| Create / update calendar event | `RopCreateMessage` / `RopOpenMessage` with `IPM.Appointment` | Phase 5–6 |
| Delete calendar event | `RopDeleteMessages` | Phase 6 |
| List contacts | Contents table of an `IPF.Contact` folder | Phase 4 |
| Create / update / delete contact | As for appointments, with `IPM.Contact` | Phase 5–6 |

The three that are not MAPI operations:

1. **Listing mailboxes.** MAPI/HTTP has no enumeration verb. What Outlook shows in its folder pane
   comes from Autodiscover, which returns an `AlternativeMailbox` element per auto-mapped shared or
   delegate mailbox. Opening one is an ordinary `Connect` with *that* mailbox's `UserDn`, still
   authenticating as the original user; the server does the access check. So the answer is a
   `mapi-autodiscover` change plus a `mapi-client` convenience, not a new ROP.
2. **"Calendars" and "address books" as first-class objects.** They do not exist. A calendar *is* a
   folder whose `PidTagContainerClass` is `IPF.Appointment`, and a contacts folder one whose class
   is `IPF.Contact`. Everything JMAP calls a calendar collection is a folder query here.
3. **Flagging.** JMAP's `$flagged` keyword and IMAP's `\Flagged` are one thing; MAPI has two —
   `PidTagMessageFlags`' read bit, which has its own ROP, and the follow-up flag of [MS-OXOFLAG],
   which is a set of ordinary properties. The API has to expose both without conflating them.

## The structural finding

**`RopLogon` does not return the Calendar, Contacts, Drafts, Tasks, Notes or Journal folder.** Its
`FolderIds` field carries exactly thirteen: Mailbox Root, Deferred Action, Spooler Queue, IPM
Subtree, Inbox, Outbox, Sent Items, Deleted Items, Common Views, Schedule, Search, Views and
Shortcuts — [MS-OXCSTOR] §2.2.1.1.3. `WellKnownFolder` already models all thirteen and no more,
which is correct and is also the whole problem: **twelve of the eighteen requested operations are
about folders the logon never names.**

Those folders are located by entry-id properties described in [MS-OXOSFLD], which is not currently
pinned. Reaching them therefore needs, in order:

1. `PtypBinary` decoding, because an entry id is binary and the codec currently *stops* on it;
2. `RopGetPropertiesSpecific`, to read the property at all;
3. Folder EntryID parsing — 46 bytes, `Flags(4) ProviderUID(16) FolderType(2) DatabaseGuid(16)
   GlobalCounter(6) Pad(2)`, [MS-OXCDATA] §2.2.4.1;
4. `RopIdFromLongTermId` (`0x44`), because that structure is a **long-term** id and `RopOpenFolder`
   takes a short-term `FolderId`. The two are not interconvertible by arithmetic.

That chain is why the phases below are ordered as they are. Nothing about calendars or contacts can
start until it works.

## Foundations

Almost every requested operation sits on one of five pieces of shared machinery, none of which
exists yet. Building them in the order below means each phase ends somewhere demonstrable.

### F1 — Property types beyond the six

`PropertyType` models six types and returns `Unsupported(_)` for the rest, which halts the row
decoder rather than guessing a length. That was the right call and it is now the binding
constraint. Needed: `PtypBinary` (`0x0102`), `PtypString8` (`0x001E`), `PtypInteger16` (`0x0002`),
`PtypFloating64` (`0x0005`), `PtypGuid` (`0x0048`), `PtypMultipleString` (`0x101F`),
`PtypMultipleBinary` (`0x1102`), `PtypMultipleInteger32` (`0x1003`), `PtypObject` (`0x000D`).

**The COUNT-width trap is now load-bearing.** `value.rs` already carries a note that `PtypBinary`'s
count is 2 bytes in a ROP buffer and 4 in a `FastTransfer` stream, which is why it was left
unmodelled. [MS-OXCDATA] §2.11.1.1 is more specific and slightly worse: byte counts for
`PtypBinary` and value counts for every `PtypMultiple` type are **16 and 32 bits respectively
inside ROP buffers**, but **both 32 bits** in extended rules ([MS-OXORULE] §2.2.4) and in the MAPI
extensions for HTTP ([MS-OXCMAPIHTTP] §2.2.5). This crate touches two of those three contexts. The
width must therefore be a parameter of the decoder, carried by the type system, not a constant —
getting it wrong silently misreads every property after the first binary one.

`PropertyValue` and `PropertyType` are both `#[non_exhaustive]`, so adding variants is not a
breaking change. One behavioural change is worth noting anyway: `PropertyType::new(0x0102)` returns
`Unsupported(0x0102)` today and will return `Binary` afterwards. `cargo-semver-checks` will not
catch that, and a caller matching on `Unsupported(0x0102)` would silently stop matching.

### F2 — Reading and writing properties

`RopGetPropertiesSpecific` (`0x07`), `RopGetPropertiesAll` (`0x08`), `RopSetProperties` (`0x0A`),
`RopDeleteProperties` (`0x0B`) — all in [MS-OXCROPS] §2.2.8, semantics in [MS-OXCPRPT].

The response to `RopGetPropertiesSpecific` is a `PropertyRow` in the same form the row decoder
already handles, so `oxcdata/row.rs` is reused rather than duplicated.

The larger piece is that **the codec currently only reads values and never writes one.**
`PropertyValue` needs an encoder, and it needs to reject what the wire cannot carry rather than
truncating — a `String` holding an interior NUL is the `LegacyDn` problem again, one field down.

### F3 — Named properties

`RopGetPropertyIdsFromNames` (`0x56`), with the `PropertyName` structure in [MS-OXCPRPT] §2.2.12.1.

This is unavoidable for calendars and half of contacts: `PidLidAppointmentStartWhole`,
`PidLidAppointmentEndWhole`, `PidLidLocation`, `PidLidBusyStatus`, `PidLidRecurring` and
`PidLidEmail1EmailAddress` are all named properties in `PSETID_Appointment` or `PSETID_Address`,
not `PidTag` constants.

**Named property ids are per-store and are not stable between mailboxes.** They are allocated from
`0x8000`–`0xFFFF` as each store first needs them ([MS-OXCDATA] §2.4.2, `ecUnexpectedId`). An id
resolved against `developer` and reused against `developer2` will read a *different property* and
report no error — the same class of bug the handle-slot newtype was built to remove, so it deserves
the same treatment: a resolved id should be a type bound to the logon that produced it, not a bare
`u16` a caller can carry across mailboxes. The two-mailbox lab makes this testable, and I would
expect the ids to differ; that expectation should be measured and recorded either way.

A per-logon cache is needed regardless, since resolving names on every request would double the
round trips for every calendar read.

### F4 — Message objects, attachments and streams

`RopOpenMessage` (`0x03`), `RopCreateMessage` (`0x06`), `RopSaveChangesMessage` (`0x0C`),
`RopModifyRecipients` (`0x0E`), `RopSetMessageReadFlag` (`0x11`), `RopDeleteMessages` (`0x1E`),
`RopSubmitMessage` (`0x32`), `RopMoveCopyMessages` (`0x33`), `RopSetReadFlags` (`0x66`).

Attachments are the same object model one level down: `RopGetAttachmentTable` (`0x21`),
`RopOpenAttachment` (`0x22`), `RopCreateAttachment` (`0x23`), `RopDeleteAttachment` (`0x24`),
`RopSaveChangesAttachment` (`0x25`), all in [MS-OXCMSG]. An attachment is a property container that
saves independently of its message, so the save ordering is load-bearing — attachment first, then
message — and getting it backwards loses the attachment without failing.

One wrinkle worth designing for rather than discovering: an attachment whose `PidTagAttachMethod`
says `afEmbeddedMessage` has no binary content at all. Its payload is another message object,
reached with `RopOpenEmbeddedMessage` (`0x46`). A client that only reads `PidTagAttachDataBinary`
reports a forwarded mail as an empty attachment — a wrong answer that looks like a right one, so
the API should make the two cases distinguishable rather than returning an empty buffer for one.

Plus streams, which are not optional: a message body larger than what fits a ROP buffer must go
through `RopOpenStream` (`0x2B`), `RopReadStream` (`0x2C`), `RopWriteStream` (`0x2D`),
`RopGetStreamSize` (`0x5E`) and `RopCommitStream` (`0x5D`). Any real HTML body clears that bar. A
client that reads bodies only up to the buffer limit would truncate silently, which is the
`TableString` problem in a place where it costs more.

Two behaviours to design for rather than discover:

- `RopMoveCopyMessages` may complete **asynchronously**, answering `RopProgress` (`0x50`). Setting
  `WantAsynchronous = 0` is the intended remedy; whether Exchange honours it for a cross-folder move
  is a live measurement, not an assumption.
- `RopSubmitMessage` requires a set of properties to be present before it will accept the message
  ([MS-OXOMSG] §3.2.4.x). Missing one yields an error at submit time, well away from the omission.
  These belong in a builder that cannot produce an incomplete message, not in a doc comment.

### F5 — One-off EntryIDs

Addressing a recipient by SMTP address, with no directory lookup, needs a One-Off EntryID —
[MS-OXCDATA] §2.2.5.1. Without it, every recipient has to be resolved through the address book
(NSPI), which is a separate endpoint and a separate protocol this workspace does not implement at
all. One-off addressing is the far cheaper path and covers ordinary sending.

## Specification documents

Nine documents need pinning in `SPEC.md`. **I have already verified that all nine are reachable at
the same URL pattern the table's existing rows use**, so `Get-Specs.ps1` and `Check-SpecVersion.ps1`
work unchanged once the rows are added — I do not need anything from you here.

| Document | Size | Why |
|---|---|---|
| MS-OXCPRPT | 2.1 MB | Property and Stream Object Protocol — F2, F3, streams |
| MS-OXCMSG | 3.1 MB | Message and Attachment Object Protocol — F4 |
| MS-OXOMSG | 3.2 MB | Email Object Protocol — recipients, submit |
| MS-OXOSFLD | 1.4 MB | Special Folders — how Calendar and Contacts are located |
| MS-OXOCAL | 5.2 MB | Appointment and Meeting Object Protocol |
| MS-OXOCNTC | 2.3 MB | Contact Object Protocol |
| MS-OXOFLAG | 1.6 MB | Flagging Object Protocol |
| MS-OXPROPS | 6.8 MB | Master property list — the lookup table for every `PidTag`/`PidLid` |
| MS-OXCICAL | 5.2 MB | iCalendar conversion — only if iCalendar interop is wanted |

That takes the corpus from eight documents to seventeen and from 747 pages to roughly 2,600.
MS-OXPROPS is a reference table rather than a document to read through, but it is the authority for
every property constant and the citation rule needs it.

## Phases

Each ends at something that can be demonstrated against the lab, and each is a stack of PRs, not
one.

**Phase 0 — Specifications.** Nine rows in `SPEC.md`, `Get-Specs.ps1`, confirm
`Check-SpecVersion.ps1` still passes. Half a day.

**Phase 1 — The property layer.** F1 and F2. Ends with `mapi-cli` able to dump every property of
the Store object, which is *"get mailbox metadata"* delivered: display name, owner, mailbox size,
quotas.

**Phase 2 — Folders the logon does not name.** F5's entry-id chain, `RopIdFromLongTermId`, the
`Depth` flag on `RopGetHierarchyTable`, `PidTagContainerClass` as a column. Ends with a full
recursive folder listing tagged by class, which delivers *"list folders"*, *"list calendars"*,
*"list contacts folders"* and *"get calendar details"* at once. **This is the phase with a genuine
unknown in it** — [MS-OXOSFLD] has to settle which object carries the entry-id properties, and it
has to be measured on both lab mailboxes, because a client that finds Calendar in the en-US mailbox
and not the nl-NL one is exactly the trap AGENTS.md already warns about.

**Phase 3 — Named properties.** F3, with the per-logon cache and the id-binding type. Ends with the
`PSETID_Appointment` and `PSETID_Address` ids resolved and printed for both mailboxes.

**Phase 4 — Reading items.** `RopOpenMessage`, property reads on messages, streams for large
values, the attachment table and attachment reads, and `RopSortTable`/`RopRestrict` for ordered and
filtered contents tables. Ends with *"list calendar events"* with real start, end and location;
*"list contacts"* with email addresses; a message body over the buffer limit read whole; and an
attachment's bytes extracted, including the embedded-message case.

**Phase 5 — Writing items.** `RopCreateMessage`, `RopSetProperties`, `RopSaveChangesMessage`,
`RopModifyRecipients`, one-off EntryIDs, `RopWriteStream`, `RopCreateAttachment` and
`RopSaveChangesAttachment`. Ends with *"draft a message"* — with an attachment — *"create a
contact"* and *"create a single-instance appointment"*.

**Phase 6 — Acting on items.** `RopSubmitMessage`, `RopMoveCopyMessages`, `RopDeleteMessages`,
`RopSetReadFlags`, and the follow-up flag properties. Ends with the remaining eight operations, and
with mail actually sent between the two lab mailboxes.

**Phase 7 — More than one mailbox.** `AlternativeMailbox` parsing in `mapi-autodiscover`, and
opening a second mailbox on one set of credentials. Ends with *"list mailboxes"* as far as the
protocol family allows.

## The fixture problem

This is the part of the plan I am least willing to hand-wave, because it is the part where the
repository's central guarantee — *"any difference at all is a finding"* — stops being free.

Every fixture today is a **read**. A write fixture breaks three assumptions at once:

1. **Re-capture mutates the mailbox.** `Verify-Fixtures.ps1` re-captures against the live lab and
   diffs. A create-message scenario run twice leaves two messages. Every write scenario therefore
   has to be self-cleaning — create, act, delete — and the cleanup has to run even when the scenario
   fails, or the lab drifts one message per failed run.
2. **Server-assigned values differ every run.** A new message gets a fresh `MessageId`,
   `PidTagChangeKey`, `PidTagSearchKey` and `PidTagCreationTime`. `normalise.rs` already handles
   exactly this shape of problem for four fields, each anchored against a layout guarantee rather
   than an offset guess, so the mechanism exists — but the list roughly triples, and each addition
   needs the same "measured, not assumed" treatment the existing four got.
3. **New redaction surfaces.** A captured draft contains its subject, its body and its recipients.
   The length-preserving scrub rule means fixture content should be authored at fixed lengths from
   the start, rather than scrubbed after the fact and found to be one character short.

And one that is not a fixture problem but belongs next to it: **`RopSubmitMessage` sends real
mail.** A capture scenario for sending will deliver to `developer2` in the lab. That is contained,
but it should be a deliberate decision rather than a surprise, and the scenario should clean up
after itself on both sides.

None of this is a reason not to do it. It is a reason to build the write-fixture harness in Phase 5
as its own piece of work, rather than assuming the read harness stretches.

## Deferred, and said so plainly

Per the changelog's convention that gaps are listed as plainly as features:

- **Expanding a recurrence into occurrences.** The blob itself is in scope: `PidLidAppointmentRecur`
  has its own grammar ([MS-OXOCAL] §2.2.1.44) — pattern, exceptions, deleted instances, embedded
  timezone rules — and it gets decoded into that structure and exposed. What is deferred is turning
  the pattern into a list of dates. That calculation depends on the embedded timezone rules and on
  each exception's overrides, and its failure mode is an event reported at the wrong time with no
  error anywhere: the most expensive kind of wrong answer this client could give. It deserves its
  own project, its own fixtures, and a lab calendar built to exercise the awkward cases (a DST
  boundary, a deleted instance, a moved instance). Until then a recurring event reports its pattern
  and declines to enumerate, which a caller can act on.
- **Meeting invitations and responses.** [MS-OXOCAL]'s meeting workflow — invitation, tracking,
  counter-proposal — is much larger than creating an appointment. Adding an attendee to an event is
  not the same operation as inviting them, and conflating the two would be worse than not offering
  it.
- **Notifications and incremental sync.** `RopRegisterNotification` and [MS-OXCFXICS] are the
  analogues of JMAP's push and `/changes`. Almost certainly wanted eventually — a client that has to
  re-list a folder to notice a new message is not one you would build a product on — but nothing
  here depends on them.
- **`Negotiate`/`NTLM`.** Unchanged from v0.1.0 and unchanged by this plan, but worth repeating in
  a conversation containing the words "production-ready": a default-configured Exchange offers only
  those two schemes, and this client speaks neither. Basic on the MAPI virtual directory or OAuth is
  still the requirement.

## Effect on the gates

Nothing here weakens one. Two are worth watching:

- **The 500-line file limit.** Nine more ROPs will not fit `rop/`'s current five modules. The
  natural split is by object — `rop/message.rs`, `rop/property.rs`, `rop/stream.rs`,
  `rop/named.rs` — which follows the specification's own division and keeps the internal layering
  that stands in for splitting `mapi-proto` into sub-crates.
- **The 95% coverage floor.** Write paths are harder to cover from fixtures than read paths, since a
  fixture proves the request bytes were accepted rather than that the outcome was right. The replay
  test already compares request bodies byte-for-byte against ones a real server accepted, which is
  the right shape — it just has to be extended to scenarios where the interesting assertion is on
  the request rather than the response.
