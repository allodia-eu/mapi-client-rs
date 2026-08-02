# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). All four crates in the
workspace share one version number, so an entry below applies to whichever of them it names.

Two conventions specific to this project:

- **Protocol claims name the server they were measured against.** "Verified against Exchange Server
  SE 15.02.2562.045" means somebody ran it on that build, not that it ought to work.
- **Gaps are listed as plainly as features.** A client that quietly does not implement something is
  worse than one that says so.

## [Unreleased]

### Added

- **Nine more property types**, taking `PropertyType` from six to fifteen: `PtypInteger16`,
  `PtypFloating64`, `PtypObject`, `PtypString8`, `PtypGuid`, `PtypBinary`, `PtypMultipleInteger32`,
  `PtypMultipleString` and `PtypMultipleBinary`. Seven of them arrive from a real Store object and
  one more from a real folder; the rest are unit-tested only, and the crate says which is which.
- **The COUNT width is a parameter of the decoder, not a constant.** A `PtypBinary` byte count is 16
  bits inside a ROP buffer and a `PtypMultiple` value count is 32, and reading either at the wrong
  width does not fail — it consumes the wrong number of bytes and silently misreads every property
  after it. [MS-OXCDATA] contradicts itself about the second one (§2.11.1.1 says 32 bits, §2.11.2.1
  says 16); §2.11.1.1 is what Exchange Server SE `15.02.2562.045` does, measured by putting a
  multivalued column in front of two whose correct values were already known.
- **The property ROPs**: `RopGetPropertiesSpecific`, `RopGetPropertiesAll`, `RopSetProperties` and
  `RopDeleteProperties`, with `PropertySet`, `TaggedValue` and `PropertyProblem`. `Logon::store()`
  reads and writes the Store object, and `mapi-cli properties` dumps it — which is *get mailbox
  metadata* delivered: display name, owner, size and quotas.
- **The codec can now write a property value**, and refuses what the wire cannot carry rather than
  truncating it: a string holding an interior NUL, a binary longer than its own COUNT can express, a
  value paired with a tag that declares a different type.
- **Two more captured exchanges per session**, so CI holds byte-exact evidence of a property fetch
  and of a refused property write.
- **The folders a logon does not name.** `RopLogon` reports thirteen folder ids and Calendar,
  Contacts, Drafts, Tasks, Notes and Journal are none of them. `Logon::special_folders()` follows
  [MS-OXOSFLD] §2.2.3's chain — read the binary entry-id properties off the Inbox, parse each
  46-byte `FolderEntryId`, and convert its long-term tail with `RopIdFromLongTermId` — in two round
  trips, whether one folder is wanted or all eight. `mapi-cli special --details` prints the lot.
- **`RopIdFromLongTermId` and `RopLongTermIdFromId`**, with `LongTermId`, `ShortTermId`,
  `FolderEntryId` and `StoreObjectType`. The two identifiers are not interconvertible by arithmetic:
  only the server holds the mapping between a 16-byte database GUID and the 2-byte replica id that
  stands for it.
- **Recursive folder listings.** `Folder::descendants()` sets the `Depth` bit of `TableFlags`, so a
  whole mailbox arrives in one table instead of one round trip per folder.
  `mapi-cli folders --recursive` renders it as a tree, and `--class IPF.Appointment` filters it —
  which is *list folders*, *list calendars* and *list contacts folders* delivered.
- **`ContainerClass`**, the property that is the whole of what makes a folder a calendar. Matching
  is on the dotted prefix, so `IPF.Contact` finds `IPF.Contact.MOC.QuickContacts` too — the lab
  mailbox has eight kinds of contacts folder and equality would have found one.
- **A folder's own properties**, via `Folder::properties()` and `FOLDER_PROPERTIES`, in one round
  trip that opens, reads and releases. That is *get calendar details*: a calendar is a folder, so
  the two are one question.
- **Six more captured exchanges per session** — a recursive hierarchy read across two pages, both
  halves of the entry-id chain, and a property read on the Calendar it found.

### Changed

- **`HIERARCHY_COLUMNS` is six tags rather than four**, adding `PidTagParentFolderId` and
  `PidTagContainerClass`. Without the first a recursive read is a flat bag of names with no way back
  to a tree; without the second a calendar and a mail folder are two names in a language the reader
  may not have.
- **`RopBatch::hierarchy_table` takes a `FolderDepth`.** The immediate children and the whole
  subtree are different questions and a default would answer one of them silently.

### Measured against Exchange Server SE `15.02.2562.045`

- **`RopGetPropertiesAll` does not return every readable property.** It returns the properties *on*
  the object ([MS-OXCPRPT] §3.2.5.2); computed ones need an explicit fetch (§3.2.5.1). A private
  mailbox logon answered with 113 properties, and `PidTagMailboxOwnerEntryId` was not among them —
  yet was 151 bytes long when asked for by name.
- **A write can succeed as a ROP and fail as a property.** [MS-OXCSTOR] lists five read/write Store
  properties and its own notes 14–16 then say Exchange 2013 SP1 and later refuse three of them with
  `ecAccessDenied`. Confirmed for `PidTagComment`, and `RopDeleteProperties` refuses it the same way
  — which the notes do not cover.
- **`PidTagStoreState` and `PidTagLocaleId` answer `ecNotFound`** on both lab mailboxes, though
  [MS-OXCSTOR] §2.2.2.1.1 lists them as read-only properties of every private mailbox logon.
- **Two different mailboxes report the same folder id for the same special folder.** Calendar is
  `0x0D01000000000001` in both lab mailboxes, Contacts `0x0E01000000000001`, and so on for six of
  the seven they have. A short-term id is only meaningful inside the logon that produced it, and
  here the numbers are literally equal — so an id cached from one mailbox and used against another
  opens a real folder and reports nothing at all. The entry ids differ, because their `Provider UID`
  is the mailbox GUID; `FolderEntryId::belongs_to` is the check that uses it.
- **The Reminders folder is not inside the IPM subtree.** It resolves to a folder a recursive walk
  of the user-visible tree does not contain — which matches [MS-OXOSFLD] §3.1.1.1, where Reminders
  sits directly under the Root folder as a sibling of Top of Personal Folders. A client that located
  special folders by walking the tree Outlook shows would never find it.
- **`PidTagContainerClass` does not always begin with `IPF.`,** though [MS-OXCFOLD] §2.2.2.2.2.3
  says it must. [MS-OXOSFLD] §2.2.1's own table gives Reminders `Outlook.Reminder`, and a freshly
  provisioned mailbox carries a folder whose class is the bare string `IPF`. Seventeen distinct
  classes were observed in a mailbox holding no user data.
- **The `Depth` flag is honoured.** A recursive read of the IPM subtree found the same 26 folders
  as walking the hierarchy one `RopGetHierarchyTable` at a time, in both lab mailboxes, and every
  row carried `PidTagParentFolderId`.
- **Neither lab mailbox has an Archive folder**, so `PidTagIpmArchiveEntryId` is absent from the
  Inbox. Reported as absent rather than as a failure: Exchange creates most special folders on
  demand.

### Known gaps

- **`RopGetPropertiesAll` is not in the fixture corpus.** Its answer carries a dozen server clocks
  that move on every logon, so a capture of it would make `Verify-Fixtures.ps1` report a difference
  on every run and lose the one that mattered. Normalising a tagged property list is its own piece of
  work and belongs with the rest of the write-fixture harness.
- **Messages and attachments are still unreachable as objects.** Store and Folder objects can be
  read and written; `RopOpenMessage` and everything below it come later.
- **The indexed special folders are not modelled.** Junk E-mail, Conflicts, Sync Issues, Local
  Failures and Server Failures are entries inside `PidTagAdditionalRenEntryIds` ([MS-OXOSFLD]
  §2.2.4) rather than properties of their own. A recursive hierarchy read still finds them by name
  and by class; nothing resolves them by index yet.
- **Delegate access reads the wrong object.** [MS-OXOSFLD] §2.2.3 says the entry-id properties come
  from the Inbox for a mailbox's owner and from the Root folder for a delegate. This crate always
  reads the Inbox, which is correct for the only case it can authenticate as.
- **`PtypFloating64`, `PtypObject`, `PtypString8`, `PtypGuid`, `PtypMultipleInteger32` and
  `PtypMultipleString` have not been seen from a real server.** They are decoded per [MS-OXCDATA]
  §2.11.1 and unit-tested; no live measurement backs them yet.

## [0.1.0] - 2026-08-02

First release. Enough of MAPI over HTTP to locate a mailbox, log on and read from it — verified
against Exchange Server SE `15.02.2562.045`, with the byte-exact captures that prove it committed
to the repository.

### Added

- **`mapi-proto`** — the sans-io codec. The MAPI/HTTP envelope (request types, meta-tags,
  `X-ResponseCode`, the session cookies), `RPC_HEADER_EXT` and the ROP buffer, the ROPs needed to
  log on and read tables, the OXCDATA property types and `PropertyRow` decoders, `ecXxx` codes as a
  typed error enum, and the session state machine. No network, no async runtime, no clock: the
  caller owns all I/O and the crate owns all bytes and all state.
- **Type-safe handle chaining.** Several ROPs chain in a single `Execute` by handle index, and a
  wrong index yields a plausible-looking wrong answer rather than an error. Issuing a ROP returns a
  `HandleSlot` that later ROPs consume, so an index is never written by hand.
- **`mapi-autodiscover`** — Autodiscover as its own crate, because it is its own protocol: XML over
  HTTPS with nothing to do with ROPs, and separately useful to anyone who only needs to find an
  endpoint. Also sans-io.
- **`mapi-client`** — the async client over the codec: HTTP/2, rustls verifying against the
  operating system's trust store, Basic and Bearer authentication, Autodiscover behind a default-on
  additive feature, and an `Observer` hook that hands every request and its response to a caller
  verbatim. Three round trips reach the first row; later pages are one each.
- **`mapi-cli`** — the diagnostic binary, and the tool that captures the fixture corpus through that
  same `Observer` hook, so the capture path is the ordinary diagnostic path. Not published.
- **Fixture corpus** — 25 byte-exact exchanges from two mailboxes in two languages, with a manifest
  recording server version, capture date and a hash per file. Replayed in CI through the real client
  against an endpoint that answers exactly what Exchange answered, comparing every request body byte
  for byte against one a real server accepted.

### Known gaps

- **Nothing is written.** This release reads: hierarchy tables, contents tables, columns and paged
  rows. Creating, modifying, moving and deleting are not implemented.
- **`Negotiate` and `NTLM` are not implemented**, and a default-configured Exchange offers only
  those two. Both are multi-leg challenge/response handshakes bound to the connection, which a
  credential that computes one header cannot express. Basic must be enabled on the MAPI virtual
  directory for this client to authenticate; `mapi-client`'s documentation covers the ways round it.
- **The MS-OXCRPC auxiliary buffer layer is deferred.** Every request declares
  `AuxiliaryBufferSize = 0` and Exchange accepts it. Responses carry a buffer, whose size field is
  read and whose contents are skipped.
- **No compression or obfuscation codec.** `NoCompression|NoXorMagic` is honoured by the servers
  measured, so neither LZ77/DIRECT2 nor the `0xA5` XOR layer is implemented. A server that refuses
  those flags is not supported.

[Unreleased]: https://github.com/allodia-eu/mapi-client-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/allodia-eu/mapi-client-rs/releases/tag/v0.1.0
