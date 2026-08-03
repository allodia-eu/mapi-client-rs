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

Reading items. `0.2.0` could reach a calendar folder and say what its columns were called; this
adds the message, the attachment, the message inside an attachment, and the body that does not fit
in a response buffer. *List calendar events*, *list contacts*, *list messages* sorted and filtered
by the server, and an attachment's bytes extracted are all delivered. Verified against Exchange
Server SE `15.02.2562.045` against two mailboxes, with a new pair of captured scenarios — the corpus
grows from 45 exchanges to 99.

### Added

- **The Message and Attachment object ROPs**: `RopOpenMessage`, `RopGetAttachmentTable`,
  `RopOpenAttachment` and `RopOpenEmbeddedMessage`, with `Message`, `Attachment` and
  `EmbeddedMessage` on the client. Reaching an attachment's bytes is one round trip, not four: the
  opens chain through a single ROP buffer like everything else here.
- **The stream ROPs**: `RopOpenStream`, `RopReadStream` and `RopGetStreamSize`, with
  `Message::stream()` and `StreamValue`. This is the only correct way to read a body —
  [MS-OXCPRPT] §2.2.3.2 has a property too large for the response buffer come back as
  `NotEnoughMemory` rather than as a value, so a property fetch answers a short message with text
  and a long one with an error. Measured: a 116,996-byte `PidTagBody` fetched that way comes back as
  `NotEnoughMemory`, and streamed comes back whole.
- **`RopSortTable` and `RopRestrict`**, with `SortOrderSet`, `SortOrder` and `Restriction`, reached
  from `TableRead::sort()` and `TableRead::filter()`. Six of the twelve restriction packet formats
  are modelled — the three that combine restrictions and the three a filter is built from — and the
  crate says which.
- **`AttachMethod`**, which is the fact an attachment reader cannot skip. An `afEmbeddedMessage`
  attachment has no `PidTagAttachDataBinary` at all, so a client that only ever reads that property
  reports a forwarded mail as an empty file. `Attachment::content()` and `Attachment::embedded()`
  are separate calls for that reason.
- **Twenty-three more property tags** — bodies, message metadata, attachment metadata and the
  contact columns with fixed ids — and five more column sets: `MESSAGE_PROPERTIES`,
  `ATTACHMENT_COLUMNS`, `ATTACHMENT_PROPERTIES`, `CONTACT_COLUMNS` and `APPOINTMENT_COLUMNS`.
- **`mapi-cli events`, `mapi-cli contacts` and `mapi-cli message`**, plus `--newest-first` and
  `--subject` on `mapi-cli messages`. Between them these are *list calendar events* with real start
  times, end times and locations; *list contacts* with their email addresses; and a message opened
  down to its body and both kinds of attachment.
- **A second pair of captured scenarios**, `items-en-us` and `items-nl-nl`, 27 exchanges each. They
  carry the shapes nothing else in the corpus does: a `TypedString` subject, a recipient table, an
  attachment table with no row count, a `RopOpenEmbeddedMessage` response, and a body reassembled
  from four round trips. The two are not copies of one another — the captured `RopSortTable` sorts
  on a named-property tag, which is a different number in each mailbox.
- **`scripts/Add-LabItems.ps1`**, which seeds a lab mailbox with the events, contacts and
  attachment-bearing message those captures need.

### Measured, and worth knowing

- **`MaxRopOut` has an effective ceiling of about 32 KiB that no document states and that raising
  it cannot pass.** Measured on Exchange Server SE `15.02.2562.045`: the field is honoured directly
  below the ceiling — a 21,099-byte output buffer succeeds at `MaxRopOut` 40,000, a 24,675-byte one
  is refused at 20,000 and succeeds at 65,536 — but a read refused at 65,536 is refused identically
  at `0x00040000`, the maximum [MS-OXCRPC] §3.1.4.2 allows. Every refusal reports a `SizeNeeded` of
  32,767 whatever was asked for. So [MS-OXCROPS] §3.1.5.1.2's remedy, resend with the buffer at
  least `SizeNeeded`, is already satisfied and changes nothing; asking for fewer bytes is the only
  way out. This crate reads 16 KiB at a time, because the read shares one buffer with the rest of
  its batch and the rest is not fixed.
- **`RopOpenEmbeddedMessage` reports a `MessageId` of zero.** [MS-OXCMSG] §2.2.3.16.2 calls the
  field a MID without qualification; both lab mailboxes answer `0x0000000000000000`.
  `OpenMessageResponse::embedded_id` reports the zero rather than folding it into `None`.
- **`RopGetAttachmentTable` reports no row count**, where the two folder tables do, so
  `Rows::row_count()` is `None` for one. So is the count after a `RopRestrict`, whose response
  carries a status and nothing else — the number the table reported when it opened is the
  unfiltered one and stays that way.
- **Reaching an embedded message opens its parent first**, so one batch carries two
  `RopOpenMessage`-shaped responses and taking the first reports the outer message's subject as the
  inner one's. `OpenMessageResponse::rop()` exists to tell them apart; the live suite asserts the
  distinction because it is a wrong answer that looks entirely right.

### Changed

- **`RopResponse::as_open_message` takes the `RopId` it is asked about**, for the reason above.
- **`Error::PageTooLarge` is now `Error::ResponseTooLarge`**, and its message no longer says the
  response exceeded the buffer this crate asks for — measurement showed that claim to be false, and
  no longer suggests a remedy the server will not honour.
- `PropertyTag`'s catalogue is split across three modules and `RopBatch`'s ROP-issuing methods
  across three more, so that none of them outgrows the workspace's 500-line file limit. No public
  item moved.

## [0.2.0] - 2026-08-03

Everything a calendar read needs except the message itself. `0.1.0` could walk a folder hierarchy
and page a table; this release adds the property layer, the entry-id chain that reaches the folders
a logon does not name, and the named-property lookup that turns `PidLidLocation` into the id one
particular store uses for it. Verified against Exchange Server SE `15.02.2562.045`, with the
byte-exact captures that prove it committed to the repository — the corpus grows from 25 exchanges
to 45, ten of them added to each of the two captured sessions.

**This is a breaking release**: three public items changed shape, listed under *Changed*.
`mapi-autodiscover` is unchanged and is republished only because all four crates share one version
number.

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
- **Named properties.** `RopGetPropertyIdsFromNames` and `RopGetNamesFromPropertyIds`, with
  `PropertyName`, `PropertySetId` and a catalogue of the ten `PidLid`s the calendar and contact
  operations need. Everything about a calendar event is a named property — start, end, location,
  busy status — and none of them has a fixed property id, so this is the step every calendar read
  now depends on. `mapi-cli named --verify` prints what one store numbers them as and then asks the
  store back what those numbers are.
- **`Logon::resolve_names()` caches per session.** [MS-OXCPRPT] §3.1.2 allows it, and a calendar
  listing that re-resolved its columns would double its round trips for ever. Asking for names
  already known sends nothing at all.
- **A resolved id is bound to the store that issued it.** `NamedPropertyId` carries the mailbox GUID
  and offers `belongs_to`; a `NamedProperties` map cannot hold an id from another mailbox at all.
  See the measurement below for what carrying one across mailboxes actually costs.
- **Two more captured exchanges per session**, covering three response shapes nothing else in the
  corpus carried: a name the store would not map, an id below `0x8000` answered out of `PS_MAPI`,
  and an id with no name at all.

### Changed

All three are breaking, which is what makes this `0.2.0` rather than `0.1.1`. Each was a choice
between a default that answers the wrong question silently and a signature that makes the caller
say which question they meant.

- **`HIERARCHY_COLUMNS` is six tags rather than four**, adding `PidTagParentFolderId` and
  `PidTagContainerClass`. Without the first a recursive read is a flat bag of names with no way back
  to a tree; without the second a calendar and a mail folder are two names in a language the reader
  may not have.
- **`RopBatch::hierarchy_table` takes a `FolderDepth`.** The immediate children and the whole
  subtree are different questions and a default would answer one of them silently.
- **`PropertyName::read` answers an `Option`, and there is no "unnamed" kind to construct.** An id a
  store has no name for is the absence of a name, not a name that is absent — [MS-OXCPRPT] §3.2.5.9
  step 3 returns a `Kind` of `0xFF` and no other data at all, property set included.

### Measured against Exchange Server SE `15.02.2562.045`

- **A `PropertyName` whose `Kind` is `0xFF` is one byte, not seventeen — and the rule for it is in a
  different document from the structure.** [MS-OXCDATA] §2.6.1's packet diagram marks `LID`,
  `NameSize` and `Name` optional and `GUID` not, so that section read alone has an entry for an id
  with no name still carrying sixteen bytes of property set. [MS-OXCPRPT] §3.2.5.9 step 3 governs
  this ROP and says the opposite outright — *"A value in the `Kind` field of `0xFF`. There is no
  other return data for this entry."* — and that is what Exchange sends: asked for the name of the
  unregistered id `0xFFFE`, it framed a 30-byte ROP whose `RopSize` ends on the `0xFF` itself.
  Reading §2.6.1's sixteen bytes there consumes whatever follows, which is how this crate found out
  it had read only half the specification. **Not a server deviation**; the shape is in the fixture
  corpus so CI checks the rule that governs the ROP rather than the diagram beside the structure.
- **The two lab mailboxes number all ten named properties differently, and every one of one
  mailbox's ids means a real, different property in the other.** `PidLidLocation` is `0x8178` in
  `developer` and `0x815B` in `developer2`; `developer`'s `0x8178` is `PSETID_Address/IsFavorite`
  over there, its `PidLidBusyStatus` id is `DisplayNameFirstLast`, and its
  `PidLidEmail1EmailAddress` id is `PS_PUBLIC_STRINGS/SkypeTeamsMeetingUrl`. Not one of the ten is
  unmapped in the other store. So a client that carried an id across mailboxes would read a
  plausible value from the wrong property with no error anywhere — the exact opposite of the folder
  ids above, where the numbers collided instead.
- **The LID is not the id.** `PidLidLocation` has LID `0x8208` and neither lab mailbox numbers it
  that. A client that skipped the lookup and used the LID would be reading something else.
- **A lookup with the create flag off registers nothing.** An invented `PS_PUBLIC_STRINGS` name
  answers `0x0000` and is still unregistered in a fresh session, which is what makes it safe for the
  capture to ask.
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
- **Nothing registers a named property.** `NameRegistration::CreateIfMissing` exists and is encoded;
  every call this workspace makes passes `Existing`, because a read that quietly writes to the
  store's mapping table is a poor sort of read. Writing a named property nothing has written before
  will need the other one.
- **A string-named property in a *response* is not in the fixture corpus.** Every catalogued
  property is named by a LID, and the string-named ones a store holds are numbered differently in
  each mailbox, so there is no id to ask about that would be stable enough to commit. The encoder
  for that form is checked against [MS-OXCPRPT] §4.1.1's own bytes, and the decoder was exercised
  live against both mailboxes.
- **Named properties are resolved but not yet read.** The ids are available and nothing uses them to
  fetch a value: `RopOpenMessage` and the message object come later, and a calendar event's start
  time lives on a message.

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

[Unreleased]: https://github.com/allodia-eu/mapi-client-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/allodia-eu/mapi-client-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/allodia-eu/mapi-client-rs/releases/tag/v0.1.0
