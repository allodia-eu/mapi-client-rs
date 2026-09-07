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

Acting on items, and then reaching mailboxes the account does not own. `0.3.0` could create, read
and delete a message; this adds *sending* one, *moving* one, and both of the things MAPI means by
*flagging* one — the read bit of `PidTagMessageFlags`, which has its own ROP, and the follow-up flag
of [MS-OXOFLAG], which is a set of ordinary properties. Then it adds **shared, delegated and archive
mailboxes**, which is the one operation on the list that is not a ROP at all.

That completes all eighteen operations the plan was written against. Every gap listed below is now a
deliberate omission rather than an operation still to come.

**And the authentication gap is closed.** `Negotiate` and `NTLM` have been listed as missing since
`0.1.0`, and they are the two schemes a default-configured Exchange offers — so until now this
client required somebody to enable Basic on the MAPI virtual directory before it would talk to an
otherwise untouched deployment. A new crate, `mapi-auth`, implements both; the whole live suite
passes over each of them, against both lab mailboxes.

Verified against Exchange Server SE `15.02.2562.045` and both lab mailboxes, with mail actually sent
between them in both directions and a shared mailbox opened on a delegate's own credentials. The
corpus grows by three scenarios and the whole of it re-captures byte for byte — 546 files identical
— with two write scenarios in it.

**This is a breaking release**: `SESSION_EXCHANGES` aside, three public items changed shape and one
behavioural change is not visible to `cargo-semver-checks` at all. Both are listed under *Changed*.

### Added

- **`NTLM` and `Negotiate` authentication**, in a new crate: **`mapi-auth`**. The gap the changelog
  has listed since `0.1.0` is closed, and with it the requirement that Basic be enabled on the MAPI
  virtual directory — a default-configured Exchange offers only these two schemes.

  `mapi-auth` is sans-io in the same sense `mapi-proto` is: it says what to put in `Authorization`
  and reads what came back in `WWW-Authenticate`, with **no network, no clock and no randomness of
  its own**. That is not tidiness. [MS-NLMP] §4.2.4 publishes worked NTLM v2 values, and they are
  only reproducible if the client challenge and the timestamp are inputs — so the boundary is what
  makes the implementation checkable against the specification rather than only against one server.
  `mapi-client` supplies the entropy from the operating system and the channel binding from the TLS
  connection it already has.

  What is inside: **NTLM v2** ([MS-NLMP] §3.3.2) with the message integrity code of §3.1.5.1.2,
  **SPNEGO** offering NTLM as its only mechanism ([RFC 4178], [MS-SPNG]), and **channel binding**
  (`tls-server-end-point`, [RFC 5929] §4.1). What is not, and why, is under *Known gaps*.
- **`Credentials::Ntlm` and `Credentials::Negotiate`**, behind a new default-on `ntlm` feature on
  `mapi-client`. Choosing either reconfigures the transport underneath — see *Changed* — because
  both authenticate a TCP connection rather than a request.
- **Autodiscover authenticates too.** The handshake runs on the discovery path as well as on the
  MAPI endpoint, which is not optional: Autodiscover is the *first* request a caller makes, so NTLM
  that worked only on the endpoint would fail one step earlier.
- **`mapi-cli --auth basic|ntlm|negotiate`** (`MAPI_LIVE_AUTH`), and `mapi-cli discover --at <URL>`
  for a deployment whose Autodiscover service is not where the candidate sequence looks.
- **`MAPI_LIVE_AUTH` drives the whole live suite**, so all twenty-eight live tests can be run over
  each scheme rather than one scheme being proved by one test.
- **`RopSubmitMessage`**, with `NewMessage::send()` for a message being created and
  `Message::send()` for a draft already in the store. Both put the submit in the same ROP buffer as
  the save that precedes it, which is the only order that works: a submit acts on what is in the
  store, so one sent before the save would send the message as it was before its properties,
  recipients and attachments were written — successfully.
- **`RopMoveCopyMessages`**, with `Folder::move_messages()` and `Folder::copy_messages()`. Both
  folders are opened in the same buffer as the move, so *archive a message* is one round trip
  however far apart they are in the hierarchy.
- **`RopSetReadFlags`**, with `Folder::set_read()` and `ReadFlags`. Addressed at a folder and a list
  of ids rather than at an open message, so marking a whole page of a contents table read is one
  ROP.
- **`RopRemoveAllRecipients`**, with `MessageUpdate::replacing_recipients()`. The gap `0.3.0` listed
  by name: `RopModifyRecipients` addresses rows by position and can never shorten a list, so this is
  the only way to clear one — and replacing a list is this ROP followed by that one, in one buffer.
- **The follow-up flag properties.** `FlagStatus`, `FollowupIcon` and `MessageFlags` in
  `mapi-proto`, eight new `PidLid`s in the named-property catalogue, and six new `PidTag`s. The
  property *lists* live in `mapi-cli` rather than in the library, as the contact and appointment
  lists do and for the same reason: [MS-OXOFLAG] leaves the choice of each to the client.
- **`Logon::register_names()`**, which asks the store to allocate an id for a named property it does
  not have. `0.3.0` listed the absence of this as a gap and understated it — see *Fixed*.
- **`MessageUpdate::delete()`**, which removes properties in the same round trip and the same commit
  as the ones being written. Needed because a property some protocols define by its *absence* has to
  actually be absent: [MS-OXOFLAG] §2.2.1.1 has `PidTagFlagStatus` exist only on a flagged message.
- **`PtypServerId`** and `ServerEntryId`, for `PidTagSentMailSvrEID` — the property that decides
  where a sent message is filed. Its `Ours` byte is not a version: `0x00` means another client
  defined the value, so both readings are variants rather than one being a parse error.
- **`STATE_PROPERTIES`**, and `mapi-cli state`, which reads back the three things "flag a message"
  can mean. Not planned: it was written to check the flag commands and immediately found a bug in
  one of them.
- **Four `mapi-cli` subcommands** — `send`, `submit`, `move`, `mark`, `flag` and `state` — and a
  ninth pair of captured scenarios, `acts-en-us` and `acts-nl-nl`.
- **Four error codes by name**: `InvalidRecipients`, `TooManyRecips`, `QuotaExceeded`,
  `MaxSubmissionExceeded` and `NullDestinationObject`.
- **`AlternativeMailbox` in `mapi-autodiscover`**, with `MailboxKind`, `MailboxAddress` and
  `Settings::alternative_mailboxes()`. This is the whole of *list mailboxes*: MAPI/HTTP has no
  enumeration verb, so these elements are the only place in the protocol family a mailbox the
  caller does not own is ever named.

  `MailboxAddress` is an enum rather than a struct of options because [MS-OXDSCLI]
  §2.2.4.1.1.2.5.2 and §2.2.4.1.1.2.5.4 make the two forms mutually exclusive in four `MUST`s — a
  distinguished name with a server, or an SMTP address to look up. A caller has to handle both and
  cannot construct the combination the document forbids.
- **`MapiClientBuilder::mailboxes()`** and `mailboxes_at()`, which list every mailbox a set of
  credentials can open, the account's own first. Plus `lookup_settings()`, for a caller that wants
  the whole Autodiscover answer rather than only the `mapiHttp` block.
- **`Mailbox`**, an alternative mailbox *resolved* to the endpoint-and-name pair a session needs —
  which on Exchange takes a second Autodiscover lookup, because it names the mailbox by address.
  `Mailbox::is_openable()` reports the one documented shape that cannot be resolved.
- **`MapiClient::for_mailbox()`** and `at()`, which re-aim an existing client at another mailbox on
  the same deployment. Sharing the client is not only an economy: `X-ClientInfo` is a GUID per
  client *instance* with a counter per Session Context ([MS-OXCMAPIHTTP] §2.2.3.3.4), so two
  mailboxes opened by one program are one instance with two contexts. A second `MapiClient::builder`
  would mint a second GUID and claim to be a second Outlook.
- **`mapi-cli mailboxes`**, with `--open` to log on to each and report the owner and Inbox count.
  Needs no `--endpoint` and no `--user-dn`, because finding those for a mailbox you do not own is
  what it does.
- **A `wrong-server` capture scenario**, and `-SharedMailbox` on `Initialize-ExchangeLab.ps1`,
  `Capture-Fixtures.ps1`, `Verify-Fixtures.ps1` and `Test-Live.ps1`. The first creates a shared
  mailbox and grants it, the middle two need one for that scenario, and the last passes only its
  *address* — resolving it is what the tests are testing.

### Fixed

- **A named property that no mailbox had ever written could not be written at all.** Every named
  property this workspace used before was one a provisioned or EWS-seeded mailbox already had an id
  for, so `resolve_names`' "only what is already registered" had never been the wrong question. It
  is the wrong question for a write, and the flag properties are the first that exposed it: both lab
  mailboxes had ids for all sixteen appointment and contact properties and for none of the eight
  flagging ones. `register_names` is the fix, and `mapi-cli`'s contact and appointment commands use
  it too — they worked only because the lab had been seeded first.
- **Clearing a follow-up flag left the flag's colour and completion time behind.** [MS-OXOFLAG]
  §3.1.4.2.3 sets nine properties back to named values and *deletes* the rest; the first version did
  only the first half, which `mapi-cli state` printed as "not flagged, red".

### Measured, and worth knowing

Each of these is recorded in the doc comment of whatever it bears on, and four are drafted as
Open Specification feedback.

- **Extended Protection is on by default, and it is not optional.** The lab's MAPI virtual
  directory reports `ExtendedProtectionTokenChecking: Require`, and an `AUTHENTICATE_MESSAGE`
  without an `MsvAvChannelBindings` pair is answered with a 401 that restarts the handshake — which
  is byte for byte what a *wrong password* looks like. Both were measured, one against the other,
  on Exchange Server SE `15.02.2562.045`: identical credentials succeed with the binding and are
  refused without it. This is the single thing most likely to make an otherwise correct NTLM
  implementation look like a credentials problem.
- **A POST with no `Content-Length` is refused with 411 *before* authentication.** `reqwest` sends
  no such header for an empty body, so the handshake leg that carries no MAPI request never reached
  the challenge it was sent for: `http.sys` answered 411 with no `WWW-Authenticate` at all. The leg
  now sets the header explicitly.
- **The server itself refuses HTTP/2 for Windows authentication.** The lab negotiates HTTP/2 by ALPN
  for an anonymous request, then resets the stream with `HTTP_1_1_REQUIRED` once the request needs
  `Negotiate` or `NTLM`. So `http1_only()` is not a precaution against multiplexing — it is what the
  server asks for, and it was measured rather than assumed.
- **IIS keeps a connection authenticated, and says so.** A completed handshake is answered with
  `Persistent-Auth: true`, and every later request on that connection needs no `Authorization`
  header at all. That is what makes the cost one extra round trip per connection rather than per
  request.
- **`reqwest` reuses one connection for sequential requests and fans out for concurrent ones.**
  Measured against a listener that stamps each response with its connection id: eight sequential
  requests all landed on one connection, four concurrent ones opened three. Since nothing in
  `reqwest` pins a request to a connection, that measurement *is* the guarantee a connection-bound
  handshake rests on — hence the mutex and the pinned pool described under *Changed*.
- **A refused credential and a restarted handshake are the same 401.** IIS reports a rejected
  password by offering the schemes again with no token attached. Read as a protocol error it sends
  the reader to the message encoding; this crate reports it as a refused credential.

- **`PidTagSentMailSvrEID` and `PidTagDeleteAfterSubmit` are not independent**, though
  [MS-OXOMSG] §3.3.5.1.3 lists them as separate bullets. Measured across all four combinations: the
  copy property *moves* the message rather than copying it, the delete property overrides it
  entirely, and with neither set the message stays where it was created. A caller setting both to be
  safe keeps no record of the send at all, which is why `NewMessage::send` documents the table and
  `mapi-cli send` offers the three outcomes rather than the two properties.
- **Filing a message mints a new id, and so does moving one.** A message saved as
  `0x51422B1800000001` arrived in Sent Items as `0xF1512B1800000001`; a message moved from Drafts to
  Deleted Items arrived under a different `PidTagMid` from the one the move named. Neither
  [MS-OXCFOLD] §2.2.1.6 nor [MS-OXCROPS] §2.2.4.6.2 says whether the identifier survives, and no
  response has room for a new one.
- **`PidTagClientSubmitTime` is not evidence of a submit.** [MS-OXOMSG] §2.2.3.11 has the server set
  it "when the e-mail message is submitted"; a draft created and saved with no `RopSubmitMessage`
  anywhere near it already carries one. `mfUnsent` and `mfSubmitted` are what answer that question.
- **`mfEverRead` is set and never cleared**, which [MS-OXCMSG] §2.2.1.6's own sentence forbids and
  its own description requires. A message at `0x0002` went to `0x0403` when marked read and back to
  `0x0402` — not `0x0002` — when marked unread. Marking a message unread does not restore the flags
  it had, and nothing a client may write can.
- **A submit with no recipients earns `ecInvalidRecips`**, `0x00000467` — a name that does not lead
  a reader to expect it, and a refusal [MS-OXOMSG] §3.3.5.1.1 does not list. The message is left
  untouched: still `mfUnsent`, still deletable. That is what makes it the one `RopSubmitMessage` the
  fixture corpus can hold.
- **Exchange filled in the sender properties itself.** [MS-OXOMSG] §3.2.4.1.2 has the client set
  them and §3.3.5.1.3.2 has the server set them from the mailbox owner; both are `MUST`s about the
  same five properties. A submit with none of them set was accepted and delivered.
- **Both halves of a submit are asynchronous.** The delivery *and* the filing settle on the server's
  own schedule, and nothing in the response says when either will happen. The live suite polls for
  both; the fixture corpus captures neither.
- **No `RopProgress` was ever seen.** Every ROP that could ask for one is sent with
  `WantAsynchronous = 0`, and Exchange honoured it for a cross-folder move — which the plan flagged
  as an assumption to measure. The response is modelled anyway, because one arriving unrecognised
  would cost the rest of the buffer.
- **Exchange names an alternative mailbox by SMTP address, never by distinguished name.**
  [MS-OXDSCLI] §2.2.4.1.1.2.5.2 offers a `LegacyDN` child, which would be everything a `Connect`
  needs; the lab sends `SmtpAddress` and no `LegacyDN` at all. So listing *n* mailboxes costs
  *n + 1* Autodiscover round trips and there is no way to make it cost fewer. The plan had this as
  "an ordinary `Connect` with that mailbox's `UserDn`", which is half right — the `Connect` is
  ordinary, and getting the `UserDn` is a second lookup.
- **The endpoint URL and the distinguished name are a matched pair, and the two halves are checked
  at different moments.** The `?MailboxId=` selects a mailbox just as the name does. Pairing one
  mailbox's URL with another's name is *accepted* by `Connect`, which answers successfully and
  reports the other mailbox's owner; the `RopLogon` in the next request is what refuses, with
  `ecWrongServer` and a redirect naming `cn=Configuration/cn=Servers/cn=<the MailboxId that would
  have worked>`. So a client that reused the first endpoint fails one request later than it looks,
  in an error about servers rather than about mailboxes. `MapiClient::at` takes both or neither for
  that reason, and the corpus carries the exchange.
- **The logon redirect's `ServerName` does not name a server, and its documented remedy is not
  actionable over MAPI/HTTP.** [MS-OXCSTOR] §2.2.1.1.2 defines the field as "the
  enterprise/site/server distinguished name (ESSDN) of server for the client to connect to", and
  §3.1.5.1 says to "create a new Session Context with the server that is specified by the
  `ServerName` field". What arrives is
  `/o=…/cn=Configuration/cn=Servers/cn=<mailbox GUID>@<domain>` — the leaf under `cn=Servers/` is
  the *mailbox's* identifier, not a server's, and it is exactly the `?MailboxId=` the URL was
  missing. Nothing says how to get from an ESSDN to an endpoint URL, and there is nothing to POST
  to an ESSDN. Useful in practice, since the GUID is the answer; drafted as Open Specification
  feedback because the field's own definition does not lead a reader there.
- **The access check is `Connect`'s, and it hides the pairing check.** A mailbox the account has no
  rights to is refused at `Connect` with `ecLoginPerm` — before the endpoint mismatch can matter.
  Only a mailbox the account may genuinely open gets as far as being told it is on the wrong server,
  which is why the `wrong-server` scenario needs a shared mailbox rather than simply a second one.
  That cost a capture run to discover.
- **Automapping is what makes a shared mailbox discoverable, not the permission.** `FullAccess`
  granted with `-AutoMapping $false` works perfectly and is never advertised: no
  `AlternativeMailbox` element, and therefore nothing in MAPI/HTTP that could name it. A permission
  a client can use and cannot discover.
- **`OwnerSmtpAddress` arrives on a `Delegate` and repeats the `SmtpAddress`.** [MS-OXDSCLI]
  §2.2.4.1.1.2.5.6 introduces the element for telling a user's own `Archive` from a delegated
  mailbox's `Archive`; on a shared mailbox it carries nothing `SmtpAddress` does not.
- **[MS-OXDSCLI] §6.2's XSD permits at most one `AlternativeMailbox`.** The element is declared
  `minOccurs="0"` with no `maxOccurs`, which defaults to one, while §2.2.4.1.1.2.5's prose describes
  a per-mailbox element and any user with both an archive and a shared mailbox has two. A reader who
  believed the schema would drop mailboxes silently; the parser reads them all.
- **A write scenario has a side effect it does not clean up, and it settles rather than drifting.**
  Capturing `acts` puts its recipient into Exchange's own `RecipientCache` folder, which moved that
  folder's row from 0 items to 1 and the Store's `PidTagContentCount` from 280 to 282. Nothing in
  the scenario wrote there and nothing can undo it — but a cache keyed by address does not grow when
  the same address recurs, so the corpus re-captures byte for byte afterwards. Worth knowing before
  reading it as drift.

### Changed

- **Choosing a connection-oriented scheme reconfigures the HTTP client.** `Credentials::Ntlm` and
  `Credentials::Negotiate` make `MapiClientBuilder::build` pin the connection pool to one connection
  per host, force HTTP/1.1, and retain the server certificate; the transport then serialises
  requests through a mutex while such credentials are in use.

  This is not a tuning choice. NTLM authenticates a TCP connection, `reqwest` offers no way to pin a
  request to one, and a handshake whose three legs land on different connections cannot complete —
  so serialising is what makes the pool's behaviour deterministic. The cost is that **cloning such a
  client no longer buys concurrency**, and that cost is unavoidable rather than merely accepted: two
  concurrent requests would need two authenticated connections, and nothing could say which
  handshake had gone to which. `Credentials::Basic` and `Credentials::Bearer` are unaffected.
- **The handshake legs are not reported to an `Observer`.** A leg is not a MAPI exchange — it has no
  `X-RequestType` and an empty body — so feeding one to the fixture recorder would write a file that
  is not a request/response pair. The exchange that carried the real request is observed as before,
  and the fixture corpus is captured with Basic.

- **`NamedProperty::ALL` grows from sixteen entries to twenty-four**, which changes its type. The
  same is true of `PropertyType`, `PropertyValue` and `RopResponse`, which gain variants — all three
  are `#[non_exhaustive]`, so that is not breaking, but a caller matching exhaustively on the raw
  `PropertyType::Unsupported(0x00FB)` would silently stop matching.
- **`ErrorCode` moved to its own module** within `mapi-proto`'s `error`, and `Attachment` and
  `EmbeddedMessage` to their own module within `mapi-client`'s `message`. Both are re-exported from
  where they were; nothing a caller writes changes.
- **The `session` capture scenario now *registers* named properties rather than resolving them**, so
  the capture is the same shape whatever the mailbox has been used for. Not a library change, but it
  is why every session fixture after the sixth renumbered.

### Known gaps

- **An alternative mailbox given as a `LegacyDN` and a `Server` cannot be opened.** A MAPI/HTTP
  endpoint needs a `?MailboxId=<guid>@<domain>` and a server's fully qualified name is not one;
  there is no arithmetic from the first to the second, and the account's own endpoint is refused at
  logon. Such a mailbox is *listed*, and `Mailbox::is_openable()` reports it as unreachable rather
  than handing back a client that fails a round trip later. Documented rather than observed: it is
  the shape [MS-OXDSCLI]'s notes 8 and 10 describe for Exchange 2007 and 2010, neither of which
  speaks MAPI/HTTP at all.
- **A shared mailbox is opened as a second Session Context, not as a second logon.** This client
  keeps one logon per connection — the two have the same lifetime, and separating them would only
  make it possible to outlive the session a handle belongs to — so *n* mailboxes cost *n*
  `Connect`s. They share one HTTP connection pool and one client identity, so the cost is a round
  trip each rather than a client each. Whether a Session Context could carry several private-mailbox
  logons at once is not measured here; [MS-OXCSTOR] §3.1.5.1 describes reusing one for a *public
  folder* logon, which is a different question.
- **A successful submit is not in the fixture corpus**, only a refused one. A captured send would
  deliver real mail on every `Verify-Fixtures.ps1` run and settle on its own schedule, which no
  byte-for-byte corpus can hold. `mapi-client`'s live suite sends between the two lab mailboxes
  instead, and is the only place that claim is checked.
- **`RopSetMessageReadFlag` is not implemented**, only `RopSetReadFlags`. The two do the same job at
  different objects, and the message-level one's extra response fields exist only in public-folder
  mode, which a private-mailbox logon cannot enter.
- **A message cannot be marked read *and* the receipt sent in one call from `mapi-cli`.**
  `rfGenerateReceiptOnly` is modelled and reachable from the library; the command line does not offer
  it, because sending a receipt without changing the read state is a thing a mail client does on the
  user's behalf rather than a thing a diagnostic tool should make easy.
- **Kerberos is not implemented.** `Negotiate` here is SPNEGO offering NTLM as its only mechanism,
  which is what every non-Windows client does and what a server with `Negotiate` enabled and `NTLM`
  disabled accepts. Kerberos needs a KDC round trip, a credential cache to read tickets from, clock
  skew handling and a great deal of unrelated ASN.1 — and advertising it without completing it would
  break deployments that work today. A server that selects it is reported by name rather than
  guessed at.
- **No `mechListMIC`.** [RFC 4178] §5 requires the exchange when the mechanism a server selects is
  not the initiator's preferred one; with a single-entry `mechTypes` list there is no other
  mechanism to select, so the case cannot arise. A server that asks for one anyway is reported
  rather than guessed at. Exchange Server SE `15.02.2562.045` does not ask.
- **NTLM v1, LM, signing and sealing are not implemented, and will not be.** [MS-NLMP] §3.3.2 notes
  the NTLM version is configured at both ends rather than negotiated, so a client that speaks only
  v2 cannot be talked down to v1. Signing and sealing are NTLM's own message protection, which HTTP
  does not carry and TLS already provides. Between them these remove DES and RC4 from the workspace
  entirely.
- **`Credentials::Ntlm` and `Credentials::Negotiate` do not read Windows' own credential store.**
  The password is passed in. Using the logged-on user's credentials means SSPI, which means `unsafe`
  FFI, which the workspace forbids at the manifest level.
- **A client using a connection-oriented scheme does not run requests concurrently.** See *Changed*.
- **Everything `0.3.0` listed that this release does not name above is still a gap**: an
  attachment's content is held in memory, an embedded message cannot be created, a recurrence is
  read rather than expanded, a meeting is not a meeting, and there is still no notification or
  incremental sync.

## [0.3.0] - 2026-08-26

Items, read and written. `0.2.0` could reach a calendar folder and say what its columns were
called; this adds the message, the attachment, the message inside an attachment, the body that does
not fit in a response buffer — and then the other direction: *draft a message* with recipients and
an attachment, *create a contact*, *create a single-instance appointment*, update one, and delete
it again.

Cumulatively the client now covers eleven of the eighteen operations the plan was written against —
everything about folders, calendars, contacts and messages except *acting* on them. What is left is
sending, moving, flagging and listing more than one mailbox, and each is named as a gap below rather
than left to be discovered.

Verified against Exchange Server SE `15.02.2562.045` against both lab mailboxes, with two new pairs
of captured scenarios. The corpus grows from 45 exchanges to 135, and one of the new scenarios
**writes** — which needed the fixture pipeline to learn three things it did not know, listed under
*Measured*.

**This is a breaking release**: four public items changed shape, listed under *Changed*.
`mapi-autodiscover` is unchanged and is republished only because all four crates share one version
number.

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
- **The coverage floor now applies to the diff as well as the whole tree**, and both arrive as
  checks on the pull request rather than as a comment. The 95% is unchanged and still lives in one
  place; what is new is that a change which clears the floor by leaving its own new lines untested
  no longer passes silently. Needs the Codecov GitHub App installed on the organisation —
  `CONTRIBUTING.md` says how to tell whether it is.
- **The Message object write ROPs**: `RopCreateMessage`, `RopSaveChangesMessage`,
  `RopModifyRecipients`, `RopCreateAttachment`, `RopSaveChangesAttachment` and `RopDeleteMessages`,
  with `Folder::create_message()`, `NewMessage`, `NewAttachment`, `SavedMessage`,
  `Message::update()` and `Folder::delete_messages()`. Two round trips to a saved draft, one more
  per attachment and one more per 16 KiB of attachment content. Nothing exists until the save, so
  every failure before it leaves the mailbox exactly as it was.
- **The stream write ROPs**: `RopWriteStream` and `RopCommitStream`, with `StreamMode` on
  `RopBatch::open_stream`. `Create` is the mode that matters — the only one that works on a property
  nothing has ever set, and the one that *deletes* the value of a property that has one.
- **One-off entry ids and recipient rows**: `OneOffEntryId` and `Recipient`, which is how a message
  is addressed without the address book. NSPI is a separate endpoint and a separate protocol this
  workspace does not implement; a one-off recipient needs no lookup at all.
- **`MessageClass`**, the counterpart of `ContainerClass` one level down, and the property that
  decides what an item *is*. Matching is case-insensitive here and case-sensitive for a folder's
  class: [MS-OXCMSG] §2.2.1.3 requires it in as many words and nothing says it about
  `PidTagContainerClass`.
- **`MessageMode`** on `RopBatch::open_message`, so a message can be opened read/write — which is
  what `Message::update()` needs and what the read path deliberately still does not ask for.
- **Six more named properties** — `PidLidResponseStatus`, `PidLidAppointmentStateFlags`,
  `PidLidSideEffects`, `PidLidFileUnder`, `PidLidEmail1OriginalDisplayName` and
  `PidLidEmail1OriginalEntryId` — with `NEW_APPOINTMENT_PROPERTIES` and `NEW_CONTACT_PROPERTIES`
  beside the read sets. Writing an item needs properties reading one has no reason to fetch, and
  `PidLidSideEffects` is the first this crate has touched in `PSETID_Common`.
- **Four more property tags** — `PidTagStartDate`, `PidTagEndDate`, `PidTagImportance` and
  `PidTagAttachExtension` — and `FileTime::from_unix_seconds`, which is the bridge a `PtypTime`
  cannot be written without.
- **`mapi-cli draft`, `contact`, `event` and `delete`**, which between them are the three operations
  this phase was written against and the way to undo them. `--folder` now accepts a special-folder
  name as well as a well-known one, so `--folder drafts` resolves through the entry-id chain.
- **A third pair of captured scenarios**, `writes-en-us` and `writes-nl-nl`, 18 exchanges each. The
  first in the corpus that is not a read — and the first evidence that a `RopSetProperties` this
  crate encodes is one a server *accepts*, since the only other one in the corpus was refused.

### Fixed

- **A stream read released the object it was reading from, in the same batch as the first read.**
  Every value in the committed corpus fitted one 16 KiB chunk, so nothing ever reached the second
  read to find out. A 40,000-byte attachment does: the second `RopReadStream` comes back as
  `GeneralFailure` on the whole `Execute`, and at a 16 KiB chunk the server does not answer at
  all — measured twice, against a 30-second client timeout and a 120-second one. `StreamRead::read`
  now keeps the chain open for the length of the read and releases it, stream first, on the way out
  of the success and the failure path alike. Nothing in [MS-OXCPRPT] says what a Stream object is
  worth once the object it was opened on is released.
- **A coverage exclusion that could never match.** `codecov.yml` excluded `**/tests/live/**` on
  the grounds that CI has no Exchange server. Integration tests are not in the report at all —
  `cargo llvm-cov` measures `src/` — so the rule did nothing while looking exactly like one that
  worked, which is the same failure mode as a scrub rule that matches nothing. Removed, with the
  reason recorded in its place so it does not come back.

### Security

- **`h2` moved from `0.4.15` to `0.4.19` in the lockfile**, for RUSTSEC-2026-0258: empty DATA
  frames queue without limit. Low severity, and patched upstream in `0.4.16`. Nothing in the
  workspace names `h2` — it arrives under `reqwest`, so a consumer resolving `mapi-client` afresh
  already picks a patched version without this. What the bump is for is `cargo deny`, which is a
  gate here rather than advice, and `mapi-cli` built `--locked` from this repository.

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
- **[MS-OXCDATA] §2.2.5.1's flag word is big-endian and §2.8.3.1's is not** — two bitfields of the
  same shape, in the same document, drawn in opposite byte orders. Reading the one-off flag word the
  usual way does not fail: it clears the `U` bit, so plainly UTF-16LE strings get decoded as 8-bit
  ones. Settled against Exchange Server SE `15.02.2562.045`, whose own
  `PidLidEmail1OriginalEntryId` for `ada@example.test` carries `01 80` — read big-endian that is
  `M` and `U` with every reserved bit zero; read little-endian it is `0x8001`, which sets both of
  the structure's reserved fields. What this crate writes is byte-identical to what the server
  writes, and a live test compares the two for every seeded contact rather than trusting the note.
- **A `RecipientRow` with no columns still ends in a `PropertyRow`, and a `PropertyRow` is never
  empty.** Leaving out its one-byte flag costs the *whole* `Execute`: Exchange answers
  `ecRpcFormat` (`0x000004B6`) — "the server is unable to parse the ROP requests in the ROP input
  buffer" — with nothing in the response naming the ROP that was wrong.
- **[MS-OXCMSG] disagrees with itself about `SaveFlags`.** §2.2.3.3.1's table gives
  `KeepOpenReadWrite` as `0x02`; every worked example in §4 sends `0x0A` and labels it with that
  name. The documented value is what goes on the wire here, and it works.
- **A write scenario can be a fixture, and the corpus still re-captures byte for byte.** Three
  things made that true: the scenario deletes what it made, everything it writes is fixed text and
  a fixed byte pattern rather than anything generated, and the message id the server mints is
  declared to the capture and zeroed wherever it appears — in the responses that carry it and in
  the two later *request* bodies that carry it too. Nothing is guessed: only values the run watched
  a server mint are touched.
- **A mailbox's size is a measurement of the moment, and the corpus was recording it.**
  `PidTagMessageSizeExtended` moves whenever anything writes to the mailbox — and the live write
  suite does exactly that, so a verify run after a test run reported two differences and buried any
  that meant something. It is now declared volatile by the scenario that reads it, like the clocks
  and the per-connection `RetryDelay` already were. `PidTagContentCount` beside it is deliberately
  left alone: the write scenario creates and deletes, so the count nets out and a change in it is a
  real finding. Measured across four captures — 280 and 312 in the two lab mailboxes, both steady,
  while the size moved every time.

### Changed

- **`RopResponse::as_open_message` takes the `RopId` it is asked about**, for the reason above.
- **`Error::PageTooLarge` is now `Error::ResponseTooLarge`**, and its message no longer says the
  response exceeded the buffer this crate asks for — measurement showed that claim to be false, and
  no longer suggests a remedy the server will not honour.
- `PropertyTag`'s catalogue is split across three modules and `RopBatch`'s ROP-issuing methods
  across four more, so that none of them outgrows the workspace's 500-line file limit. No public
  item moved.
- **`RopBatch::open_message` and `RopBatch::open_stream` take a mode.** Both defaulted to read-only
  and now say so at the call site, because the write path needs the other values and a silent
  default is not the place to decide which.
- **`RecipientType` moved from `rop` to `oxcdata`**, beside the `RecipientRow` that writing one
  produces. Its public path is unchanged.
- `NamedProperty::ALL` is sixteen entries rather than ten, which changes its type. The captured
  named-property exchanges changed with it.

### Known gaps

- **Nothing is sent.** `RopSubmitMessage` is not implemented, so a draft stays a draft. Neither is
  `RopMoveCopyMessages`, so *archive a message* is not available either — a delete is, and it is a
  soft delete rather than a move to Deleted Items.
- **Nothing is flagged.** MAPI has two things where JMAP has one: the read bit of
  `PidTagMessageFlags`, which has its own ROP, and the follow-up flag of [MS-OXOFLAG], which is a
  set of ordinary properties. Neither is here, and conflating them would be worse than the gap.
- **Recipients can be added and changed, not cleared.** `RopModifyRecipients` addresses each row by
  a `RowId` that is its position in the list, so sending a shorter list leaves the surplus
  recipients in place. `RopRemoveAllRecipients` is what clears them and is not implemented.
- **Every recipient is a one-off.** An address is carried in the message rather than looked up, so
  nothing resolves a display name against the directory. The address book is NSPI — a separate
  endpoint and a separate protocol — and one-off addressing is what makes ordinary sending reachable
  without it.
- **A named property is still never registered.** `NameRegistration::CreateIfMissing` exists and is
  encoded; every call this workspace makes passes `Existing`. That now matters more than it did: a
  write needs its properties mapped, and a mailbox that has never held an appointment would answer
  `0x0000` for the calendar ones. `mapi-cli` says which property was unmapped rather than writing an
  item without it.
- **An attachment's content is held in memory.** `NewAttachment` takes the bytes rather than a
  reader. A value the caller cannot hold is one it could not send here anyway, but a streaming
  source would be a real improvement.
- **An embedded message cannot be created**, only read. `RopOpenEmbeddedMessage` is read-only here,
  so a message cannot be attached to another message.
- **A recurrence is still read rather than expanded**, and a meeting is still not a meeting.
  `PidLidAppointmentRecur` is decoded as the blob it is; turning a pattern into a list of dates
  depends on embedded timezone rules and each exception's overrides, and its failure mode is an
  event reported at the wrong time with no error anywhere. Adding an attendee to an appointment is
  not the same operation as inviting them, and this crate offers neither.
- **`RopGetPropertiesAll` is still not in the fixture corpus.** The write-fixture harness now
  exists, and it does not help here: it zeroes values a scenario *knows* the server minted, and a
  tagged property list's dozen server clocks are not values any scenario is handed. Normalising
  those needs a decoder in the capture pipeline, which is its own piece of work.
- **`Negotiate` and `NTLM` are still not implemented.** Unchanged, and still the thing that decides
  whether this crate can talk to a default-configured Exchange at all.

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

[Unreleased]: https://github.com/allodia-eu/mapi-client-rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/allodia-eu/mapi-client-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/allodia-eu/mapi-client-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/allodia-eu/mapi-client-rs/releases/tag/v0.1.0
