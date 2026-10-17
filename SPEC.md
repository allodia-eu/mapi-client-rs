# Specification authority

**The Microsoft Open Specification documents are the authoritative resource — always.** Not this
repository's documentation, not a blog post, not another implementation, and not an inference from
an observed transcript.

Where a real server is observed to disagree with the specification, **both facts get recorded**:
the specification citation *and* the observed deviation, together with the server version that
produced it. An undocumented deviation is a landmine for the next reader, and "the server does X"
without "the spec says Y" is unverifiable.

## Pinned documents

Seventeen of the twenty-two share one release; [MS-OXDSCLI] and [MS-OXOCAL] were revised three
months later, and the three authentication documents are on their own schedule entirely — which is
exactly the drift the version pin exists to make visible. This table is the single source of truth:
`scripts/Get-Specs.ps1` parses it to download, and `scripts/Check-SpecVersion.ps1` parses it to
verify.

Note the **two hosts**. The Exchange documents are published under `officeprotocoldoc`; [MS-NLMP],
[MS-SPNG] and [MS-KILE] are Windows protocols and live under `winprotocoldoc`. The URL is read from this
table rather than composed from the document name, so the split costs nothing — but a row added by
copying the one above it will 404.

<!-- SPEC-TABLE-START -->

| Document | Version | Pages | Covers | URL |
|---|---|---:|---|---|
| MS-OXCMAPIHTTP | v20250520 | 96 | MAPI extensions for HTTP — the envelope | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCMAPIHTTP/%5bMS-OXCMAPIHTTP%5d.pdf |
| MS-OXCROPS | v20250520 | 236 | ROP list and encoding | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCROPS/%5bMS-OXCROPS%5d.pdf |
| MS-OXCDATA | v20250520 | 137 | Data structures, property types, PropertyRow | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCDATA/%5bMS-OXCDATA%5d.pdf |
| MS-OXCRPC | v20250520 | 94 | Wire Format Protocol — `RPC_HEADER_EXT`, the 32 KB payload limit, packing | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCRPC/%5bMS-OXCRPC%5d.pdf |
| MS-OXCTABL | v20250520 | 64 | Table Object Protocol | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCTABL/%5bMS-OXCTABL%5d.pdf |
| MS-OXCSTOR | v20250520 | 63 | Store Object Protocol (logon) | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCSTOR/%5bMS-OXCSTOR%5d.pdf |
| MS-OXCFOLD | v20250520 | 72 | Folder Object Protocol | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCFOLD/%5bMS-OXCFOLD%5d.pdf |
| MS-OXCPRPT | v20250520 | 66 | Property and Stream Object Protocol | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCPRPT/%5bMS-OXCPRPT%5d.pdf |
| MS-OXCMSG | v20250520 | 91 | Message and Attachment Object Protocol | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCMSG/%5bMS-OXCMSG%5d.pdf |
| MS-OXCFXICS | v20250520 | 213 | Bulk Data Transfer — FastTransfer streams and incremental sync (ICS) | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCFXICS/%5bMS-OXCFXICS%5d.pdf |
| MS-OXOMSG | v20250520 | 101 | Email Object Protocol — recipients, submit | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXOMSG/%5bMS-OXOMSG%5d.pdf |
| MS-OXOSFLD | v20250520 | 40 | Special Folders — how Calendar and Contacts are located | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXOSFLD/%5bMS-OXOSFLD%5d.pdf |
| MS-OXOCAL | v20250819 | 185 | Appointment and Meeting Object Protocol | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXOCAL/%5bMS-OXOCAL%5d.pdf |
| MS-OXOCNTC | v20250520 | 74 | Contact Object Protocol | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXOCNTC/%5bMS-OXOCNTC%5d.pdf |
| MS-OXOFLAG | v20250520 | 41 | Informational Flagging Protocol — the follow-up flag, not the read bit | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXOFLAG/%5bMS-OXOFLAG%5d.pdf |
| MS-OXPROPS | v20250520 | 377 | Master property list — the lookup table for every PidTag and PidLid | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXPROPS/%5bMS-OXPROPS%5d.pdf |
| MS-OXCICAL | v20250520 | 247 | iCalendar to Appointment Object conversion algorithm | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCICAL/%5bMS-OXCICAL%5d.pdf |
| MS-OXDISCO | v20250520 | 26 | Autodiscover HTTP Service — where to look for the service | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXDISCO/%5bMS-OXDISCO%5d.pdf |
| MS-OXDSCLI | v20250819 | 53 | Autodiscover Publishing and Lookup — the XML, and the mapiHttp block | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXDSCLI/%5bMS-OXDSCLI%5d.pdf |
| MS-NLMP | v20260330 | 99 | NTLM authentication — the three messages, NTLM v2 and the MIC | https://winprotocoldoc.z19.web.core.windows.net/MS-NLMP/%5bMS-NLMP%5d.pdf |
| MS-SPNG | v20260714 | 33 | SPNEGO, which is what the `Negotiate` scheme negotiates with | https://winprotocoldoc.z19.web.core.windows.net/MS-SPNG/%5bMS-SPNG%5d.pdf |
| MS-KILE | v20260928 | 91 | Kerberos Protocol Extensions — what Windows adds to RFC 4120, and what it requires | https://winprotocoldoc.z19.web.core.windows.net/MS-KILE/%5bMS-KILE%5d.pdf |

<!-- SPEC-TABLE-END -->

Seventeen released **20 May 2025**; [MS-OXDSCLI] and [MS-OXOCAL] on **19 August 2025**; [MS-NLMP] on
**30 March 2026**, [MS-SPNG] on **14 July 2026** and [MS-KILE] on **28 September 2026**.

[MS-NLMP] and [MS-SPNG] were added when the client learned to speak `NTLM` and `Negotiate`. They
earn their place for the same reason the rest do — [MS-NLMP] §4.2 publishes worked cryptographic
values, and reproducing them is the difference between an implementation that is right and one that
has only ever been tried against one server. [MS-KILE] was added with Kerberos: it is not Kerberos
itself, which is the RFCs below, but everything a Windows KDC adds to it or requires of a client.

[MS-OXOCAL]'s later date was read off the PDF when it was pinned, not inherited from the documents
it arrived with. That is the rule generally: a version in this table asserts that somebody extracted
that stamp from that file, so a row is added by measuring, never by copying the row above it.

## RFCs

Kerberos is mostly not a Microsoft document. [MS-KILE] is written as a set of differences from
[RFC 4120], and the cryptography, the GSS-API framing and the channel binding are each their own
RFC. They are pinned here so that a citation of one can be checked as readily as a citation of
[MS-OXCROPS]: `scripts/Get-Specs.ps1` fetches each one's plain text into `spec/RFC<n>.txt`, next
to the Microsoft extracts.

An RFC has no release stamp to pin, because its number *is* its version: RFC 4120 has said the same
thing since 2005. What changes is the documents around it. A later RFC can update one — RFC 6542
changed how RFC 4121 binds a channel — or obsolete it outright, and the RFC's own text never says
so. So the pin is the **Updated by** column, transcribed from the RFC Editor's metadata for that
RFC, which `Get-Specs.ps1` saves as `spec/RFC<n>.json` alongside the text. `Check-SpecVersion.ps1`
fails when the saved metadata names an update or an obsoleting RFC that this column does not, which
is the same deliberate review a Microsoft version bump forces: read the new RFC, then edit the row.

<!-- RFC-TABLE-START -->

| RFC | Updated by | Covers | URL |
|---|---|---|---|
| RFC2743 | 5554, 5896 | GSS-API: the `InitialContextToken` framing every first token carries | https://www.rfc-editor.org/rfc/rfc2743.txt |
| RFC2744 | 5896 | GSS-API C bindings: the channel-bindings structure RFC 4121 hashes | https://www.rfc-editor.org/rfc/rfc2744.txt |
| RFC2782 | 6335, 8553 | DNS SRV records: how a client orders a realm's KDCs by priority and weight | https://www.rfc-editor.org/rfc/rfc2782.txt |
| RFC3961 | 8429 | The Kerberos encryption and checksum framework: key derivation, `n-fold` | https://www.rfc-editor.org/rfc/rfc3961.txt |
| RFC3962 | 9141 | AES-CTS-HMAC-SHA1-96 for Kerberos, and its string-to-key test vectors | https://www.rfc-editor.org/rfc/rfc3962.txt |
| RFC4120 | 4537, 5021, 5896, 6111, 6112, 6113, 6649, 6806, 7751, 8062, 8129, 8429, 8553 | Kerberos V5: the messages, the exchanges, the errors | https://www.rfc-editor.org/rfc/rfc4120.txt |
| RFC4121 | 5896, 6112, 6542, 6649, 8062 | The Kerberos GSS-API mechanism: the AP-REQ token, its checksum and channel binding | https://www.rfc-editor.org/rfc/rfc4121.txt |
| RFC4178 | none | SPNEGO, which [MS-SPNG] extends | https://www.rfc-editor.org/rfc/rfc4178.txt |
| RFC5929 | 9266 | Channel bindings for TLS, including `tls-server-end-point` | https://www.rfc-editor.org/rfc/rfc5929.txt |
| RFC6113 | none | FAST, the armoring this client does not do, and why | https://www.rfc-editor.org/rfc/rfc6113.txt |
| RFC6542 | none | Channel binding hash agility for the Kerberos GSS-API mechanism | https://www.rfc-editor.org/rfc/rfc6542.txt |
| RFC6806 | none | Principal name canonicalization and referrals | https://www.rfc-editor.org/rfc/rfc6806.txt |
| RFC8009 | none | AES with HMAC-SHA2 for Kerberos, which [MS-KILE] §3.1.5.2 makes a MUST | https://www.rfc-editor.org/rfc/rfc8009.txt |
| RFC8429 | none | Deprecating 3DES and RC4 in Kerberos, which is why RC4 stays out | https://www.rfc-editor.org/rfc/rfc8429.txt |
| RFC9266 | none | Channel bindings for TLS 1.3, which update RFC 5929 | https://www.rfc-editor.org/rfc/rfc9266.txt |

<!-- RFC-TABLE-END -->

## URLs in the repository, PDFs never

`scripts/Get-Specs.ps1` reads both tables above, downloads all twenty-two documents and the fifteen
RFCs into a **gitignored `spec/`** directory, and extracts each PDF to text alongside it. A fresh clone is therefore one command
away from having the authoritative sources, and the repository carries no Microsoft PDFs.

```powershell
powershell.exe -File scripts\Get-Specs.ps1
```

The Microsoft IP notice permits local copies "in order to develop implementations", but committing
58 MB of Microsoft PDFs to a public repository is both unnecessary and muddies the licensing story.

The `spec/*.txt` extracts are the useful artefact day to day: 2,499 pages of PDF are painful to
search, but `Select-String` over the text extracts is instant.

```powershell
Select-String -Path spec\MS-OXCROPS.txt -Pattern 'RopQueryRows' -Context 2
```

## Drift detection

Two tripwires, watching from opposite directions:

| Script | Catches |
|---|---|
| `scripts/Check-SpecVersion.ps1` | Microsoft revised a document, or the IETF updated an RFC. Runs `pdftotext` over each local PDF and greps the `v(\d{8})` release stamp; reads each saved RFC's metadata for an update or an obsoleting RFC the table does not name. Fails on any mismatch with the tables above. |
| `scripts/Verify-Fixtures.ps1` | The server changed its behaviour. Re-captures against the live lab and diffs against the committed fixtures. |

A version bump therefore forces a deliberate review rather than silent drift. When one happens:
bump the table, re-run `Get-Specs.ps1`, and read the revision summary in the document's own change
log before touching any code.

## Citation rule

**Every protocol item cites its source in a doc comment** — `[MS-OXCROPS] §2.2.4.1.1`, not just
"the spec". With 2,499 pages across twenty-two documents and fifteen RFCs, an uncited constant is
unverifiable in practice, which in a binary protocol means it is indistinguishable from a
transcription error.

[MS-OXPROPS] is the one to reach for first when a property constant needs a citation. It is a
lookup table rather than a document to read through — every `PidTag` and `PidLid` in the family,
with its id, its type and the protocol that defines it — so it resolves the "which document owns
this?" question that the other sixteen otherwise turn into a search.

```rust
/// Requests rows from a table object.
///
/// [MS-OXCROPS] §2.2.5.4 — RopQueryRows
/// [MS-OXCTABL] §2.2.2.13 — semantics, including the cursor interaction
pub struct QueryRows { /* ... */ }
```

## Patents

The Microsoft IP notice grants copyright permission to implement, but explicitly grants **no patent
licence**, pointing instead at the Open Specifications Promise and the Patent Map. Exchange
protocols are historically in scope of the Promise, but that is worth confirming rather than
assuming.

This gates publishing to crates.io only. Scaffolding, development and private use are unaffected.
