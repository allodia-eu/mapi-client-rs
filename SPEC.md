# Specification authority

**The Microsoft Open Specification documents are the authoritative resource — always.** Not this
repository's documentation, not a blog post, not another implementation, and not an inference from
an observed transcript.

Where a real server is observed to disagree with the specification, **both facts get recorded**:
the specification citation *and* the observed deviation, together with the server version that
produced it. An undocumented deviation is a landmine for the next reader, and "the server does X"
without "the spec says Y" is unverifiable.

## Pinned documents

Six of the eight share one release; [MS-OXDSCLI] was revised three months later, which is exactly
the drift the version pin exists to make visible. This table is the single source of truth:
`scripts/Get-Specs.ps1` parses it to download, and `scripts/Check-SpecVersion.ps1` parses it to
verify.

<!-- SPEC-TABLE-START -->

| Document | Version | Pages | Covers | URL |
|---|---|---:|---|---|
| MS-OXCMAPIHTTP | v20250520 | 96 | MAPI extensions for HTTP — the envelope | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCMAPIHTTP/%5bMS-OXCMAPIHTTP%5d.pdf |
| MS-OXCROPS | v20250520 | 236 | ROP list and encoding | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCROPS/%5bMS-OXCROPS%5d.pdf |
| MS-OXCDATA | v20250520 | 137 | Data structures, property types, PropertyRow | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCDATA/%5bMS-OXCDATA%5d.pdf |
| MS-OXCTABL | v20250520 | 64 | Table Object Protocol | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCTABL/%5bMS-OXCTABL%5d.pdf |
| MS-OXCSTOR | v20250520 | 63 | Store Object Protocol (logon) | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCSTOR/%5bMS-OXCSTOR%5d.pdf |
| MS-OXCFOLD | v20250520 | 72 | Folder Object Protocol | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCFOLD/%5bMS-OXCFOLD%5d.pdf |
| MS-OXDISCO | v20250520 | 26 | Autodiscover HTTP Service — where to look for the service | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXDISCO/%5bMS-OXDISCO%5d.pdf |
| MS-OXDSCLI | v20250819 | 53 | Autodiscover Publishing and Lookup — the XML, and the mapiHttp block | https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXDSCLI/%5bMS-OXDSCLI%5d.pdf |

<!-- SPEC-TABLE-END -->

Six released **20 May 2025**; [MS-OXDSCLI] on **19 August 2025**.

## URLs in the repository, PDFs never

`scripts/Get-Specs.ps1` reads the table above, downloads all eight documents into a **gitignored
`spec/`** directory, and extracts each to text alongside it. A fresh clone is therefore one command
away from having the authoritative sources, and the repository carries no Microsoft PDFs.

```powershell
powershell.exe -File scripts\Get-Specs.ps1
```

The Microsoft IP notice permits local copies "in order to develop implementations", but committing
29 MB of Microsoft PDFs to a public repository is both unnecessary and muddies the licensing story.

The `spec/*.txt` extracts are the useful artefact day to day: 747 pages of PDF are painful to
search, but `Select-String` over the text extracts is instant.

```powershell
Select-String -Path spec\MS-OXCROPS.txt -Pattern 'RopQueryRows' -Context 2
```

## Drift detection

Two tripwires, watching from opposite directions:

| Script | Catches |
|---|---|
| `scripts/Check-SpecVersion.ps1` | Microsoft revised a document. Runs `pdftotext` over each local PDF, greps the `v(\d{8})` release stamp, and fails on any mismatch with the table above. |
| `scripts/Verify-Fixtures.ps1` | The server changed its behaviour. Re-captures against the live lab and diffs against the committed fixtures. |

A version bump therefore forces a deliberate review rather than silent drift. When one happens:
bump the table, re-run `Get-Specs.ps1`, and read the revision summary in the document's own change
log before touching any code.

## Citation rule

**Every protocol item cites its source in a doc comment** — `[MS-OXCROPS] §2.2.4.1.1`, not just
"the spec". With 747 pages across eight documents, an uncited constant is unverifiable in practice,
which in a binary protocol means it is indistinguishable from a transcription error.

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
