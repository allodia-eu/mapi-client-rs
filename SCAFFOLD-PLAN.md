# `mapi-client-rs` — scaffolding plan

**Status: approved plan, ready to execute. No code has been written yet** — see §12 for the exact
state of this folder and the first actions to take.

Decisions locked from your answers: sans-io core + async I/O · `MIT OR Apache-2.0` ·
v0.1 = transport + ROP + tables · PowerShell **5.1 only** · GitHub **`allodia-eu/mapi-client-rs`**,
**public** · relicensing the spike from MPL-2.0 to MIT/Apache **approved** · **Rust API Guidelines
followed strictly** (§4a).

---

## 1. Why this repo exists (the README's first paragraph)

A pure-Rust, cross-platform client for **MAPI over HTTP** — the protocol Outlook actually speaks to
Exchange. The only MAPI crate on crates.io today is `outlook-mapi`, which is Windows-only COM
bindings to `olmapi32.dll` and requires Outlook to be installed. This crate talks the wire
protocol directly: no COM, no Outlook, no Windows requirement, runs anywhere Rust runs.

Feasibility is not speculative — it was measured against a real Exchange Server SE before this repo
existed. Two findings make it tractable: `NoCompression|NoXorMagic` is honoured (no LZ77/DIRECT2
codec, no 0xA5 XOR obfuscation) and `AuxiliaryBufferSize = 0` is accepted (the MS-OXCRPC aux layer
can be deferred).

## 2. Workspace layout

```
mapi-client-rs/
├─ Cargo.toml                 workspace · [workspace.lints] · [profile.dev]
├─ rust-toolchain.toml        pinned 1.97.0 (single source of truth)
├─ rustfmt.toml               nightly options (style_edition 2024, error_on_line_overflow, …)
├─ deny.toml                  permissive licences only
├─ codecov.yml                the coverage floor, defined once
├─ SPEC.md                    authoritative spec versions + URLs  ← see §6
├─ spec/                      GITIGNORED · populated by scripts/Get-Specs.ps1
├─ README.md · LICENSE-MIT · LICENSE-APACHE · CONTRIBUTING.md · SECURITY.md
├─ crates/
│  ├─ mapi-proto/             sans-io core: no async, no network, no I/O at all
│  ├─ mapi-autodiscover/      Autodiscover (a separate protocol; separately useful)
│  ├─ mapi-client/            async client built on mapi-proto
│  └─ mapi-cli/               dev/diagnostic binary (successor to tools/mapi-spike)
├─ fixtures/
│  ├─ MANIFEST.toml           server version, capture date, spec version, sha256 per file
│  └─ exchange-se/<scenario>/NN-<type>.{request,response}.bin + .meta.txt
├─ scripts/                   PowerShell 5.1 only  ← see §7
├─ .claude/skills/exchange-live/SKILL.md
└─ .github/workflows/ci.yml
```

**Four crates, and why each boundary is real** (not split for its own sake):

| Crate | Justification |
|---|---|
| `mapi-proto` | The sans-io core. No I/O means fixtures replay straight through it, which is what makes a 95% floor achievable rather than aspirational. Publishable alone for anyone writing their own transport. |
| `mapi-autodiscover` | Genuinely a *different protocol* — XML over HTTPS, nothing to do with ROPs. Useful standalone to anyone locating an Exchange endpoint. Also the only place the `X-MapiHttpCapability: 1` quirk lives. |
| `mapi-client` | Where async, HTTP, TLS, auth and retry live. Depends on `mapi-proto`; nothing depends on it. |
| `mapi-cli` | Keeps diagnostic/capture tooling out of the library's dependency tree. Also *is* the fixture capture tool, so the capture path is exercised by real use. |

I am deliberately **not** splitting `mapi-proto` further (into `mapi-wire` / `mapi-rop` /
`mapi-oxcdata`). Those layers share types densely — `PropertyTag` is used by both the ROP and the
row decoder — and splitting now buys pub-visibility gymnastics rather than isolation. Internal
modules enforce the layering; the 500-line limit forces the file split anyway. Revisit if a
boundary proves real.

### `mapi-proto` internals (every file under 500 lines by construction)

```
lib.rs
wire/{reader,writer}.rs   bounds-checked little-endian primitives; the never-panic layer
http/{request,response,cookie}.rs   MAPI/HTTP envelope: request types, meta-tags, X-ResponseCode
rop/{buffer,id,logon,folder,table}.rs   RPC_HEADER_EXT, RopSize, handle table, the ROPs
oxcdata/{tag,value,row,ids}.rs   property types, Standard/Flagged PropertyRow, FolderId/MessageId
error.rs      ecXxx codes as a typed enum
session.rs    the state machine: cookies, request-id sequencing, what is legal when
```

## 3. The API — where the DX budget goes

**Sans-io core.** The caller owns all I/O; the library owns all bytes and all state.

```rust
let mut session = Session::new();
let req = session.begin_connect(&user_dn)?;      // -> request type + body bytes
//  ... caller POSTs req.body() however it likes ...
let outcome = session.on_response(&headers, &body)?;
```

**Type-safe handle chaining.** The spike proved that four ROPs chain in a single `Execute` by
*handle index*, and that getting an index wrong yields a plausible-looking wrong answer rather than
an error. So indices are never written by hand — issuing a ROP returns a token that later ROPs
consume:

```rust
let mut batch = RopBatch::new();
let folder = batch.open_folder(logon, folder_id);        // -> HandleSlot
let table  = batch.get_contents_table(folder);           // consumes the slot
batch.set_columns(table, &[PropTag::SUBJECT, PropTag::MESSAGE_DELIVERY_TIME]);
batch.query_rows(table, 50);
let req = session.execute(batch)?;                       // one round trip
```

That single decision removes an entire bug class, and it is the kind of thing that makes a library
feel considered rather than transcribed from a spec.

**Async layer.**

```rust
let client = MapiClient::builder()
    .endpoint(url)                       // from mapi-autodiscover
    .credentials(Credentials::basic(user, pass))
    .build()?;

let logon = client.connect().await?.logon().await?;
let mut rows = logon.folder(WellKnown::Inbox)
    .contents()
    .columns([PropTag::SUBJECT, PropTag::MESSAGE_DELIVERY_TIME])
    .rows();

while let Some(row) = rows.try_next().await? {
    println!("{}", row.str(PropTag::SUBJECT).unwrap_or_default());
}
```

Non-negotiables for the public API: newtypes for every identity (`FolderId`, `MessageId`,
`LegacyDn`, `SessionCookie`, `HandleSlot`) so nothing can be crossed; `#[non_exhaustive]` error
enums via `thiserror`; `#![deny(missing_docs)]` with every public item citing its spec section; and
compiling doctests on the main entry points.

**One correctness trap to encode in the types, not the docs:** Exchange silently truncates table
string values at 255 chars with a literal `...` and no error flag. A `row.str()` that hands back a
corrupted subject is a data-loss bug in the consumer's index. The row API will surface truncation
explicitly (e.g. `Truncated(&str)` rather than a bare `&str`) so it cannot be ignored by accident.

## 4. Quality gates

- **`unsafe`**: `unsafe_code = "forbid"` at the workspace level. Not "deny" — forbid, so no module
  can opt back in.
- **Clippy**: `all` + `pedantic` + `cargo` denied. Plus, specifically for a binary parser:
  `indexing_slicing`, `arithmetic_side_effects`, `unwrap_used`, `expect_used`, `panic`,
  `as_conversions`, `cast_possible_truncation`, `todo`, `unimplemented`, `dbg_macro`. Relaxed in
  `#[cfg(test)]` only. `indexing_slicing` is the important one — it forces `.get()` everywhere and
  makes the never-panic property structural rather than hoped-for.
- **rustdoc**: `-D warnings`, plus `missing_docs` denied.
- **Files ≤ 500 lines**: `scripts/Check-FileLength.ps1`, CI-enforced.
- **Coverage ≥ 95%**: floor defined once in `codecov.yml`, read by CI and by the local script.
  Live tests excluded from the metric, exactly as the engine excludes its harness.
- **`cargo-deny`**: allowlist of permissive licences only (MIT, Apache-2.0, BSD-*, ISC, Unicode-3.0,
  Zlib). This is what mechanically enforces your "no non-permissive code" rule at the dependency
  level — a copyleft transitive dep fails the build.
- **`cargo-public-api`**: API diff posted on every PR. **`cargo-semver-checks`**: gate before publish.
- **`[profile.dev] debug = "line-tables-only"`** from commit one — the engine's own detached-workspace
  `target/` grew to 1.19 GB for one dependency because it silently opted out of this.

## 5. Fixtures — the part that matters most

CI will never see the Exchange server, so **the fixtures are the only thing standing between CI and
a false green**. The offline-fake problem is sharper here than for a JSON protocol: a fake answers
canned bytes whatever you send, and a wrong `RopBuffer` is not readable by inspection.

- `scripts/Capture-Fixtures.ps1` — drives `mapi-cli` against the live server, writes byte-exact
  request/response pairs, scrubs, and updates `MANIFEST.toml`.
- `fixtures/MANIFEST.toml` — records `X-ServerApplication` (currently `15.02.2562.000`), capture
  date, spec version and a sha256 per file, so drift is *detectable* rather than assumed absent.
- `scripts/Verify-Fixtures.ps1` — re-captures against the live server and diffs against what is
  committed. This is your "did Microsoft change the protocol" button.
- `scripts/Assert-NoSecrets.ps1` — greps every fixture for the known identifiers before commit,
  and runs in CI too.
- `.claude/skills/exchange-live/SKILL.md` — so an agent knows how to run live tests and refresh
  fixtures without rediscovering the procedure.

The full script set (all PS 5.1, all dot-sourcing `_Boot.ps1`): `Get-Specs.ps1`,
`Check-SpecVersion.ps1`, `Check-FileLength.ps1`, `Capture-Fixtures.ps1`, `Verify-Fixtures.ps1`,
`Assert-NoSecrets.ps1`, `Test-Live.ps1`, `Initialize-ExchangeLab.ps1` (mailbox creation + enabling
Basic on the MAPI vdir, via the local Exchange snapin), and `Invoke-Gate.ps1` (the full local
verification gate, mirroring CI exactly).

**Three scrubbing rules, each of which already cost real debugging time in the spike:**
1. Replacements must be **length-preserving** — fixtures are read by byte offset; a shifted offset
   is worse than an unscrubbed name.
2. Both **ASCII and UTF-16LE** must be scrubbed — MAPI carries both in the same body.
3. Matching is **case-sensitive, so every case a server uses needs its own rule.** Exchange echoes
   the hostname uppercase while the URL carries it lowercase; a single lowercase rule silently left
   the real hostname in the capture, and I only caught it by grepping before the push.

`Assert-NoSecrets.ps1` exists precisely because rule 3 is invisible: a rule that matched nothing
looks identical to a rule that worked.

## 6. Spec authority

**The Microsoft Open Specification documents are the authoritative resource — always.** Not this
repo's docs, not a blog post, not another implementation, and not an inference from an observed
transcript. Where a real server disagrees with the spec, both facts get recorded: the spec citation
*and* the observed deviation, with the server version that produced it.

All six documents happen to share one release, which makes the pin unusually clean:

| Document | Version | Pages | Covers | URL |
|---|---|---:|---|---|
| **[MS-OXCMAPIHTTP]** | v20250520 | 96 | MAPI extensions for HTTP — the envelope | [pdf](https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCMAPIHTTP/%5bMS-OXCMAPIHTTP%5d.pdf) |
| **[MS-OXCROPS]** | v20250520 | 236 | ROP list and encoding | [pdf](https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCROPS/%5bMS-OXCROPS%5d.pdf) |
| **[MS-OXCDATA]** | v20250520 | 137 | Data structures, property types, `PropertyRow` | [pdf](https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCDATA/%5bMS-OXCDATA%5d.pdf) |
| **[MS-OXCTABL]** | v20250520 | 64 | Table Object Protocol | [pdf](https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCTABL/%5bMS-OXCTABL%5d.pdf) |
| **[MS-OXCSTOR]** | v20250520 | 63 | Store Object Protocol (logon) | [pdf](https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCSTOR/%5bMS-OXCSTOR%5d.pdf) |
| **[MS-OXCFOLD]** | v20250520 | 72 | Folder Object Protocol | [pdf](https://officeprotocoldoc.z19.web.core.windows.net/files/MS-OXCFOLD/%5bMS-OXCFOLD%5d.pdf) |

All released **May 20, 2025**. This table lives in `SPEC.md` and is the single source of truth;
every download is scripted from it.

- **URLs in the repo, PDFs never.** `scripts/Get-Specs.ps1` reads `SPEC.md`, downloads all six into
  a **gitignored `spec/`** directory, and verifies each one's version string. So a fresh clone is
  one command from having the authoritative sources, and the repo carries no Microsoft PDFs. (The
  IP notice permits local copies "in order to develop implementations"; committing 22 MB of
  Microsoft PDFs to a public repo is both unnecessary and muddies the licensing story.)
- `scripts/Check-SpecVersion.ps1` runs `pdftotext` over each local PDF, greps `v(\d{8})`, and fails
  on any mismatch with `SPEC.md`. That is the tripwire for "Microsoft revised the protocol":
  a version bump forces a deliberate review rather than silent drift. Pairs with
  `Verify-Fixtures.ps1` (§5), which catches the same drift from the server side.
- **Every protocol item cites its source** in a doc comment — `[MS-OXCROPS] §2.2.4.1.1`, not just
  "the spec". With 668 pages across six documents, an uncited constant is unverifiable in practice.
- On patents: the notice grants copyright permission to implement but explicitly grants **no patent
  licence**, pointing instead at the Open Specifications Promise and the Patent Map. Still worth
  confirming before publish — §11.

## 6a. Rust API Guidelines — strictly followed

<https://rust-lang.github.io/api-guidelines/> is the standard for every public item, and
`CONTRIBUTING.md` carries the full checklist as a PR gate. The ones that will actually bite a
binary-protocol library, and what each means concretely here:

| Guideline | What it forces on us |
|---|---|
| **C-COMMON-TRAITS** | Every public type eagerly implements `Debug`, `Clone`, `PartialEq`/`Eq`, `Hash` where sane. Non-negotiable for `FolderId`, `PropertyTag`, `RopId` — users will put these in maps and assert on them in tests. |
| **C-NEWTYPE** | Already our rule: `FolderId`, `MessageId`, `LegacyDn`, `HandleSlot` are newtypes, never raw `u64`/`String`. |
| **C-GOOD-ERR** | Errors carry the *failing context*, not just a code. `ecUnknownUser` should say which DN failed to map — the exact thing that cost an hour of debugging in the spike. |
| **C-CONV** | Strict `as_`/`to_`/`into_` naming by cost and ownership. Easy to get wrong on byte-view methods. |
| **C-METHOD / C-GETTER** | Getters are `fn subject()`, never `fn get_subject()`. |
| **C-ITER / C-ITER-TY** | `rows()`/`iter()` naming, and each returns a named public iterator type — not `impl Iterator`, which users cannot store in a struct. |
| **C-BUILDER** | `MapiClient::builder()` for anything with more than a couple of knobs. |
| **C-SEND-SYNC** | Public types are `Send + Sync`; CI asserts it with a static test so a stray `Rc` cannot regress it silently. |
| **C-FEATURE** | Features are strictly additive — no feature ever removes an item. Checked with `cargo hack --feature-powerset`. |
| **C-STABLE / C-SEMVER** | `cargo-semver-checks` gates every release; `cargo-public-api` posts the API diff on every PR, so an accidental breaking change is visible in review rather than after publish. |
| **C-CRATE-DOC / C-EXAMPLE / C-LINK** | Crate-level docs with a working example, doctests that compile in CI, intra-doc links throughout. |
| **C-QUESTION-MARK / C-NON-EXHAUSTIVE** | Errors compose with `?`; public enums are `#[non_exhaustive]` so adding a ROP or error code is not a breaking change. |
| **C-PERMISSIVE** | Satisfied: `MIT OR Apache-2.0`. |

Enforcement is layered so this is not merely aspirational: clippy `pedantic` catches a slice of it
mechanically, `cargo-public-api` makes every API change reviewable, `cargo-semver-checks` blocks
bad releases, and the `CONTRIBUTING.md` checklist covers what tooling cannot judge.

## 7. PowerShell policy

Per your call: **Windows PowerShell 5.1 (Desktop) is required.** Verified on this machine:

| | PS 5.1 Desktop | PS 7.6 Core |
|---|---|---|
| `Add-PSSnapin` Exchange snapin | works | **impossible** (cmdlet absent from Core) |
| `Invoke-Command` into Exchange session | works | fails (NoLanguage runspace) |
| `Import-PSSession` implicit remoting | works | works, but **unsupported by Microsoft** |

Every script dot-sources `scripts/_Boot.ps1`, which hard-fails on anything that is not 5.1 Desktop:

```powershell
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw "mapi-client-rs scripts require Windows PowerShell 5.1 (Desktop). " +
          "You are on $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)). " +
          "Run 'powershell.exe', not 'pwsh'."
}
```

Consequence worth stating plainly: PS 5.1 is Windows-only, so these scripts cannot run on Linux CI.
That costs nothing, because CI has no Exchange access anyway — CI runs pure `cargo` against
committed fixtures. The scripts are local/lab tooling only.

## 8. CI (GitHub Actions)

Mirrors the engine's discipline: `toolchain` (parses `rust-toolchain.toml`) → `fmt` (pinned
nightly) → `clippy -D warnings` → `build` → `test` (ubuntu **and** windows) → `doc` → `coverage`
(fail-under from `codecov.yml`) → `deny` → `public-api` → `typos` → `file-length`.

No live job. The README says so explicitly, so nobody mistakes a green CI badge for
"verified against Exchange".

## 9. Sequence

1. Scaffold: workspace, lints, toolchain pins, licences, CI, scripts + PS guard, `SPEC.md`.
2. Port the spike's proven code into `mapi-proto`, restructured for the sans-io boundary and the
   handle-slot API, with its 54 tests carried over.
3. `mapi-autodiscover` (small, and unblocks everything else).
4. `mapi-client` async layer + `wiremock`-driven tests for the transport boundary.
5. `mapi-cli` + the fixture pipeline; capture the full fixture set from the live server.
6. Drive coverage to the 95% floor; publish `0.1.0`.

## 10. Tooling status on this machine — all green

| Tool | Status |
|---|---|
| `cargo-llvm-cov`, `cargo-binutils` | installed (yours) |
| **poppler 25.07.0** | installed, on persisted PATH, verified against all six PDFs |
| `cargo-deny` · `cargo-nextest` · `cargo-public-api` · `cargo-semver-checks` · `typos` | installed |
| Rust 1.97.0 pinned + nightly · `gh` authenticated · 24 GB free | ready |

All six spec PDFs downloaded and version-verified (`v20250520` across the board).

One cosmetic note: my PDF *reader* still needs a Claude Code restart to see poppler — my process
captured PATH at startup. `pdftotext` works from scripts right now, so nothing is blocked.

## 11. Open questions

**All blocking items are now resolved.** The six specs are downloaded and pinned (§6), the GitHub
home is `allodia-eu/mapi-client-rs` (public), and relicensing the spike to MIT/Apache is approved.

Two items remain, neither blocking the scaffold:

1. **Patent diligence before publishing to crates.io.** The IP notice grants copyright permission to
   implement but explicitly no patent licence, pointing at the Open Specifications Promise and the
   Patent Map. Exchange protocols historically are in scope, but that is worth confirming rather
   than assuming — and I am not the right party to give a legal answer. Scaffolding and developing
   are unaffected; this gates `cargo publish` only.
2. **Auth scope (assumption you can veto).** Auth ships as a trait with **Basic** implemented first,
   since that is what the lab proves. NTLM/Negotiate is a genuine v1.0 gap — every
   default-configured Exchange requires it — but not a scaffolding one.

## 12. Starting point — read this first

### What is already in this folder

| Path | What it is |
|---|---|
| `SCAFFOLD-PLAN.md` | this file |
| `.gitignore` | already excludes `/spec/`, `/target/`, and unscrubbed fixture staging |
| `spec/` | **all six PDFs plus `pdftotext -layout` extracts** (26 MB, gitignored) |
| `.git/` | initialised on branch `main`, **nothing committed yet** |

The `spec/*.txt` extracts are the useful bit day to day: 668 pages of PDF are painful to search,
but `Select-String` over the text extracts is instant. Regenerate any of them with
`pdftotext -layout spec/MS-OXCROPS.pdf spec/MS-OXCROPS.txt`.

### Environment (all verified on this machine)

Rust 1.97.0 pinned, nightly 1.99.0 present · `cargo-llvm-cov`, `cargo-binutils`, `cargo-deny`,
`cargo-nextest`, `cargo-public-api`, `cargo-semver-checks`, `typos` · **poppler 25.07.0** on the
persisted PATH · `gh` authenticated as `dennisameling` · ~24 GB free.

The Exchange lab is up and the full live chain was re-verified today: `Connect` → `ecSuccess`,
13 FolderIds, 15 hierarchy rows, 5 contents rows, 3 round trips to first row.

**Two traps that already cost real debugging time — do not rediscover them:**

1. **Never pass the LegacyDN through Git Bash.** MSYS rewrites the leading `/o=` into
   `C:/Program Files/Git/o=…`, and Exchange reports that as `ecUnknownUser`, which reads like a
   credential or server fault. Use PowerShell. When a `Connect` fails, the real cause is named
   explicitly in `V15\Logging\MapiHttp\Mailbox\*.LOG`.
2. **Fixture scrubbing is case-sensitive.** Exchange echoes the hostname uppercase while the URL
   carries it lowercase, so a single lowercase rule silently leaves the real hostname in the
   capture. A rule that matched nothing looks exactly like a rule that worked — hence
   `Assert-NoSecrets.ps1` (§5).

### First actions

1. Workspace skeleton: root `Cargo.toml` (`[workspace.lints]`, `[profile.dev] debug =
   "line-tables-only"`), `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml`, `codecov.yml`,
   `LICENSE-MIT` + `LICENSE-APACHE`, `SPEC.md` (the §6 table).
2. `scripts/` — `_Boot.ps1` (the PS 5.1 hard gate), `Get-Specs.ps1`, `Check-SpecVersion.ps1`,
   `Check-FileLength.ps1`, `Invoke-Gate.ps1`. Get the spec pipeline provably working *before* any
   protocol code exists.
3. CI, `CONTRIBUTING.md` (carrying the §6a API-guidelines checklist), `README.md`.
4. Create and push `allodia-eu/mapi-client-rs` as public.
5. **Stop and review the skeleton** before porting the spike into `mapi-proto`.

The spike being ported lives at `C:\repos\email-calendar-sync-engine\tools\mapi-spike` on branch
`spike/mapi-over-http` (commit `4d458ba`) — 1,298 source lines, 54 passing tests, plus byte-exact
transcripts under `tools/mapi-spike/transcripts/` that become the first fixtures. Relicensing it
from MPL-2.0 to `MIT OR Apache-2.0` is approved; note that in `CONTRIBUTING.md`.
