# Contributing to `mapi-client-rs`

## The local gate

One command, mirroring CI step for step:

```powershell
powershell.exe -File scripts\Invoke-Gate.ps1
```

If it is green locally it should be green in CI, and if those two ever disagree that is a bug in
the gate worth fixing before the change that exposed it.

```powershell
powershell.exe -File scripts\Invoke-Gate.ps1 -List            # step names
powershell.exe -File scripts\Invoke-Gate.ps1 -Only fmt,clippy # a subset while iterating
powershell.exe -File scripts\Invoke-Gate.ps1 -SkipCoverage    # skip the slow one
```

Scripts require **Windows PowerShell 5.1 (Desktop)**. Run `powershell.exe`, not `pwsh` —
`scripts/_Boot.ps1` will stop you with an explanation if you forget.

## Specification authority

**The Microsoft Open Specification documents are the authoritative resource — always.** Not this
repository's docs, not a blog post, not another implementation, and not an inference from an
observed transcript.

Get the documents (never committed, gitignored under `spec/`):

```powershell
powershell.exe -File scripts\Get-Specs.ps1
```

Then grep the text extracts rather than the PDFs — 668 pages across six documents:

```powershell
Select-String -Path spec\MS-OXCROPS.txt -Pattern 'RopQueryRows' -Context 2
```

**Every protocol item cites its source in a doc comment**, by section:

```rust
/// Requests rows from a table object.
///
/// [MS-OXCROPS] §2.2.5.4 — RopQueryRows
/// [MS-OXCTABL] §2.2.2.13 — semantics, including the cursor interaction
pub struct QueryRows { /* ... */ }
```

An uncited constant is, in practice, indistinguishable from a transcription error. Where a real
server disagrees with the spec, record **both**: the citation *and* the deviation, with the server
version that produced it.

## Rust API Guidelines — strictly followed

<https://rust-lang.github.io/api-guidelines/> is the standard for every public item. Tooling
catches a slice of this mechanically; the rest is this checklist, and it is a PR gate.

- [ ] **C-COMMON-TRAITS** — public types eagerly implement `Debug`, `Clone`, `PartialEq`/`Eq`,
      `Hash` where sane. Non-negotiable for `FolderId`, `PropertyTag`, `RopId`: users will put
      these in maps and assert on them in tests.
- [ ] **C-NEWTYPE** — every identity is a newtype. `FolderId`, `MessageId`, `LegacyDn`,
      `SessionCookie`, `HandleSlot` — never a raw `u64` or `String`, so nothing can be crossed.
- [ ] **C-GOOD-ERR** — errors carry the *failing context*, not just a code. `ecUnknownUser` should
      name the DN that failed to map; that exact omission cost an hour of debugging in the spike.
- [ ] **C-CONV** — `as_` / `to_` / `into_` used strictly by cost and ownership. Easy to get wrong
      on byte-view methods.
- [ ] **C-METHOD / C-GETTER** — getters are `fn subject()`, never `fn get_subject()`.
- [ ] **C-ITER / C-ITER-TY** — `rows()` / `iter()` naming, and each returns a *named public*
      iterator type. Not `impl Iterator`, which users cannot store in a struct.
- [ ] **C-BUILDER** — `MapiClient::builder()` for anything with more than a couple of knobs.
- [ ] **C-SEND-SYNC** — public types are `Send + Sync`, asserted by a static test so a stray `Rc`
      cannot regress it silently.
- [ ] **C-FEATURE** — features are strictly additive; no feature ever removes an item.
- [ ] **C-STABLE / C-SEMVER** — `cargo-public-api` posts the diff on every PR;
      `cargo-semver-checks` gates every release.
- [ ] **C-CRATE-DOC / C-EXAMPLE / C-LINK** — crate-level docs with a working example, doctests that
      compile in CI, intra-doc links throughout.
- [ ] **C-QUESTION-MARK / C-NON-EXHAUSTIVE** — errors compose with `?` via `thiserror`; public
      enums are `#[non_exhaustive]`, so adding a ROP or an error code is not a breaking change.
- [ ] **C-PERMISSIVE** — satisfied by `MIT OR Apache-2.0`.

## Code constraints

- **No `unsafe`.** `unsafe_code = "forbid"` at the workspace level: `deny` can be overridden by a
  module, `forbid` cannot.
- **No indexing.** `indexing_slicing` is denied, so use `.get()`. This is the lint that makes
  "never panics on hostile input" structural rather than hoped-for. The same applies to
  `arithmetic_side_effects` (use `checked_*` / `wrapping_*` deliberately), `unwrap_used`,
  `expect_used` and `panic`.
- **500 lines per file.** Enforced by `scripts/Check-FileLength.ps1`. It forces the module split
  that keeps each layer reviewable on its own.
- **95% coverage.** Defined once in `codecov.yml`.

All of the above are relaxed inside `#[cfg(test)]` (see `clippy.toml`). A test that indexes a
fixture at a known offset is saying something true about that fixture; the same code in the parser
would be a panic waiting for a malformed packet.

## Fixtures

CI never sees the Exchange server, so **the fixtures are the only thing standing between CI and a
false green**. Treat them accordingly.

```powershell
powershell.exe -File scripts\Capture-Fixtures.ps1    # drives mapi-cli against the live server
powershell.exe -File scripts\Verify-Fixtures.ps1     # "did the protocol change?"
powershell.exe -File scripts\Assert-NoSecrets.ps1    # runs pre-commit and in CI
```

**Three scrubbing rules, each of which already cost real debugging time:**

1. **Replacements must be length-preserving.** Fixtures are read by byte offset; a shifted offset
   is worse than an unscrubbed name, because it fails somewhere unrelated.
2. **Scrub both ASCII and UTF-16LE.** MAPI carries both encodings in the same body.
3. **Matching is case-sensitive, so every case a server uses needs its own rule.** Exchange echoes
   the hostname uppercase while the URL carries it lowercase. A single lowercase rule silently left
   the real hostname in a capture, and it was caught only by grepping before the push.

`Assert-NoSecrets.ps1` exists precisely because rule 3 is invisible: **a rule that matched nothing
looks identical to a rule that worked.** Never trust a scrub you have not grepped.

## Two traps worth not rediscovering

1. **Never pass a LegacyDN through Git Bash.** MSYS rewrites the leading `/o=` into
   `C:/Program Files/Git/o=…`, and Exchange reports the result as `ecUnknownUser` — which reads
   like a credential or server fault and sends you debugging the wrong thing entirely. Use
   PowerShell. When a `Connect` fails, the real cause is named explicitly in
   `V15\Logging\MapiHttp\Mailbox\*.LOG` on the server.
2. **PowerShell scripts must be UTF-8 *with* a BOM.** Windows PowerShell 5.1 reads a BOM-less file
   as ANSI, so one em dash in a comment can break the parse — and because a dot-sourced file that
   fails to parse does *not* stop its caller, the script then runs with no helpers defined and
   exits 0. `Invoke-Gate.ps1` checks the BOM mechanically; `scripts\Repair-ScriptEncoding.ps1`
   fixes it.

## Licensing of contributions

This project is `MIT OR Apache-2.0`. Contributions are dual-licensed on the same terms, per the
Apache-2.0 definition, without any additional terms or conditions.

Dependencies must be permissively licensed. `cargo-deny` enforces this with an allowlist, so a
copyleft transitive dependency fails the build rather than being discovered at publish time. Adding
a licence to the allowlist is a deliberate decision made in a PR, not a surprise.

**Provenance note:** the protocol code in `mapi-proto` originates from a spike that was licensed
MPL-2.0. Relicensing it to `MIT OR Apache-2.0` was approved by its sole author before the port.
