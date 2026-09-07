# Working in `mapi-client-rs`

A pure-Rust client for **MAPI over HTTP**, the protocol Outlook speaks to Exchange. Five crates:
`mapi-proto` (sans-io codec), `mapi-autodiscover` (finding the endpoint), `mapi-auth` (sans-io NTLM
and SPNEGO handshakes), `mapi-client` (the async client that does the I/O) and `mapi-cli`
(diagnostics, and the fixture capture tool).

This file is the standing brief. `CLAUDE.md` is a symlink to it, so there is one copy rather than
two that drift. What follows is not style preference — every rule here is either mechanically
enforced or was paid for in debugging time, and the note attached to each says which.

## Specification authority

**The Microsoft Open Specification documents are the authoritative resource — always.** Not this
repository's documentation, not a blog post, not another implementation, and not an inference from
an observed transcript. Nineteen documents, pinned by version in [`SPEC.md`](SPEC.md), fetched with
`scripts\Get-Specs.ps1` into a gitignored `spec/` and never committed.

Read the `spec/*.txt` extracts, not the PDFs — 2,101 pages are painful to page through and instant
to `Select-String`. Start a property lookup in [MS-OXPROPS], which is an index rather than a
narrative: it maps every `PidTag` and `PidLid` to its id, its type and the document that defines it,
which is usually the question being asked.

- **Every protocol item cites its section** in a doc comment: `[MS-OXCROPS] §2.2.4.1.1`, never just
  "the spec". In a binary protocol an uncited constant is indistinguishable from a transcription
  error.
- **Where a real server disagrees with the specification, record both facts** — the citation *and*
  the observed deviation, with the server version that produced it.
- **When a version-tied claim is re-measured, re-measure it — do not renumber it.** A doc comment
  naming a server build asserts that somebody measured it on that build. Editing the number without
  running anything turns a measurement into a guess wearing its clothes.

Patents are the one open item: the IP notice grants copyright permission to implement but no patent
licence. See [`SPEC.md`](SPEC.md#patents). It gates publishing, nothing else.

## The sans-io boundary

`mapi-proto` owns all bytes and all state; the caller owns all I/O. **Nothing in `mapi-proto` may
gain a network call, an async fn, a clock or a source of randomness.** That boundary is not
tidiness — it is what lets captured request/response pairs replay straight through the codec with
nothing stubbed, which is what makes the 95% coverage floor achievable rather than aspirational.

The consequences show up in odd places and are load-bearing in all of them: `mapi-client` generates
the `X-RequestId` GUID because a sans-io crate cannot obtain randomness, and `mapi-proto` sets the
`Cookie` header itself because the Session Context's cookies are protocol state rather than
transport state.

`mapi-proto` is deliberately **not** split further into wire/rop/oxcdata crates. Those layers share
types densely — `PropertyTag` is used by both the ROP layer and the row decoder — so splitting buys
pub-visibility gymnastics rather than isolation. Internal modules enforce the layering. Revisit only
if a boundary proves real.

`mapi-client` depends on `mapi-proto`, and nothing depends on `mapi-client`.

## Quality gates

All mechanically enforced. `scripts\Invoke-Gate.ps1` runs the lot and mirrors CI step for step.

| Gate | Rule |
|---|---|
| `unsafe` | `forbid` at the workspace level — `deny` can be overridden by a module, `forbid` cannot |
| Clippy | `all` + `pedantic` + `cargo`, plus `indexing_slicing`, `arithmetic_side_effects`, `unwrap_used`, `expect_used`, `panic`, `as_conversions`, `todo`, `dbg_macro` and friends |
| rustdoc | `-D warnings`, `missing_docs` denied |
| File length | 500 lines, checked by `scripts\Check-FileLength.ps1` |
| Coverage | 95% floor, defined once in `codecov.yml` and read from there by both CI and the local gate |
| Licences | `cargo-deny` allowlist of permissive licences only, so a copyleft transitive dependency fails the build |
| API stability | `cargo-public-api` diffs every PR; `cargo-semver-checks` gates every release |

`indexing_slicing` is the one that matters most: it forces `.get()` everywhere, which makes "this
parser never panics on hostile input" a structural property rather than a hoped-for one.

**All of these relax inside `#[cfg(test)]`** (see `clippy.toml`). A test that indexes a fixture at a
known offset is saying something true about that fixture; the same code in the parser is a panic
waiting for a malformed packet.

Never weaken a gate to make a change fit. Never add `#[allow]` to production code without a comment
saying what makes this case different — and prefer restructuring the code over the allow.

## Public API

<https://rust-lang.github.io/api-guidelines/> is followed strictly. The full checklist is a PR gate
in [`CONTRIBUTING.md`](CONTRIBUTING.md). The ones that bite a binary-protocol library:

- **Newtypes for every identity.** `FolderId`, `MessageId`, `LegacyDn`, `SessionCookie`,
  `HandleSlot` — never a raw `u64` or `String`, so nothing can be crossed.
- **Handle indices are never written by hand.** Issuing a ROP returns a token later ROPs consume.
  Getting an index wrong yields a plausible-looking wrong answer rather than an error, so the type
  system removes the whole bug class.
- **Errors carry the failing context, not just a code**, and are `#[non_exhaustive]` via
  `thiserror`, so adding a ROP or an error code is not a breaking change.
- **Named public iterator types**, not `impl Iterator`, which callers cannot store in a struct.
- **`Send + Sync`**, asserted by a static test so a stray `Rc` cannot regress it silently.
- **Features are strictly additive.** No feature ever removes an item.
- **Encode correctness traps in the types, not the docs.** Exchange silently truncates table strings
  at 255 characters with a literal `...` and no error flag; the row API surfaces that explicitly,
  because a `str()` handing back a corrupted subject is a data-loss bug in the consumer's index.

## Fixtures

CI never sees an Exchange server, so **the committed fixtures are the only thing standing between CI
and a false green.** A fake would answer canned bytes whatever you sent it, and a wrong `RopBuffer`
is not readable by inspection — hence byte-exact captures with a manifest recording server version,
capture date and a hash per file.

Refresh them with `scripts\Capture-Fixtures.ps1`; the [`exchange-live`](.agents/skills/exchange-live/SKILL.md)
skill has the procedure. Three scrubbing rules, each already paid for:

1. **Replacements must be length-preserving.** Fixtures are read by byte offset, and a shifted
   offset fails somewhere unrelated to the change that caused it. `mapi-cli` refuses a rule whose
   two sides differ in length.
2. **Scrub both ASCII and UTF-16LE.** MAPI carries both encodings in the same body.
3. **Matching is case-sensitive.** Exchange echoes the host name uppercase in `X-FEServer` while the
   URL carries it lowercase. Each rule expands automatically to as-written, lowercased and
   uppercased; any other casing needs its own rule.

**A scrub rule that matched nothing looks exactly like one that worked.** That invisibility is why
`Assert-NoSecrets.ps1` exists as an independent second look, and why it runs in CI on every pull
request, where there is no lab at all. Never trust a scrub you have not grepped.

**A scenario that writes has two more obligations, and both are load-bearing.** It must be
self-cleaning — create, act, delete, with the delete running even when the scenario fails — because
`Verify-Fixtures.ps1` re-captures against the live lab, and a scenario that leaves an item behind
drifts the mailbox one item per run until the counts other scenarios assert stop holding. And it
must **declare every value the server minted** through `Recorder::server_assigned`, because a
message id travels in the *request* bodies of everything done with it afterwards and the replay
tests compare those byte for byte. Nothing checks that a scenario declared one: forgetting shows up
as a difference on the next `Verify-Fixtures.ps1`, which is the right place for it to show up.

**Never edit a fixture by hand.** It breaks the hash in `MANIFEST.toml` and, if the edit is not
length-preserving, every byte offset after it. Widen the rules and capture again.

Nothing that identifies the lab is ever committed: the host name, the mailbox GUIDs, the
`legacyExchangeDN` blobs, the AD domain, the password. Lab details come from the Exchange snapin at
run time, or from `MAPI_LIVE_*` environment variables.

## PowerShell

**Windows PowerShell 5.1 (Desktop) only.** Run `powershell.exe`, not `pwsh`. This is not a
preference: `Add-PSSnapin` and the Exchange management snapin do not exist in Core. Every script
dot-sources `scripts\_Boot.ps1`, which hard-fails on anything else rather than half-working.

5.1 is Windows-only, so these scripts cannot run on Linux CI. That costs nothing, because CI has no
Exchange access anyway and runs pure `cargo`.

**Scripts must be UTF-8 *with* a BOM.** 5.1 reads a BOM-less file as ANSI, so one em dash in a
comment breaks the parse — and because a dot-sourced file that fails to parse does *not* stop its
caller, the script then runs with no helpers defined and exits 0. `Invoke-Gate.ps1` checks the BOM;
`scripts\Repair-ScriptEncoding.ps1` fixes it.

## Traps already paid for

1. **Never pass a `legacyExchangeDN` through Git Bash.** MSYS rewrites the leading `/o=` into
   `C:/Program Files/Git/o=…`, and Exchange reports the result as `ecUnknownUser` — which reads like
   a credential or server fault and sends you debugging the wrong thing entirely. Use PowerShell.
2. **When a `Connect` fails, the server says why.** `V15\Logging\MapiHttp\Mailbox\*.LOG` on the
   Exchange server names the real cause, which the wire response usually does not.
3. **`powershell.exe -File` flattens an array argument** into one comma-joined string, so
   `-Mailbox developer,developer2` arrives as a single element. Every script here splits on commas.
4. **Run two mailboxes, in two languages.** Folder names are localised to the language a mailbox was
   provisioned with, so a client subtly wrong about names passes against an English mailbox and
   fails against a Dutch one — the most misleading way for a test to be wrong. Folders are addressed
   by the id a logon reports, never by name.
5. **A mailbox is named by an endpoint URL *and* a distinguished name, and they are a matched pair.**
   The `?MailboxId=` selects a mailbox as surely as the `UserDn` does. Pairing the wrong two is
   accepted by `Connect`, which reports the other mailbox's owner as though it had worked, and
   refused by the `RopLogon` in the next request with `ecWrongServer` — so the mistake surfaces a
   request later than it is made, in an error about servers. Never change one without the other.
6. **Granting mailbox access is not the same as making it discoverable.** `FullAccess` without
   `-AutoMapping $true` works and is never advertised, and Autodiscover's `AlternativeMailbox`
   element is the only place MAPI/HTTP names a mailbox the caller does not own. A permission a
   client can use and cannot find.
7. **A 401 from IIS says nothing about *why*.** Exchange ships with
   `ExtendedProtectionTokenChecking: Require`, so an NTLM `AUTHENTICATE_MESSAGE` without a channel
   binding is refused — with the same bare `WWW-Authenticate: NTLM` that a wrong password earns, and
   the same one the handshake opened with. Three different faults, one response. Check
   `Get-MapiVirtualDirectory | fl ExtendedProtection*` before suspecting the credential.
8. **`reqwest` sends no `Content-Length` for an empty body, and `http.sys` answers 411.** Before
   authenticating anything — so a bodyless handshake leg never reaches the challenge it was sent
   for, and the 411 carries no `WWW-Authenticate` to hint at why. Any request this crate sends with
   no body sets the header itself.
9. **An unread response body costs the connection.** `reqwest` returns a connection to the pool only
   once the body is consumed, so a handshake leg whose body is dropped hands the next leg a *fresh*
   connection — one the server never challenged. It authenticates a connection, not a request, so
   the answer arrives with nothing to answer. Read the body even when it is empty and uninteresting.

## Working conventions

- **Run the gate before pushing:** `powershell.exe -File scripts\Invoke-Gate.ps1`. If local and CI
  ever disagree, that is a bug in the gate worth fixing before the change that exposed it.
- **A green CI badge never means "verified against Exchange."** Live verification is
  `scripts\Test-Live.ps1`, run deliberately, on a machine that has the lab.
- **Measure with `scripts\Invoke-Cli.ps1`, and read the item back.** It runs one `mapi-cli` command
  against a named mailbox with everything but the password derived from Exchange, which is how a
  claim in a doc comment gets made. The operations that change a mailbox report almost nothing — a
  bare `ReturnValue`, or one byte — so what a response says is not evidence that the operation did
  what it says. `mapi-cli state` is.
- **Commit messages explain why, not what.** The diff already says what changed; the message says
  what was measured, what it cost, and what would otherwise be re-derived. See `git log`.
- **Review fixes belong in the commit that introduced the code**, then restack — not in a follow-up
  commit that leaves the original wrong for anyone reading history.
