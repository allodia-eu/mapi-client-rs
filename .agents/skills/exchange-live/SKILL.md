---
name: exchange-live
description: >
  Run mapi-client-rs against a real Exchange Server, and refresh the committed fixture corpus.
  Use when asked to verify against the live lab, to re-capture fixtures, to check whether the
  server or the protocol has changed, or when a change touches wire encoding, the session state
  machine, or anything under fixtures/.
---

# Live Exchange, and the fixture corpus

CI never sees an Exchange server. A green CI badge on this repository means "the committed
fixtures still decode and every gate passed" — it does not and cannot mean "verified against
Exchange". That proof is a separate, deliberate act, and this is how to perform it.

## Before anything

**Windows PowerShell 5.1, not PowerShell 7.** Every script here dot-sources `scripts/_Boot.ps1`,
which hard-fails on anything else. The Exchange management snapin does not exist in Core, so this
is not a preference. Run `powershell.exe`, not `pwsh`.

**Never pass a `legacyExchangeDN` through Git Bash.** MSYS rewrites the leading `/o=` into
`C:/Program Files/Git/o=…`, and Exchange reports the result as `ecUnknownUser` — which reads like a
credential or server fault and sends you debugging the wrong thing entirely.

The lab's host name, mailbox GUIDs and password are deliberately **not in this repository**. They
come from the Exchange snapin, which every script here calls for itself, plus a password you
supply.

## Verify the client against the server

```powershell
powershell.exe -File scripts\Test-Live.ps1 -Mailbox developer,developer2 -Password '<password>'
```

Everything else is derived from Exchange. This runs the `#[ignore]`d tests in
`crates/mapi-client/tests/live.rs` — `PING`, `Connect`, `RopLogon`, both kinds of table, paging and
`Disconnect` — once per mailbox.

**Run more than one mailbox, and make them differ in language.** A mailbox's folder names are
localised to the language it was provisioned with: `developer` is en-US and calls its Inbox
`Inbox`; `developer2` is nl-NL and calls it `Postvak IN`. A client that is subtly wrong about names
passes against the first and fails against the second, which is the most misleading way for a test
to be wrong. The live test therefore finds the Inbox by the folder id the logon reported, never by
name, and prints what that folder is called so a human can see the difference.

For a lab reached some other way, the four `MAPI_LIVE_*` environment variables still work — see the
comment-based help at the top of the script.

## Refresh the fixture corpus

```powershell
powershell.exe -File scripts\Capture-Fixtures.ps1 -Mailbox developer,developer2 -Password '<password>'
```

That single command asks Exchange for the deployment's details, derives the redaction rules from
them, drives `mapi-cli capture` through every scenario, rebuilds `fixtures/MANIFEST.toml`, and runs
`Assert-NoSecrets.ps1` over the result. It refuses to finish if anything identifying survives.

**One of those scenarios writes.** `writes` creates a draft with an attachment in the mailbox, reads
it back and deletes it, so a successful run leaves the mailbox exactly as it found it. A run that
fails part way through says which draft it left behind — remove that before capturing again, because
the next run would otherwise be capturing a mailbox that is not the one the other scenarios assert
counts against.

It is also the one scenario whose *requests* are not the same bytes every time: the server mints a
message id for the draft, and the read and the delete carry it. The scenario declares that id, and
the capture zeroes every occurrence of it in requests and responses alike — so a re-capture still
agrees byte for byte, and the replay tests can still compare request bodies. Nothing is guessed:
only values the run watched a server mint are touched.

Then, always:

```powershell
cargo test --package mapi-cli --test replay
```

The replay tests drive the real client against a fake endpoint that answers exactly what Exchange
answered, and compare **every request body byte for byte** against what was really sent. A change
to any encoding shows up there.

## Has the server changed?

```powershell
powershell.exe -File scripts\Verify-Fixtures.ps1 -Mailbox developer,developer2 -Password '<password>'
```

Re-captures into a scratch directory and demands byte-for-byte equality with what is committed.
Any difference is a finding. That rule is only usable because capture already removes the few
things that genuinely differ every time — the clocks, the per-connection `RetryDelay`, the logon
timestamps, and the response auxiliary buffer, whose length and contents change on every
connection. Each capture's `.meta.txt` itemises exactly what was removed.

Two more are removed by the *scenario* saying so rather than by an anchored offset: the message id a
save mints, and **`PidTagMessageSizeExtended`**, which is how large the mailbox is at the moment of
the capture. The second is not obvious and was found the hard way — a mailbox grows whenever
anything writes to it, and `Test-Live.ps1` writes to it, so without this every verify run after a
test run reported two differences and buried the one that meant something. `PidTagContentCount`
beside it is deliberately *not* removed: the write scenario creates and deletes, so the count nets
out, and a change in it would be a real finding.

When it reports a difference, in rough order of likelihood:

1. **The mailbox changed.** A message arrived, a folder was created. Re-capture.
2. **The server was updated.** Re-measure the version-tied claims in the source — *re-measure them,
   do not renumber them* — and commit the new corpus with the new version in `MANIFEST.toml`.
3. **This workspace changed what it sends.** The interesting one, and why request bodies are
   compared too.

## Preparing a lab from scratch

```powershell
powershell.exe -File scripts\Initialize-ExchangeLab.ps1 `
    -Mailbox developer:en-US,developer2:nl-NL -Password '<password>' -EnableBasic -Seed

powershell.exe -File scripts\Add-LabItems.ps1 -Mailbox developer,developer2 -Password '<password>'
```

Two things a lab needs that are not the default: **Basic** on the MAPI virtual directory, because
that is the only scheme `mapi-client` implements, and **two mailboxes in different languages**.

The second command is what an *item* read needs, and the first cannot do it: `-Seed` sends mail,
which is all a folder-and-table client ever needed. `Add-LabItems.ps1` adds four appointments, three
contacts, and one message with a 60 KB body and one attachment of each of the two kinds — through
EWS, deliberately, because a corpus this client built for itself would prove nothing about this
client.

**Seeding adds; it does not reset.** Both the live suite and the `items` capture assert exact
counts, so run it against a mailbox that does not already hold them. Both say which script to run
when they find nothing, rather than reporting an empty calendar as a passing read.

## Things that have already cost time here

* **A scrub rule that matches nothing looks exactly like one that worked.** `mapi-cli` refuses to
  write a file that still carries a needle, and `Assert-NoSecrets.ps1` then looks again,
  independently and case-insensitively, for GUIDs, long hexadecimal runs, URL hosts and this
  machine's own names. Never trust a scrub you have not grepped.
* **Replacements must be length-preserving.** Fixtures are read by byte offset, and a shifted
  offset fails somewhere unrelated to the change that caused it. `mapi-cli` refuses a rule whose
  two sides differ in length.
* **Matching is case-sensitive.** Exchange echoes a host name uppercase in `X-FEServer` while the
  URL carries it lowercase. Each rule expands automatically to the as-written, lowercased and
  uppercased forms; any other casing needs its own rule.
* **PowerShell scripts must be UTF-8 with a BOM.** 5.1 reads a BOM-less file as ANSI, so one
  accented character becomes mojibake — and a dot-sourced file that fails to parse does *not* stop
  its caller, which then runs with no helpers defined and exits 0. `scripts\Repair-ScriptEncoding.ps1`
  fixes it; `Invoke-Gate.ps1` checks it. This bites data as well as code: seeding a mailbox from a
  BOM-less script put mojibake subjects in a mailbox that are still there.
* **`powershell.exe -File` flattens an array argument** into one comma-joined string, so
  `-Mailbox developer,developer2` arrives as a single element. Every script here splits on commas
  for that reason.
* **When a `Connect` fails, the server says why.** `V15\Logging\MapiHttp\Mailbox\*.LOG` on the
  Exchange server names the real cause, which the wire response usually does not.

## What never goes in a commit

The host name, the mailbox GUIDs, the `legacyExchangeDN` blobs, the AD domain, and the password.
The committed corpus names `exchange-lab-01`, `lab.local` and zero GUIDs, and nothing else. If
`Assert-NoSecrets.ps1` reports anything, widen the rules in `Capture-Fixtures.ps1` and capture
again — do not edit a fixture by hand, which would break both its hash and its byte offsets.
