# `mapi-client-rs`

[![CI](https://github.com/allodia-eu/mapi-client-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/allodia-eu/mapi-client-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/mapi-client?logo=rust&logoColor=white)](https://crates.io/crates/mapi-client)
[![docs.rs](https://img.shields.io/docsrs/mapi-client?logo=docsdotrs&logoColor=white)](https://docs.rs/mapi-client)
[![codecov](https://codecov.io/gh/allodia-eu/mapi-client-rs/graph/badge.svg?token=1KS19O3UH1)](https://codecov.io/gh/allodia-eu/mapi-client-rs)
[![MSRV](https://img.shields.io/badge/MSRV-1.97.0-dea584?logo=rust&logoColor=white)](rust-toolchain.toml)
[![Licence](https://img.shields.io/badge/licence-MIT%20OR%20Apache--2.0-blue)](#licence)

A pure-Rust, cross-platform client for **MAPI over HTTP** — the protocol Outlook actually speaks to
Exchange.

> The CI badge means every gate passed against the committed fixtures. It does **not** mean
> "verified against Exchange" — see [What CI does and does not prove](#what-ci-does-and-does-not-prove).

The only MAPI crate on crates.io today is [`outlook-mapi`], which is Windows-only COM bindings to
`olmapi32.dll` and requires Outlook to be installed. This crate talks the wire protocol directly:
no COM, no Outlook, no Windows requirement. It runs anywhere Rust runs.

Feasibility is not speculative — it was measured against a real Exchange Server SE before this
repository existed. Two findings make it tractable:

- **`NoCompression|NoXorMagic` is honoured**, so there is no LZ77/DIRECT2 codec to implement and no
  `0xA5` XOR obfuscation to undo.
- **`AuxiliaryBufferSize = 0` is accepted**, so the MS-OXCRPC auxiliary buffer layer can be
  deferred rather than being a prerequisite.

[`outlook-mapi`]: https://crates.io/crates/outlook-mapi

> **Status: `0.1.0` released, and the property layer landed since.** What works is what the corpus
> proves: locate an endpoint by Autodiscover, connect, log on, walk the folder hierarchy, open a
> contents table, choose columns and page rows, and read or write the Store object's own properties
> — verified against Exchange Server SE `15.02.2562.045`. What is missing is everything about
> messages and about folders the logon does not name, and `Negotiate`/`NTLM` authentication. The
> gaps are stated below and in the changelog rather than left to be discovered.

## Install

```toml
[dependencies]
mapi-client = "0.1"
```

`mapi-proto` and `mapi-autodiscover` are published separately and are useful on their own — the
first if you want the codec with your own transport, the second if you only need to find an
endpoint. `mapi-cli` is not published; build it from this repository with `cargo build -p mapi-cli`.

## What CI does and does not prove

**CI never sees an Exchange server.** A green badge means the committed fixtures still decode and
every gate passes. It does not mean "verified against Exchange".

Live verification is a separate, deliberate act: `scripts/Test-Live.ps1`, run on a machine that has
the lab. That separation is stated here so nobody has to infer it from a workflow file.

Because CI has no server, **the fixtures are the only thing standing between CI and a false green**
— which is why they are byte-exact captures with a manifest recording the server version, capture
date and a hash per file, rather than hand-written fakes. A fake answers canned bytes whatever you
send it, and a wrong `RopBuffer` is not readable by inspection.

What CI does with them is the part that matters: every captured exchange is replayed through the
real client against an endpoint that answers exactly what Exchange answered, and **every request
body is compared byte for byte against the one a real server accepted**. A change to any encoding
fails there rather than months later against somebody's deployment.

Two mailboxes are captured, in two languages, because a mailbox's folder names are localised to the
language it was provisioned with — a Dutch mailbox calls its Inbox `Postvak IN`. A client that
looked folders up by name would work perfectly against one and return nothing against the other, so
folders are addressed by the id a logon reports and the corpus proves it in both.

## Crates

| Crate | What it is | |
|---|---|---|
| [`mapi-proto`](crates/mapi-proto) | The sans-io core: wire envelope, ROPs, OXCDATA structures. No network, no async, no I/O at all. | [docs](https://docs.rs/mapi-proto) |
| [`mapi-autodiscover`](crates/mapi-autodiscover) | Autodiscover — a genuinely different protocol (XML over HTTPS), separately useful for locating an endpoint. | [docs](https://docs.rs/mapi-autodiscover) |
| [`mapi-client`](crates/mapi-client) | The async client: HTTP, TLS, auth, retry. Depends on `mapi-proto`; nothing depends on it. | [docs](https://docs.rs/mapi-client) |
| [`mapi-cli`](crates/mapi-cli) | Diagnostic binary, and the fixture capture tool. Not published. | |

The split is load-bearing rather than decorative: because `mapi-proto` does no I/O, captured
request/response pairs replay straight through it with nothing stubbed. That is what makes a 95%
coverage floor achievable rather than aspirational.

## Design

**Sans-io core.** The caller owns all I/O; the library owns all bytes and all state.

```rust,ignore
let mut session = Session::new();
let req = session.begin_connect(&user_dn)?;      // -> request type + body bytes
//  ... caller POSTs req.body() however it likes ...
let outcome = session.on_response(&headers, &body)?;
```

**Type-safe handle chaining.** Four ROPs chain in a single `Execute` by *handle index*, and getting
an index wrong yields a plausible-looking wrong answer rather than an error. So indices are never
written by hand — issuing a ROP returns a token that later ROPs consume:

```rust,ignore
let mut batch = RopBatch::new();
let folder = batch.open_folder(logon, folder_id);   // -> HandleSlot
let table  = batch.get_contents_table(folder);      // consumes the slot
batch.set_columns(table, &[PropTag::SUBJECT, PropTag::MESSAGE_DELIVERY_TIME]);
batch.query_rows(table, 50);
let req = session.execute(batch)?;                  // one round trip
```

**Async layer.** Three round trips reach the first row, and the borrow checker enforces the
protocol's "one request in flight per Session Context" rule for free.

```rust,ignore
let client = MapiClient::builder()
    .credentials(Credentials::basic(user, password))
    .discover(&EmailAddress::new("alice@example.test")?)   // or .endpoint(url).user_dn(dn).build()?
    .await?;

let mut logon = client.connect().await?.logon().await?;
let mut rows  = logon.well_known(WellKnownFolder::Inbox)?
    .contents()
    .columns([PropertyTag::SUBJECT, PropertyTag::MESSAGE_DELIVERY_TIME])
    .rows();

while let Some(row) = rows.try_next().await? {
    println!("{:?}", row.string(PropertyTag::SUBJECT));
}
logon.disconnect().await?;
```

Authentication is Basic or Bearer. **`Negotiate` and `NTLM` are not implemented** — a genuine gap,
because a default-configured Exchange offers only those two. Both are multi-leg challenge/response
handshakes bound to the connection, which a "compute one header" credential cannot express; see
`mapi-client`'s documentation for the ways round it.

**One correctness trap encoded in the types, not the docs.** Exchange silently truncates table
string values at 255 characters with a literal `...` and no error flag. A `row.str()` that hands
back a corrupted subject is a data-loss bug in the consumer's index, so the row API surfaces
truncation explicitly rather than letting it be ignored by accident.

**Failures name what to do about them.** A 401 reports the schemes the server offered alongside the
one that was sent, because "the password is wrong" and "this client cannot speak any scheme this
server accepts" are different problems with a single status code. A refused `Connect` names the
distinguished name it refused. A request that fails in transit poisons the connection rather than
letting the next one read the previous answer.

## Specification authority

The Microsoft Open Specification documents are authoritative — over this repository's docs, over
any blog post, over any other implementation, and over any inference from an observed transcript.
Every protocol item cites its section: `[MS-OXCROPS] §2.2.4.1.1`, never just "the spec".

Seventeen documents — fifteen pinned at `v20250520`, `[MS-OXDSCLI]` and `[MS-OXOCAL]` at
`v20250819`. They are **never committed**; [`SPEC.md`](SPEC.md) carries the URLs and one command
fetches them into a gitignored `spec/`:

```powershell
powershell.exe -File scripts\Get-Specs.ps1
```

Where a real server disagrees with the spec, both facts are recorded: the citation *and* the
observed deviation, with the server version that produced it.

## Quality gates

| Gate | Setting |
|---|---|
| `unsafe` | `forbid` at the workspace level, so no module can opt back in |
| Clippy | `all` + `pedantic` + `cargo`, plus `indexing_slicing`, `arithmetic_side_effects`, `unwrap_used`, `panic`, `as_conversions` and friends. Relaxed in `#[cfg(test)]` only |
| rustdoc | `-D warnings`, `missing_docs` denied, every public item cites its spec section |
| File length | 500 lines, CI-enforced |
| Coverage | 95% floor, defined once in `codecov.yml`. Currently 98% of lines, excluding `mapi-cli` and the live tests |
| Licences | `cargo-deny` allowlist of permissive licences only |
| API stability | `cargo-public-api` diff on every PR, `cargo-semver-checks` before publish |

`indexing_slicing` is the one that matters most: it forces `.get()` everywhere, which makes "this
parser never panics on hostile input" a structural property rather than a hoped-for one.

Run the whole thing locally — it mirrors CI step for step:

```powershell
powershell.exe -File scripts\Invoke-Gate.ps1
```

## Development

Scripts require **Windows PowerShell 5.1 (Desktop)**, not PowerShell 7, because the Exchange
management snapin does not exist in Core. `scripts/_Boot.ps1` hard-fails on anything else rather
than half-working. They are local and lab tooling; CI runs pure `cargo`.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the Rust API Guidelines checklist that gates every PR,
and [`AGENTS.md`](AGENTS.md) for the standing brief — the rules that are not negotiable and the
traps that have already been paid for. `CLAUDE.md` is a symlink to it, so there is one copy rather
than two that drift.

Releases are cut by tagging `v<version>`; [`.github/workflows/release.yml`](.github/workflows/release.yml)
runs `cargo-semver-checks` and publishes the three library crates in dependency order.

## Licence

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT licence ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this work by you, as defined in the Apache-2.0 licence, shall be dual licensed as above, without
any additional terms or conditions.
