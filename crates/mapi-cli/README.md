# `mapi-cli`

Diagnostic command-line client for **MAPI over HTTP**, and the fixture capture tool driven by
`scripts/Capture-Fixtures.ps1`.

Two jobs, deliberately in one binary: the capture path is the same code path you use when a live
server misbehaves and you need to see the bytes, so it stays exercised.

Not published to crates.io — it is tooling, and keeping it unpublished keeps its dependencies out
of anything a consumer resolves.

Part of [`mapi-client-rs`](https://github.com/allodia-eu/mapi-client-rs).

```text
mapi-cli ping                          is the endpoint there, and do the credentials work?
mapi-cli connect                       what the server says about the mailbox, and its folder ids
mapi-cli discover alice@example.test   what Autodiscover says about this mailbox
mapi-cli folders --recursive           the whole folder tree, tagged by container class
mapi-cli folders --class IPF.Contact   only the contact folders, refinements included
mapi-cli special --details             find Calendar, Contacts, Drafts and the rest, and open them
mapi-cli named --verify                what this store numbers each PidLid as, then asks it back
mapi-cli messages --folder inbox       read a contents table
mapi-cli properties                    dump every property of the Store object
mapi-cli capture session --scrub r.tsv record a conversation as fixtures
```

Everything that identifies a deployment is read from the environment — the same four variables
`scripts/Test-Live.ps1` uses — so nothing about anybody's lab has to be typed and a password never
reaches a shell history. Add `--dump` to any command to hex-dump every request and response, which
is the reason this binary exists: a wrong `RopBuffer` is not readable by inspection, and a decoded
view of it is a view through the very code you are doubting.

**Status:** tracks the workspace, at `0.2.0`. Never published: `cargo build -p mapi-cli` from the
repository.

## Licence

`MIT OR Apache-2.0`, at your option.
