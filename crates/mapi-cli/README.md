# `mapi-cli`

Diagnostic command-line client for **MAPI over HTTP**, and the fixture capture tool driven by
`scripts/Capture-Fixtures.ps1`.

Two jobs, deliberately in one binary: the capture path is the same code path you use when a live
server misbehaves and you need to see the bytes, so it stays exercised.

Not published to crates.io — it is tooling, and keeping it unpublished keeps its dependencies out
of anything a consumer resolves.

Part of [`mapi-client-rs`](https://github.com/allodia-eu/mapi-client-rs).

**Status:** pre-release scaffolding — no subcommands yet.

## Licence

`MIT OR Apache-2.0`, at your option.
