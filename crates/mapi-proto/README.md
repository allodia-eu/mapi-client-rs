# `mapi-proto`

Sans-io codec for **MAPI over HTTP** — the wire envelope, the ROP layer, and the OXCDATA
structures. No network, no async runtime, no I/O of any kind: the caller owns the transport, this
crate owns the bytes and the protocol state.

That boundary is what makes the tests meaningful. Request/response pairs captured from a real
Exchange Server replay straight through the codec with nothing stubbed.

Part of [`mapi-client-rs`](https://github.com/allodia-eu/mapi-client-rs). Every protocol item
cites its Microsoft Open Specification section; see `SPEC.md` in the repository root for the
pinned document versions.

**Status:** pre-release scaffolding — no public API yet.

## Licence

`MIT OR Apache-2.0`, at your option.
