# `mapi-client`

Async client for **MAPI over HTTP**, built on the sans-io [`mapi-proto`](https://docs.rs/mapi-proto)
codec. HTTP, TLS, authentication and retry live here so that the codec stays free of them.

Nothing in the workspace depends on this crate, so a caller who wants a different transport can
use `mapi-proto` directly and skip this layer.

Part of [`mapi-client-rs`](https://github.com/allodia-eu/mapi-client-rs).

**Status:** pre-release scaffolding — no public API yet.

## Licence

`MIT OR Apache-2.0`, at your option.
