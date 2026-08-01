# `mapi-autodiscover`

Exchange **Autodiscover** client: locates the MAPI over HTTP endpoint for a mailbox.

A separate protocol from the ROP layer — XML over HTTPS — and separately useful, so it is a
separate crate. It is also the one place the `X-MapiHttpCapability: 1` request header lives,
without which a server will not advertise its MAPI/HTTP URL at all.

Part of [`mapi-client-rs`](https://github.com/allodia-eu/mapi-client-rs).

**Status:** pre-release scaffolding — no public API yet.

## Licence

`MIT OR Apache-2.0`, at your option.
