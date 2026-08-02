# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). All four crates in the
workspace share one version number, so an entry below applies to whichever of them it names.

Two conventions specific to this project:

- **Protocol claims name the server they were measured against.** "Verified against Exchange Server
  SE 15.02.2562.045" means somebody ran it on that build, not that it ought to work.
- **Gaps are listed as plainly as features.** A client that quietly does not implement something is
  worse than one that says so.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-08-02

First release. Enough of MAPI over HTTP to locate a mailbox, log on and read from it — verified
against Exchange Server SE `15.02.2562.045`, with the byte-exact captures that prove it committed
to the repository.

### Added

- **`mapi-proto`** — the sans-io codec. The MAPI/HTTP envelope (request types, meta-tags,
  `X-ResponseCode`, the session cookies), `RPC_HEADER_EXT` and the ROP buffer, the ROPs needed to
  log on and read tables, the OXCDATA property types and `PropertyRow` decoders, `ecXxx` codes as a
  typed error enum, and the session state machine. No network, no async runtime, no clock: the
  caller owns all I/O and the crate owns all bytes and all state.
- **Type-safe handle chaining.** Several ROPs chain in a single `Execute` by handle index, and a
  wrong index yields a plausible-looking wrong answer rather than an error. Issuing a ROP returns a
  `HandleSlot` that later ROPs consume, so an index is never written by hand.
- **`mapi-autodiscover`** — Autodiscover as its own crate, because it is its own protocol: XML over
  HTTPS with nothing to do with ROPs, and separately useful to anyone who only needs to find an
  endpoint. Also sans-io.
- **`mapi-client`** — the async client over the codec: HTTP/2, rustls verifying against the
  operating system's trust store, Basic and Bearer authentication, Autodiscover behind a default-on
  additive feature, and an `Observer` hook that hands every request and its response to a caller
  verbatim. Three round trips reach the first row; later pages are one each.
- **`mapi-cli`** — the diagnostic binary, and the tool that captures the fixture corpus through that
  same `Observer` hook, so the capture path is the ordinary diagnostic path. Not published.
- **Fixture corpus** — 25 byte-exact exchanges from two mailboxes in two languages, with a manifest
  recording server version, capture date and a hash per file. Replayed in CI through the real client
  against an endpoint that answers exactly what Exchange answered, comparing every request body byte
  for byte against one a real server accepted.

### Known gaps

- **Nothing is written.** This release reads: hierarchy tables, contents tables, columns and paged
  rows. Creating, modifying, moving and deleting are not implemented.
- **`Negotiate` and `NTLM` are not implemented**, and a default-configured Exchange offers only
  those two. Both are multi-leg challenge/response handshakes bound to the connection, which a
  credential that computes one header cannot express. Basic must be enabled on the MAPI virtual
  directory for this client to authenticate; `mapi-client`'s documentation covers the ways round it.
- **The MS-OXCRPC auxiliary buffer layer is deferred.** Every request declares
  `AuxiliaryBufferSize = 0` and Exchange accepts it. Responses carry a buffer, whose size field is
  read and whose contents are skipped.
- **No compression or obfuscation codec.** `NoCompression|NoXorMagic` is honoured by the servers
  measured, so neither LZ77/DIRECT2 nor the `0xA5` XOR layer is implemented. A server that refuses
  those flags is not supported.

[Unreleased]: https://github.com/allodia-eu/mapi-client-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/allodia-eu/mapi-client-rs/releases/tag/v0.1.0
