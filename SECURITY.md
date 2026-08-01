# Security policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/allodia-eu/mapi-client-rs/security/advisories/new),
not in a public issue.

Expect an acknowledgement within a few working days. If you have not heard back within a week,
please follow up — a missed notification should not cost you a response.

## Scope

This crate parses **untrusted input by definition**: every byte it decodes comes off the network
from a server, and a compromised or hostile Exchange endpoint can send whatever it likes. The
security-relevant properties are therefore:

- **No `unsafe`.** `unsafe_code = "forbid"` at the workspace level, so memory-safety bugs are not
  reachable through this crate's own code. `forbid` rather than `deny` means no module can opt back
  in.
- **No panics on malformed input.** `indexing_slicing`, `arithmetic_side_effects`, `unwrap_used`,
  `expect_used` and `panic` are denied outside tests, which makes bounds-checked decoding
  structural rather than a matter of care. A panic reachable from network bytes **is** a
  vulnerability in a library — it is a denial of service in the caller's process.
- **No unbounded allocation from attacker-controlled length fields.** A length prefix read off the
  wire is a claim, not a fact, and is validated against the remaining buffer before it is used to
  reserve.

Reports in any of those categories are in scope, as is anything that leaks credentials or mailbox
content into logs, errors or fixtures.

## Out of scope

- Vulnerabilities in Exchange Server itself. Report those to Microsoft.
- Behaviour that requires the caller to have already supplied attacker-controlled credentials to an
  attacker-controlled endpoint deliberately.

## Fixtures and secrets

Fixtures are byte-exact captures from a real server, which makes accidental disclosure a live risk
rather than a theoretical one. `scripts/Assert-NoSecrets.ps1` runs before commit and in CI.

Note that scrubbing is **case-sensitive** and must be **length-preserving**, and that a scrub rule
which matched nothing looks identical to one that worked. If you believe a committed fixture
contains real identifiers, that is a report worth making.

## Supported versions

Pre-1.0: only the latest release is supported. This will be revisited at 1.0.
