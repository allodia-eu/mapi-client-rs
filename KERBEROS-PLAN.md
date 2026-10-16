# Plan: Kerberos

Temporary, like `SCAFFOLD-PLAN.md` and `OPERATIONS-PLAN.md` before it: retired into the CHANGELOG
when the work lands. Nothing outside this file refers to its steps by number.

`Negotiate` today is SPNEGO carrying NTLM alone. This adds Kerberos as the preferred mechanism, so
that a client with a password authenticates the way a domain-joined Windows client would — and
removes the *Kerberos is not implemented* entry from the CHANGELOG's Known gaps, which under the
no-known-gaps rule cannot stay there.

## Decisions taken

| Question | Decision |
|---|---|
| Messages and crypto | Our own DER, extending `mapi-auth`'s `der.rs` as SPNEGO did; RFC 3961/3962/8009 composed from RustCrypto primitives. No Kerberos crate as a dependency. |
| What `Credentials::Negotiate` does | Kerberos first, NTLM second in `mechTypes`, like Windows. NTLM is used when no service ticket can be had; once an AP-REQ has been sent and refused, that is a refusal, not a reason to fall back. |
| Finding the KDC | DNS SRV `_kerberos._tcp.<realm>` ([RFC 4120] §7.2.3.2, [MS-KILE] §3.2.3), answered by a **host-provided resolver** behind a small trait — the shape `mail-calendar`'s `MxResolver` already has, so its native resolvers plug straight in. `hickory-resolver` is an optional, additive default for callers with no resolver of their own, and an explicit KDC on the builder overrides both. |
| `DOMAIN\user` names | **Rule:** a NetBIOS domain is not a realm, and mapping one to the other is DC-locator work this client does not do. Kerberos needs `user@realm` or an explicit realm; with `DOMAIN\user` alone `Negotiate` uses NTLM, and says so. |
| Cross-realm referrals | Verified live against a **child domain** added to the lab for the purpose, with its own DC, and a user there authenticating to the parent realm's Exchange. |
| Scope | AES only. RC4 and FAST are excluded **as rules with reasons**, not listed as gaps. |
| Specification corpus | [MS-KILE] and fifteen RFCs pinned in `SPEC.md` (done, first commit on this branch). |

References to other implementations: `kerbeiros` and its family are AGPL-3.0 and are not read.
`picky-krb`, `sspi`, `krb5-rs` and `kerbcore` are permissively licensed and may be read; none is an
authority, and none is a dependency.

## What the specifications require of this client

Each row is one requirement, and what this branch does about it. "Rule" means stated in the
contract (crate docs, README, CHANGELOG) with its reason, per the no-known-gaps rule.

| Source | Requirement | Here |
|---|---|---|
| [MS-KILE] §3.1.5.2 | MUST support AES256/AES128-CTS-HMAC-SHA1-96 (18, 17) and AES128-CTS-HMAC-SHA256-128 / AES256-CTS-HMAC-SHA384-192 (19, 20) | All four, offered strongest first. Notes `<14>`/`<15>` (on §2.2.7) say 19 and 20 are supported from Windows Server 2025 but "disabled by default", and **measured, the lab's KDC refuses both** — an empty `PA-ETYPE-INFO2` and `KDC_ERR_ETYPE_NOSUPP` when asked for only those. No document names the switch, so 18 is what runs live and 19/20 are pinned by the [RFC 8009] vectors. |
| [MS-KILE] §3.1.5.2 | SHOULD support RC4-HMAC, DES | **Rule: not supported.** [RFC 8429] deprecates RC4 in Kerberos; leaving it out keeps RC4 out of the workspace, as the NTLM work did. DES is gone from every supported Windows. |
| [MS-KILE] §3.1.5.1, §3.2.5.5 | PA-ENC-TIMESTAMP for password logon; always a PA-PAC-REQUEST | Both. |
| [RFC 4120] §3.1, §5.2.7.5 | Pre-auth from PA-ETYPE-INFO2: the salt and `s2kparams` come from the KDC | Yes — the salt is never guessed. |
| [MS-KILE] §3.2.5.1 | Set `canonicalize` | Yes. |
| [RFC 6806] §11 | MUST send `PA-REQ-ENC-PA-REP` (149) in every AS-REQ, and reject a reply whose `enc-pa-rep` ticket flag is set but whose checksum over the request is absent or wrong | Yes. [MS-KILE] cites [Referrals-11], which predates §11 and does not list 149 — but **measured**, Windows Server 2025 KDCs in both lab realms set flag 15 and return the checksum (type 16, key usage 56, over the AS-REQ as sent). It is what makes the unauthenticated first leg tamper-evident. |
| [MS-KILE] §3.1.5.10, [RFC 6806] §7–8 | MUST support cross-realm referrals | Both kinds, at most five per acquisition, never back to a realm already asked; unit-tested against a synthetic KDC and **verified live in both directions**: a child-domain user's TGS-REQ for the parent's Exchange is answered with a referral TGT, which the client follows; and a UPN sent to the wrong realm as `NT-ENTERPRISE` is answered `KDC_ERR_WRONG_REALM` naming the user's realm in `crealm` (measured — §7 itself also says "realm field"), which the client follows. |
| [MS-KILE] §3.2.5.7 | TGS-REQ: PA-PAC-OPTIONS (branch aware) | Yes. §2.2.10 prints the structure as `SEQUENCE { KerberosFlags }` with no tag; **measured** from a Windows client's own TGS-REQ (SSPI, explicit credentials) it is `SEQUENCE { [0] KerberosFlags }`, Branch Aware being flag 1. The same host's logon-session client sent none. |
| [MS-KILE] §3.2.5.7–8 | KERB_AUTH_DATA_LOOPBACK (142) | **Rule: not sent.** §2.2.4 makes its content implementation-specific Windows LSA data that the server MUST ignore unless the client is local. |
| [MS-KILE] §3.2.5.8 | KERB_AUTH_DATA_TOKEN_RESTRICTIONS (141) | **Rule: not sent.** Note `<43>`: Windows does not use it. |
| [MS-KILE] §3.2.5.8 | KERB_AUTH_DATA_CLIENT_TARGET (144) | **Rule: not sent.** The document describes its content ("the server's name qualified with the realm name") and gives it no encoding, and it travels inside the encrypted authenticator, so no capture can show Windows' choice. §3.1.5.5: a server "ignores the unknown data". |
| [MS-KILE] §3.2.5.8, §3.4.5 | AD-AUTH-DATA-AP-OPTIONS (143) with KERB_AP_OPTIONS_CBT whenever there is a channel binding | Yes, as the document says. **Measured, it is not what Extended Protection checks**: Exchange with EPA `Require` refuses an all-zero `Bnd` and accepts the right `Bnd` with or without this element beside it. |
| [RFC 4121] §4.1.1, [RFC 2744] §3.11 | Authenticator checksum 0x8003: `Bnd` = MD5 of the channel-bindings structure, GSS flags | Yes; `Bnd` reuses the NTLM work's `tls-server-end-point` binding. |
| [RFC 6542] | Channel binding hash agility | Read; adopted only if Windows is measured to use it. |
| [MS-KILE] §3.2.5.1 | MUTUAL-REQUIRED; verify the AP-REP | Yes — the AP-REP's `ctime`/`cusec` must match, and its subkey is taken. |
| [MS-KILE] §3.2.5.8, [RFC 4120] §3.1.5 | On KRB_AP_ERR_SKEW, retry with the KDC's time | Yes, once per exchange, keeping the offset rather than trusting it further: the KDC's `KRB-ERROR` is not authenticated. Done for the KDC exchanges and for the AP exchange; measured end to end against IIS, which answers a skewed AP-REQ with `KRB_AP_ERR_SKEW` and `KERB-ERROR-DATA` and accepts the retry. |
| [MS-SPNG] note `<8>` | AES Kerberos: a server's `mechListMIC` has to be processed | Verified when present ([RFC 4121] §4.2.6.1 MIC token). The lab sends none (measured). |
| [RFC 4178] §5 | `mechListMIC` when the selected mechanism is not the preferred one | NTLM selected after Kerberos was offered first: the NTLM `mechListMIC`, which exists. |
| [MS-KILE] §3.2.5.4, §3.2.1 | FAST only when EnableCBACandArmor (default FALSE) on a domain-joined client | **Rule: no FAST.** Armoring needs a TGT for a machine account, which a non-joined client has none of; the spec's own default is off. |
| [MS-KILE] §3.1.5.5 | KRB_ERR_RESPONSE_TOO_BIG | TCP only ([RFC 4120] §7.2.2 makes TCP mandatory for clients), so the UDP size limit never arises. |
| [MS-KILE] §3.1.5.7 | Names: UTF-8, case-insensitive comparison, no normalisation | Yes. |
| [RFC 4120] §5.4.1 | `nonce` is a `UInt32` | Kept to 31 bits: a Windows Server 2025 KDC was **measured** closing the connection without a reply when the top bit is set. |
| [RFC 4120] §5.4.1 | `till` of `19700101000000Z` asks for the KDC's maximum | Used; measured honoured (ten hours, the default policy). |

## Measured on the lab, before any code

Read-only, except that failure auditing was turned on. Nothing here identifies the lab.

- The Exchange server is also the domain controller and KDC; domain and forest functional level
  Windows 2025. SRV records for `_kerberos._tcp` and `_udp` exist.
- No explicit `HTTP/` SPN: the host's `HOST/` SPNs serve it, because the forest's SPN mappings map
  `HTTP` to `HOST`. No alternate service account; IIS `Negotiate` runs in user mode.
- Every ticket is AES256 (etype 18). Pre-authentication is required. FAST is not required.
- MAPI has Extended Protection `Require`; Autodiscover has none — so both the bound and the unbound
  AP-REQ are exercised.
- Windows' own client (.NET `SocketsHttpHandler`) gets Kerberos on both endpoints. IIS's final
  token is `accept-completed`, `supportedMech` echoing the client's first OID, a GSS-wrapped AP-REP
  (etype 18) — and **no `mechListMIC`**.
- With failure auditing on, a refused pre-authentication leaves event 4771 with the RFC 4120
  failure code (0x18 for a wrong password). That is the KDC's own account of a failure, and the
  first place to look.

## Architecture

**`mapi-auth`** — sans-io, as now. No network, no clock, no randomness of its own.

- `kerberos::crypto`: RFC 3961 (`n-fold`, DK, the simplified profile), RFC 3962 (AES-CTS,
  PBKDF2 string-to-key, HMAC-SHA1-96), RFC 8009 (AES-SHA2). One RustCrypto generation for every
  primitive — the existing `hmac 0.12`/`sha2 0.10` line, so `aes 0.8`, `pbkdf2 0.12`, `sha1 0.10`
  — rather than two copies of `digest` in the tree.
- `kerberos::asn1`: the RFC 4120 §5 messages and the MS-KILE structures above, on `der.rs`.
- `kerberos::exchange`: a state machine that emits "send these bytes to the KDC" and consumes the
  reply — AS (with the PREAUTH_REQUIRED round trip), TGS (with referrals) — and ends in a service
  ticket and session key. It never opens a socket.
- `kerberos::gss`: the AP-REQ token ([RFC 4121] §4.1), the AP-REP check, MIC-token verification.
- `spnego`: two mechanisms, with the preferred/selected logic and both `mechListMIC`s.
- `Entropy` grows to supply what Kerberos consumes — nonces, confounders, a subkey, a sequence
  number — from a caller-filled pool, plus the current time, so every test is deterministic.

**`mapi-client`** — the I/O.

- KDC transport: TCP with the four-byte length prefix ([RFC 4120] §7.2.2), timeouts and the next
  KDC on failure ([MS-KILE] §3.2.6).
- KDC location: DNS SRV through a `SrvResolver` trait the host implements with its own native
  resolver, so the device's real DNS settings apply. A `hickory-resolver` implementation (MIT OR
  Apache-2.0) behind an additive feature serves callers with none, and the builder takes an
  explicit KDC that overrides discovery entirely.
- A ticket cache per client, shared by its clones and by `for_mailbox`, so each new connection
  costs an AP-REQ and not a fresh AS and TGS exchange.
- Discovery and the MAPI transport both drive it, as they do NTLM today.
- A way for a caller — and the live suite — to know which mechanism actually authenticated, since
  a silent fallback to NTLM would otherwise pass every test.

## Order of work

Each is a commit, reviewed and green on its own:

1. **Corpus** — [MS-KILE] and the RFCs pinned. *(done)*
2. **Crypto** — the four AES enctypes, pinned byte-for-byte to the RFC 3961 `n-fold`, RFC 3962
   Appendix B and RFC 8009 Appendix A vectors.
3. **Messages** — DER encode/decode for every message and structure used, round-tripped and
   fuzzed for panics like the rest of the parsers.
4. **AS and TGS exchanges** — sans-io, tested against a synthetic KDC built from the same code
   paths, including PREAUTH_REQUIRED, wrong password, skew and a referral chain.
5. **GSS and SPNEGO** — AP-REQ with channel binding and CBT, AP-REP verification, the two-mechanism
   SPNEGO and its `mechListMIC`s.
6. **mapi-client** — KDC transport and discovery, the ticket cache, the fallback, the API.
7. **Live** — the whole suite over `Negotiate` against both mailboxes, asserting Kerberos was what
   authenticated; the KDC's 4768/4769 events as a second witness; the AES-SHA2 measurement; the
   CHANGELOG, the rules, and the Known gaps entry removed.

## The second realm

[MS-KILE] §3.1.5.10 makes referrals a MUST, and one realm cannot exercise them. So the lab gains a
**child domain** of its own forest, on a second domain controller: the parent-child trust is
automatic, two-way and transitive, and a user in the child authenticating to Exchange in the parent
is exactly the referral path. The child user's AS exchange goes to the child KDC; its TGS-REQ for
the Exchange SPN comes back as a referral TGT for the parent realm, which the client takes to the
parent KDC. Authentication is what is being verified, so the child user needs no mailbox.

How it is set up lives in the operator's notes, not here: nothing that identifies the lab is
committed.

## Effect on the gates

- New dependencies (`aes`, `pbkdf2`, `sha1`, possibly `hickory-resolver`): permissive, checked by
  `cargo-deny`; `cargo hack` covers the feature combinations.
- Coverage stays at 95%: the crypto is pinned by published vectors, the exchanges by the synthetic
  KDC, and the parsers by the same malformed-input tests as everywhere else.
- `mapi-auth`'s public API grows; `cargo-public-api` will show it.
