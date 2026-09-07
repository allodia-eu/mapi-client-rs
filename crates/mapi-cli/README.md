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
mapi-cli mailboxes alice@... --open    every mailbox these credentials can open, and open each
mapi-cli folders --recursive           the whole folder tree, tagged by container class
mapi-cli folders --class IPF.Contact   only the contact folders, refinements included
mapi-cli special --details             find Calendar, Contacts, Drafts and the rest, and open them
mapi-cli named --verify                what this store numbers each PidLid as, then asks it back
mapi-cli messages --folder inbox       read a contents table
mapi-cli messages --newest-first       let the server sort it, and --subject to let it filter
mapi-cli events                        calendar entries with start, end, location and busy status
mapi-cli contacts                      contacts with their email addresses
mapi-cli message --id 0x... --body     one message: properties, body, attachments, embedded message
mapi-cli draft --to ada@example.test   write into Drafts, with recipients and an attachment
mapi-cli contact --name .. --email ..  create a contact, one-off entry id included
mapi-cli event --subject .. --start .. create an appointment, both instants in UTC
mapi-cli send --to ada@example.test    write one and hand it to the transport. This sends real mail
mapi-cli submit --id 0x...             send a draft that is already there
mapi-cli move --to deleted-items --id  archive one: a move between two folders, in one round trip
mapi-cli mark --id 0x... --unread      the read bit of PidTagMessageFlags, receipt suppressed
mapi-cli flag --id 0x... --colour red  the follow-up flag, which is a different thing entirely
mapi-cli state --id 0x...              read all three back: read, sent, flagged
mapi-cli delete --folder drafts --id . take one back out again: a soft delete, by id
mapi-cli properties                    dump every property of the Store object
mapi-cli capture session --scrub r.tsv record a conversation as fixtures
```

`mailboxes` is the odd one out: it is the only subcommand whose answer comes from Autodiscover
rather than from a ROP, because MAPI/HTTP has no verb that asks a server what else you may open. It
therefore needs no `--endpoint` and no `--user-dn` — finding those for a mailbox you do not own is
the work. It costs one Autodiscover round trip per mailbox plus one, because Exchange names each
alternative mailbox by address rather than by distinguished name.

**Six of those change a mailbox and one of them sends mail to a real address.** There is no dry-run
mode: the subcommand is the consent. `send` reports what it did with the message afterwards, because
where a sent message ends up is two properties that interact in a way [MS-OXOMSG] does not describe
— see the changelog.

`--folder` takes one of the thirteen folders a logon names, one of the eight it does not —
`drafts` resolves through the entry-id chain — or a raw folder id as `0x...`.

Everything that identifies a deployment is read from the environment — the same four variables
`scripts/Test-Live.ps1` uses — so nothing about anybody's lab has to be typed and a password never
reaches a shell history. Add `--dump` to any command to hex-dump every request and response, which
is the reason this binary exists: a wrong `RopBuffer` is not readable by inspection, and a decoded
view of it is a view through the very code you are doubting.

Against a lab this machine can ask Exchange about, `scripts/Invoke-Cli.ps1` sets those variables for
one mailbox and runs a single command, which saves getting either of the two values wrong that are
easy to get wrong by hand:

```powershell
powershell.exe -File scripts\Invoke-Cli.ps1 -Mailbox developer -Password '<password>' messages --folder inbox
```

**Status:** tracks the workspace, at `0.3.0`, with `mailboxes` and a tenth captured scenario
unreleased on top of it. Never published: `cargo build -p mapi-cli` from the repository.

## Licence

`MIT OR Apache-2.0`, at your option.
