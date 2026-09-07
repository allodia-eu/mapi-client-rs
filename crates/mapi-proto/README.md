# `mapi-proto`

Sans-io codec for **MAPI over HTTP** — the wire envelope, the ROP layer, and the OXCDATA
structures. No network, no async runtime, no I/O of any kind: the caller owns the transport, this
crate owns the bytes and the protocol state.

That boundary is what makes the tests meaningful. Request/response pairs captured from a real
Exchange Server replay straight through the codec with nothing stubbed.

Part of [`mapi-client-rs`](https://github.com/allodia-eu/mapi-client-rs). Every protocol item
cites its Microsoft Open Specification section; see `SPEC.md` in the repository root for the
pinned document versions.

```rust
use mapi_proto::{FolderDepth, FolderId, HIERARCHY_COLUMNS, ObjectHandle, RopBatch};

// Handle indices are never written by hand: issuing a ROP returns a token later ROPs consume.
let mut batch = RopBatch::new();
let folder = batch.open_folder(logon, FolderId::new(0x0D00_0000_0000_0001));
let table = batch.hierarchy_table(folder, FolderDepth::Recursive);
batch.set_columns(table, &HIERARCHY_COLUMNS).query_rows(table, 50);

let request = session.execute(batch)?;   // one round trip for the whole chain
```

**Status:** `0.3.0` released, and the tree is ahead of it. The transport envelope, the ROP layer,
the OXCDATA structures and the session state machine are implemented. `Connect`, `Execute`,
`Disconnect` and `PING` are the request types covered, with the logon, folder, table, property,
long-term-id, named-property, message, attachment and stream ROPs on top — enough to walk a whole
folder tree, read and write a Store or Folder object's properties, reach the folders a logon does
not name, ask a store which id it has allocated for a `PidLid`, sort and filter a table on the
server, and read a message down to its body and its attachments. Then the other direction:
`RopCreateMessage`, `RopModifyRecipients`, `RopCreateAttachment`, `RopWriteStream`,
`RopSaveChangesMessage` and `RopDeleteMessages`, with the one-off entry ids that address a recipient
without an address book. Unreleased on top of that: `RopSubmitMessage`, `RopMoveCopyMessages`,
`RopSetReadFlags` and `RopRemoveAllRecipients`, and `RopProgress` modelled so that a server which
answers one unasked does not desynchronise the rest of the buffer. Sixteen of the OXCDATA property
types are modelled, and six of the twelve restriction formats. No notifications, no ICS and no
address book endpoint.

## Licence

`MIT OR Apache-2.0`, at your option.
