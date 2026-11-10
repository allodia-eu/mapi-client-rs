//! The responses to the ROPs of an incremental download, and a stream to put in them.

use mapi_client::{FolderId, Guid, Logon};

use super::{Bytes, LOGON_HANDLE, MapiServer, connect_ok, execute_body, logon_response};

/// The context handle the fake server gives the download.
pub(crate) const CONTEXT: u32 = 0x0000_0009;

/// The replica GUID the fake server's `RopLongTermIdFromId` names.
pub(crate) const REPLICA: [u8; 16] = [0xAB; 16];

/// The mailbox GUID the support module's logon response reports.
pub(crate) fn mailbox(logon: &Logon) -> Guid {
    logon.mailbox().mailbox_guid()
}

/// The folder downloaded: replica 1, as a real mailbox numbers its own folders and messages.
pub(crate) fn inbox() -> FolderId {
    FolderId::new(u64::from_le_bytes([1, 0, 0, 0, 0, 0, 0, 4]))
}

/// A `RopLongTermIdFromId` success response naming [`REPLICA`]. [MS-OXCROPS] §2.2.3.8.2
pub(crate) fn long_term_id_response(slot: u8) -> Vec<u8> {
    Bytes::new()
        .u8(0x43)
        .u8(slot)
        .u32(0)
        .raw(&REPLICA)
        .raw(&[0, 0, 0, 0, 0, 4])
        .u16(0)
        .done()
}

/// A ROP that answers with a bare `ReturnValue`.
pub(crate) fn bare(rop: u8, slot: u8, code: u32) -> Vec<u8> {
    Bytes::new().u8(rop).u8(slot).u32(code).done()
}

/// A `RopFastTransferSourceGetBuffer` success response. [MS-OXCROPS] §2.2.12.4.2
pub(crate) fn buffer(slot: u8, status: u16, data: &[u8]) -> Vec<u8> {
    Bytes::new()
        .u8(0x4E)
        .u8(slot)
        .u32(0)
        .u16(status)
        .u16(1)
        .u16(1)
        .u8(0)
        .u16(u16::try_from(data.len()).unwrap())
        .raw(data)
        .done()
}

/// A stream with one full message change, MID and CN counter `n`, then a state and the end.
pub(crate) fn stream(n: u8) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tag = |tag: u32| out.extend_from_slice(&tag.to_le_bytes());
    tag(0x4012_0003); // IncrSyncChg
    tag(0x65E0_0102); // PidTagSourceKey
    let mut bytes = out;
    bytes.extend_from_slice(&22_u32.to_le_bytes());
    bytes.extend_from_slice(&[n; 22]);
    for (tag, value) in [
        (0x674A_0014_u32, [1, 0, 0, 0, 0, 0, 0, n]), // PidTagMid
        (0x67A4_0014, [1, 0, 0, 0, 0, 0, 1, n]),     // PidTagChangeNumber
    ] {
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&value);
    }
    for marker in [0x4015_0003_u32, 0x403A_0003, 0x403B_0003, 0x4014_0003] {
        // IncrSyncMessage, IncrSyncStateBegin, IncrSyncStateEnd, IncrSyncEnd
        bytes.extend_from_slice(&marker.to_le_bytes());
    }
    bytes
}

/// The handle table of the opening batch: the logon, the folder, the context.
pub(crate) const OPENING: [u32; 3] = [LOGON_HANDLE, 0x0000_0001, CONTEXT];

pub(crate) async fn logged_on(server: &MapiServer) -> Logon {
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap()
}
