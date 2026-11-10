//! A download's opening refused after the folder opened, against a fake server: the folder is not
//! opened a second time, and not left open.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use mapi_client::mapi_proto::fasttransfer::SyncEvent;
use mapi_client::{ContentsDownload, Error};
use support::sync::{OPENING, bare, buffer, inbox, logged_on, long_term_id_response, stream};
use support::{Bytes, LOGON_HANDLE, MapiServer, execute_body, opcodes, open_folder_response};

/// The folder handle the fake server's `RopOpenFolder` gives.
const FOLDER: u32 = 0x0000_0001;

/// A `RopBackoff` in place of the configure: the long-term id and the folder were done, and nothing
/// after. [MS-OXCROPS] §2.2.15.2, §3.2.4.2
fn opening_backed_off_at_the_configure() -> Vec<u8> {
    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(Bytes::new().u8(0xF9).u8(0).u32(2_000).u8(0).u16(0).done());
    opening
}

/// The handle table the nth request sent: what follows the ROP list in its `RopBuffer`.
async fn handles_sent(server: &MapiServer, index: usize) -> Vec<u32> {
    let requests = server.requests().await;
    let body = &requests[index].body;
    let buffer_size = usize::try_from(u32::from_le_bytes(body[4..8].try_into().unwrap())).unwrap();
    let rop_size = usize::from(u16::from_le_bytes([body[16], body[17]]));
    body[16 + rop_size..8 + buffer_size]
        .chunks_exact(4)
        .map(|handle| u32::from_le_bytes(handle.try_into().unwrap()))
        .collect()
}

#[tokio::test]
async fn the_retry_uses_the_folder_the_refused_opening_left_open() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;
    server.reply_ok(execute_body(
        &opening_backed_off_at_the_configure(),
        &[LOGON_HANDLE, FOLDER, 0xFFFF_FFFF],
    ));
    let mut retry = long_term_id_response(0);
    retry.extend(bare(0x70, 2, 0));
    retry.extend(buffer(2, 0x0003, &stream(1)));
    server.reply_ok(execute_body(&retry, &OPENING));

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), None)
        .unwrap();
    let backoff = download.try_next().await.unwrap_err();
    assert!(
        matches!(backoff, Error::Backoff { duration_ms: 2_000 }),
        "{backoff:?}"
    );
    assert!(matches!(
        download.try_next().await.unwrap(),
        Some(SyncEvent::Message(_))
    ));

    let sent = opcodes(&server.rops(3).await);
    assert!(
        !sent.contains(&0x02),
        "the folder is not opened again: {sent:02X?}"
    );
    assert_eq!(
        &sent[..3],
        [0x43, 0x70, 0x01],
        "configured on it, then released"
    );
    assert!(handles_sent(&server, 3).await.contains(&FOLDER));
}

#[tokio::test]
async fn closing_after_the_refusal_releases_the_folder_it_left_open() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;
    server.reply_ok(execute_body(
        &opening_backed_off_at_the_configure(),
        &[LOGON_HANDLE, FOLDER, 0xFFFF_FFFF],
    ));
    server.reply_ok(execute_body(&[], &[FOLDER]));

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), None)
        .unwrap();
    assert!(download.try_next().await.is_err());
    download.close().await.unwrap();

    assert_eq!(opcodes(&server.rops(3).await), [0x01]);
    assert_eq!(handles_sent(&server, 3).await, [FOLDER]);
}
