//! An incremental download against a fake server: what it sends, and what it makes of the answers.
//!
//! The protocol half — the stream grammar, the IDSETs, the state — is proved in `mapi-proto`
//! against the documents' own bytes. What is proved here is the driving: one round trip per buffer,
//! the state uploaded before the first, the replica learnt from the server, and each refusal turned
//! into the error that says what to do.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use mapi_client::mapi_proto::fasttransfer::SyncEvent;
use mapi_client::{
    ContentsDownload, Error, ErrorCode, GlobCnt, Guid, IcsState, MessageId, PropertyTag,
    Restriction, SyncScope, WellKnownFolder,
};
use support::sync::{
    CONTEXT, OPENING, REPLICA, bare, buffer, inbox, logged_on, long_term_id_response, mailbox,
    stream,
};
use support::{Bytes, LOGON_HANDLE, MapiServer, execute_body, opcodes, open_folder_response};

/// A first download: the opening batch names the folder's replica, opens the folder, configures
/// the download, releases the folder and asks for the first buffer — and later buffers are one
/// `GetBuffer` each, until the server says `Done`.
#[tokio::test]
async fn a_first_download_opens_configures_and_reads_buffer_by_buffer() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let whole = stream(7);
    let (head, tail) = whole.split_at(13);
    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(bare(0x70, 2, 0));
    opening.extend(buffer(2, 0x0001, head));
    server.reply_ok(execute_body(&opening, &OPENING));
    server.reply_ok(execute_body(&buffer(0, 0x0003, tail), &[CONTEXT]));
    server.reply_ok(execute_body(&[], &[CONTEXT]));

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), None)
        .unwrap();
    let mut events = Vec::new();
    while let Some(event) = download.try_next().await.unwrap() {
        events.push(event);
    }
    assert!(matches!(events[0], SyncEvent::Message(_)));
    assert!(matches!(events[1], SyncEvent::State(_)));
    assert!(matches!(events[2], SyncEvent::End));

    let state = download.close().await.unwrap();
    assert_eq!(
        state.replica_guid(mapi_client::ReplicaId::new(1)),
        Some(Guid::from_bytes(REPLICA)),
        "the replica is learnt from the folder's long-term id"
    );

    assert_eq!(
        opcodes(&server.rops(2).await),
        [0x43, 0x02, 0x70, 0x01, 0x4E]
    );
    assert_eq!(opcodes(&server.rops(3).await), [0x4E]);
    assert_eq!(
        opcodes(&server.rops(4).await),
        [0x01],
        "closing releases the context"
    );
}

/// A checkpoint folds each message as it is handed over, under the replica the server named —
/// which is what lets a download cut short resume without that message.
#[tokio::test]
async fn each_message_is_folded_into_the_checkpoint_as_it_is_handed_over() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(bare(0x70, 2, 0));
    opening.extend(buffer(2, 0x0001, &stream(5)[..40]));
    server.reply_ok(execute_body(&opening, &OPENING));
    server.reply_ok(execute_body(
        &buffer(0, 0x0001, &stream(5)[40..]),
        &[CONTEXT],
    ));

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), None)
        .unwrap();
    let Some(SyncEvent::Message(change)) = download.try_next().await.unwrap() else {
        panic!("a message first")
    };
    let id = change.header().id().unwrap();
    let checkpoint = download.checkpoint();
    let counter = GlobCnt::from_bytes(id.as_u64().to_le_bytes()[2..].try_into().unwrap());
    assert!(
        checkpoint
            .idset_given()
            .contains(Guid::from_bytes(REPLICA), counter)
    );
    assert_eq!(
        id,
        MessageId::new(u64::from_le_bytes([1, 0, 0, 0, 0, 0, 0, 5]))
    );
}

/// A state with something in it is uploaded before the first buffer: begin, the bytes, end, for
/// each state property — split across requests once it outgrows one.
#[tokio::test]
async fn a_large_state_is_uploaded_before_the_first_buffer_across_requests() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let scope = SyncScope::contents(mailbox(&logon), inbox(), None).unwrap();
    let mut state = IcsState::initial(scope);
    state.map_replica(mapi_client::ReplicaId::new(1), Guid::from_bytes(REPLICA));
    // Isolated counters ten apart, so no Bitmask can pack them: two bytes each, past 16 KiB.
    for n in 0..12_000_u64 {
        let id = MessageId::new(1 | ((n * 10) << 40));
        let cn = mapi_client::ChangeNumber::new(1 | ((n * 10 + 1) << 40));
        assert!(state.record_message(id, cn, false));
    }

    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(bare(0x70, 2, 0));
    opening.extend(bare(0x75, 2, 0));
    opening.extend(bare(0x76, 2, 0));
    server.reply_ok(execute_body(&opening, &OPENING));
    for _ in 0..8 {
        server.reply_ok(execute_body(&bare(0x76, 0, 0), &[CONTEXT]));
    }

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), Some(state))
        .unwrap();
    let _ = download.try_next().await;

    let first = opcodes(&server.rops(2).await);
    assert_eq!(&first[..5], [0x43, 0x02, 0x70, 0x01, 0x75]);
    assert_eq!(
        first[5], 0x76,
        "the first part of the state goes with the configure"
    );
    assert!(
        !first.contains(&0x4E),
        "no buffer is asked for before the state is all there"
    );
    assert_eq!(
        opcodes(&server.rops(3).await)[0],
        0x76,
        "the next part goes in the next request"
    );
}

/// A busy server is waited out: the error says how long, and the next call asks again for the same
/// buffer rather than starting over.
#[tokio::test]
async fn a_busy_server_is_reported_with_its_wait_and_the_download_carries_on() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(bare(0x70, 2, 0));
    opening.extend(
        Bytes::new()
            .u8(0x4E)
            .u8(2)
            .u32(0x0000_0480)
            .u16(0)
            .u16(0)
            .u16(1)
            .u8(0)
            .u16(0)
            .u32(2_500)
            .done(),
    );
    server.reply_ok(execute_body(&opening, &OPENING));
    server.reply_ok(execute_body(&buffer(0, 0x0003, &stream(1)), &[CONTEXT]));

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), None)
        .unwrap();
    let busy = download.try_next().await.unwrap_err();
    assert!(
        matches!(busy, Error::Backoff { duration_ms: 2_500 }),
        "{busy:?}"
    );
    assert!(matches!(
        download.try_next().await.unwrap(),
        Some(SyncEvent::Message(_))
    ));
    assert_eq!(
        opcodes(&server.rops(3).await),
        [0x4E],
        "the context was kept"
    );
}

/// A small state goes up whole with the opening, and a busy `GetBuffer` after it is waited out
/// without uploading the state again: the context already holds it.
#[tokio::test]
async fn a_busy_server_after_the_upload_is_not_handed_the_state_twice() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let scope = SyncScope::contents(mailbox(&logon), inbox(), None).unwrap();
    let mut state = IcsState::initial(scope);
    state.map_replica(mapi_client::ReplicaId::new(1), Guid::from_bytes(REPLICA));
    let id = MessageId::new(1 | (3 << 40));
    let cn = mapi_client::ChangeNumber::new(1 | (4 << 40));
    assert!(state.record_message(id, cn, false));

    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(bare(0x70, 2, 0));
    opening.extend(
        Bytes::new()
            .u8(0x4E)
            .u8(2)
            .u32(0x0000_0480)
            .u16(0)
            .u16(0)
            .u16(1)
            .u8(0)
            .u16(0)
            .u32(1_000)
            .done(),
    );
    server.reply_ok(execute_body(&opening, &OPENING));
    server.reply_ok(execute_body(&buffer(0, 0x0003, &stream(1)), &[CONTEXT]));

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), Some(state))
        .unwrap();
    let busy = download.try_next().await.unwrap_err();
    assert!(
        matches!(busy, Error::Backoff { duration_ms: 1_000 }),
        "{busy:?}"
    );
    assert!(matches!(
        download.try_next().await.unwrap(),
        Some(SyncEvent::Message(_))
    ));

    let first = opcodes(&server.rops(2).await);
    assert_eq!(&first[..4], [0x43, 0x02, 0x70, 0x01]);
    let uploads = &first[4..first.len() - 1];
    assert!(
        uploads
            .split_inclusive(|rop| *rop == 0x77)
            .all(|one| one.first() == Some(&0x75) && one.last() == Some(&0x77)),
        "every property begun is ended in the same request: {first:02X?}"
    );
    assert!(first.contains(&0x76), "{first:02X?}");
    assert_eq!(
        first.last(),
        Some(&0x4E),
        "the whole state goes up with the opening, then the first buffer is asked for"
    );
    assert_eq!(
        opcodes(&server.rops(3).await),
        [0x4E],
        "the retry asks for the buffer and nothing else"
    );
}

/// A buffer whose status is `Error` beside a successful `ReturnValue` is the server failing
/// without saying why — not a stream that ended early, which is what parsing on would report.
#[tokio::test]
async fn a_buffer_reporting_an_error_without_a_code_is_not_taken_for_a_short_stream() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(bare(0x70, 2, 0));
    opening.extend(buffer(2, 0x0000, &stream(1)[..13]));
    server.reply_ok(execute_body(&opening, &OPENING));

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), None)
        .unwrap();
    let error = download.try_next().await.unwrap_err();
    assert!(
        matches!(
            error,
            Error::Unexpected {
                found: "a successful ReturnValue",
                ..
            }
        ),
        "{error:?}"
    );
}

/// A `GetBuffer` refused outright is named as the fetch, with the server's code.
#[tokio::test]
async fn a_refused_get_buffer_is_named_as_the_fetch() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(bare(0x70, 2, 0));
    // As Exchange Server SE sends one: the transfer fields, zeroed, and an empty buffer.
    opening.extend(bare(0x4E, 2, 0x8004_0102));
    opening.extend([0; 9]);
    server.reply_ok(execute_body(&opening, &OPENING));

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), None)
        .unwrap();
    let error = download.try_next().await.unwrap_err();
    assert!(
        matches!(
            error,
            Error::Rop {
                during: "fetching the next buffer",
                code: ErrorCode::NOT_SUPPORTED,
            }
        ),
        "{error:?}"
    );
}

/// A whole-batch `RopBackoff` in place of the opening is a backoff too, and the retry opens the
/// download from the beginning, since nothing of the first attempt was carried out.
#[tokio::test]
async fn a_backoff_instead_of_the_opening_is_waited_out_and_the_opening_sent_again() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    // RopBackoff: opcode, LogonId, Duration, RopCount, AdditionalDataSize. [MS-OXCROPS] §2.2.15.2
    let backoff = Bytes::new().u8(0xF9).u8(0).u32(3_000).u8(0).u16(0).done();
    server.reply_ok(execute_body(
        &backoff,
        &[LOGON_HANDLE, 0xFFFF_FFFF, 0xFFFF_FFFF],
    ));
    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(bare(0x70, 2, 0));
    opening.extend(buffer(2, 0x0003, &stream(1)));
    server.reply_ok(execute_body(&opening, &OPENING));

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), None)
        .unwrap();
    let busy = download.try_next().await.unwrap_err();
    assert!(
        matches!(busy, Error::Backoff { duration_ms: 3_000 }),
        "{busy:?}"
    );
    assert!(matches!(
        download.try_next().await.unwrap(),
        Some(SyncEvent::Message(_))
    ));
    assert_eq!(
        opcodes(&server.rops(3).await),
        opcodes(&server.rops(2).await),
        "the opening is sent again"
    );
}

/// A refused configure says what was being done.
#[tokio::test]
async fn a_refused_configure_is_named_as_such() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(bare(0x70, 2, 0x8004_0102));
    server.reply_ok(execute_body(&opening, &OPENING));

    let mut download = logon
        .download(inbox(), ContentsDownload::new(), None)
        .unwrap();
    let refused = download.try_next().await.unwrap_err();
    assert!(
        matches!(
            refused,
            Error::Rop {
                during: "configuring the download",
                code: ErrorCode::NOT_SUPPORTED
            }
        ),
        "{refused:?}"
    );
}

/// A state from another scope is refused before anything is sent — and so is one from another
/// mailbox, which looks the same until the GUID is compared.
#[tokio::test]
async fn a_state_from_another_scope_is_refused_before_anything_is_sent() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;
    let unfiltered =
        IcsState::initial(SyncScope::contents(mailbox(&logon), inbox(), None).unwrap());

    let narrowed = ContentsDownload::new().restriction(Restriction::exists(PropertyTag::SUBJECT));
    let refused = logon
        .download(inbox(), narrowed, Some(unfiltered))
        .unwrap_err();
    assert!(refused.to_string().contains("restriction"), "{refused}");

    let elsewhere = IcsState::initial(
        SyncScope::contents(Guid::from_bytes([0x5A; 16]), inbox(), None).unwrap(),
    );
    let refused = logon
        .download(inbox(), ContentsDownload::new(), Some(elsewhere))
        .unwrap_err();
    assert!(refused.to_string().contains("mailbox"), "{refused}");

    let other_folder = logon.folder_id(WellKnownFolder::Outbox).unwrap();
    let scoped = IcsState::initial(SyncScope::contents(mailbox(&logon), inbox(), None).unwrap());
    assert!(
        logon
            .download(other_folder, ContentsDownload::new(), Some(scoped))
            .is_err()
    );
    assert_eq!(server.requests().await.len(), 2, "connect and logon only");
}
