//! A server that has gone back in time, against a fake server: the download refuses its final
//! state rather than keeping it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use mapi_client::mapi_proto::fasttransfer::SyncEvent;
use mapi_client::{
    ChangeNumber, ContentsDownload, Error, GlobCnt, Guid, IcsState, MessageId, ReplicaId, SyncScope,
};
use support::sync::{
    OPENING, REPLICA, bare, buffer, inbox, logged_on, long_term_id_response, mailbox, stream,
};
use support::{MapiServer, execute_body, open_folder_response};

/// A counter of replica 1 as a change number or message id carries it.
fn replica_one(counter: u64) -> u64 {
    let g = GlobCnt::from_u64(counter).unwrap().as_bytes();
    u64::from_le_bytes([1, 0, g[0], g[1], g[2], g[3], g[4], g[5]])
}

/// [`stream`]'s message, then a final state whose `MetaTagCnsetSeen` runs from 1 to `newest`, as
/// Exchange encodes one: the replica's GUID, a bare `Range`, `End`. [MS-OXCFXICS] §2.2.4.3.25
fn stream_ending_at(newest: u64) -> Vec<u8> {
    let mut out = stream(1);
    out.truncate(out.len() - 12); // IncrSyncStateBegin, IncrSyncStateEnd, IncrSyncEnd
    let mut cnset = REPLICA.to_vec();
    cnset.push(0x52);
    cnset.extend_from_slice(&GlobCnt::from_u64(1).unwrap().as_bytes());
    cnset.extend_from_slice(&GlobCnt::from_u64(newest).unwrap().as_bytes());
    cnset.push(0x00);
    out.extend_from_slice(&0x403A_0003_u32.to_le_bytes());
    out.extend_from_slice(&0x6796_0102_u32.to_le_bytes());
    out.extend_from_slice(&u32::try_from(cnset.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&cnset);
    out.extend_from_slice(&0x403B_0003_u32.to_le_bytes());
    out.extend_from_slice(&0x4014_0003_u32.to_le_bytes());
    out
}

/// A state that has seen change `0x500`, and the download that resumes from it with a server whose
/// final state runs to `newest`.
async fn resume_against(newest: u64) -> (MapiServer, mapi_client::Logon, IcsState) {
    let server = MapiServer::start().await;
    let logon = logged_on(&server).await;
    let mut state = IcsState::initial(SyncScope::contents(mailbox(&logon), inbox(), None).unwrap());
    state.map_replica(ReplicaId::new(1), Guid::from_bytes(REPLICA));
    assert!(state.record_message(
        MessageId::new(replica_one(0x20)),
        ChangeNumber::new(replica_one(0x500)),
        false
    ));

    let mut opening = long_term_id_response(0);
    opening.extend(open_folder_response(1));
    opening.extend(bare(0x70, 2, 0));
    opening.extend(buffer(2, 0x0003, &stream_ending_at(newest)));
    server.reply_ok(execute_body(&opening, &OPENING));
    server.reply_ok(execute_body(&[], &[0x0000_0009]));
    (server, logon, state)
}

/// The newest change the server reports is older than one the state has seen: the final state is
/// refused, the checkpoint keeps what it had, and the stream still ends.
#[tokio::test]
async fn a_final_state_behind_the_checkpoint_is_refused_and_not_kept() {
    let (_server, mut logon, state) = resume_against(0x400).await;
    let mut download = logon
        .download(inbox(), ContentsDownload::new(), Some(state))
        .unwrap();

    assert!(matches!(
        download.try_next().await.unwrap(),
        Some(SyncEvent::Message(_))
    ));
    let refused = download.try_next().await.unwrap_err();
    let Error::Protocol(mapi_proto::Error::IcsStateAheadOfServer { seen, newest, .. }) = refused
    else {
        panic!("{refused:?}")
    };
    assert_eq!(seen, GlobCnt::from_u64(0x500).unwrap());
    assert_eq!(newest, GlobCnt::from_u64(0x400).unwrap());

    let replica = Guid::from_bytes(REPLICA);
    assert!(
        download
            .checkpoint()
            .cnset_seen()
            .contains(replica, GlobCnt::from_u64(0x500).unwrap()),
        "the checkpoint is not replaced"
    );
    assert!(matches!(
        download.try_next().await.unwrap(),
        Some(SyncEvent::End)
    ));
    assert!(download.try_next().await.unwrap().is_none());
    let kept = download.close().await.unwrap();
    assert!(
        !kept
            .cnset_seen()
            .contains(replica, GlobCnt::from_u64(0x300).unwrap()),
        "nothing of the refused state's range was taken"
    );
}

/// A server level with or past the state is the ordinary case, and its final state is kept.
#[tokio::test]
async fn a_final_state_past_the_checkpoint_replaces_it() {
    let (_server, mut logon, state) = resume_against(0x600).await;
    let mut download = logon
        .download(inbox(), ContentsDownload::new(), Some(state))
        .unwrap();
    let mut events = Vec::new();
    while let Some(event) = download.try_next().await.unwrap() {
        events.push(event);
    }
    assert!(matches!(events[1], SyncEvent::State(_)));
    let kept = download.close().await.unwrap();
    assert!(
        kept.cnset_seen()
            .contains(Guid::from_bytes(REPLICA), GlobCnt::from_u64(0x300).unwrap()),
        "the server's 1 to 0x600"
    );
}
