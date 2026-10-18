//! A server gone back in time, against a real mailbox: a state that has seen change numbers the
//! server has not issued — which is what a client holds after the server was restored from a
//! backup — is refused at the end of its download, and an honest one is not.
//!
//! Nothing here restores anything. The state is made to claim the future instead, which puts the
//! client exactly where a rollback would. Self-cleaning like the rest of the sync suite.

use mapi_client::mapi_proto::fasttransfer::SyncEvent;
use mapi_client::{
    ChangeNumber, ContentsDownload, Error, FileTime, GlobCnt, IcsState, PropertyTag, PropertyValue,
    RelationalOperator, Restriction, SpecialFolder, TaggedValue,
};

use super::{create, drain, messages, subject, sweep};

/// The newest change of the folder's replica a state has seen.
fn newest(state: &IcsState, replica: mapi_client::Guid) -> GlobCnt {
    state
        .cnset_seen()
        .get(replica)
        .and_then(|set| set.ranges().last())
        .map(|(_, high)| high)
        .expect("a CnsetSeen for the folder's replica")
}

#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_state_ahead_of_the_server_is_refused_and_an_honest_one_is_not() {
    let mut logon = super::super::client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let drafts = logon.special_folder(SpecialFolder::Drafts).await.unwrap();
    sweep(&mut logon, drafts).await;

    let seen = create(&mut logon, drafts, "seen before the rollback").await;
    let (_, honest) = drain(&mut logon, drafts, ContentsDownload::new(), None).await;
    let replica = honest
        .replica_guid(drafts.replica_id())
        .expect("the folder's replica, learnt by the download");
    let server_newest = newest(&honest, replica);

    // A client that has seen the next 200 change numbers: the server has lost them.
    let mut ahead = honest.clone();
    for step in 1..=200_u64 {
        let counter = GlobCnt::from_u64(server_newest.as_u64() + step).unwrap();
        let [b0, b1, b2, b3, b4, b5] = counter.as_bytes();
        let change = ChangeNumber::new(u64::from_le_bytes([1, 0, b0, b1, b2, b3, b4, b5]));
        assert!(ahead.record_message(seen, change, false));
    }
    let claimed = newest(&ahead, replica);
    let after = create(&mut logon, drafts, "created after the rollback").await;

    // Ahead: the message made since is not reported, and the final state is refused.
    let mut download = logon
        .download(drafts, ContentsDownload::new(), Some(ahead))
        .unwrap();
    let mut reported = Vec::new();
    let refusal = loop {
        match download.try_next().await {
            Ok(Some(SyncEvent::Message(change))) => reported.push(subject(&change)),
            Ok(Some(_)) => {}
            Ok(None) => break None,
            Err(error) => break Some(error),
        }
    };
    while let Ok(Some(_)) = download.try_next().await {}
    let kept = download.close().await.unwrap();
    println!("  ahead: reported {reported:?}, refused with {refusal:?}");

    // Honest: the same message is reported, and nothing is refused.
    let (events, _) = drain(&mut logon, drafts, ContentsDownload::new(), Some(honest)).await;
    let honest_reported: Vec<String> = messages(&events).into_iter().map(subject).collect();
    println!("  honest: reported {honest_reported:?}");

    // A restricted scope's final state is bounded the same way: no false alarm there either.
    let floor = Restriction::property(
        RelationalOperator::GreaterThan,
        TaggedValue::new(
            PropertyTag::LAST_MODIFICATION_TIME,
            PropertyValue::Time(FileTime::new(0)),
        )
        .unwrap(),
    );
    let floored = || ContentsDownload::new().restriction(floor.clone());
    let (_, first) = drain(&mut logon, drafts, floored(), None).await;
    let (events, _) = drain(&mut logon, drafts, floored(), Some(first)).await;
    let floored_again = messages(&events).len();

    sweep(&mut logon, drafts).await;
    logon.disconnect().await.unwrap();

    let Some(Error::Protocol(mapi_proto::Error::IcsStateAheadOfServer {
        replica: refused_replica,
        seen,
        newest: reported_newest,
    })) = refusal
    else {
        panic!("the state ahead of the server was not refused: {refusal:?}")
    };
    assert_eq!(refused_replica, replica);
    assert_eq!(seen, claimed);
    assert!(
        reported_newest < claimed && reported_newest > server_newest,
        "{reported_newest}"
    );
    assert!(
        !reported
            .iter()
            .any(|s| s.ends_with("created after the rollback")),
        "the hazard itself: a change numbered with a seen change number is skipped"
    );
    assert_eq!(
        newest(&kept, replica),
        claimed,
        "the refused final state was not kept"
    );
    assert!(
        honest_reported
            .iter()
            .any(|s| s.ends_with("created after the rollback")),
        "{honest_reported:?}"
    );
    assert_eq!(
        floored_again, 0,
        "a restricted resume reports nothing, and is not refused"
    );
    let _ = after;
}
