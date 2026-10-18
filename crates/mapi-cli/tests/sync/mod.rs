//! Replaying the sync corpus: a first incremental download of the Inbox, and one resumed from its
//! checkpoint.
//!
//! Its own file because it is its own scenario, and because `replay.rs` is close to the workspace's
//! 500-line limit.
//!
//! This makes the same two claims the other replays do — every request body matches what Exchange
//! actually accepted, and every recorded response still decodes — over what no other part of CI
//! can check against a real server's bytes:
//!
//! * `RopSynchronizationConfigure` with an `OnlySpecifiedProperties` list, and the ICS state upload
//!   that resumes a download — three ROPs per state property, built from a client-side checkpoint.
//! * A `FastTransfer` stream split across `RopFastTransferSourceGetBuffer` responses wherever the
//!   server chose to split it, read back to the same seven messages and a final state.

use mapi_client::mapi_proto::fasttransfer::SyncEvent;
use mapi_client::{
    ContentsDownload, Credentials, Lcid, MapiClient, PropertyFilter, PropertyTag, PropertyValue,
    WellKnownFolder,
};

use crate::corpus::{assert_requests_match, scenario, server, user_dn};

/// The metadata set `mapi-cli capture sync` asked for, which the configure request carries.
const METADATA: [PropertyTag; 5] = [
    PropertyTag::SUBJECT,
    PropertyTag::MESSAGE_CLASS,
    PropertyTag::MESSAGE_DELIVERY_TIME,
    PropertyTag::MESSAGE_FLAGS,
    PropertyTag::BODY_HTML,
];

/// How many exchanges one captured sync session holds: `Connect`, the logon, the first download's
/// buffers and its release, the resumed download — its state upload and its one buffer in a single
/// request — and its release, and the `Disconnect`.
pub(crate) const SYNC_EXCHANGES: usize = 9;

/// What one replayed sync session produced.
struct Synced {
    subjects: Vec<String>,
    states: usize,
    resumed_changes: usize,
}

fn configuration() -> ContentsDownload {
    ContentsDownload::new().properties(PropertyFilter::Only(METADATA.to_vec()))
}

/// Drives one captured sync session, then checks every request body against the corpus.
///
/// The order is `mapi-cli capture sync`'s order exactly, because that is what produced the corpus.
async fn replay(name: &str, locale: Lcid) -> Synced {
    let exchanges = scenario(name);
    assert_eq!(
        exchanges.len(),
        SYNC_EXCHANGES,
        "{name} has the wrong shape"
    );
    let server = server(&exchanges).await;

    let client = MapiClient::builder()
        .endpoint(format!("{}/mapi/emsmdb/", server.uri()))
        .user_dn(user_dn(&exchanges))
        .credentials(Credentials::basic("replay@example.test", "hunter2"))
        .locale(locale)
        .danger_allow_plaintext_http()
        .build()
        .expect("a client");
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let inbox = logon.folder_id(WellKnownFolder::Inbox).expect("an Inbox");

    let mut download = logon
        .download(inbox, configuration(), None)
        .expect("a download");
    let mut subjects = Vec::new();
    let mut checkpoint = None;
    let mut states = 0_usize;
    while let Some(event) = download.try_next().await.expect("an event") {
        match event {
            SyncEvent::Message(change) => {
                // As the capture took it: after the last message, before the final state.
                checkpoint = Some(download.checkpoint().clone());
                subjects.push(
                    change
                        .property(PropertyTag::SUBJECT)
                        .and_then(PropertyValue::as_string)
                        .map(|text| text.as_str().to_owned())
                        .unwrap_or_default(),
                );
            }
            SyncEvent::State(_) => states += 1,
            _ => {}
        }
    }
    let finished = download.close().await.expect("the context released");
    assert!(
        finished.replica_guid(inbox.replica_id()).is_some(),
        "the replica, learnt from the folder's long-term id"
    );

    let mut resumed = logon
        .download(inbox, configuration(), checkpoint)
        .expect("a resumed download");
    let mut resumed_changes = 0_usize;
    while let Some(event) = resumed.try_next().await.expect("an event") {
        match event {
            SyncEvent::Message(_) => resumed_changes += 1,
            SyncEvent::State(_) => states += 1,
            _ => {}
        }
    }
    resumed.close().await.expect("the context released");

    logon.disconnect().await.expect("Disconnect");
    assert_requests_match(&server, &exchanges).await;

    Synced {
        subjects,
        states,
        resumed_changes,
    }
}

fn check(synced: &Synced) {
    assert_eq!(synced.subjects.len(), 7, "{:?}", synced.subjects);
    assert!(
        synced
            .subjects
            .iter()
            .any(|subject| subject == "Seeded message with a large body and two attachments")
    );
    assert_eq!(synced.states, 2, "each download ends with a state");
    assert_eq!(
        synced.resumed_changes, 0,
        "the resumed download reports nothing"
    );
}

#[tokio::test]
async fn an_en_us_download_and_its_resumption_replay_byte_for_byte() {
    check(&replay("sync-en-us", Lcid::EN_US).await);
}

#[tokio::test]
async fn an_nl_nl_download_and_its_resumption_replay_byte_for_byte() {
    check(&replay("sync-nl-nl", Lcid::new(0x0413)).await);
}
