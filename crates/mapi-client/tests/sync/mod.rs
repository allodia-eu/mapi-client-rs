//! Incremental synchronization against a real mailbox: a first download, the next one, the changes
//! in between, and a download cut short and resumed.
//!
//! Part of `tests/live.rs`, ignored for the same reason: CI never sees an Exchange Server. The
//! change test is **self-cleaning** like the `writes` suite — everything it creates carries
//! [`MARKER`] and is swept away before it starts and before it asserts — because the counts the
//! `items` suite asserts are exact.

mod stamps;

use std::sync::{Arc, Mutex};

use mapi_client::mapi_proto::fasttransfer::{MessageChange, PartialGroup, SyncEvent};
use mapi_client::{
    CONTENTS_COLUMNS, ContentsDownload, Exchange, FolderId, FuzzyLevel, IcsState, Logon,
    MessageClass, MessageId, Observer, PropertyName, PropertySetId, PropertyTag, PropertyType,
    PropertyValue, ReadFlags, RequestType, Restriction, SpecialFolder, TaggedValue,
    WellKnownFolder,
};

/// The subject every message this suite creates starts with.
pub(super) const MARKER: &str = "mapi-client-rs sync test";

/// Counts the `Execute` requests a client sends.
#[derive(Debug, Default)]
struct Executes(Mutex<usize>);

impl Observer for Executes {
    fn observe(&self, exchange: &Exchange<'_>) {
        if exchange.request_type() == RequestType::Execute {
            let mut count = self.0.lock().unwrap();
            *count = count.saturating_add(1);
        }
    }
}

/// Reads a whole download, returning its events and the state it ends with.
async fn drain(
    logon: &mut Logon,
    folder: FolderId,
    configuration: ContentsDownload,
    state: Option<IcsState>,
) -> (Vec<SyncEvent>, IcsState) {
    let mut download = logon
        .download(folder, configuration, state)
        .expect("a download");
    let mut events = Vec::new();
    while let Some(event) = download.try_next().await.expect("an event") {
        events.push(event);
    }
    let state = download.close().await.expect("the context released");
    (events, state)
}

fn subject(change: &MessageChange) -> String {
    change
        .property(PropertyTag::SUBJECT)
        .and_then(PropertyValue::as_string)
        .map(|text| text.as_str().to_owned())
        .unwrap_or_default()
}

fn messages(events: &[SyncEvent]) -> Vec<&MessageChange> {
    events
        .iter()
        .filter_map(|event| match event {
            SyncEvent::Message(change) => Some(change),
            _ => None,
        })
        .collect()
}

/// A first synchronization of the Inbox reports every message, across at least three
/// `RopFastTransferSourceGetBuffer` responses, and one from the state it ends with reports nothing
/// but a state.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_first_sync_reports_everything_and_the_next_nothing() {
    let executes = Arc::new(Executes::default());
    let client = super::builder()
        .observer(Arc::clone(&executes))
        .build()
        .unwrap();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let inbox = logon.folder_id(WellKnownFolder::Inbox).unwrap();

    let before = *executes.0.lock().unwrap();
    let (events, state) = drain(&mut logon, inbox, ContentsDownload::new(), None).await;
    // Less the release that closes it.
    let buffers = executes
        .0
        .lock()
        .unwrap()
        .saturating_sub(before)
        .saturating_sub(1);
    let subjects: Vec<String> = messages(&events).into_iter().map(subject).collect();
    println!(
        "cold: {} message(s) in {buffers} round trip(s)",
        subjects.len()
    );
    for subject in &subjects {
        println!("  {subject:.70}");
    }
    assert!(
        buffers >= 3,
        "the stream spans {buffers} GetBuffer response(s)"
    );
    assert!(subjects.iter().any(|s| s == "First seeded message"));
    assert!(matches!(events.last(), Some(SyncEvent::End)));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, SyncEvent::State(_)))
    );

    let (again, _) = drain(&mut logon, inbox, ContentsDownload::new(), Some(state)).await;
    assert!(messages(&again).is_empty(), "{again:?}");
    assert!(
        !again
            .iter()
            .any(|event| matches!(event, SyncEvent::Deletions(_) | SyncEvent::ReadStates(_))),
        "{again:?}"
    );
    logon.disconnect().await.unwrap();
}

/// A download abandoned part way resumes from its checkpoint, and between the two nothing is lost
/// and nothing is delivered twice.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_download_cut_short_resumes_from_its_checkpoint() {
    let mut logon = super::client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let inbox = logon.folder_id(WellKnownFolder::Inbox).unwrap();
    let (whole, _) = drain(&mut logon, inbox, ContentsDownload::new(), None).await;
    let all: Vec<String> = messages(&whole).into_iter().map(subject).collect();

    let mut first = Vec::new();
    let checkpoint = {
        let mut download = logon
            .download(inbox, ContentsDownload::new(), None)
            .unwrap();
        while first.len() < 3 {
            match download.try_next().await.unwrap() {
                Some(SyncEvent::Message(change)) => first.push(subject(&change)),
                Some(_) => {}
                None => panic!("the Inbox holds fewer than four messages"),
            }
        }
        download.checkpoint().clone()
    };
    let (rest, _) = drain(&mut logon, inbox, ContentsDownload::new(), Some(checkpoint)).await;
    let second: Vec<String> = messages(&rest).into_iter().map(subject).collect();
    println!("first {first:?}\nthen {second:?}");

    for subject in &first {
        assert!(!second.contains(subject), "{subject:?} was delivered twice");
    }
    let mut together: Vec<String> = first.into_iter().chain(second).collect();
    together.sort();
    let mut expected = all;
    expected.sort();
    assert_eq!(together, expected, "every message, once");
    logon.disconnect().await.unwrap();
}

/// A state obtained without a restriction is refused for a download with one, and nothing is sent.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_state_for_another_scope_is_refused_before_anything_is_sent() {
    let mut logon = super::client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let inbox = logon.folder_id(WellKnownFolder::Inbox).unwrap();
    let (_, state) = drain(&mut logon, inbox, ContentsDownload::new(), None).await;

    let narrowed = ContentsDownload::new().restriction(Restriction::exists(PropertyTag::SUBJECT));
    let refused = logon.download(inbox, narrowed, Some(state)).unwrap_err();
    assert!(refused.to_string().contains("restriction"), "{refused}");
    logon.disconnect().await.unwrap();
}

/// Creates a message in `folder` with a subject after the marker.
async fn create(logon: &mut Logon, folder: FolderId, name: &str) -> MessageId {
    logon
        .folder(folder)
        .create_message(MessageClass::Note)
        .set([TaggedValue::new(
            PropertyTag::SUBJECT,
            PropertyValue::String(format!("{MARKER}: {name}").into()),
        )
        .unwrap()])
        .save()
        .await
        .unwrap()
        .id()
}

/// Deletes every message in `folder` whose subject carries the marker.
async fn sweep(logon: &mut Logon, folder: FolderId) {
    let rows = logon
        .folder(folder)
        .contents()
        .columns(CONTENTS_COLUMNS)
        .filter(Restriction::all([
            Restriction::exists(PropertyTag::SUBJECT),
            Restriction::content(
                FuzzyLevel::substring().ignoring_case(),
                TaggedValue::new(PropertyTag::SUBJECT, PropertyValue::String(MARKER.into()))
                    .unwrap(),
            ),
        ]))
        .collect()
        .await
        .unwrap();
    let ids: Vec<MessageId> = rows
        .iter()
        .filter_map(mapi_client::PropertyRow::message_id)
        .collect();
    if !ids.is_empty() {
        logon.folder(folder).delete_messages(&ids).await.unwrap();
    }
}

/// Each kind of change, made between two downloads of Drafts, reported by the second exactly as
/// what it was: new and changed messages as changes — a category change as a partial one naming
/// the group that holds `Keywords` — deletions and moves out as deletions, and a read flag as a
/// read-state change.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn the_next_sync_reports_exactly_what_changed() {
    let mut logon = super::client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let drafts = logon.special_folder(SpecialFolder::Drafts).await.unwrap();
    let deleted_items = logon.folder_id(WellKnownFolder::DeletedItems).unwrap();
    sweep(&mut logon, drafts).await;
    sweep(&mut logon, deleted_items).await;

    let keywords = PropertyName::named(PropertySetId::PUBLIC_STRINGS, "Keywords").unwrap();
    let keywords_tag = logon
        .register_names([keywords.clone()])
        .await
        .unwrap()
        .tag(&keywords, PropertyType::MultipleString)
        .unwrap();

    let modified = create(&mut logon, drafts, "to be modified").await;
    let gone = create(&mut logon, drafts, "to be deleted").await;
    let moved_out = create(&mut logon, drafts, "to be moved out").await;
    let unread = create(&mut logon, drafts, "to be marked unread").await;
    let categorised = create(&mut logon, drafts, "to be categorised").await;
    let moved_in = create(&mut logon, deleted_items, "moved in").await;

    let configuration = || ContentsDownload::new().partial_items(true);
    let (_, baseline) = drain(&mut logon, drafts, configuration(), None).await;

    logon
        .message(drafts, modified)
        .update()
        .set([TaggedValue::new(
            PropertyTag::SUBJECT,
            PropertyValue::String(format!("{MARKER}: modified").into()),
        )
        .unwrap()])
        .save()
        .await
        .unwrap();
    logon.folder(drafts).delete_messages(&[gone]).await.unwrap();
    logon
        .folder(drafts)
        .move_messages(&[moved_out], deleted_items)
        .await
        .unwrap();
    logon
        .folder(deleted_items)
        .move_messages(&[moved_in], drafts)
        .await
        .unwrap();
    logon
        .folder(drafts)
        .set_read(&[unread], ReadFlags::Unread)
        .await
        .unwrap();
    logon
        .message(drafts, categorised)
        .update()
        .set([TaggedValue::new(
            keywords_tag,
            PropertyValue::MultipleString(vec!["Blue Category".into()]),
        )
        .unwrap()])
        .save()
        .await
        .unwrap();
    create(&mut logon, drafts, "created").await;

    let (events, _) = drain(&mut logon, drafts, configuration(), Some(baseline)).await;
    for event in &events {
        match event {
            SyncEvent::Message(change) => println!(
                "  change{} {:?} groups {:?}",
                if change.is_partial() {
                    " (partial)"
                } else {
                    ""
                },
                subject(change),
                change
                    .groups()
                    .iter()
                    .map(PartialGroup::index)
                    .collect::<Vec<_>>()
            ),
            other => println!("  {other:?}"),
        }
    }
    let outcome = check(&events, &keywords, [gone, moved_out], unread);

    sweep(&mut logon, drafts).await;
    sweep(&mut logon, deleted_items).await;
    logon.disconnect().await.unwrap();
    outcome.unwrap();
}

/// What the second download of the change test has to have reported, as a result so that the
/// sweep runs before anything fails.
fn check(
    events: &[SyncEvent],
    keywords: &PropertyName,
    removed: [MessageId; 2],
    unread: MessageId,
) -> Result<(), String> {
    let changes = messages(events);
    let mut subjects: Vec<String> = changes.iter().map(|change| subject(change)).collect();
    subjects.sort();
    let expected = ["created", "modified", "moved in", "to be categorised"]
        .map(|name| format!("{MARKER}: {name}"));
    if subjects != expected {
        return Err(format!("changes {subjects:?}, expected {expected:?}"));
    }

    let categorised = changes
        .iter()
        .find(|change| subject(change).ends_with("to be categorised"))
        .ok_or("no category change")?;
    if categorised.is_partial() {
        let mapping = categorised
            .group_mapping()
            .ok_or("a partial change with no mapping")?;
        let group = mapping
            .group_of_name(keywords)
            .ok_or("no group in the mapping names Keywords")?;
        if !categorised
            .groups()
            .iter()
            .any(|changed| changed.index() == group)
        {
            return Err(format!(
                "the Keywords group {group} is not among the changed groups"
            ));
        }
    } else {
        return Err("the category change arrived whole, not as a partial change".to_owned());
    }

    let deletions = events
        .iter()
        .find_map(|event| match event {
            SyncEvent::Deletions(deletions) => Some(deletions),
            _ => None,
        })
        .ok_or("no deletions")?;
    for id in removed {
        if !deletions.deleted().contains_message(id) {
            return Err(format!("{id} is not among the deletions"));
        }
    }

    let read = events
        .iter()
        .find_map(|event| match event {
            SyncEvent::ReadStates(read) => Some(read),
            _ => None,
        })
        .ok_or("no read-state changes")?;
    if !read.marked_unread().contains_message(unread) {
        return Err(format!("{unread} is not among the messages marked unread"));
    }
    Ok(())
}
