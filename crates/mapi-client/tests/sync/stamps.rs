//! Folder stamps against a real mailbox: which changes move a folder's stamp, and which folders'.
//!
//! Self-cleaning like the rest of the sync suite: everything it creates carries [`MARKER`] and is
//! swept away before it starts and before it asserts.

use mapi_client::{
    FolderId, Logon, PropertyName, PropertySetId, PropertyTag, PropertyType, PropertyValue,
    ReadFlags, SpecialFolder, TaggedValue, WellKnownFolder,
};

use super::{MARKER, create, sweep};

/// The folders a change moved the stamp of, among `watched`.
async fn moved(
    logon: &mut Logon,
    watched: &[FolderId],
    before: &mapi_client::FolderStamps,
) -> (Vec<FolderId>, mapi_client::FolderStamps) {
    let after = logon.folder_stamps().await.unwrap();
    let moved = watched
        .iter()
        .copied()
        .filter(|folder| !after.is_unchanged_since(*folder, before.get(*folder).unwrap()))
        .collect();
    (moved, after)
}

/// Every change the change test makes moves the stamp of the folder it was made in, a move moves
/// both folders', and a folder nothing touched keeps its stamp.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn every_change_moves_its_folders_stamp_and_no_other() {
    let mut logon = super::super::client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let drafts = logon.special_folder(SpecialFolder::Drafts).await.unwrap();
    let deleted = logon.folder_id(WellKnownFolder::DeletedItems).unwrap();
    let inbox = logon.folder_id(WellKnownFolder::Inbox).unwrap();
    sweep(&mut logon, drafts).await;
    sweep(&mut logon, deleted).await;
    let watched = [drafts, deleted, inbox];

    let keywords = PropertyName::named(PropertySetId::PUBLIC_STRINGS, "Keywords").unwrap();
    let keywords_tag = logon
        .register_names([keywords.clone()])
        .await
        .unwrap()
        .tag(&keywords, PropertyType::MultipleString)
        .unwrap();

    let mut stamps = logon.folder_stamps().await.unwrap();
    println!("  {} folder(s) stamped", stamps.len());
    for folder in watched {
        assert!(stamps.get(folder).is_some(), "{folder} has no stamp");
    }
    let mut outcomes = Vec::new();
    let mut step = |name: &'static str, moved: Vec<FolderId>, expected: Vec<FolderId>| {
        println!("  {name}: moved {moved:?}");
        outcomes.push((name, moved, expected));
    };

    let (same, after) = moved(&mut logon, &watched, &stamps).await;
    step("nothing", same, vec![]);
    stamps = after;

    let message = create(&mut logon, drafts, "stamped").await;
    let (changed, after) = moved(&mut logon, &watched, &stamps).await;
    step("create", changed, vec![drafts]);
    stamps = after;

    logon
        .message(drafts, message)
        .update()
        .set([TaggedValue::new(
            PropertyTag::SUBJECT,
            PropertyValue::String(format!("{MARKER}: stamped, modified").into()),
        )
        .unwrap()])
        .save()
        .await
        .unwrap();
    let (changed, after) = moved(&mut logon, &watched, &stamps).await;
    step("modify", changed, vec![drafts]);
    stamps = after;

    logon
        .folder(drafts)
        .set_read(&[message], ReadFlags::Unread)
        .await
        .unwrap();
    let (changed, after) = moved(&mut logon, &watched, &stamps).await;
    step("read flag", changed, vec![drafts]);
    stamps = after;

    logon
        .message(drafts, message)
        .update()
        .set([TaggedValue::new(
            keywords_tag,
            PropertyValue::MultipleString(vec!["Blue Category".into()]),
        )
        .unwrap()])
        .save()
        .await
        .unwrap();
    let (changed, after) = moved(&mut logon, &watched, &stamps).await;
    step("category", changed, vec![drafts]);
    stamps = after;

    logon
        .folder(drafts)
        .move_messages(&[message], deleted)
        .await
        .unwrap();
    let (changed, after) = moved(&mut logon, &watched, &stamps).await;
    step("move out", changed, vec![drafts, deleted]);
    stamps = after;

    let gone = create(&mut logon, drafts, "to be deleted").await;
    stamps = moved(&mut logon, &watched, &stamps).await.1;
    logon.folder(drafts).delete_messages(&[gone]).await.unwrap();
    let after = logon.folder_stamps().await.unwrap();
    let deleted_more =
        after.get(drafts).unwrap().deleted_count() > stamps.get(drafts).unwrap().deleted_count();
    let (changed, after) = moved(&mut logon, &watched, &stamps).await;
    step("delete", changed, vec![drafts]);
    stamps = after;

    sweep(&mut logon, drafts).await;
    sweep(&mut logon, deleted).await;
    logon.disconnect().await.unwrap();

    for (name, moved, expected) in outcomes {
        assert_eq!(moved, expected, "{name}");
    }
    assert!(deleted_more, "a delete raises PidTagDeletedCountTotal");
    let _ = stamps;
}
