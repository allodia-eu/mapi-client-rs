//! The folders a logon does not name, and the identifier conversions that reach them.
//!
//! Split from `live.rs` because it is a different question: that file asks whether the session and
//! the table reads work at all, and this one asks whether [MS-OXOSFLD]'s entry-id chain finds real
//! folders. Both run under `cargo test --test live`, and this is a `mod.rs` in a directory so that
//! Cargo does not also build it as a test target of its own.

use mapi_client::{
    ContainerClass, FOLDER_PROPERTIES, FolderId, PropertyRow, PropertyTag, PropertyValue,
    SpecialFolder, SpecialFolderState, StoreObjectType, TableString, WellKnownFolder,
};

use super::client;

/// **The entry-id chain**: the folders a logon does not name, found and opened.
///
/// Twelve of this workspace's eighteen target operations are about folders `RopLogon` never
/// reports. Reaching one is three facts stacked on each other, and this is where all three are
/// checked against a server rather than against the document:
///
/// 1. the entry ids live on the **Inbox** ([MS-OXOSFLD] §2.2.3 — Root folder for a delegate, which
///    this crate does not do);
/// 2. each is a 46-byte Folder `EntryID` whose provider is the mailbox's own GUID;
/// 3. its long-term tail converts to a short-term folder id only through the server.
///
/// The proof that the chain is right is not that it produces an id — a wrong id is still an id —
/// but that the folder the id **opens** carries the container class [MS-OXOSFLD] §2.2.1 gives that
/// folder. That is asserted below, by reading each one's properties.
///
/// **Not every special folder is inside the IPM subtree.** Measured on Exchange Server SE
/// `15.02.2562.045`: Reminders resolves to a folder that a recursive walk of the IPM subtree does
/// not contain, which is not a bug — [MS-OXOSFLD] §3.1.1.1 puts Reminders directly under the Root
/// folder, a sibling of Top of Personal Folders rather than a child of it. A client that located
/// special folders by walking the user-visible tree would not find it at all.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn the_special_folders_resolve_to_folders_that_exist() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let mailbox_guid = logon.mailbox().mailbox_guid();
    let subtree = logon
        .folder_id(WellKnownFolder::IpmSubtree)
        .expect("the IPM subtree");

    let special = logon.special_folders().await.expect("the special folders");
    println!("special folders, by the entry ids on the Inbox:");
    for entry in &special {
        println!("  {entry}");
    }

    // Every entry id this mailbox carries was issued by this mailbox. A mismatch would mean the
    // conversion answered for a folder in somebody else's store — a plausible id for the wrong
    // folder, which no error would report.
    for entry in &special {
        if let SpecialFolderState::Found { entry_id, .. } = entry.state() {
            assert!(
                entry_id.belongs_to(mailbox_guid),
                "{}'s entry id names {} rather than this mailbox",
                entry.folder(),
                entry_id.provider_uid()
            );
            assert_eq!(entry_id.object_type(), StoreObjectType::PRIVATE_FOLDER);
        }
    }

    assert!(
        special.get(SpecialFolder::Calendar).is_some(),
        "a provisioned mailbox has a Calendar folder"
    );
    assert!(special.get(SpecialFolder::Contacts).is_some());

    // Open each one and ask what it is. This is *"get calendar details"* as well as the check that
    // the conversion produced the right id: a folder that opens and reports `IPF.Appointment` is
    // the calendar, whatever it is called in this mailbox's language.
    for entry in &special {
        let Some(id) = entry.id() else { continue };
        let details = logon
            .folder(id)
            .properties()
            .read(FOLDER_PROPERTIES)
            .await
            .unwrap_or_else(|error| panic!("{} at {id} would not open: {error}", entry.folder()));

        let name = details
            .string(PropertyTag::DISPLAY_NAME)
            .map(TableString::as_str)
            .unwrap_or_default()
            .to_owned();
        let class = details
            .string(PropertyTag::CONTAINER_CLASS)
            .map(TableString::as_str)
            .unwrap_or_default()
            .to_owned();
        let messages = details
            .get(PropertyTag::CONTENT_COUNT)
            .and_then(PropertyValue::as_u32);
        println!(
            "  {} is {name:?}, class {class:?}, {messages:?} item(s)",
            entry.folder()
        );

        assert!(!name.is_empty(), "{} has no display name", entry.folder());
        assert_eq!(
            ContainerClass::new(&class),
            entry.folder().container_class(),
            "{} carries a class [MS-OXOSFLD] §2.2.1 does not give it",
            entry.folder()
        );
    }

    // The ones the specification puts inside the user-visible tree are in it, and Reminders is
    // not. Both halves are asserted, because the second is the surprise.
    let inside: Vec<FolderId> = logon
        .folder(subtree)
        .descendants()
        .collect()
        .await
        .expect("a recursive hierarchy table")
        .iter()
        .filter_map(PropertyRow::folder_id)
        .collect();

    for folder in [
        SpecialFolder::Calendar,
        SpecialFolder::Contacts,
        SpecialFolder::Drafts,
    ] {
        let id = special.get(folder).unwrap_or_else(|| panic!("{folder}"));
        assert!(
            inside.contains(&id),
            "[MS-OXOSFLD] §3.1.1.1 puts {folder} inside Top of Personal Folders, and it is not"
        );
    }

    if let Some(reminders) = special.get(SpecialFolder::Reminders) {
        assert!(
            !inside.contains(&reminders),
            "Reminders has moved into the IPM subtree; re-measure the claim that it does not live \
             there rather than deleting it"
        );
        println!("Reminders is {reminders}, outside the IPM subtree as [MS-OXOSFLD] §3.1.1.1 says");
    }

    logon.disconnect().await.expect("Disconnect");
}

/// **The identifier round trip.**
///
/// A long-term id and a short-term one are not interconvertible by arithmetic — only the server
/// holds the mapping — so the only way to know this crate encodes the 24-byte structure correctly
/// is to send one out and get the same one back. Both directions are exercised: the folder id of
/// the Inbox becomes a long-term id, and that long-term id becomes the folder id again.
///
/// It also settles the byte order of `GlobalCounter`, which the documents depict but do not name:
/// the counter read out of the long-term id has to equal the counter of the short-term id it came
/// from, or one of the two readings is wrong.
///
/// [MS-OXCROPS] §2.2.3.8 — `RopLongTermIdFromId`
/// [MS-OXCROPS] §2.2.3.9 — `RopIdFromLongTermId`
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_folder_id_survives_the_round_trip_through_a_long_term_id() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let inbox = logon.folder_id(WellKnownFolder::Inbox).expect("an Inbox");

    let long_term = logon
        .long_term_id(inbox.into())
        .await
        .expect("RopLongTermIdFromId");
    println!("{inbox} is {long_term}");

    assert_eq!(
        long_term.global_counter(),
        inbox.global_counter(),
        "the two readings of GlobalCounter disagree, so one of them is the wrong byte order"
    );

    let back = logon
        .short_term_id(&long_term)
        .await
        .expect("RopIdFromLongTermId");
    assert_eq!(
        back.as_folder_id(),
        inbox,
        "the conversion did not round trip"
    );

    // The replica id is the short form of the database GUID, so the same folder read through both
    // is the same folder in the same store.
    println!(
        "replica {} stands for {}",
        inbox.replica_id(),
        long_term.database_guid()
    );

    logon.disconnect().await.expect("Disconnect");
}

/// **The `Depth` measurement.**
///
/// [MS-OXCFOLD] §2.2.1.13.1 documents a `Depth` bit that makes a hierarchy table list every folder
/// below the one asked about. Whether a given Exchange honours it is not something the document
/// settles — so this walks the hierarchy the slow way, one `RopGetHierarchyTable` per folder, and
/// demands that the recursive read found exactly the same set.
///
/// It also checks the column the recursion is useless without: with `Depth` set the rows arrive
/// flat, and `PidTagParentFolderId` is the only thing in them that says where each folder sits.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_recursive_hierarchy_read_finds_what_walking_it_by_hand_finds() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let subtree = logon
        .folder_id(WellKnownFolder::IpmSubtree)
        .expect("the IPM subtree");

    let recursive = logon
        .folder(subtree)
        .descendants()
        .collect()
        .await
        .expect("a recursive hierarchy table");

    // The same question asked the expensive way: one round trip per folder, breadth first.
    let mut walked: Vec<FolderId> = Vec::new();
    let mut queue = vec![subtree];
    while let Some(parent) = queue.pop() {
        let children = logon
            .folder(parent)
            .subfolders()
            .collect()
            .await
            .expect("a hierarchy table");
        for row in &children {
            if let Some(id) = row.folder_id() {
                walked.push(id);
                queue.push(id);
            }
        }
    }

    let mut from_depth: Vec<FolderId> = recursive
        .iter()
        .filter_map(PropertyRow::folder_id)
        .collect();
    from_depth.sort_unstable();
    walked.sort_unstable();

    println!(
        "Depth found {} folder(s); walking by hand found {}",
        from_depth.len(),
        walked.len()
    );
    assert_eq!(
        from_depth, walked,
        "the Depth flag and a hand walk disagree about this mailbox's folders"
    );

    // A flat list is only useful if each row says where it sits.
    let parents: Vec<Option<u64>> = recursive
        .iter()
        .map(|row| {
            row.get(PropertyTag::PARENT_FOLDER_ID)
                .and_then(PropertyValue::as_u64)
        })
        .collect();
    assert!(
        parents.iter().all(Option::is_some),
        "PidTagParentFolderId is absent from a hierarchy row, so a Depth read cannot be a tree"
    );
    assert!(
        parents.iter().flatten().any(|id| *id != subtree.as_u64()),
        "every folder claims the subtree as its parent, so this mailbox has no nesting to prove \
         the recursion with"
    );

    // What the whole point of the class column is: telling a calendar from a mail folder.
    let classes: Vec<String> = {
        let mut names: Vec<String> = recursive
            .iter()
            .filter_map(|row| row.string(PropertyTag::CONTAINER_CLASS))
            .map(|class| class.as_str().to_owned())
            .filter(|class| !class.is_empty())
            .collect();
        names.sort();
        names.dedup();
        names
    };
    println!("container classes in this mailbox: {classes:?}");
    assert!(
        classes.iter().any(|class| class == "IPF.Appointment"),
        "no folder in this mailbox is a calendar"
    );

    logon.disconnect().await.expect("Disconnect");
}
