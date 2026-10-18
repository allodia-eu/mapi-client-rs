//! Folder stamps against a fake server: one hierarchy-table read of the whole mailbox, and what is
//! made of the rows.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use mapi_client::{FileTime, FolderId, FolderStamp, WellKnownFolder};
use support::{
    BOOKMARK_END, Bytes, LOGON_HANDLE, MapiServer, OPEN_FOLDER_SLOT, TABLE_HANDLE, columns_of,
    connect_ok, execute_body, get_table_response, logon_response, open_folder_response,
    query_rows_response, rop_list, set_columns_response, well_known_folder_id,
};

/// One row read with [`FolderStamp::COLUMNS`], in standard form.
fn stamp_row(folder: u64, ticks: u64, deleted: u32) -> Vec<u8> {
    Bytes::new().u64(folder).u64(ticks).u32(deleted).done()
}

/// The stamps come from the mailbox root's descendants, asked for with the three columns a stamp
/// is read from, and each folder's is looked up by its id.
#[tokio::test]
async fn every_folders_stamp_comes_from_one_read_of_the_whole_hierarchy() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    let mut table = open_folder_response(OPEN_FOLDER_SLOT);
    table.extend(get_table_response(0x04, 2, 2));
    table.extend(set_columns_response(2));
    table.extend(query_rows_response(
        2,
        BOOKMARK_END,
        &[
            stamp_row(0x0D00_0000_0000_0011, 134_367_827_013_744_798, 431),
            stamp_row(0x0D00_0000_0000_0012, 134_367_386_693_198_719, 154),
        ],
    ));
    server.reply_ok(execute_body(
        &table,
        &[LOGON_HANDLE, 0x0000_0001, TABLE_HANDLE],
    ));
    server.reply_ok(execute_body(&[], &[TABLE_HANDLE]));

    let mut logon = server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap();
    let stamps = logon.folder_stamps().await.unwrap();

    assert_eq!(stamps.len(), 2);
    let drafts = FolderId::new(0x0D00_0000_0000_0011);
    let kept = FolderStamp::new(FileTime::new(134_367_827_013_744_798), 431);
    assert_eq!(stamps.get(drafts), Some(kept));
    assert!(stamps.is_unchanged_since(drafts, kept));
    assert!(!stamps.is_unchanged_since(FolderId::new(0x0D00_0000_0000_0012), kept));

    let sent = server.rops(2).await;
    let rops = rop_list(&sent);
    let (_, open) = rops.iter().find(|(rop, _)| *rop == 0x02).unwrap();
    assert_eq!(
        &open[4..12],
        &well_known_folder_id(u64::try_from(WellKnownFolder::MailboxRoot.index()).unwrap())
            .to_le_bytes(),
        "the whole mailbox, from its root"
    );
    let (_, table) = rops.iter().find(|(rop, _)| *rop == 0x04).unwrap();
    assert_ne!(
        table[4] & 0x04,
        0,
        "Depth: every folder below the root, not its children"
    );
    let (_, columns) = rops.iter().find(|(rop, _)| *rop == 0x12).unwrap();
    assert_eq!(columns_of(columns), FolderStamp::COLUMNS);
}
