use super::*;
use crate::oxcdata::ValueContext;
use crate::wire::{Reader, Writer};

/// A hierarchy row read with [`FolderStamp::COLUMNS`], in the flagged form a table uses when a
/// column may be missing: `None` for a stamp half the folder does not have.
fn row(folder: u64, last_commit: Option<u64>, deleted: Option<u32>) -> PropertyRow {
    let mut w = Writer::new();
    w.u8(0x01).u8(0x00).u64(folder);
    match last_commit {
        Some(ticks) => w.u8(0x00).u64(ticks),
        None => w.u8(0x0A).u32(0x8004_010F),
    };
    match deleted {
        Some(count) => w.u8(0x00).u32(count),
        None => w.u8(0x01),
    };
    let bytes = w.finish();
    PropertyRow::read(
        &mut Reader::new(&bytes),
        &FolderStamp::COLUMNS,
        ValueContext::TableRow,
    )
    .unwrap()
}

/// The Drafts stamp before and after a message was created in it, as Exchange Server SE
/// `15.02.2562.056` reported them.
const BEFORE: (u64, u32) = (134_367_827_013_744_798, 431);
const AFTER_CREATE: (u64, u32) = (134_367_840_146_688_658, 431);

fn stamp((ticks, deleted): (u64, u32)) -> FolderStamp {
    FolderStamp::new(FileTime::new(ticks), deleted)
}

#[test]
fn a_row_is_a_folder_and_its_stamp() {
    let (folder, found) =
        FolderStamp::from_row(&row(0x10, Some(BEFORE.0), Some(BEFORE.1))).unwrap();
    assert_eq!(folder, FolderId::new(0x10));
    assert_eq!(found, stamp(BEFORE));
    assert_eq!(found.last_commit(), FileTime::new(BEFORE.0));
    assert_eq!(found.deleted_count(), 431);
}

/// Unchanged means the same: later is a change, and so is earlier — a restored server.
#[test]
fn only_an_identical_stamp_is_unchanged() {
    assert!(stamp(BEFORE).is_unchanged_since(stamp(BEFORE)));
    assert!(!stamp(AFTER_CREATE).is_unchanged_since(stamp(BEFORE)));
    assert!(
        !stamp(BEFORE).is_unchanged_since(stamp(AFTER_CREATE)),
        "a stamp that went backwards"
    );
    assert!(
        !stamp((BEFORE.0, 432)).is_unchanged_since(stamp(BEFORE)),
        "a delete alone"
    );
}

#[test]
fn a_folder_without_a_whole_stamp_has_none() {
    assert_eq!(FolderStamp::from_row(&row(0x10, None, Some(1))), None);
    assert_eq!(FolderStamp::from_row(&row(0x10, Some(1), None)), None);
}

#[test]
fn stamps_are_looked_up_by_folder_and_a_missing_one_is_never_unchanged() {
    let stamps = FolderStamps::from_rows(&[
        row(0x30, Some(AFTER_CREATE.0), Some(AFTER_CREATE.1)),
        row(0x10, Some(BEFORE.0), Some(BEFORE.1)),
        row(0x20, None, Some(5)),
        row(0x10, Some(BEFORE.0), Some(BEFORE.1)),
    ]);
    assert_eq!(
        stamps.len(),
        2,
        "the stampless folder is left out, the repeat folded"
    );
    assert!(!stamps.is_empty());
    assert_eq!(stamps.get(FolderId::new(0x10)), Some(stamp(BEFORE)));
    assert_eq!(stamps.get(FolderId::new(0x20)), None);

    assert!(stamps.is_unchanged_since(FolderId::new(0x10), stamp(BEFORE)));
    assert!(!stamps.is_unchanged_since(FolderId::new(0x30), stamp(BEFORE)));
    assert!(!stamps.is_unchanged_since(FolderId::new(0x20), stamp(BEFORE)));
    assert!(!stamps.is_unchanged_since(FolderId::new(0x40), stamp(BEFORE)));

    let folders: Vec<FolderId> = stamps.iter().map(|(folder, _)| folder).collect();
    assert_eq!(folders, [FolderId::new(0x10), FolderId::new(0x30)]);
    assert_eq!(stamps.iter().size_hint(), (2, Some(2)));
    assert_eq!((&stamps).into_iter().count(), 2);
    assert!(FolderStamps::default().is_empty());
}
