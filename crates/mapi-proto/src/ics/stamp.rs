//! Whether anything in a folder has changed, from one row of a hierarchy table.
//!
//! A pass that downloads every folder pays a configure and a state upload per folder, and in most
//! folders learns that nothing changed. Two properties of a folder say whether anything directly in
//! it has, and one hierarchy-table read returns both for every folder in a mailbox:
//! `PidTagLocalCommitTimeMax`, "the most recent time that a top level object within a folder was
//! changed", and `PidTagDeletedCountTotal`, "the total number of messages that have been deleted
//! from a folder". A [`FolderStamp`] is the pair.
//!
//! Measured on Exchange Server SE `15.02.2562.056`, reading Drafts, Deleted Items and the Inbox
//! after each change in turn: `PidTagLocalCommitTimeMax` moved for a create, a modify, a message
//! marked unread and marked read again, a delete, and a move — on both folders of the move. A
//! delete and a move out also raised the source folder's `PidTagDeletedCountTotal`. The folder not
//! touched did not move at all. The hierarchy table and the folder's own properties reported the
//! same values.
//!
//! [MS-OXCFOLD] §2.2.2.2.1.14 — `PidTagLocalCommitTimeMax`
//! [MS-OXCFOLD] §2.2.2.2.1.15 — `PidTagDeletedCountTotal`

use crate::oxcdata::{FileTime, FolderId, PropertyRow, PropertyTag};

/// When a folder last changed and how many messages it has lost, as one value: compare two, and a
/// folder whose stamp is the same has nothing to download.
///
/// Three rules make the comparison sound, and the type can enforce only the first:
///
/// * **Any difference is a change, earlier as much as later.** A stamp that went *backwards* is a
///   server restored from a backup, and that folder has to be downloaded for anything to notice. So
///   there is [`is_unchanged_since`](Self::is_unchanged_since) and no ordering.
/// * **Read the stamps before the downloads, and keep each with the state its download produced.**
///   A stamp read after a download also covers whatever changed while it ran, and that change would
///   never be downloaded.
/// * **A folder with no stamp is downloaded.** A folder that cannot say has not said it is
///   unchanged.
///
/// A changed stamp means *something* changed, not that a download will report it: a subfolder
/// counts as a top-level object of its parent, so renaming one moves the parent's stamp too. That
/// errs the cheap way — a download that reports only a state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FolderStamp {
    last_commit: FileTime,
    deleted: u32,
}

impl FolderStamp {
    /// The hierarchy-table columns [`FolderStamps::from_rows`] reads: the folder's id and its
    /// stamp.
    pub const COLUMNS: [PropertyTag; 3] = [
        PropertyTag::FOLDER_ID,
        PropertyTag::LOCAL_COMMIT_TIME_MAX,
        PropertyTag::DELETED_COUNT_TOTAL,
    ];

    /// A stamp from its two parts, as a consumer that persisted them reads them back.
    #[must_use]
    pub const fn new(last_commit: FileTime, deleted: u32) -> Self {
        Self {
            last_commit,
            deleted,
        }
    }

    /// `PidTagLocalCommitTimeMax`: when a message or subfolder directly in the folder last changed.
    #[must_use]
    pub const fn last_commit(self) -> FileTime {
        self.last_commit
    }

    /// `PidTagDeletedCountTotal`: how many messages have ever been deleted from the folder.
    #[must_use]
    pub const fn deleted_count(self) -> u32 {
        self.deleted
    }

    /// Whether nothing directly in the folder has changed between `earlier` and this stamp.
    ///
    /// Equality, deliberately: a stamp earlier than the one kept is as much a change as a later
    /// one.
    #[must_use]
    pub fn is_unchanged_since(self, earlier: Self) -> bool {
        self == earlier
    }

    /// The folder and its stamp from one row read with [`COLUMNS`](Self::COLUMNS); `None` when the
    /// row lacks any of the three.
    #[must_use]
    pub fn from_row(row: &PropertyRow) -> Option<(FolderId, Self)> {
        let folder = row.folder_id()?;
        let last_commit = row.get(PropertyTag::LOCAL_COMMIT_TIME_MAX)?.as_time()?;
        let deleted = row.get(PropertyTag::DELETED_COUNT_TOTAL)?.as_u32()?;
        Some((folder, Self::new(last_commit, deleted)))
    }
}

/// The stamp of every folder a hierarchy table listed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FolderStamps {
    /// Sorted by folder id, for lookup.
    stamps: Vec<(FolderId, FolderStamp)>,
}

impl FolderStamps {
    /// The stamps in rows read with [`FolderStamp::COLUMNS`]. A row without a stamp is left out,
    /// and its folder then has none — which says to download it.
    #[must_use]
    pub fn from_rows(rows: &[PropertyRow]) -> Self {
        let mut stamps: Vec<_> = rows.iter().filter_map(FolderStamp::from_row).collect();
        stamps.sort_unstable_by_key(|(folder, _)| folder.as_u64());
        stamps.dedup_by_key(|(folder, _)| *folder);
        Self { stamps }
    }

    /// The stamp of one folder, if the table listed it with one.
    #[must_use]
    pub fn get(&self, folder: FolderId) -> Option<FolderStamp> {
        self.stamps
            .binary_search_by_key(&folder.as_u64(), |(known, _)| known.as_u64())
            .ok()
            .and_then(|at| self.stamps.get(at))
            .map(|(_, stamp)| *stamp)
    }

    /// Whether `folder` has nothing to download since `earlier`: its stamp is there, and the same.
    ///
    /// `false` for a folder the table listed without a stamp, or did not list at all.
    #[must_use]
    pub fn is_unchanged_since(&self, folder: FolderId, earlier: FolderStamp) -> bool {
        self.get(folder)
            .is_some_and(|stamp| stamp.is_unchanged_since(earlier))
    }

    /// How many folders have a stamp.
    #[must_use]
    pub fn len(&self) -> usize {
        self.stamps.len()
    }

    /// Whether no folder has one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stamps.is_empty()
    }

    /// Every folder and its stamp, in ascending folder id order.
    #[must_use]
    pub fn iter(&self) -> FolderStampsIter<'_> {
        FolderStampsIter(self.stamps.iter())
    }
}

impl<'a> IntoIterator for &'a FolderStamps {
    type IntoIter = FolderStampsIter<'a>;
    type Item = (FolderId, FolderStamp);

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The folders of a [`FolderStamps`] and their stamps, in ascending folder id order.
#[derive(Clone, Debug)]
pub struct FolderStampsIter<'a>(core::slice::Iter<'a, (FolderId, FolderStamp)>);

impl Iterator for FolderStampsIter<'_> {
    type Item = (FolderId, FolderStamp);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().copied()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

#[cfg(test)]
mod tests;
