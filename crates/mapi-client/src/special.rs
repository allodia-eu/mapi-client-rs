//! Resolving the folders a logon does not name.
//!
//! `RopLogon` reports thirteen folder ids and Calendar, Contacts, Drafts, Tasks, Notes and Journal
//! are none of them. Each of those is named by a binary property on the Inbox holding a 46-byte
//! Folder `EntryID`, and an entry id is long-term while `RopOpenFolder` takes a short-term id — so
//! reaching one is **two round trips**: read the properties, then ask the server to convert them.
//!
//! Both halves are batched, so eight folders cost the same two round trips as one. That is why
//! [`Logon::special_folders`](crate::Logon::special_folders) resolves everything rather than
//! offering a per-folder lookup that would look cheaper and not be.
//!
//! [MS-OXOSFLD] §2.2.3 — the binary identification properties
//! [MS-OXOSFLD] §4.1 — the three-step procedure this implements

use core::slice;

use mapi_proto::{ErrorCode, FolderEntryId, FolderId, SpecialFolder};

/// What a mailbox said about one special folder.
///
/// Four distinct answers, kept apart because the action each calls for is different: a mailbox
/// that has never had a Journal folder is not a mailbox whose Journal entry id the server refused
/// to convert, and neither is a corrupt property value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpecialFolderState {
    /// The folder exists, and this is the id `RopOpenFolder` takes.
    Found {
        /// The short-term id, converted by `RopIdFromLongTermId`.
        id: FolderId,
        /// The entry id the Inbox carried, which names the mailbox that issued it.
        entry_id: FolderEntryId,
    },
    /// The Inbox holds no entry id for this folder.
    ///
    /// Ordinary rather than exceptional: Exchange creates most special folders on demand, so a
    /// mailbox nobody has opened a journal in has no Journal folder and no property naming one.
    Absent,
    /// The Inbox named the folder and the server would not convert its entry id.
    Refused(ErrorCode),
    /// The property held something that is not a Folder `EntryID` structure.
    ///
    /// Reported rather than skipped: 46 bytes that fail the structure's own rules mean either the
    /// mailbox holds something unexpected or this crate is reading the wrong property, and
    /// silently treating that as "no calendar" hides both.
    Unreadable {
        /// Which of the structure's rules the value broke.
        reason: &'static str,
    },
}

impl SpecialFolderState {
    /// The folder id, when there is one.
    #[must_use]
    pub const fn id(&self) -> Option<FolderId> {
        match self {
            Self::Found { id, .. } => Some(*id),
            _ => None,
        }
    }
}

impl core::fmt::Display for SpecialFolderState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Found { id, .. } => write!(f, "{id}"),
            Self::Absent => f.write_str("not in this mailbox"),
            Self::Refused(code) => write!(f, "the server would not convert its entry id: {code}"),
            Self::Unreadable { reason } => write!(f, "unreadable entry id: {reason}"),
        }
    }
}

/// One special folder and what the mailbox said about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecialFolderEntry {
    folder: SpecialFolder,
    state: SpecialFolderState,
}

impl SpecialFolderEntry {
    pub(crate) const fn new(folder: SpecialFolder, state: SpecialFolderState) -> Self {
        Self { folder, state }
    }

    /// Which folder this is.
    #[must_use]
    pub const fn folder(&self) -> SpecialFolder {
        self.folder
    }

    /// What the mailbox said about it.
    #[must_use]
    pub const fn state(&self) -> &SpecialFolderState {
        &self.state
    }

    /// Its id, when it has one.
    #[must_use]
    pub const fn id(&self) -> Option<FolderId> {
        self.state.id()
    }
}

impl core::fmt::Display for SpecialFolderEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.folder, self.state)
    }
}

/// Everything one mailbox said about the folders its logon does not name.
///
/// Carries an entry for **every** folder [MS-OXOSFLD] §2.2.3 defines, present or not, so that
/// "this mailbox has no Journal" and "nobody asked about the Journal" stay different answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecialFolders {
    entries: Vec<SpecialFolderEntry>,
}

impl SpecialFolders {
    pub(crate) const fn new(entries: Vec<SpecialFolderEntry>) -> Self {
        Self { entries }
    }

    /// One folder's id, or `None` if this mailbox does not have it.
    #[must_use]
    pub fn get(&self, folder: SpecialFolder) -> Option<FolderId> {
        self.state(folder).and_then(SpecialFolderState::id)
    }

    /// What the mailbox said about one folder, including why it has no id.
    #[must_use]
    pub fn state(&self, folder: SpecialFolder) -> Option<&SpecialFolderState> {
        self.entries
            .iter()
            .find(|entry| entry.folder == folder)
            .map(SpecialFolderEntry::state)
    }

    /// Every folder that was asked about, in [`SpecialFolder::ALL`] order.
    #[must_use]
    pub fn iter(&self) -> SpecialFoldersIter<'_> {
        SpecialFoldersIter {
            inner: self.entries.iter(),
        }
    }

    /// How many of them this mailbox actually has.
    #[must_use]
    pub fn found(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.id().is_some())
            .count()
    }

    /// Whether the mailbox has none of them at all.
    ///
    /// Deliberately not `is_empty`: iterating a [`SpecialFolders`] always yields one entry per
    /// [`SpecialFolder::ALL`], because "this mailbox has no Journal" is an answer rather than an
    /// absence. An `is_empty` that disagreed with its own iterator about the same value is the
    /// kind of thing a reader trusts without checking.
    #[must_use]
    pub fn found_none(&self) -> bool {
        self.found() == 0
    }
}

impl<'a> IntoIterator for &'a SpecialFolders {
    type IntoIter = SpecialFoldersIter<'a>;
    type Item = &'a SpecialFolderEntry;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Every entry in a [`SpecialFolders`], in [`SpecialFolder::ALL`] order.
///
/// A named type rather than `impl Iterator`, so a caller can store one in a struct.
#[derive(Clone, Debug)]
pub struct SpecialFoldersIter<'a> {
    inner: slice::Iter<'a, SpecialFolderEntry>,
}

impl<'a> Iterator for SpecialFoldersIter<'a> {
    type Item = &'a SpecialFolderEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for SpecialFoldersIter<'_> {}

impl DoubleEndedIterator for SpecialFoldersIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(raw: u64) -> SpecialFolderState {
        SpecialFolderState::Found {
            id: FolderId::new(raw),
            entry_id: FolderEntryId::parse(&entry_id_bytes()).expect("a folder entry id"),
        }
    }

    fn entry_id_bytes() -> [u8; 46] {
        let mut bytes = [0_u8; 46];
        // FolderType = PrivateFolder, at offset 4 + 16.
        if let Some(slot) = bytes.get_mut(20) {
            *slot = 0x01;
        }
        bytes
    }

    fn folders() -> SpecialFolders {
        SpecialFolders::new(vec![
            SpecialFolderEntry::new(SpecialFolder::Calendar, found(0x11)),
            SpecialFolderEntry::new(SpecialFolder::Contacts, found(0x22)),
            SpecialFolderEntry::new(SpecialFolder::Journal, SpecialFolderState::Absent),
            SpecialFolderEntry::new(
                SpecialFolder::Notes,
                SpecialFolderState::Refused(ErrorCode::NOT_FOUND),
            ),
            SpecialFolderEntry::new(
                SpecialFolder::Tasks,
                SpecialFolderState::Unreadable {
                    reason: "a Folder `EntryID` is 46 bytes",
                },
            ),
        ])
    }

    #[test]
    fn a_folder_that_resolved_yields_its_id() {
        let folders = folders();
        assert_eq!(
            folders.get(SpecialFolder::Calendar),
            Some(FolderId::new(0x11))
        );
        assert_eq!(
            folders.get(SpecialFolder::Contacts),
            Some(FolderId::new(0x22))
        );
        assert_eq!(folders.found(), 2);
        assert!(!folders.found_none());
    }

    /// The four states exist so that "this mailbox has no Journal" is not confused with "the
    /// server refused" or "the property was unreadable". Every one of them answers `None` for an
    /// id and something different for the reason.
    #[test]
    fn each_way_of_not_having_a_folder_stays_distinguishable() {
        let folders = folders();
        for folder in [
            SpecialFolder::Journal,
            SpecialFolder::Notes,
            SpecialFolder::Tasks,
        ] {
            assert_eq!(folders.get(folder), None, "{folder}");
        }

        assert_eq!(
            folders.state(SpecialFolder::Journal),
            Some(&SpecialFolderState::Absent)
        );
        assert!(
            folders
                .state(SpecialFolder::Notes)
                .is_some_and(|state| matches!(state, SpecialFolderState::Refused(_)))
        );
        assert!(
            folders
                .state(SpecialFolder::Tasks)
                .is_some_and(|state| matches!(state, SpecialFolderState::Unreadable { .. }))
        );
        assert_eq!(folders.state(SpecialFolder::Drafts), None, "never asked");
    }

    #[test]
    fn every_state_prints_something_a_person_can_act_on() {
        let folders = folders();
        let lines: Vec<String> = folders.iter().map(ToString::to_string).collect();

        assert!(
            lines
                .first()
                .is_some_and(|line| line.starts_with("Calendar"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("not in this mailbox"))
        );
        assert!(lines.iter().any(|line| line.contains("would not convert")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("unreadable entry id"))
        );
    }

    #[test]
    fn the_iterator_is_exact_sized_and_double_ended() {
        let folders = folders();
        let mut iter = folders.iter();
        assert_eq!(iter.len(), 5);
        assert_eq!(
            iter.next().map(SpecialFolderEntry::folder),
            Some(SpecialFolder::Calendar)
        );
        assert_eq!(
            iter.next_back().map(SpecialFolderEntry::folder),
            Some(SpecialFolder::Tasks)
        );
        assert_eq!((&folders).into_iter().count(), 5);
    }

    #[test]
    fn a_mailbox_with_none_of_them_says_so() {
        let empty = SpecialFolders::new(vec![SpecialFolderEntry::new(
            SpecialFolder::Calendar,
            SpecialFolderState::Absent,
        )]);
        assert!(empty.found_none());
        assert_eq!(empty.found(), 0);
    }
}
