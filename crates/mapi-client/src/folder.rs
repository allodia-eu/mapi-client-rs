//! A folder that has been named, and the four questions that can be asked of it.
//!
//! Nothing here sends anything on its own. A [`Folder`] is a folder id and a borrow of the
//! [`Logon`](crate::Logon) it came from; the ROP that opens it travels in the same buffer as the
//! read that follows, so naming a folder costs nothing and reading one costs a single round trip.

use mapi_proto::{FolderDepth, FolderId, ObjectHandle};

use crate::connection::Connection;
use crate::properties::Properties;
use crate::table::{TableKind, TableRead};

/// A folder that has been named but not yet opened.
///
/// Borrows the [`Logon`](crate::Logon) rather than copying anything out of it, which is what stops
/// a folder being read on a session that has already been disconnected.
#[derive(Debug)]
pub struct Folder<'a> {
    pub(crate) connection: &'a mut Connection,
    pub(crate) logon: ObjectHandle,
    pub(crate) id: FolderId,
}

impl<'a> Folder<'a> {
    pub(crate) fn new(connection: &'a mut Connection, logon: ObjectHandle, id: FolderId) -> Self {
        Self {
            connection,
            logon,
            id,
        }
    }

    /// This folder's id.
    #[must_use]
    pub const fn id(&self) -> FolderId {
        self.id
    }

    /// The messages in this folder — its contents table.
    ///
    /// [MS-OXCROPS] §2.2.4.14 — `RopGetContentsTable`
    #[must_use]
    pub fn contents(self) -> TableRead<'a> {
        TableRead::new(self, TableKind::Contents)
    }

    /// The folders directly inside this one — its hierarchy table.
    ///
    /// Immediate children only. For everything below, at every level, see
    /// [`descendants`](Self::descendants).
    ///
    /// [MS-OXCROPS] §2.2.4.13 — `RopGetHierarchyTable`
    #[must_use]
    pub fn subfolders(self) -> TableRead<'a> {
        TableRead::new(self, TableKind::Hierarchy(FolderDepth::Immediate))
    }

    /// Every folder below this one, at every level, in one table.
    ///
    /// The `Depth` flag on `RopGetHierarchyTable`. One round trip per page instead of one per
    /// folder, which is what makes a whole-mailbox listing cheap — but the rows arrive **flat**,
    /// with nothing in them saying where each folder sits, so
    /// [`PidTagParentFolderId`](mapi_proto::PropertyTag::PARENT_FOLDER_ID) has to be among the
    /// columns for a tree to be rebuilt. [`HIERARCHY_COLUMNS`](crate::HIERARCHY_COLUMNS) includes
    /// it; a caller passing its own columns has to.
    ///
    /// ```no_run
    /// # use mapi_client::{Logon, PropertyTag, WellKnownFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let all = logon
    ///     .well_known(WellKnownFolder::IpmSubtree)?
    ///     .descendants()
    ///     .collect()
    ///     .await?;
    /// for row in &all {
    ///     println!(
    ///         "{:?} in {:?}",
    ///         row.string(PropertyTag::DISPLAY_NAME),
    ///         row.get(PropertyTag::PARENT_FOLDER_ID)
    ///     );
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [MS-OXCFOLD] §2.2.1.13.1 — `TableFlags`, `Depth`
    #[must_use]
    pub fn descendants(self) -> TableRead<'a> {
        TableRead::new(self, TableKind::Hierarchy(FolderDepth::Recursive))
    }

    /// This folder's own properties — what it is, what it holds, and where it sits.
    ///
    /// One round trip: the folder is opened, read and released in a single `Execute`. Reading
    /// [`FOLDER_PROPERTIES`](crate::FOLDER_PROPERTIES) is *"get calendar details"* — a calendar is
    /// a folder, so the two are the same question.
    ///
    /// ```no_run
    /// # use mapi_client::{FOLDER_PROPERTIES, Logon, SpecialFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let calendar = logon.special_folder(SpecialFolder::Calendar).await?;
    /// let details = logon
    ///     .folder(calendar)
    ///     .properties()
    ///     .read(FOLDER_PROPERTIES)
    ///     .await?;
    /// for cell in &details {
    ///     println!("{cell}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [MS-OXCFOLD] §2.2.2.2 — Folder object properties
    #[must_use]
    pub fn properties(self) -> Properties<'a> {
        Properties::for_folder(self.connection, self.logon, self.id)
    }
}
