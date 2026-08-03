//! The table ROPs a batch can issue: opening one, choosing its columns, ordering it, filtering it
//! and reading rows out of it.
//!
//! [MS-OXCROPS] §2.2.4.13 — `RopGetHierarchyTable`
//! [MS-OXCROPS] §2.2.4.14 — `RopGetContentsTable`
//! [MS-OXCROPS] §2.2.5 — `RopSetColumns`, `RopSortTable`, `RopRestrict`, `RopQueryRows`

use crate::oxcdata::{PropertyTag, Restriction, SortOrderSet};
use crate::rop::RopId;
use crate::rop::batch::{HandleSlot, ObjectHandle, RopBatch};
use crate::rop::table::{
    FolderDepth, TABLE_FLAGS_NONE, encode_get_table, encode_query_rows, encode_restrict,
    encode_set_columns, encode_sort_table,
};

impl RopBatch {
    /// Opens the folder's contents table — its messages.
    ///
    /// [MS-OXCROPS] §2.2.4.14 — `RopGetContentsTable`
    pub fn contents_table(&mut self, folder: HandleSlot) -> HandleSlot {
        self.get_table(RopId::GET_CONTENTS_TABLE, folder, TABLE_FLAGS_NONE)
    }

    /// Opens the folder's hierarchy table — its subfolders.
    ///
    /// The depth is a parameter rather than a default because the two answers are different
    /// questions: [`FolderDepth::Recursive`] lists every folder below this one in one round trip,
    /// and its rows say nothing about where each folder sits unless
    /// [`PidTagParentFolderId`](crate::PropertyTag::PARENT_FOLDER_ID) is among the columns.
    ///
    /// [MS-OXCROPS] §2.2.4.13 — `RopGetHierarchyTable`
    /// [MS-OXCFOLD] §2.2.1.13.1 — `TableFlags`, `Depth`
    pub fn hierarchy_table(&mut self, folder: HandleSlot, depth: FolderDepth) -> HandleSlot {
        self.get_table(RopId::GET_HIERARCHY_TABLE, folder, depth.flags())
    }

    /// Orders a table's rows, so that "the ten newest" is ten rows rather than all of them.
    ///
    /// **Every column sorted on must already have been given to the table.** [MS-OXCTABL] §2.2.2.3
    /// requires it and a server refuses the sort otherwise, without saying which column was the
    /// problem — so this checks against the column set recorded for that handle by
    /// [`set_columns`](Self::set_columns) and fails the batch by name when it does not cover the
    /// key. A table whose columns were set in an earlier round trip is not covered by that check
    /// and is left to the server.
    ///
    /// Sent synchronously: the asynchronous form answers at once and leaves the rows in their old
    /// order for a while, with nothing in a later read saying so.
    ///
    /// [MS-OXCROPS] §2.2.5.2 — `RopSortTable`
    pub fn sort_table(&mut self, table: HandleSlot, orders: &SortOrderSet) -> &mut Self {
        if self.check(table) {
            let columns = self
                .columns
                .get(usize::from(table.index()))
                .and_then(Option::as_deref)
                .map(<[PropertyTag]>::to_vec);
            // `None` means the columns were set in an earlier round trip, which this batch cannot
            // see. Sending the sort and letting the server judge beats refusing a request that is
            // very likely correct.
            self.try_push(|w| encode_sort_table(w, table.index(), orders, columns.as_deref()));
        }
        self
    }

    /// Filters a table, so that the server discards the rows nobody asked for.
    ///
    /// **The row count from opening the table is stale afterwards** and the response does not
    /// replace it: [MS-OXCROPS] §2.2.5.3.2 carries a `TableStatus` and nothing else. How many rows
    /// survived is only answerable by reading them.
    ///
    /// [MS-OXCROPS] §2.2.5.3 — `RopRestrict`
    pub fn restrict(&mut self, table: HandleSlot, restriction: &Restriction) -> &mut Self {
        if self.check(table) {
            self.try_push(|w| encode_restrict(w, table.index(), restriction));
        }
        self
    }

    /// Sets the column set every row read from this table is encoded against.
    ///
    /// The columns are remembered for the table's handle, so rows arriving now or in a later round
    /// trip decode without the caller passing them again.
    ///
    /// [MS-OXCROPS] §2.2.5.1 — `RopSetColumns`
    pub fn set_columns(&mut self, table: HandleSlot, columns: &[PropertyTag]) -> &mut Self {
        if self.check(table) {
            self.push(|w| encode_set_columns(w, table.index(), columns));
            if let Some(slot) = self.columns.get_mut(usize::from(table.index())) {
                *slot = Some(columns.to_vec());
            }
        }
        self
    }

    /// Reads up to `count` rows forward from the table's current position.
    ///
    /// [MS-OXCROPS] §2.2.5.4 — `RopQueryRows`
    pub fn query_rows(&mut self, table: HandleSlot, count: u16) -> &mut Self {
        if self.check(table) {
            self.push(|w| encode_query_rows(w, table.index(), count));
        }
        self
    }

    fn get_table(&mut self, rop: RopId, folder: HandleSlot, flags: u8) -> HandleSlot {
        let known = self.check(folder);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.push(|w| encode_get_table(w, rop, folder.index(), output.index(), flags));
        }
        output
    }
}
