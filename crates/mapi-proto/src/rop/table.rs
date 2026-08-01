//! The table ROPs: opening one, choosing its columns, and reading rows out of it.
//!
//! [MS-OXCROPS] §2.2.4.13 — `RopGetHierarchyTable`
//! [MS-OXCROPS] §2.2.4.14 — `RopGetContentsTable`
//! [MS-OXCROPS] §2.2.5.1 — `RopSetColumns`
//! [MS-OXCROPS] §2.2.5.4 — `RopQueryRows`
//! [MS-OXCTABL] §2.2.2 — table semantics

use crate::error::Result;
use crate::oxcdata::{PropertyRow, PropertyTag, RowForm};
use crate::rop::RopId;
use crate::rop::batch::LOGON_ID;
use crate::wire::{Reader, Writer};

/// `TableFlags`: no `Depth`, no `Associated`, no `DeferredErrors` — the immediate children, and
/// answer only once the table really exists.
///
/// [MS-OXCFOLD] §2.2.1.13.1 — hierarchy table flags
/// [MS-OXCFOLD] §2.2.1.14.1 — contents table flags
const TABLE_FLAGS_NONE: u8 = 0x00;

/// `SetColumnsFlags`: block until the column set has been applied rather than answering
/// asynchronously, so the rows in the same batch are encoded against these columns.
///
/// [MS-OXCTABL] §2.2.2.2 — `RopSetColumns`
const SET_COLUMNS_SYNCHRONOUS: u8 = 0x00;

/// `QueryRowsFlags`: `Advance` — move the cursor past the rows returned.
///
/// [MS-OXCTABL] §2.2.2.5.1 — `QueryRowsFlags`
const QUERY_ROWS_ADVANCE: u8 = 0x00;

/// `ForwardRead`: read from the current position towards the end of the table.
///
/// [MS-OXCROPS] §2.2.5.4.1 — `ForwardRead`
const FORWARD_READ: u8 = 0x01;

/// Where the table cursor sits after a read.
///
/// [MS-OXCTABL] §2.2.2.1.1 — predefined bookmarks
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Bookmark {
    /// `BOOKMARK_BEGINNING`, `0x00`: the first row.
    Beginning,
    /// `BOOKMARK_CURRENT`, `0x01`: the current row.
    Current,
    /// `BOOKMARK_END`, `0x02`: past the last row — there is nothing more to read.
    End,
    /// A value outside the predefined set.
    Other(u8),
}

impl Bookmark {
    /// Reads a bookmark value as the wire carries it.
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        match raw {
            0x00 => Self::Beginning,
            0x01 => Self::Current,
            0x02 => Self::End,
            other => Self::Other(other),
        }
    }

    /// The value as the wire carries it.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Beginning => 0x00,
            Self::Current => 0x01,
            Self::End => 0x02,
            Self::Other(raw) => raw,
        }
    }
}

/// The status of asynchronous work on a table.
///
/// [MS-OXCTABL] §2.2.2.1.3 — `TableStatus`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TableStatus(u8);

impl TableStatus {
    /// `TBLSTAT_COMPLETE`, `0x00`: nothing is in progress.
    pub const COMPLETE: Self = Self(0x00);
    /// `TBLSTAT_RESTRICTING`, `0x0E`.
    pub const RESTRICTING: Self = Self(0x0E);
    /// `TBLSTAT_RESTRICT_ERROR`, `0x0F`.
    pub const RESTRICT_ERROR: Self = Self(0x0F);
    /// `TBLSTAT_SETTING_COLS`, `0x0B`.
    pub const SETTING_COLUMNS: Self = Self(0x0B);
    /// `TBLSTAT_SETCOL_ERROR`, `0x0D`.
    pub const SET_COLUMNS_ERROR: Self = Self(0x0D);
    /// `TBLSTAT_SORTING`, `0x09`.
    pub const SORTING: Self = Self(0x09);
    /// `TBLSTAT_SORT_ERROR`, `0x0A`.
    pub const SORT_ERROR: Self = Self(0x0A);

    /// Wraps a raw status.
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// The status as the wire carries it.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Whether the table is idle.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.0 == Self::COMPLETE.0
    }
}

/// What opening a table reports: how many rows it holds.
///
/// [MS-OXCROPS] §2.2.4.13.2 — `RowCount`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetTableResponse {
    row_count: u32,
}

impl GetTableResponse {
    /// The number of rows in the table.
    #[must_use]
    pub const fn row_count(self) -> u32 {
        self.row_count
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            row_count: r.u32()?,
        })
    }
}

/// What `RopSetColumns` reports.
///
/// [MS-OXCROPS] §2.2.5.1.2 — success response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetColumnsResponse {
    status: TableStatus,
}

impl SetColumnsResponse {
    /// The table's status once the columns were applied.
    #[must_use]
    pub const fn status(self) -> TableStatus {
        self.status
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            status: TableStatus::new(r.u8()?),
        })
    }
}

/// Rows read from a table, decoded against the column set that was set on it.
///
/// [MS-OXCROPS] §2.2.5.4.2 — success response buffer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryRowsResponse {
    bookmark: Bookmark,
    rows: Vec<PropertyRow>,
}

impl QueryRowsResponse {
    /// Where the cursor ended up. [`Bookmark::End`] means there is nothing left to read.
    #[must_use]
    pub const fn bookmark(&self) -> Bookmark {
        self.bookmark
    }

    /// The rows, in table order.
    #[must_use]
    pub fn rows(&self) -> &[PropertyRow] {
        &self.rows
    }

    /// How many rows arrived in each encoding: standard first, flagged second.
    ///
    /// The form is the server's choice per row, so this is a measurement of a deployment rather
    /// than of the request.
    #[must_use]
    pub fn form_counts(&self) -> (usize, usize) {
        let flagged = self
            .rows
            .iter()
            .filter(|row| row.form() == RowForm::Flagged)
            .count();
        (self.rows.len().saturating_sub(flagged), flagged)
    }

    /// Reads the response body, after `RopId`, `InputHandleIndex` and a zero `ReturnValue`.
    pub(crate) fn read(r: &mut Reader<'_>, columns: &[PropertyTag]) -> Result<Self> {
        let bookmark = Bookmark::new(r.u8()?);
        let row_count = r.u16()?;
        let mut rows = Vec::new();
        for _ in 0..row_count {
            rows.push(PropertyRow::read(r, columns)?);
        }
        Ok(Self { bookmark, rows })
    }
}

/// Encodes `RopGetHierarchyTable` or `RopGetContentsTable`, which share a layout.
///
/// [MS-OXCROPS] §2.2.4.13.1 — request buffer
pub(crate) fn encode_get_table(w: &mut Writer, rop: RopId, input: u8, output: u8) {
    w.u8(rop.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(output)
        .u8(TABLE_FLAGS_NONE);
}

/// Encodes a `RopSetColumns` request.
///
/// [MS-OXCROPS] §2.2.5.1.1 — request buffer
pub(crate) fn encode_set_columns(w: &mut Writer, input: u8, columns: &[PropertyTag]) {
    w.u8(RopId::SET_COLUMNS.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(SET_COLUMNS_SYNCHRONOUS)
        .u16(u16::try_from(columns.len()).unwrap_or(u16::MAX));
    for tag in columns {
        w.u32(tag.as_u32());
    }
}

/// Encodes a `RopQueryRows` request.
///
/// [MS-OXCROPS] §2.2.5.4.1 — request buffer
pub(crate) fn encode_query_rows(w: &mut Writer, input: u8, count: u16) {
    w.u8(RopId::QUERY_ROWS.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(QUERY_ROWS_ADVANCE)
        .u8(FORWARD_READ)
        .u16(count);
}

#[cfg(test)]
mod tests;
