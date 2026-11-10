//! Reading a table, one page per round trip.
//!
//! A table read is two requests' worth of work in the general case and one in the common one:
//! opening the folder, opening its table, setting the columns and reading the first page all chain
//! through a single `Execute`, because ROPs in one buffer consume the handles earlier ROPs in the
//! same buffer produced. Later pages are one round trip each.
//!
//! **Later pages do not re-send the column set.** The session remembers which columns belong to
//! which table handle, so a page request is a `RopQueryRows` and nothing else. Verified against
//! Exchange Server SE `15.02.2562.056`: eight consecutive pages of a hierarchy table decoded
//! correctly with `RopSetColumns` sent only in the first batch.
//!
//! [MS-OXCROPS] §2.2.5.1 — `RopSetColumns`
//! [MS-OXCROPS] §2.2.5.4 — `RopQueryRows`
//! [MS-OXCTABL] §2.2.2 — table semantics

use core::borrow::Borrow;

use mapi_proto::{
    ATTACHMENT_COLUMNS, CONTENTS_COLUMNS, FolderDepth, HIERARCHY_COLUMNS, HandleSlot, PropertyRow,
    PropertyTag, Restriction, RopBatch, SortOrderSet,
};

use crate::connection::Connection;
use crate::error::Result;
use crate::target::Target;

/// Rows arriving a page at a time, and the table handle they are read through.
mod rows;

pub use rows::Rows;
use rows::Start;

/// Rows per round trip, unless the caller says otherwise.
///
/// The ceiling this has to stay under is the 64 KiB output buffer the codec asks for. A table
/// bounds every string value at 255 characters — the server truncates rather than refusing — so a
/// row of four columns cannot exceed roughly 540 bytes, and 50 of them cannot come close to
/// filling the buffer. A caller asking for many wide columns can still overrun it, which is
/// reported as [`Error::ResponseTooLarge`](crate::Error::ResponseTooLarge) rather than
/// guessed at.
const DEFAULT_PAGE_SIZE: u16 = 50;

/// Which table an object offers.
///
/// Two of the three hang off a folder and one off a message, which is why the object a table comes
/// from is a [`Target`] rather than a folder id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TableKind {
    /// The messages in a folder.
    Contents,
    /// The folders inside a folder, to the given depth.
    Hierarchy(FolderDepth),
    /// The attachments on a message.
    ///
    /// **The server reports no row count for this one**, unlike the other two: [MS-OXCROPS]
    /// §2.2.6.17.2 has no such field at all.
    Attachments,
}

impl TableKind {
    /// The columns to read when the caller has not chosen any.
    const fn default_columns(self) -> &'static [PropertyTag] {
        match self {
            Self::Contents => &CONTENTS_COLUMNS,
            Self::Hierarchy(_) => &HIERARCHY_COLUMNS,
            Self::Attachments => &ATTACHMENT_COLUMNS,
        }
    }

    /// Opens the table on an object already placed in the batch.
    fn open_on(self, batch: &mut RopBatch, object: HandleSlot) -> HandleSlot {
        match self {
            Self::Contents => batch.contents_table(object),
            Self::Hierarchy(depth) => batch.hierarchy_table(object, depth),
            Self::Attachments => batch.attachment_table(object),
        }
    }
}

/// A table read that has not started yet.
///
/// Nothing is sent until [`rows`](Self::rows) or [`collect`](Self::collect) is called, so the
/// column set and the page size are still open to change.
#[derive(Debug)]
pub struct TableRead<'a> {
    connection: &'a mut Connection,
    object: Target,
    kind: TableKind,
    columns: Option<Vec<PropertyTag>>,
    sort: Option<SortOrderSet>,
    filter: Option<Restriction>,
    page_size: u16,
}

impl<'a> TableRead<'a> {
    pub(crate) const fn new(
        connection: &'a mut Connection,
        object: Target,
        kind: TableKind,
    ) -> Self {
        Self {
            connection,
            object,
            kind,
            columns: None,
            sort: None,
            filter: None,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }

    /// Orders the rows on the server, so that "the ten newest" is ten rows and not all of them.
    ///
    /// **Every column sorted on must be among the columns read.** [MS-OXCTABL] §2.2.2.3 requires
    /// it; a sort key naming a column the table was not given is refused by the server, and the
    /// refusal does not say which column. This crate catches that before the round trip and names
    /// it — see [`Error::Protocol`](crate::Error::Protocol) carrying `SortColumnNotSet`.
    ///
    /// ```no_run
    /// # use mapi_client::{Logon, PropertyTag, SortOrder, SortOrderSet, WellKnownFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let newest = logon
    ///     .well_known(WellKnownFolder::Inbox)?
    ///     .contents()
    ///     .sort(SortOrderSet::new([SortOrder::descending(
    ///         PropertyTag::MESSAGE_DELIVERY_TIME,
    ///     )]))
    ///     .page_size(10)
    ///     .rows();
    /// # let _ = newest;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [MS-OXCROPS] §2.2.5.2 — `RopSortTable`
    #[must_use]
    pub fn sort(mut self, orders: SortOrderSet) -> Self {
        self.sort = Some(orders);
        self
    }

    /// Filters the rows on the server, so it discards what nobody asked for.
    ///
    /// **The row count reported when the table opens is the unfiltered one.** [MS-OXCROPS]
    /// §2.2.5.3.2 carries only a status, so [`Rows::row_count`] keeps saying how many rows the
    /// folder holds while the read produces however many survive the filter. The two disagreeing
    /// is the expected outcome here rather than a sign of anything.
    ///
    /// [MS-OXCROPS] §2.2.5.3 — `RopRestrict`
    #[must_use]
    pub fn filter(mut self, restriction: Restriction) -> Self {
        self.filter = Some(restriction);
        self
    }

    /// The columns to read.
    ///
    /// Defaults to [`CONTENTS_COLUMNS`] or [`HIERARCHY_COLUMNS`], whichever suits the table.
    /// Takes anything that yields tags, so an array literal and a borrowed constant both work:
    ///
    /// ```no_run
    /// # use mapi_client::{HIERARCHY_COLUMNS, Logon, PropertyTag, WellKnownFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let inbox = logon.well_known(WellKnownFolder::Inbox)?;
    /// let rows = inbox
    ///     .contents()
    ///     .columns([PropertyTag::SUBJECT, PropertyTag::MESSAGE_DELIVERY_TIME])
    ///     .collect()
    ///     .await?;
    /// # let _ = (rows, HIERARCHY_COLUMNS);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// A row carries values and nothing else — no tags, no types, no lengths — so these tags are
    /// also what the response is decoded against. Asking for a column whose type this crate does
    /// not model stops the decode rather than guessing at the value's length.
    ///
    /// [MS-OXCDATA] §2.8 — `PropertyRow`
    #[must_use]
    pub fn columns<I>(mut self, columns: I) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<PropertyTag>,
    {
        self.columns = Some(
            columns
                .into_iter()
                .map(|tag| *tag.borrow())
                .collect::<Vec<_>>(),
        );
        self
    }

    /// How many rows to ask for per round trip. Defaults to 50; clamped to at least 1.
    ///
    /// Larger pages mean fewer round trips and a bigger response. The response has to fit in a
    /// 64 KiB buffer, so a page of many wide columns can overrun it — see
    /// [`Error::ResponseTooLarge`](crate::Error::ResponseTooLarge).
    #[must_use]
    pub const fn page_size(mut self, rows: u16) -> Self {
        self.page_size = if rows == 0 { 1 } else { rows };
        self
    }

    /// Starts reading, a page at a time.
    #[must_use]
    pub fn rows(self) -> Rows<'a> {
        let columns = self
            .columns
            .unwrap_or_else(|| self.kind.default_columns().to_vec());
        Rows::new(
            self.connection,
            Start {
                object: self.object,
                kind: self.kind,
                columns,
                sort: self.sort,
                filter: self.filter,
            },
            self.page_size,
        )
    }

    /// Reads every row, then releases the table.
    ///
    /// # Cancellation
    ///
    /// Safe to drop at any await. A future dropped while its request is in flight leaves the
    /// connection [poisoned](crate::Connection#cancellation), never wedged, and
    /// [`reconnect`](crate::Connection::reconnect) makes it usable again. Nothing was changed, so
    /// the call can simply be made again.
    ///
    /// # Errors
    ///
    /// Whatever [`Rows::try_next`] and [`Rows::close`] report.
    pub async fn collect(self) -> Result<Vec<PropertyRow>> {
        self.rows().collect().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_table_has_a_sensible_default_column_set() {
        assert_eq!(TableKind::Contents.default_columns(), &CONTENTS_COLUMNS);
        for depth in [FolderDepth::Immediate, FolderDepth::Recursive] {
            assert_eq!(
                TableKind::Hierarchy(depth).default_columns(),
                &HIERARCHY_COLUMNS
            );
        }
    }

    /// A recursive hierarchy read has to carry the parent id, or its rows are a flat bag with no
    /// way back to a tree — which is the one thing the `Depth` flag makes it easy to get wrong.
    #[test]
    fn the_default_hierarchy_columns_can_rebuild_a_tree() {
        assert!(HIERARCHY_COLUMNS.contains(&PropertyTag::FOLDER_ID));
        assert!(HIERARCHY_COLUMNS.contains(&PropertyTag::PARENT_FOLDER_ID));
        assert!(HIERARCHY_COLUMNS.contains(&PropertyTag::CONTAINER_CLASS));
    }
}
