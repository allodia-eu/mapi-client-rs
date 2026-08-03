//! Reading a table, one page per round trip.
//!
//! A table read is two requests' worth of work in the general case and one in the common one:
//! opening the folder, opening its table, setting the columns and reading the first page all chain
//! through a single `Execute`, because ROPs in one buffer consume the handles earlier ROPs in the
//! same buffer produced. Later pages are one round trip each.
//!
//! **Later pages do not re-send the column set.** The session remembers which columns belong to
//! which table handle, so a page request is a `RopQueryRows` and nothing else. Verified against
//! Exchange Server SE `15.02.2562.045`: eight consecutive pages of a hierarchy table decoded
//! correctly with `RopSetColumns` sent only in the first batch.
//!
//! [MS-OXCROPS] §2.2.5.1 — `RopSetColumns`
//! [MS-OXCROPS] §2.2.5.4 — `RopQueryRows`
//! [MS-OXCTABL] §2.2.2 — table semantics

use core::borrow::Borrow;
use std::vec;

use mapi_proto::{
    ATTACHMENT_COLUMNS, Bookmark, CONTENTS_COLUMNS, Execution, FolderDepth, HIERARCHY_COLUMNS,
    ObjectHandle, PropertyRow, PropertyTag, Restriction, RopBatch, RopResponse, SortOrderSet,
    TableStatus,
};

use crate::connection::Connection;
use crate::error::Result;
use crate::target::{Opened, Target};

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
    fn open_on(
        self,
        batch: &mut RopBatch,
        object: mapi_proto::HandleSlot,
    ) -> mapi_proto::HandleSlot {
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

        Rows {
            connection: self.connection,
            start: Some(Start {
                object: self.object,
                kind: self.kind,
                columns,
                sort: self.sort,
                filter: self.filter,
            }),
            table: None,
            page: Vec::new().into_iter(),
            page_size: self.page_size,
            row_count: None,
            table_status: None,
            finished: false,
        }
    }

    /// Reads every row, then releases the table.
    ///
    /// # Errors
    ///
    /// Whatever [`Rows::try_next`] and [`Rows::close`] report.
    pub async fn collect(self) -> Result<Vec<PropertyRow>> {
        self.rows().collect().await
    }
}

/// What the first round trip needs, before there is a table handle to page with.
#[derive(Debug)]
struct Start {
    object: Target,
    kind: TableKind,
    columns: Vec<PropertyTag>,
    sort: Option<SortOrderSet>,
    filter: Option<Restriction>,
}

/// Rows arriving a page at a time.
///
/// ```no_run
/// # use mapi_client::{Logon, PropertyTag, WellKnownFolder};
/// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
/// let mut rows = logon.well_known(WellKnownFolder::Inbox)?.contents().rows();
/// while let Some(row) = rows.try_next().await? {
///     println!("{:?}", row.string(PropertyTag::SUBJECT));
/// }
/// rows.close().await?;
/// # Ok(())
/// # }
/// ```
///
/// This is not a [`Stream`]: producing one would mean holding a boxed future for the request in
/// flight, and `try_next` says the same thing without the allocation or the pinning.
///
/// [`Stream`]: https://docs.rs/futures-core/latest/futures_core/stream/trait.Stream.html
#[derive(Debug)]
pub struct Rows<'a> {
    connection: &'a mut Connection,
    /// The unopened table, taken by the first fetch.
    start: Option<Start>,
    /// The table handle, once the server has given one.
    table: Option<ObjectHandle>,
    page: vec::IntoIter<PropertyRow>,
    page_size: u16,
    row_count: Option<u32>,
    table_status: Option<TableStatus>,
    finished: bool,
}

impl Rows<'_> {
    /// The next row, fetching a page when the current one runs out.
    ///
    /// # Errors
    ///
    /// Whatever the round trip failed with, including [`Error::Rop`](crate::Error::Rop) if the
    /// server refused to open the folder or the table.
    pub async fn try_next(&mut self) -> Result<Option<PropertyRow>> {
        loop {
            if let Some(row) = self.page.next() {
                return Ok(Some(row));
            }
            if self.finished {
                return Ok(None);
            }
            self.fetch().await?;
        }
    }

    /// How many rows the table holds, known once the first page has arrived.
    ///
    /// This is the count the server reported when the table was opened. A table is a live view of
    /// a folder, so it is a measurement rather than a promise about how many rows will arrive.
    ///
    /// Three things leave it `None` or stale, all of them documented rather than incidental: an
    /// attachment table is not given one at all ([MS-OXCROPS] §2.2.6.17.2 has no such field), a
    /// [`filter`](TableRead::filter) narrows the table without replacing the count, and the folder
    /// can change under the read.
    ///
    /// [MS-OXCROPS] §2.2.4.13.2 — `RowCount`
    #[must_use]
    pub const fn row_count(&self) -> Option<u32> {
        self.row_count
    }

    /// What the server said about the table after a sort or a filter was applied.
    ///
    /// `None` when neither was asked for. Anything other than
    /// [`TableStatus::COMPLETE`](mapi_proto::TableStatus::COMPLETE) means the server took the work
    /// asynchronously and the rows being read are the old ones — this crate asks for the
    /// synchronous form, so it is a deviation worth seeing rather than a state to wait on.
    ///
    /// [MS-OXCTABL] §2.2.2.1.3 — `TableStatus`
    #[must_use]
    pub const fn table_status(&self) -> Option<TableStatus> {
        self.table_status
    }

    /// Reads whatever is left, then releases the table.
    ///
    /// # Errors
    ///
    /// Whatever [`Rows::try_next`] and [`Rows::close`] report.
    pub async fn collect(mut self) -> Result<Vec<PropertyRow>> {
        let mut all = Vec::new();
        while let Some(row) = self.try_next().await? {
            all.push(row);
        }
        self.close().await?;
        Ok(all)
    }

    /// Releases the table handle the server is holding.
    ///
    /// Dropping a `Rows` instead is not an error: the handle then lives until the Session Context
    /// ends. Closing matters for a long-lived session that reads many tables, where the handles
    /// would otherwise accumulate for the life of the session.
    ///
    /// # Errors
    ///
    /// Whatever the round trip failed with.
    ///
    /// [MS-OXCROPS] §2.2.15.3 — `RopRelease`
    pub async fn close(mut self) -> Result<()> {
        let Some(table) = self.table.take() else {
            return Ok(());
        };
        let mut batch = RopBatch::new();
        let slot = batch.bind(table);
        batch.release(slot);
        self.connection
            .execute(batch, "releasing the table")
            .await?;
        Ok(())
    }

    /// Fetches one page, opening the table first if this is the first one.
    ///
    /// A failed open is put back rather than swallowed. Without that, the next `try_next` would
    /// find nothing left to do and report the end of the table — turning a server that refused to
    /// open the folder into an empty inbox, which is the worst kind of wrong answer because it
    /// looks exactly like a right one.
    async fn fetch(&mut self) -> Result<()> {
        if let Some(start) = self.start.take() {
            let result = self.open(&start).await;
            if result.is_err() {
                self.start = Some(start);
            }
            return result;
        }

        let Some(table) = self.table else {
            self.finished = true;
            return Ok(());
        };

        let mut batch = RopBatch::new();
        let slot = batch.bind(table);
        batch.query_rows(slot, self.page_size);
        let execution = self
            .connection
            .execute(batch, "reading a page of rows")
            .await?;
        self.absorb(&execution);
        Ok(())
    }

    /// The first round trip: open the object, open its table, set the columns, sort, filter, read
    /// a page.
    ///
    /// The object's own handles are released in the same batch. A table is a Server object in its
    /// own right and outlives the folder or message handle it was obtained from — verified against
    /// Exchange Server SE `15.02.2562.045`, where paging continued normally after the release — so
    /// keeping them open would tie up server objects for nothing.
    ///
    /// **Order matters here and is not arbitrary.** `RopSetColumns` comes first because
    /// [MS-OXCTABL] §2.2.2.3 requires the sort key to be among the columns already set, and the
    /// restriction comes before the read because a filter applied after one would return the rows
    /// nobody asked for.
    ///
    /// [MS-OXCROPS] §3.1.4.1 — one ROP consumes the handle an earlier ROP produced
    async fn open(&mut self, start: &Start) -> Result<()> {
        let mut batch = RopBatch::new();
        let opened: Opened = start.object.open(&mut batch);
        let table = start.kind.open_on(&mut batch, opened.slot);
        batch.set_columns(table, &start.columns);
        if let Some(orders) = &start.sort {
            batch.sort_table(table, orders);
        }
        if let Some(filter) = &start.filter {
            batch.restrict(table, filter);
        }
        batch.query_rows(table, self.page_size);
        opened.release(&mut batch);

        let execution = self.connection.execute(batch, "opening the table").await?;
        self.table = execution.handle(table).filter(|handle| !handle.is_none());
        self.table_status = execution
            .responses()
            .iter()
            .find_map(RopResponse::as_table_status)
            .map(mapi_proto::TableStatusResponse::status);
        self.absorb(&execution);
        Ok(())
    }

    /// Takes the rows and the row count out of an executed batch.
    ///
    /// A page whose bookmark is `End` is the last one, and it still carries rows: measured against
    /// Exchange Server SE `15.02.2562.045`, the final page of a fifteen-row table arrived as one
    /// row *with* `End`, and only a further read returned zero rows. An empty page ends the read
    /// too, which is belt and braces against a server that never says `End` at all.
    ///
    /// [MS-OXCTABL] §2.2.2.1.1 — `BOOKMARK_END`
    fn absorb(&mut self, execution: &Execution) {
        for response in execution.responses() {
            if let RopResponse::GetTable(table) = response {
                self.row_count = Some(table.row_count());
            }
        }

        let Some(rows) = execution.rows() else {
            self.finished = true;
            return;
        };

        self.finished = rows.bookmark() == Bookmark::End || rows.rows().is_empty();
        self.page = rows.rows().to_vec().into_iter();
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
