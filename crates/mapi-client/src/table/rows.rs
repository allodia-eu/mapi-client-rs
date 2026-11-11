//! Rows arriving a page at a time, and the table handle they are read through.

use std::vec;

use mapi_proto::{
    Bookmark, Execution, HandleSlot, PropertyRow, PropertyTag, Restriction, RopBatch, RopResponse,
    SortOrderSet, TableStatus,
};

use super::TableKind;
use crate::connection::{Connection, Lease};
use crate::error::Result;
use crate::target::{Opened, Target};

/// What the first round trip needs, before there is a table handle to page with.
#[derive(Debug)]
pub(super) struct Start {
    pub(super) object: Target,
    pub(super) kind: TableKind,
    pub(super) columns: Vec<PropertyTag>,
    pub(super) sort: Option<SortOrderSet>,
    pub(super) filter: Option<Restriction>,
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
    /// The table handle, once the server has given one — given back to the connection if this is
    /// dropped still holding it.
    table: Lease,
    page: vec::IntoIter<PropertyRow>,
    page_size: u16,
    row_count: Option<u32>,
    table_status: Option<TableStatus>,
    finished: bool,
}

impl<'a> Rows<'a> {
    pub(super) fn new(connection: &'a mut Connection, start: Start, page_size: u16) -> Self {
        let table = connection.lease();
        Self {
            connection,
            start: Some(start),
            table,
            page: Vec::new().into_iter(),
            page_size,
            row_count: None,
            table_status: None,
            finished: false,
        }
    }

    /// The next row, fetching a page when the current one runs out.
    ///
    /// # Cancellation
    ///
    /// Safe to drop at any await. A future dropped while its request is in flight leaves the
    /// connection [poisoned](crate::Connection#cancellation), never wedged, and
    /// [`reconnect`](crate::Connection::reconnect) makes it usable again. Nothing was changed, so
    /// the call can simply be made again.
    ///
    /// Whatever was dropped is then done with. Drop it, and the server handle it holds is released
    /// by the connection's next request.
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
    /// [`filter`](super::TableRead::filter) narrows the table without replacing the count, and the
    /// folder can change under the read.
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
    pub async fn collect(mut self) -> Result<Vec<PropertyRow>> {
        let mut all = Vec::new();
        while let Some(row) = self.try_next().await? {
            all.push(row);
        }
        self.close().await?;
        Ok(all)
    }

    /// Releases the table handle the server is holding, now.
    ///
    /// Dropping a `Rows` instead is not an error either: the release is queued, and travels with
    /// the next request this connection sends, at no extra round trip. It matters that one of the
    /// two happens. A Session Context may hold 500 objects — measured against Exchange Server SE
    /// `15.02.2562.056`, which refused the next with `ecMaxObjsExceeded` — so a long-lived session
    /// that left every table it read open would stop being able to open anything.
    ///
    /// # Cancellation
    ///
    /// Safe to drop at any await. A future dropped while its request is in flight leaves the
    /// connection [poisoned](crate::Connection#cancellation), never wedged, and
    /// [`reconnect`](crate::Connection::reconnect) makes it usable again. Nothing was changed, so
    /// the call can simply be made again.
    ///
    /// Dropping the object instead of closing it is no leak either: its release is queued, and
    /// travels with the connection's next request.
    ///
    /// # Errors
    ///
    /// Whatever the round trip failed with.
    ///
    /// [MS-OXCROPS] §2.2.15.3 — `RopRelease`
    pub async fn close(mut self) -> Result<()> {
        // Held until the release is settled, so that a close that never reached the server — or was
        // dropped before it did — still leaves the table to be released by the next request.
        self.connection
            .release_now(&mut [&mut self.table], "releasing the table")
            .await
    }

    /// Fetches one page, opening the table first if this is the first one.
    ///
    /// The open is forgotten only once it has succeeded. Otherwise the next `try_next` would find
    /// nothing left to do and report the end of the table — turning a server that refused to open
    /// the folder into an empty inbox, which is the worst kind of wrong answer because it looks
    /// exactly like a right one. Taking the open out and putting it back on failure is not enough:
    /// a future dropped mid-open never reaches the putting back.
    async fn fetch(&mut self) -> Result<()> {
        if let Some(start) = &self.start {
            let (execution, table) = Self::open(self.connection, start, self.page_size).await?;
            self.start = None;
            self.opened(&execution, table);
            return Ok(());
        }

        let Some(table) = self.table.held() else {
            self.finished = true;
            return Ok(());
        };

        let mut batch = RopBatch::new();
        let slot = self
            .connection
            .bind(&mut batch, table, "reading a page of rows")?;
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
    /// Exchange Server SE `15.02.2562.056`, where paging continued normally after the release — so
    /// keeping them open would tie up server objects for nothing.
    ///
    /// **Order matters here and is not arbitrary.** `RopSetColumns` comes first because
    /// [MS-OXCTABL] §2.2.2.3 requires the sort key to be among the columns already set, and the
    /// restriction comes before the read because a filter applied after one would return the rows
    /// nobody asked for.
    ///
    /// [MS-OXCROPS] §3.1.4.1 — one ROP consumes the handle an earlier ROP produced
    ///
    /// An associated function rather than a method, so that [`fetch`](Self::fetch) can lend it the
    /// unopened table while the open is still in flight.
    async fn open(
        connection: &mut Connection,
        start: &Start,
        page_size: u16,
    ) -> Result<(Execution, HandleSlot)> {
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
        batch.query_rows(table, page_size);
        opened.release(&mut batch);

        let execution = connection.execute(batch, "opening the table").await?;
        Ok((execution, table))
    }

    /// Takes the table handle and the first page out of the opening round trip.
    fn opened(&mut self, execution: &Execution, table: HandleSlot) {
        let held = execution
            .handle(table)
            .filter(|handle| !handle.is_none())
            .map(|handle| self.connection.hold(handle));
        self.table.hold(held);
        self.table_status = execution
            .responses()
            .iter()
            .find_map(RopResponse::as_table_status)
            .map(mapi_proto::TableStatusResponse::status);
        self.absorb(execution);
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
