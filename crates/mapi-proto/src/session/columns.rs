//! Which column set belongs to which table handle, across round trips.
//!
//! A `RopQueryRows` response is decoded against the columns its table was given, and those columns
//! were usually set in an earlier `Execute`. So the session remembers them by server handle — and
//! forgets them as soon as the handle can mean something else, because a released handle value is
//! the server's to hand out again.
//!
//! [MS-OXCTABL] §2.2.2.1 — `RopSetColumns` sets the column set a table's rows are returned in

use super::Session;
use crate::oxcdata::PropertyTag;
use crate::rop::ObjectHandle;

impl Session {
    /// Fills in the column set for slots bound to a table this session has already configured, so
    /// paging through a table does not mean re-sending `RopSetColumns`.
    pub(super) fn recall_columns(
        &self,
        columns: &mut [Option<Vec<PropertyTag>>],
        initial_handles: &[ObjectHandle],
    ) {
        for (slot, entry) in columns.iter_mut().enumerate() {
            if entry.is_some() {
                continue;
            }
            let Some(handle) = initial_handles.get(slot) else {
                continue;
            };
            if let Some((_, known)) = self.table_columns.iter().find(|(h, _)| h == handle) {
                *entry = Some(known.clone());
            }
        }
    }

    /// Records which column set now belongs to which server handle.
    pub(super) fn remember_columns(
        &mut self,
        columns: &[Option<Vec<PropertyTag>>],
        handles: &[ObjectHandle],
    ) {
        for (slot, entry) in columns.iter().enumerate() {
            let (Some(tags), Some(&handle)) = (entry.as_ref(), handles.get(slot)) else {
                continue;
            };
            if handle.is_none() {
                continue;
            }
            match self.table_columns.iter_mut().find(|(h, _)| *h == handle) {
                Some(known) => known.1.clone_from(tags),
                None => self.table_columns.push((handle, tags.clone())),
            }
        }
    }

    /// Drops the column sets of the handles this batch released.
    ///
    /// A released handle value is the server's to hand out again. Keeping its column set would
    /// mean a later table given that same value decodes its rows against the *previous* table's
    /// columns — silently, and as plausible-looking wrong values rather than as an error. It also
    /// bounds this list, which paging through many tables would otherwise grow without limit.
    ///
    /// Both handle tables are consulted: a slot bound from an earlier round trip carries its
    /// handle in `before`, while `after` holds whatever the server left in the released slot —
    /// which is not required to be the empty handle, and would otherwise be recorded as though it
    /// were a table in its own right.
    pub(super) fn forget_columns(
        &mut self,
        released: &[u8],
        before: &[ObjectHandle],
        after: &[ObjectHandle],
    ) {
        for slot in released.iter().map(|&slot| usize::from(slot)) {
            let gone = [before.get(slot), after.get(slot)];
            self.table_columns
                .retain(|(handle, _)| !gone.contains(&Some(handle)));
        }
    }
}
