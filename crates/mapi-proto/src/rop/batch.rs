//! Building a ROP list whose handle indices cannot be written by hand.
//!
//! The server walks the ROP list in order and updates the handle table in place, so one ROP can
//! consume a handle that an earlier ROP in the *same* buffer produced. That is what turns a folder
//! walk into a single round trip. It is also the sharpest edge in the protocol: an index is one
//! byte with no type, and getting it wrong yields a plausible-looking wrong answer instead of an
//! error.
//!
//! So indices are never written by hand here. Issuing a ROP hands back a [`HandleSlot`], and the
//! only way to reference a handle is to pass that token to a later ROP.
//!
//! [MS-OXCROPS] §3.1.4.1 — creating a ROP input buffer

//! The ROP-issuing methods themselves are grouped by what they act on — [`objects`], the tables in
//! [`tables`], the properties in [`props`], the ROPs that create and destroy in [`writes`] — so
//! that no one file grows past what a reader can hold, and so that the grouping follows the
//! specification's own division.

use crate::error::{Error, Result};
use crate::oxcdata::{LegacyDn, PropertyTag};
use crate::rop::RopId;
use crate::rop::buffer::RopBuffer;
use crate::rop::logon::encode_logon;
use crate::wire::Writer;

mod objects;
mod props;
mod tables;
mod writes;

/// A ROP addresses the handle table with one byte, so a batch can hold this many slots.
const MAX_SLOTS: usize = 256;

/// The logon this crate operates under. Every ROP carries it; only one logon is used per session.
///
/// [MS-OXCROPS] §2.2.3.1.1 — `LogonId`
pub(crate) const LOGON_ID: u8 = 0;

/// A handle held by the server on the client's behalf.
///
/// Opaque: its only uses are being placed in a batch's handle table with [`RopBatch::bind`] and
/// being compared.
///
/// [MS-OXCROPS] §2.2.1 — `ServerObjectHandleTable`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectHandle(u32);

impl ObjectHandle {
    /// The value an unowned slot is initialised to, `0xFFFFFFFF`.
    ///
    /// [MS-OXCROPS] §3.1.4.1 — entries referenced only as output SHOULD be filled with this
    pub const NONE: Self = Self(0xFFFF_FFFF);

    /// Wraps a handle received from a server.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The handle as the wire carries it.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Whether this is the unowned-slot value.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == Self::NONE.0
    }
}

impl core::fmt::Display for ObjectHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_none() {
            f.write_str("<none>")
        } else {
            write!(f, "0x{:08X}", self.0)
        }
    }
}

/// A position in one batch's handle table, handed out by [`RopBatch`].
///
/// There is deliberately no way to build one from an integer: a slot is only ever obtained from
/// the ROP that produces the handle, which is what keeps a chain honest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HandleSlot(u8);

impl HandleSlot {
    /// The index this slot occupies in the handle table.
    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }
}

impl core::fmt::Display for HandleSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "slot {}", self.0)
    }
}

/// A list of ROPs to execute in one round trip, with the handle table they index into.
///
/// Errors are sticky rather than returned per call, so a chain reads as a chain; the first problem
/// surfaces when the batch is handed to [`Session::execute`](crate::Session::execute).
///
/// ```
/// use mapi_proto::{FolderDepth, FolderId, HIERARCHY_COLUMNS, ObjectHandle, RopBatch};
///
/// let mut batch = RopBatch::new();
/// let logon = batch.bind(ObjectHandle::new(0x0000_002A));
/// let folder = batch.open_folder(logon, FolderId::new(0x0D00_0000_0000_0001));
/// let table = batch.hierarchy_table(folder, FolderDepth::Immediate);
/// batch
///     .set_columns(table, &HIERARCHY_COLUMNS)
///     .query_rows(table, 50);
/// ```
#[derive(Debug)]
pub struct RopBatch {
    rops: Writer,
    handles: Vec<ObjectHandle>,
    columns: Vec<Option<Vec<PropertyTag>>>,
    property_tags: Vec<Vec<PropertyTag>>,
    released: Vec<u8>,
    error: Option<Error>,
    count: usize,
}

impl Default for RopBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl RopBatch {
    /// An empty batch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rops: Writer::new(),
            handles: Vec::new(),
            columns: Vec::new(),
            property_tags: Vec::new(),
            released: Vec::new(),
            error: None,
            count: 0,
        }
    }

    /// How many ROPs the batch holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether no ROP has been added yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Places a handle from an earlier round trip into this batch's table.
    ///
    /// This is how a logon obtained from one `Execute` is used by the next.
    pub fn bind(&mut self, handle: ObjectHandle) -> HandleSlot {
        self.allocate(handle)
    }

    /// Logs on to a private mailbox, producing the handle every later ROP hangs off.
    ///
    /// [MS-OXCROPS] §2.2.3.1 — `RopLogon`
    /// [MS-OXCSTOR] §2.2.1.1.1 — request buffer
    pub fn logon(&mut self, user_dn: &LegacyDn) -> HandleSlot {
        let output = self.allocate(ObjectHandle::NONE);
        self.push(|w| encode_logon(w, output.index(), user_dn.as_str()));
        output
    }

    /// Releases a handle the server is holding.
    ///
    /// A released handle value is free for the server to hand out again, so the session forgets
    /// any column set it had recorded against it. Without that, a recycled handle would silently
    /// decode a new table's rows against the old table's columns.
    ///
    /// [MS-OXCROPS] §2.2.15.3 — `RopRelease`
    pub fn release(&mut self, slot: HandleSlot) -> &mut Self {
        if self.check(slot) {
            self.released.push(slot.index());
            self.push(|w| {
                w.u8(RopId::RELEASE.as_u8()).u8(LOGON_ID).u8(slot.index());
            });
        }
        self
    }

    /// Adds a slot, or records the first failure and hands back a slot that will never be sent.
    fn allocate(&mut self, initial: ObjectHandle) -> HandleSlot {
        let Ok(index) = u8::try_from(self.handles.len()) else {
            self.fail(Error::TooManyHandles { limit: MAX_SLOTS });
            return HandleSlot(u8::MAX);
        };
        self.handles.push(initial);
        self.columns.push(None);
        HandleSlot(index)
    }

    /// Rejects a slot index this batch has not allocated, which would address a handle-table entry
    /// that does not exist.
    ///
    /// This is a range check, not proof of provenance: a slot from another batch whose index
    /// happens to be in range passes, because a `HandleSlot` carries no batch identity. What it
    /// does catch — and what the type exists for — is the index that was never allocated at all.
    fn check(&mut self, slot: HandleSlot) -> bool {
        if usize::from(slot.index()) < self.handles.len() {
            return true;
        }
        self.fail(Error::UnknownHandleSlot {
            index: slot.index(),
        });
        false
    }

    fn push(&mut self, encode: impl FnOnce(&mut Writer)) {
        if self.error.is_some() {
            return;
        }
        encode(&mut self.rops);
        self.count = self.count.saturating_add(1);
    }

    /// Adds a ROP whose encoding can refuse, leaving the buffer untouched when it does.
    ///
    /// The scratch buffer is the point: an encoder that fails halfway — a string with an interior
    /// NUL found after two values were already written — would otherwise leave a partial ROP in
    /// the buffer, and a batch that reported an error while still holding half a request is a
    /// worse thing to debug than one that reports the error alone.
    fn try_push(&mut self, encode: impl FnOnce(&mut Writer) -> Result<()>) {
        if self.error.is_some() {
            return;
        }
        let mut scratch = Writer::new();
        match encode(&mut scratch) {
            Ok(()) => {
                self.rops.bytes(&scratch.finish());
                self.count = self.count.saturating_add(1);
            }
            Err(error) => self.fail(error),
        }
    }

    fn fail(&mut self, error: Error) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// Serialises the batch, or reports the first problem hit while building it.
    pub(crate) fn build(self) -> Result<Built> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let buffer = RopBuffer {
            rops: self.rops.finish(),
            handles: self.handles,
        };
        Ok(Built {
            bytes: buffer.serialize()?,
            initial_handles: buffer.handles,
            columns: self.columns,
            property_tags: self.property_tags,
            released: self.released,
        })
    }
}

/// A serialised batch, plus what the session needs to make sense of the response.
#[derive(Clone, Debug)]
pub(crate) struct Built {
    /// The ROP buffer, framed and ready to go into an `Execute` body.
    pub(crate) bytes: Vec<u8>,
    /// The handle each slot started with, so bound handles can be matched to known column sets.
    pub(crate) initial_handles: Vec<ObjectHandle>,
    /// The column set each slot's table was given, indexed by slot.
    pub(crate) columns: Vec<Option<Vec<PropertyTag>>>,
    /// The tag list of each `RopGetPropertiesSpecific` in the batch, in the order they were
    /// issued. A queue rather than a table indexed by slot: the same object can be asked two
    /// different questions in one batch.
    pub(crate) property_tags: Vec<Vec<PropertyTag>>,
    /// The slots this batch asks the server to release, so the session can forget the column sets
    /// of whichever handles they held.
    pub(crate) released: Vec<u8>,
}

#[cfg(test)]
mod tests;
