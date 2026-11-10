//! The ICS ROPs a batch can issue: configuring a download, uploading the state it starts from, and
//! fetching its stream.
//!
//! [MS-OXCROPS] §2.2.12.4 — `RopFastTransferSourceGetBuffer`
//! [MS-OXCROPS] §2.2.13 — the ICS ROPs

use crate::oxcdata::PropertyTag;
use crate::rop::batch::{HandleSlot, ObjectHandle, RopBatch};
use crate::rop::sync::{
    ContentsDownload, encode_configure, encode_get_buffer, encode_get_transfer_state,
    encode_upload_state_begin, encode_upload_state_continue, encode_upload_state_end,
};

impl RopBatch {
    /// Opens a content synchronization download on a folder, producing the download context every
    /// later ICS ROP takes.
    ///
    /// The context holds no state until one is uploaded into it; a download started without one is
    /// a first synchronization, which reports every message in scope.
    ///
    /// [MS-OXCROPS] §2.2.13.1 — `RopSynchronizationConfigure`
    pub fn synchronization_configure(
        &mut self,
        folder: HandleSlot,
        download: &ContentsDownload,
    ) -> HandleSlot {
        let known = self.check(folder);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.try_push(|w| encode_configure(w, folder.index(), output.index(), download));
        }
        output
    }

    /// Begins uploading one ICS state property of `size` bytes into a download context.
    ///
    /// [MS-OXCROPS] §2.2.13.9 — `RopSynchronizationUploadStateStreamBegin`
    pub fn upload_state_begin(
        &mut self,
        context: HandleSlot,
        property: PropertyTag,
        size: u32,
    ) -> &mut Self {
        if self.check(context) {
            self.push(|w| encode_upload_state_begin(w, context.index(), property, size));
        }
        self
    }

    /// Uploads the next part of the property begun with
    /// [`upload_state_begin`](Self::upload_state_begin).
    ///
    /// A large state takes several of these, across as many round trips as the request limit
    /// requires: [MS-OXCRPC] §3.1.4.2.1.2.1 has each request carry at most 32 KB of ROP data.
    ///
    /// [MS-OXCROPS] §2.2.13.10 — `RopSynchronizationUploadStateStreamContinue`
    pub fn upload_state_continue(&mut self, context: HandleSlot, data: &[u8]) -> &mut Self {
        if self.check(context) {
            self.try_push(|w| encode_upload_state_continue(w, context.index(), data));
        }
        self
    }

    /// Ends the property upload in progress.
    ///
    /// [MS-OXCROPS] §2.2.13.11 — `RopSynchronizationUploadStateStreamEnd`
    pub fn upload_state_end(&mut self, context: HandleSlot) -> &mut Self {
        if self.check(context) {
            self.push(|w| encode_upload_state_end(w, context.index()));
        }
        self
    }

    /// Fetches the next buffer of a download's stream, sized by the server.
    ///
    /// [MS-OXCROPS] §2.2.12.4 — `RopFastTransferSourceGetBuffer`
    pub fn fast_transfer_get_buffer(&mut self, context: HandleSlot) -> &mut Self {
        if self.check(context) {
            self.push(|w| encode_get_buffer(w, context.index()));
        }
        self
    }

    /// Opens a transfer object holding a download context's current ICS state, whose stream
    /// [`fast_transfer_get_buffer`](Self::fast_transfer_get_buffer) then reads.
    ///
    /// **Not a checkpoint on Exchange.** Notes `<2>` and `<42>` of [MS-OXCFXICS] have Exchange 2010
    /// and later answer with the *initial* state until the download's stream has ended, and
    /// §3.3.5.9.1 warns that items can be missed when it is taken from a download part way.
    /// Checkpoint with [`IcsState::record_message`](crate::IcsState::record_message) instead.
    ///
    /// [MS-OXCROPS] §2.2.13.8 — `RopSynchronizationGetTransferState`
    pub fn synchronization_get_transfer_state(&mut self, context: HandleSlot) -> HandleSlot {
        let known = self.check(context);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.push(|w| encode_get_transfer_state(w, context.index(), output.index()));
        }
        output
    }
}
