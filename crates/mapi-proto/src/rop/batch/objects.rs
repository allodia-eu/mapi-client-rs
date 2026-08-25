//! The ROPs that open a Server object: folders, messages, attachments and streams.
//!
//! Every one of them allocates an output slot and hands it back, which is the whole of how a chain
//! stays honest — a handle index is never written by hand anywhere in this crate.
//!
//! The nesting is the reason these belong together: an attachment hangs off a message, an embedded
//! message off an attachment, and a stream off any of them. All of it goes in one buffer.
//!
//! [MS-OXCROPS] §2.2.4.1 — `RopOpenFolder`
//! [MS-OXCROPS] §2.2.6 — the Message and Attachment object ROPs
//! [MS-OXCROPS] §2.2.9 — the stream ROPs

use crate::oxcdata::{FolderId, LongTermId, MessageId, PropertyTag, ShortTermId};
use crate::rop::batch::{HandleSlot, ObjectHandle, RopBatch};
use crate::rop::folder::encode_open_folder;
use crate::rop::longterm::{encode_id_from_long_term_id, encode_long_term_id_from_id};
use crate::rop::message::{
    MessageMode, encode_get_attachment_table, encode_open_attachment, encode_open_embedded_message,
    encode_open_message,
};
use crate::rop::stream::{
    StreamMode, encode_get_stream_size, encode_open_stream, encode_read_stream,
};

impl RopBatch {
    /// Opens a folder by id, producing a folder handle.
    ///
    /// [MS-OXCROPS] §2.2.4.1 — `RopOpenFolder`
    pub fn open_folder(&mut self, parent: HandleSlot, folder: FolderId) -> HandleSlot {
        // Checked before the output slot is added, or a foreign slot 0 would be made valid by the
        // very allocation this call performs.
        let known = self.check(parent);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.push(|w| encode_open_folder(w, parent.index(), output.index(), folder));
        }
        output
    }

    /// Opens a message in a folder, producing a message handle.
    ///
    /// The folder is named by id rather than by handle: `RopOpenMessage` takes both ids itself, so
    /// a message can be opened without a `RopOpenFolder` in front of it and a whole read costs one
    /// ROP fewer than the shape of the API suggests.
    ///
    /// **The mode is a request, not a permission the caller holds.** A read/write open on a message
    /// another client already has open can be refused where a read-only open would have succeeded —
    /// and a message opened read-only will not save. See [`MessageMode`].
    ///
    /// [MS-OXCROPS] §2.2.6.1 — `RopOpenMessage`
    /// [MS-OXCMSG] §2.2.3.1.1 — `OpenModeFlags`
    pub fn open_message(
        &mut self,
        logon: HandleSlot,
        folder: FolderId,
        message: MessageId,
        mode: MessageMode,
    ) -> HandleSlot {
        let known = self.check(logon);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.push(|w| {
                encode_open_message(w, logon.index(), output.index(), folder, message, mode);
            });
        }
        output
    }

    /// Opens a message's attachment table.
    ///
    /// **Its response carries no row count**, unlike the two folder tables, so how many attachments
    /// there are is only known once the rows have been read.
    ///
    /// [MS-OXCROPS] §2.2.6.17 — `RopGetAttachmentTable`
    pub fn attachment_table(&mut self, message: HandleSlot) -> HandleSlot {
        let known = self.check(message);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.push(|w| encode_get_attachment_table(w, message.index(), output.index()));
        }
        output
    }

    /// Opens one attachment, by the `PidTagAttachNumber` its row reported.
    ///
    /// [MS-OXCROPS] §2.2.6.12 — `RopOpenAttachment`
    /// [MS-OXCMSG] §2.2.2.6 — `PidTagAttachNumber` is the `AttachmentID`
    pub fn open_attachment(&mut self, message: HandleSlot, number: u32) -> HandleSlot {
        let known = self.check(message);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.push(|w| encode_open_attachment(w, message.index(), output.index(), number));
        }
        output
    }

    /// Opens an attachment as the message it holds.
    ///
    /// Valid only where `PidTagAttachMethod` is `afEmbeddedMessage` — see
    /// [`AttachMethod`](crate::AttachMethod). Such an attachment has no
    /// `PidTagAttachDataBinary` at all, so this is not an alternative reading of the same bytes but
    /// the only reading there is.
    ///
    /// [MS-OXCROPS] §2.2.6.16 — `RopOpenEmbeddedMessage`
    pub fn open_embedded_message(&mut self, attachment: HandleSlot) -> HandleSlot {
        let known = self.check(attachment);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.push(|w| encode_open_embedded_message(w, attachment.index(), output.index()));
        }
        output
    }

    /// Opens one property of an object for streaming, producing a Stream object handle.
    ///
    /// The response reports the stream's length, so an open and a
    /// [`stream_size`](Self::stream_size) in the same batch are the same question asked twice.
    ///
    /// **The mode is not a detail.** [`StreamMode::Create`] deletes the current property value
    /// before opening, so passing it on a body read destroys the body — and it is the only mode
    /// that works on a property that has never been set, which is every property of an attachment
    /// created moments ago.
    ///
    /// [MS-OXCROPS] §2.2.9.1 — `RopOpenStream`
    /// [MS-OXCPRPT] §2.2.14 — valid on Folder, Message and Attachment objects
    pub fn open_stream(
        &mut self,
        object: HandleSlot,
        tag: PropertyTag,
        mode: StreamMode,
    ) -> HandleSlot {
        let known = self.check(object);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.push(|w| encode_open_stream(w, object.index(), output.index(), tag, mode));
        }
        output
    }

    /// Reads up to `bytes` from an open stream, advancing its cursor.
    ///
    /// A read that answers with nothing is how the end of the stream is reported; there is no flag
    /// for it. Asking for more than 65,535 bytes is refused rather than clamped, because
    /// `DataSize` is two bytes and a short answer is indistinguishable from the end.
    ///
    /// [MS-OXCROPS] §2.2.9.2 — `RopReadStream`
    pub fn read_stream(&mut self, stream: HandleSlot, bytes: usize) -> &mut Self {
        if self.check(stream) {
            self.try_push(|w| encode_read_stream(w, stream.index(), bytes));
        }
        self
    }

    /// Asks how many bytes an open stream holds.
    ///
    /// [MS-OXCROPS] §2.2.9.6 — `RopGetStreamSize`
    pub fn stream_size(&mut self, stream: HandleSlot) -> &mut Self {
        if self.check(stream) {
            self.push(|w| encode_get_stream_size(w, stream.index()));
        }
        self
    }

    /// Converts a long-term id into one a ROP will take.
    ///
    /// The step that makes the folders a logon does not name reachable: a `PidTagIpm*EntryId`
    /// property holds a [`FolderEntryId`](crate::FolderEntryId) whose tail is a
    /// [`LongTermId`], and `RopOpenFolder` takes a [`FolderId`]. Only the server holds the mapping
    /// between the two, so this is a round trip rather than arithmetic.
    ///
    /// Operates on the Logon object, and answers **for the store that logon named** — converting
    /// an entry id issued by a different mailbox produces a valid-looking id for the wrong folder,
    /// which is what [`FolderEntryId::belongs_to`](crate::FolderEntryId::belongs_to) is for.
    ///
    /// [MS-OXCROPS] §2.2.3.9 — `RopIdFromLongTermId`
    /// [MS-OXOSFLD] §2.2.2 — entry ids MUST be converted before use
    pub fn id_from_long_term_id(&mut self, logon: HandleSlot, id: &LongTermId) -> &mut Self {
        if self.check(logon) {
            self.push(|w| encode_id_from_long_term_id(w, logon.index(), id));
        }
        self
    }

    /// Converts a folder or message id into one that survives leaving the store.
    ///
    /// The inverse of [`id_from_long_term_id`](Self::id_from_long_term_id), and what a client
    /// needs to *write* an entry-id property rather than read one.
    ///
    /// [MS-OXCROPS] §2.2.3.8 — `RopLongTermIdFromId`
    pub fn long_term_id_from_id(&mut self, logon: HandleSlot, id: ShortTermId) -> &mut Self {
        if self.check(logon) {
            self.push(|w| encode_long_term_id_from_id(w, logon.index(), id));
        }
        self
    }
}
