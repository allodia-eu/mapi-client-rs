//! The ROPs that put an item into a mailbox, commit it, and take it out again.
//!
//! Grouped apart from [`objects`](super::objects) because opening something and creating something
//! fail in opposite ways. An open that goes wrong is refused; a create that goes wrong **succeeds**
//! — a message never saved leaves nothing behind, an attachment saved after its message is lost,
//! and a delete that deleted nothing still returns success. Every one of those is reported in a
//! field a caller has to look at rather than in a return value.
//!
//! [MS-OXCROPS] §2.2.6 — the Message and Attachment object ROPs
//! [MS-OXCROPS] §2.2.9 — the stream ROPs
//! [MS-OXCROPS] §2.2.4.11 — `RopDeleteMessages`

use crate::oxcdata::{FolderId, MessageId, Recipient};
use crate::rop::batch::{HandleSlot, ObjectHandle, RopBatch};
use crate::rop::create::{
    encode_create_attachment, encode_create_message, encode_delete_messages,
    encode_modify_recipients, encode_save_changes_attachment, encode_save_changes_message,
};
use crate::rop::stream::{encode_commit_stream, encode_write_stream};

impl RopBatch {
    /// Creates a message in a folder, producing a message handle.
    ///
    /// **Nothing is in the mailbox when this returns.** [MS-OXCMSG] §3.2.5.2 holds the new Message
    /// object until a [`save_message`](Self::save_message) arrives, so a batch that creates a
    /// message and stops is a batch that did nothing — with no error to say so. The handle is what
    /// every property write, recipient list and attachment hangs off in the meantime.
    ///
    /// The folder is named by id rather than by handle, as `RopOpenMessage` names it: the ROP takes
    /// the id itself, so no `RopOpenFolder` is needed in front of it.
    ///
    /// [MS-OXCROPS] §2.2.6.2 — `RopCreateMessage`
    pub fn create_message(&mut self, logon: HandleSlot, folder: FolderId) -> HandleSlot {
        // Checked before the output slot is added, or a foreign slot 0 would be made valid by the
        // very allocation this call performs.
        let known = self.check(logon);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.push(|w| encode_create_message(w, logon.index(), output.index(), folder));
        }
        output
    }

    /// Commits a message, and reports the id it now has.
    ///
    /// The handle stays open afterwards — `SaveFlags` is `KeepOpenReadWrite` — so one Session
    /// Context can create a message, save it, add an attachment to the same handle and save again.
    ///
    /// **After every attachment's own save, never before.** [MS-OXCPRPT] §3.1.4.16 persists an
    /// Attachment object with `RopSaveChangesAttachment` *followed by* this, and the other order
    /// loses the attachment without failing.
    ///
    /// [MS-OXCROPS] §2.2.6.3 — `RopSaveChangesMessage`
    pub fn save_message(&mut self, message: HandleSlot) -> &mut Self {
        if self.check(message) {
            self.push(|w| encode_save_changes_message(w, message.index()));
        }
        self
    }

    /// Adds or modifies the recipients of an open message.
    ///
    /// **This does not replace the list.** A row's `RowId` names the recipient it is about
    /// ([MS-OXCMSG] §3.1.5.5), and the ids here are positions in `recipients` — so sending the same
    /// list twice modifies the same recipients rather than doubling them, and sending a shorter
    /// list leaves the surplus ones in place. On a message that was just created there are none, so
    /// the two readings coincide; on an existing one they do not.
    ///
    /// Every recipient is addressed one-off, which is what makes this reachable without the address
    /// book — see [`Recipient`].
    ///
    /// [MS-OXCROPS] §2.2.6.5 — `RopModifyRecipients`
    pub fn modify_recipients(
        &mut self,
        message: HandleSlot,
        recipients: &[Recipient],
    ) -> &mut Self {
        if self.check(message) {
            self.try_push(|w| encode_modify_recipients(w, message.index(), recipients));
        }
        self
    }

    /// Adds an attachment to an open message, producing an attachment handle.
    ///
    /// The number the attachment was given comes back in the response — see
    /// [`CreateAttachmentResponse`](crate::CreateAttachmentResponse) — and is the only way to name
    /// it afterwards.
    ///
    /// [MS-OXCROPS] §2.2.6.13 — `RopCreateAttachment`
    pub fn create_attachment(&mut self, message: HandleSlot) -> HandleSlot {
        let known = self.check(message);
        let output = self.allocate(ObjectHandle::NONE);
        if known {
            self.push(|w| encode_create_attachment(w, message.index(), output.index()));
        }
        output
    }

    /// Commits an attachment.
    ///
    /// Then [`save_message`](Self::save_message), which is what actually puts it in the store.
    ///
    /// [MS-OXCROPS] §2.2.6.15 — `RopSaveChangesAttachment`
    pub fn save_attachment(&mut self, attachment: HandleSlot) -> &mut Self {
        if self.check(attachment) {
            self.push(|w| encode_save_changes_attachment(w, attachment.index()));
        }
        self
    }

    /// Writes bytes at an open stream's cursor.
    ///
    /// The stream has to have been opened writable — see [`StreamMode`](crate::StreamMode). A write
    /// larger than 65,535 bytes is refused rather than split, because `DataSize` is two bytes and
    /// how many round trips to spend is the caller's decision.
    ///
    /// The response says how many bytes landed, and it is worth reading: a short write succeeds.
    ///
    /// [MS-OXCROPS] §2.2.9.3 — `RopWriteStream`
    pub fn write_stream(&mut self, stream: HandleSlot, data: &[u8]) -> &mut Self {
        if self.check(stream) {
            self.try_push(|w| encode_write_stream(w, stream.index(), data));
        }
        self
    }

    /// Pushes what has been written into the property the stream was opened on.
    ///
    /// **Required for a Folder object's property and ambiguous for the other two.**
    /// [MS-OXCPRPT] §3.1.4.16 has a Message or Attachment object's stream persisted by that
    /// object's own save ROP; §3.2.5.15 has this ROP set the property from the stream whatever the
    /// object is. Sending it costs one ROP in a buffer that is making several round trips anyway,
    /// and settles the question in the direction that cannot lose data.
    ///
    /// [MS-OXCROPS] §2.2.9.5 — `RopCommitStream`
    pub fn commit_stream(&mut self, stream: HandleSlot) -> &mut Self {
        if self.check(stream) {
            self.push(|w| encode_commit_stream(w, stream.index()));
        }
        self
    }

    /// Deletes messages from a folder, by id.
    ///
    /// A **soft** delete: the server keeps a back-up copy a client can restore or delete
    /// permanently ([MS-OXCFOLD] §1.1). It does not move the message to Deleted Items — that is a
    /// `RopMoveCopyMessages` a client does first, and this crate does not implement it.
    ///
    /// Sent synchronously. The asynchronous form answers `RopProgress` instead of a result, which
    /// nothing here can interpret — and [MS-OXCROPS] §2.2.4.11.1 makes that a request flag rather
    /// than a server decision, so asking for it plainly is the remedy.
    ///
    /// **The response says whether it deleted everything it was given**, and the ROP succeeds
    /// either way — see [`DeleteMessagesResponse`](crate::DeleteMessagesResponse).
    ///
    /// [MS-OXCROPS] §2.2.4.11 — `RopDeleteMessages`
    pub fn delete_messages(&mut self, folder: HandleSlot, messages: &[MessageId]) -> &mut Self {
        if self.check(folder) {
            self.try_push(|w| encode_delete_messages(w, folder.index(), messages));
        }
        self
    }
}
