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
use crate::rop::send::{
    ReadFlags, SubmitFlags, encode_move_copy_messages, encode_remove_all_recipients,
    encode_set_read_flags, encode_submit_message,
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

    /// Takes every recipient off an open message.
    ///
    /// The only way to shorten a recipient list.
    /// [`modify_recipients`](Self::modify_recipients) addresses each row by a `RowId` that is its
    /// position in the list it was given, so it can rewrite and it can extend and it can never
    /// remove — which means "replace the recipients" is this ROP followed by that one, and
    /// forgetting the first leaves the old addresses on a message about to be submitted.
    ///
    /// [MS-OXCROPS] §2.2.6.4 — `RopRemoveAllRecipients`
    pub fn remove_all_recipients(&mut self, message: HandleSlot) -> &mut Self {
        if self.check(message) {
            self.push(|w| encode_remove_all_recipients(w, message.index()));
        }
        self
    }

    /// Hands an open message to the transport.
    ///
    /// **This sends real mail**, and the response says only that the server accepted it — there is
    /// no dry run and no delivery report. The message has to be saved first: `RopSubmitMessage`
    /// acts on what is in the store, not on uncommitted changes to the handle.
    ///
    /// The properties a message needs before a server will accept it are [MS-OXOMSG] §3.2.4.1's
    /// and not this layer's, and the refusals are worth recognising by name:
    /// [`ecTooManyRecips`](crate::ErrorCode::TOO_MANY_RECIPIENTS) means **none** of the recipients
    /// got it ([MS-OXOMSG] §3.3.5.1), and
    /// [`ecAccessDenied`](crate::ErrorCode::ACCESS_DENIED) is what an FAI message is refused with,
    /// which reads like a permission problem and is not.
    ///
    /// [MS-OXCROPS] §2.2.7.1 — `RopSubmitMessage`
    pub fn submit_message(&mut self, message: HandleSlot, flags: SubmitFlags) -> &mut Self {
        if self.check(message) {
            self.push(|w| encode_submit_message(w, message.index(), flags));
        }
        self
    }

    /// Moves or copies messages from one open folder to another.
    ///
    /// Both folders are handles rather than ids, and they are the reason this cannot be done in
    /// fewer round trips than it takes to open them — which is none, because the opens chain in
    /// the same buffer.
    ///
    /// Sent synchronously, as [`delete_messages`](Self::delete_messages) is. **Whether Exchange
    /// honours that for a cross-folder move is a measurement rather than an assumption**, so a
    /// [`RopProgress`](crate::RopResponse::Progress) arriving here is reported rather than
    /// treated as impossible.
    ///
    /// **The response says whether it moved everything it was given**, and the ROP succeeds either
    /// way — see [`MoveCopyMessagesResponse`](crate::MoveCopyMessagesResponse). There is also a
    /// third response shape when the destination handle resolves to nothing, which is decoded
    /// rather than skipped.
    ///
    /// [MS-OXCROPS] §2.2.4.6 — `RopMoveCopyMessages`
    /// [MS-OXCFOLD] §2.2.1.6 — semantics
    pub fn move_copy_messages(
        &mut self,
        source: HandleSlot,
        destination: HandleSlot,
        messages: &[MessageId],
        copy: bool,
    ) -> &mut Self {
        if self.check(source) && self.check(destination) {
            self.try_push(|w| {
                encode_move_copy_messages(w, source.index(), destination.index(), messages, copy)
            });
        }
        self
    }

    /// Changes the read state of messages in an open folder.
    ///
    /// Addressed at the folder and a list of ids rather than at an open message, which is what
    /// makes marking a page of a contents table read one ROP instead of one per message.
    ///
    /// **It is not only a property write.** [MS-OXCMSG] §2.2.3.10 has the server send the read
    /// receipt the sender asked for as part of this, so a client marking messages read on a user's
    /// behalf wants [`ReadFlags::ReadQuietly`](crate::ReadFlags::ReadQuietly) rather than the
    /// default — see [`ReadFlags`](crate::ReadFlags).
    ///
    /// **The response says whether it changed everything it was given**, and the ROP succeeds
    /// either way.
    ///
    /// [MS-OXCROPS] §2.2.6.10 — `RopSetReadFlags`
    pub fn set_read_flags(
        &mut self,
        folder: HandleSlot,
        flags: ReadFlags,
        messages: &[MessageId],
    ) -> &mut Self {
        if self.check(folder) {
            self.try_push(|w| encode_set_read_flags(w, folder.index(), flags, messages));
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
