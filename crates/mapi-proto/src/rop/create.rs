//! The ROPs that put an item into a mailbox, and the ones that take it out again.
//!
//! Everything here is the write half of [MS-OXCMSG]: creating a Message object, addressing it,
//! hanging an attachment off it, committing each of those, and deleting the result.
//!
//! Four things about them are load-bearing, and each is a wrong answer that looks like a right one
//! if it is got wrong.
//!
//! * **`RopCreateMessage` commits nothing.** [MS-OXCMSG] §3.2.5.2 has the server hold the new
//!   Message object until a `RopSaveChangesMessage` arrives, so a batch that creates a message and
//!   stops leaves the mailbox exactly as it found it — and a caller that forgets the save gets no
//!   error and no message.
//! * **An attachment saves before its message, never after.** [MS-OXCPRPT] §3.1.4.16: a change to
//!   an Attachment object is persisted by `RopSaveChangesAttachment` *followed by*
//!   `RopSaveChangesMessage`. Reversing the two loses the attachment without failing.
//! * **`RopModifyRecipients` adds and modifies; it does not replace.** A row's `RowId` names the
//!   recipient it is about ([MS-OXCMSG] §3.1.5.5), so sending the same list twice against one
//!   message overwrites rather than duplicating — and sending a *shorter* list leaves the surplus
//!   recipients in place. `RopRemoveAllRecipients` is what clears them, and is not modelled here.
//! * **`RopDeleteMessages` can succeed and delete nothing.** Its `PartialCompletion` byte is the
//!   only place that is reported.
//!
//! [MS-OXCROPS] §2.2.6.2 — `RopCreateMessage`
//! [MS-OXCROPS] §2.2.6.3 — `RopSaveChangesMessage`
//! [MS-OXCROPS] §2.2.6.5 — `RopModifyRecipients`
//! [MS-OXCROPS] §2.2.6.13 — `RopCreateAttachment`
//! [MS-OXCROPS] §2.2.6.15 — `RopSaveChangesAttachment`
//! [MS-OXCROPS] §2.2.4.11 — `RopDeleteMessages`

use crate::error::{Error, Result};
use crate::oxcdata::{AttachmentNumber, FolderId, MessageId, Recipient};
use crate::rop::RopId;
use crate::rop::batch::LOGON_ID;
use crate::wire::{Reader, Writer};

/// `CodePageId`: use the Session Context's own code page rather than naming another.
///
/// [MS-OXCMSG] §2.2.3.2.1 — `CodePageId`
const CODE_PAGE_FROM_LOGON: u16 = 0x0FFF;

/// `AssociatedFlag`: an ordinary message rather than an FAI one.
///
/// FAI messages are the folder's own configuration data and do not appear in a contents table, so
/// creating one by accident produces an item nothing can find.
///
/// [MS-OXCMSG] §2.2.3.2.1 — `AssociatedFlag`
const NOT_ASSOCIATED: u8 = 0x00;

/// `SaveFlags`: `KeepOpenReadWrite`.
///
/// The handle stays usable afterwards, which is what lets one Session Context create a message,
/// save it, hang an attachment off the same handle and save again. `ForceSave` is deliberately not
/// combined in: it suppresses `ecObjectModified`, and being told that somebody else changed the
/// message is the point of the code.
///
/// **[MS-OXCMSG] contradicts itself about the value.** §2.2.3.3.1's table gives
/// `KeepOpenReadWrite` as `0x02`; every worked example in §4 sends `0x0A` and labels it
/// `KeepOpenReadWrite`. `0x0A` is `0x02` with `0x08` set, and the same section says other flags
/// "are not valid and are ignored by the server", so the two agree on what the server does. The
/// documented value is the one sent here.
///
/// [MS-OXCMSG] §2.2.3.3.1 — `SaveFlags`
const KEEP_OPEN_READ_WRITE: u8 = 0x02;

/// `WantAsynchronous`: no.
///
/// A delete the server ran asynchronously would answer `RopProgress` rather than a result, and
/// nothing here can interpret one.
///
/// [MS-OXCROPS] §2.2.4.11.1 — `WantAsynchronous`
const SYNCHRONOUS: u8 = 0x00;

/// `NotifyNonRead`: do not send a non-read receipt to the sender of a deleted message.
///
/// [MS-OXCROPS] §2.2.4.11.1 — `NotifyNonRead`
const NO_NON_READ_RECEIPT: u8 = 0x00;

/// What creating a message reported.
///
/// [MS-OXCROPS] §2.2.6.2.2 — success response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateMessageResponse {
    id: Option<MessageId>,
}

impl CreateMessageResponse {
    /// The id the new message was given, if the server named one.
    ///
    /// `None` is a documented answer rather than a fault: `HasMessageId` is a Boolean and
    /// [MS-OXCMSG] §2.2.3.2.2 has the buffer end there when it is zero. The id that matters is the
    /// one [`SaveChangesResponse::message_id`] reports, because nothing exists until the save.
    #[must_use]
    pub const fn message_id(self) -> Option<MessageId> {
        self.id
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            id: if r.u8()? == 0 {
                None
            } else {
                Some(MessageId::new(r.u64()?))
            },
        })
    }
}

/// What committing a message reported.
///
/// [MS-OXCROPS] §2.2.6.3.2 — success response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaveChangesResponse {
    id: MessageId,
}

impl SaveChangesResponse {
    /// The id of the message that was saved.
    ///
    /// This is the identifier a caller keeps: it names the message in `RopOpenMessage`,
    /// `RopDeleteMessages` and every later operation, and it is what a contents-table row's
    /// `PidTagMid` reports.
    #[must_use]
    pub const fn message_id(self) -> MessageId {
        self.id
    }

    /// Reads the body, which begins with the request's `InputHandleIndex` rather than with the id.
    ///
    /// The generic decoder has already taken `ResponseHandleIndex` and `ReturnValue`; this ROP is
    /// the only one in the crate whose success body starts with a *second* handle index.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let _input_handle_index = r.u8()?;
        Ok(Self {
            id: MessageId::new(r.u64()?),
        })
    }
}

/// What creating an attachment reported.
///
/// [MS-OXCROPS] §2.2.6.13.2 — success response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateAttachmentResponse {
    number: AttachmentNumber,
}

impl CreateAttachmentResponse {
    /// The number the new attachment was given, which is its `PidTagAttachNumber`.
    ///
    /// The only way to name the attachment afterwards: it has no other identity, and the number is
    /// an index within *this* message rather than something that travels.
    ///
    /// [MS-OXCMSG] §2.2.2.6 — `PidTagAttachNumber`
    #[must_use]
    pub const fn number(self) -> AttachmentNumber {
        self.number
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            number: AttachmentNumber::new(r.u32()?),
        })
    }
}

/// What deleting messages reported.
///
/// [MS-OXCROPS] §2.2.4.11.2 — response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeleteMessagesResponse {
    partial: bool,
}

impl DeleteMessagesResponse {
    /// Whether the server deleted some of the messages and not others.
    ///
    /// **The ROP succeeds either way.** A caller that only looked at the return value would report
    /// a message that is still there as gone — which for a write-fixture scenario means the lab
    /// drifts one item per run with nothing saying so.
    #[must_use]
    pub const fn is_partial(self) -> bool {
        self.partial
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            partial: r.u8()? != 0,
        })
    }
}

/// Encodes a `RopCreateMessage` request.
///
/// [MS-OXCROPS] §2.2.6.2.1 — request buffer
pub(crate) fn encode_create_message(w: &mut Writer, input: u8, output: u8, folder: FolderId) {
    w.u8(RopId::CREATE_MESSAGE.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(output)
        .u16(CODE_PAGE_FROM_LOGON)
        .u64(folder.as_u64())
        .u8(NOT_ASSOCIATED);
}

/// Encodes a `RopSaveChangesMessage` request.
///
/// `ResponseHandleIndex` and `InputHandleIndex` are the same slot here. The document lets them
/// differ — the response is written into the first and the message is read from the second — and
/// nothing in this crate needs a response addressed anywhere but at the object it is about.
///
/// [MS-OXCROPS] §2.2.6.3.1 — request buffer
pub(crate) fn encode_save_changes_message(w: &mut Writer, message: u8) {
    w.u8(RopId::SAVE_CHANGES_MESSAGE.as_u8())
        .u8(LOGON_ID)
        .u8(message)
        .u8(message)
        .u8(KEEP_OPEN_READ_WRITE);
}

/// Encodes a `RopModifyRecipients` request.
///
/// `ColumnCount` is zero and every row's `RecipientColumnCount` is zero with it. Everything a
/// one-off recipient carries is already a field of the `RecipientRow`, and [MS-OXCMSG] §2.2.3.5.1
/// forbids naming those properties in `RecipientColumns` at all — so a column set here would have
/// to be extra properties, and there are none.
///
/// `RowId` is the row's position in the list. It is an identity rather than an ordinal: sending the
/// same list again modifies the same recipients, which is what makes this safe to repeat.
///
/// # Errors
///
/// [`Error::RopBufferTooLarge`] if one recipient's row does not fit the 16-bit `RecipientRowSize`
/// field, or if there are more recipients than `RowCount` can express.
///
/// [MS-OXCROPS] §2.2.6.5.1 — request buffer
/// [MS-OXCROPS] §2.2.6.5.1.1 — `ModifyRecipientRow`
pub(crate) fn encode_modify_recipients(
    w: &mut Writer,
    message: u8,
    recipients: &[Recipient],
) -> Result<()> {
    let count = u16::try_from(recipients.len()).map_err(|_| Error::RopBufferTooLarge {
        bytes: recipients.len(),
        limit: usize::from(u16::MAX),
    })?;

    w.u8(RopId::MODIFY_RECIPIENTS.as_u8())
        .u8(LOGON_ID)
        .u8(message)
        .u16(0)
        .u16(count);

    for (index, recipient) in recipients.iter().enumerate() {
        let mut row = Writer::new();
        recipient.write_row(&mut row);
        let row = row.finish();
        let size = u16::try_from(row.len()).map_err(|_| Error::RopBufferTooLarge {
            bytes: row.len(),
            limit: usize::from(u16::MAX),
        })?;

        // Infallible: `count` above already proved the list is shorter than `u16::MAX`, and this
        // index is smaller than that. `unwrap_or` rather than a cast keeps the file free of `as`.
        w.u32(u32::try_from(index).unwrap_or(u32::MAX))
            .u8(recipient.kind().as_u8())
            .u16(size)
            .bytes(&row);
    }
    Ok(())
}

/// Encodes a `RopCreateAttachment` request.
///
/// [MS-OXCROPS] §2.2.6.13.1 — request buffer
pub(crate) fn encode_create_attachment(w: &mut Writer, message: u8, output: u8) {
    w.u8(RopId::CREATE_ATTACHMENT.as_u8())
        .u8(LOGON_ID)
        .u8(message)
        .u8(output);
}

/// Encodes a `RopSaveChangesAttachment` request.
///
/// [MS-OXCROPS] §2.2.6.15.1 — request buffer
pub(crate) fn encode_save_changes_attachment(w: &mut Writer, attachment: u8) {
    w.u8(RopId::SAVE_CHANGES_ATTACHMENT.as_u8())
        .u8(LOGON_ID)
        .u8(attachment)
        .u8(attachment)
        .u8(KEEP_OPEN_READ_WRITE);
}

/// Encodes a `RopDeleteMessages` request.
///
/// # Errors
///
/// [`Error::RopBufferTooLarge`] if there are more ids than `MessageIdCount` can express.
///
/// [MS-OXCROPS] §2.2.4.11.1 — request buffer
pub(crate) fn encode_delete_messages(
    w: &mut Writer,
    folder: u8,
    messages: &[MessageId],
) -> Result<()> {
    let count = u16::try_from(messages.len()).map_err(|_| Error::RopBufferTooLarge {
        bytes: messages.len(),
        limit: usize::from(u16::MAX),
    })?;

    w.u8(RopId::DELETE_MESSAGES.as_u8())
        .u8(LOGON_ID)
        .u8(folder)
        .u8(SYNCHRONOUS)
        .u8(NO_NON_READ_RECEIPT)
        .u16(count);
    for id in messages {
        w.u64(id.as_u64());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
