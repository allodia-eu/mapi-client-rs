//! The ROPs that act on an item already in a mailbox: send it, move it, mark it read, and take its
//! recipients off it.
//!
//! Four ROPs, and every one of them can succeed while doing less than it was asked to. That is the
//! thread running through the file:
//!
//! * **`RopMoveCopyMessages` and `RopSetReadFlags` both carry `PartialCompletion`**, and the ROP
//!   returns success either way. A caller that read only the return value would report a message
//!   still sitting in its old folder as moved.
//! * **`RopMoveCopyMessages` has a *third* response shape.** [MS-OXCROPS] §2.2.4.6.3: a
//!   `ReturnValue` of `0x00000503` — `ecDstNullObject`, and **not** the `ecNullObject` four codes
//!   earlier — is followed by a `DestHandleIndex` and a `PartialCompletion` rather than stopping
//!   where every other failure stops. That `DestHandleIndex` is **four bytes** where the request's
//!   is one. Reading it as an ordinary failure leaves five bytes in the stream, and the next
//!   `RopId` is then whatever the third byte of a handle index happens to be.
//! * **Either may answer asynchronously**, with `RopProgress` in place of the response that was
//!   asked for. `WantAsynchronous = 0` is the documented way to decline, and it is a request flag
//!   rather than a server decision — but a server that answered one anyway would otherwise
//!   desynchronise the buffer, so [`ProgressResponse`] exists to be recognised rather than to be
//!   driven.
//! * **`RopSubmitMessage` is the one with no partial answer at all**, and the compensation is that
//!   a message has to be *complete* before it is accepted. What "complete" means is [MS-OXOMSG]
//!   §3.2.4.1's, not this layer's.
//!
//! [MS-OXCROPS] §2.2.7.1 — `RopSubmitMessage`
//! [MS-OXCROPS] §2.2.4.6 — `RopMoveCopyMessages`
//! [MS-OXCROPS] §2.2.6.10 — `RopSetReadFlags`
//! [MS-OXCROPS] §2.2.6.4 — `RopRemoveAllRecipients`
//! [MS-OXCROPS] §2.2.8.13 — `RopProgress`

use crate::error::{Error, ErrorCode, Result};
use crate::oxcdata::MessageId;
use crate::rop::RopId;
use crate::rop::batch::LOGON_ID;
use crate::wire::{Reader, Writer};

/// `WantAsynchronous`: no.
///
/// An operation the server ran asynchronously answers `RopProgress` rather than a result, and
/// nothing here can drive one. [MS-OXCROPS] §2.2.4.6.1 makes this a request flag rather than a
/// server decision, so asking plainly is the whole remedy.
const SYNCHRONOUS: u8 = 0x00;

/// `Reserved`: the four bytes `RopRemoveAllRecipients` carries and the server ignores.
///
/// [MS-OXCROPS] §2.2.6.4.1 — "The client SHOULD set this field to 0x00000000"
const RESERVED: u32 = 0x0000_0000;

/// How a message is handed to the transport.
///
/// [MS-OXOMSG] §2.2.4.1.1 — `SubmitFlags`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SubmitFlags {
    /// `None`, `0x00` — the server sends it.
    #[default]
    None,
    /// `PreProcess`, `0x01` — the server is asked to pre-process the message first.
    PreProcess,
    /// `NeedsSpooler`, `0x02` — the message goes into the spooler queue folder for a client
    /// spooler to pick up, and the server does **not** send it.
    ///
    /// Only useful to a client that implements its own spooler, which means `RopSetSpooler` and
    /// `RopSpoolerLockMessage` ([MS-OXOMSG] §3.2.3) — neither of which this crate has. Modelled
    /// so that the flag can be named, not so that it can be relied on: setting it here submits a
    /// message nothing will ever pick up.
    NeedsSpooler,
}

impl SubmitFlags {
    /// The byte this is written as.
    const fn as_u8(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::PreProcess => 0x01,
            Self::NeedsSpooler => 0x02,
        }
    }

    /// Whether the server will actually send the message, rather than parking it for a spooler.
    ///
    /// [MS-OXOMSG] §3.3.5.1.2 — with `NeedsSpooler` set, the server MUST place the message into
    /// the spooler queue folder instead of delivering it.
    #[must_use]
    pub const fn sends(self) -> bool {
        !matches!(self, Self::NeedsSpooler)
    }
}

/// What to do to the read state of some messages, and what to do about the read receipt.
///
/// The receipt is why this is a type rather than a boolean. Marking a message read is also the
/// moment the server sends the sender the read receipt they asked for, and a client that never
/// meant to send one has to say so in the same byte.
///
/// **`rfClearReadFlag` alone is not a legal request.** [MS-OXCMSG] §2.2.3.10.1: "the client MUST
/// include the rfSuppressReceipt bit with this flag". [`Unread`](Self::Unread) sends both, which
/// is why this is an enum of intentions rather than a bitfield a caller assembles.
///
/// [MS-OXCMSG] §2.2.3.10.1 — the `ReadFlags` table
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ReadFlags {
    /// `rfDefault`, `0x00` — set the read flag and send the read receipt the sender asked for.
    #[default]
    Read,
    /// `rfSuppressReceipt`, `0x01` — set the read flag and cancel any pending read receipt.
    ///
    /// What a client marking messages read on the user's behalf should send, rather than telling
    /// a sender the user has read something they have not looked at.
    ReadQuietly,
    /// `rfClearReadFlag | rfSuppressReceipt`, `0x05` — clear the read flag.
    ///
    /// The suppress bit is not optional here and is not a choice this crate is making: see the
    /// type's own documentation.
    Unread,
    /// `rfGenerateReceiptOnly`, `0x10` — send the pending read receipt and leave `mfRead` alone.
    ReceiptOnly,
}

impl ReadFlags {
    /// `rfClearReadFlag`, `0x04`.
    const CLEAR_READ_FLAG: u8 = 0x04;
    /// `rfGenerateReceiptOnly`, `0x10`.
    const GENERATE_RECEIPT_ONLY: u8 = 0x10;
    /// `rfSuppressReceipt`, `0x01`.
    const SUPPRESS_RECEIPT: u8 = 0x01;

    /// The byte this is written as.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Read => 0x00,
            Self::ReadQuietly => Self::SUPPRESS_RECEIPT,
            Self::Unread => Self::CLEAR_READ_FLAG | Self::SUPPRESS_RECEIPT,
            Self::ReceiptOnly => Self::GENERATE_RECEIPT_ONLY,
        }
    }

    /// What `mfRead` will be afterwards, or `None` for a request that does not touch it.
    #[must_use]
    pub const fn read_afterwards(self) -> Option<bool> {
        match self {
            Self::Read | Self::ReadQuietly => Some(true),
            Self::Unread => Some(false),
            Self::ReceiptOnly => None,
        }
    }
}

/// What moving or copying messages reported.
///
/// [MS-OXCROPS] §2.2.4.6.2 — response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoveCopyMessagesResponse {
    partial: bool,
}

impl MoveCopyMessagesResponse {
    /// Whether the server moved some of the messages and not others.
    ///
    /// **The ROP succeeds either way**, so this is the only thing that says a message is still
    /// where it was.
    #[must_use]
    pub const fn is_partial(self) -> bool {
        self.partial
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            partial: r.u8()? != 0,
        })
    }

    /// Reads the null-destination failure body, which is not where a failure normally stops.
    ///
    /// `DestHandleIndex` is **four bytes** here against the request's one. Nothing in the document
    /// explains the widening; what matters is that reading it as one byte leaves four in the
    /// stream, and the next `RopId` is then whatever the third byte of a handle index happens to
    /// be.
    ///
    /// [MS-OXCROPS] §2.2.4.6.3 — null destination failure response buffer
    pub(crate) fn read_null_destination(r: &mut Reader<'_>) -> Result<Self> {
        let _destination_handle_index = r.u32()?;
        Self::read(r)
    }
}

/// What setting read flags reported.
///
/// [MS-OXCROPS] §2.2.6.10.2 — response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetReadFlagsResponse {
    partial: bool,
}

impl SetReadFlagsResponse {
    /// Whether the server changed some of the messages and not others.
    ///
    /// [MS-OXCMSG] §2.2.3.10.2: nonzero means the server "was unable to modify one or more of the
    /// Message objects represented in the `MessageIds` field". The ROP succeeds either way.
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

/// How far an asynchronous operation has got.
///
/// Nothing in this crate asks for one — every ROP here sends `WantAsynchronous = 0`. This exists
/// so that a server which answered one anyway is *reported* rather than allowed to desynchronise
/// the rest of the buffer, which is what skipping nine unread bytes would do.
///
/// [MS-OXCROPS] §2.2.8.13.2 — success response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgressResponse {
    completed: u32,
    total: u32,
}

impl ProgressResponse {
    /// How many of the server's tasks are done.
    #[must_use]
    pub const fn completed(self) -> u32 {
        self.completed
    }

    /// How many there are.
    #[must_use]
    pub const fn total(self) -> u32 {
        self.total
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let _logon_id = r.u8()?;
        Ok(Self {
            completed: r.u32()?,
            total: r.u32()?,
        })
    }
}

/// Encodes a `RopSubmitMessage` request.
///
/// [MS-OXCROPS] §2.2.7.1.1 — request buffer
pub(crate) fn encode_submit_message(w: &mut Writer, message: u8, flags: SubmitFlags) {
    w.u8(RopId::SUBMIT_MESSAGE.as_u8())
        .u8(LOGON_ID)
        .u8(message)
        .u8(flags.as_u8());
}

/// Encodes a `RopMoveCopyMessages` request.
///
/// # Errors
///
/// [`Error::RopBufferTooLarge`] if there are more ids than `MessageIdCount` can express.
///
/// [MS-OXCROPS] §2.2.4.6.1 — request buffer
pub(crate) fn encode_move_copy_messages(
    w: &mut Writer,
    source: u8,
    destination: u8,
    messages: &[MessageId],
    copy: bool,
) -> Result<()> {
    w.u8(RopId::MOVE_COPY_MESSAGES.as_u8())
        .u8(LOGON_ID)
        .u8(source)
        .u8(destination);
    write_ids(w, messages)?;
    w.u8(SYNCHRONOUS).u8(u8::from(copy));
    Ok(())
}

/// Encodes a `RopSetReadFlags` request.
///
/// # Errors
///
/// [`Error::RopBufferTooLarge`] if there are more ids than `MessageIdCount` can express.
///
/// [MS-OXCROPS] §2.2.6.10.1 — request buffer
pub(crate) fn encode_set_read_flags(
    w: &mut Writer,
    folder: u8,
    flags: ReadFlags,
    messages: &[MessageId],
) -> Result<()> {
    w.u8(RopId::SET_READ_FLAGS.as_u8())
        .u8(LOGON_ID)
        .u8(folder)
        .u8(SYNCHRONOUS)
        .u8(flags.as_u8());
    write_ids(w, messages)
}

/// Encodes a `RopRemoveAllRecipients` request.
///
/// [MS-OXCROPS] §2.2.6.4.1 — request buffer
pub(crate) fn encode_remove_all_recipients(w: &mut Writer, message: u8) {
    w.u8(RopId::REMOVE_ALL_RECIPIENTS.as_u8())
        .u8(LOGON_ID)
        .u8(message)
        .u32(RESERVED);
}

/// A `MessageIdCount` and that many ids, refusing a list the count cannot describe.
fn write_ids(w: &mut Writer, messages: &[MessageId]) -> Result<()> {
    let count = u16::try_from(messages.len()).map_err(|_| Error::RopBufferTooLarge {
        bytes: messages.len(),
        limit: usize::from(u16::MAX),
    })?;
    w.u16(count);
    for id in messages {
        w.u64(id.as_u64());
    }
    Ok(())
}

/// Whether a `RopMoveCopyMessages` refusal is the one that carries a body.
///
/// `as_u32` rather than `==` because a derived `PartialEq` is not usable in a `const fn`.
pub(crate) const fn is_null_destination(code: ErrorCode) -> bool {
    code.as_u32() == ErrorCode::NULL_DESTINATION_OBJECT.as_u32()
}

#[cfg(test)]
mod tests;
