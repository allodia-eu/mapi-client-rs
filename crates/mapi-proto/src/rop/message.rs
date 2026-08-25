//! The Message and Attachment object ROPs: opening a message, its attachment table, one
//! attachment, and the message an attachment can turn out to be.
//!
//! Two things here are worth stating before the code.
//!
//! **`RopOpenMessage` answers with the recipient table whether or not it was wanted.** There is no
//! request flag that suppresses it, so a decoder that skipped the tail would misread every later
//! response in the buffer. What saves this from needing [MS-OXCDATA] §2.8.3.2's whole
//! `RecipientRow` grammar is that [MS-OXCROPS] §2.2.6.1.2.1 puts a `RecipientRowSize` in front of
//! each one — so the framing is exact and the contents are handed back as bytes, which is what
//! [`OpenRecipient`] says plainly rather than pretending to a parse it does not do.
//!
//! **`RopGetAttachmentTable`'s response carries no row count**, unlike the two folder tables. How
//! many attachments a message has is therefore only known once its rows have been read, which is
//! why nothing here reports one.
//!
//! [MS-OXCROPS] §2.2.6.1 — `RopOpenMessage`
//! [MS-OXCROPS] §2.2.6.12 — `RopOpenAttachment`
//! [MS-OXCROPS] §2.2.6.16 — `RopOpenEmbeddedMessage`
//! [MS-OXCROPS] §2.2.6.17 — `RopGetAttachmentTable`
//! [MS-OXCMSG] §2.2.3 — semantics

use crate::error::{Error, Result};
use crate::oxcdata::{FolderId, MessageId, RecipientType};
use crate::rop::RopId;
use crate::rop::batch::LOGON_ID;
use crate::wire::{Reader, Writer};

/// `CodePageId`: use the Session Context's own code page rather than naming another.
///
/// `0x0FFF` is the documented "the code page of the Logon object is used". It governs
/// `PtypString8` values only, and this crate asks for `PtypString` everywhere it has the choice.
///
/// [MS-OXCMSG] §2.2.3.1.1 — `CodePageId`
const CODE_PAGE_FROM_LOGON: u16 = 0x0FFF;

/// How a message is opened, which decides what may then be done to it.
///
/// **Not merely a permission.** A read/write open on a message another client already has open can
/// be refused where a read-only open would have succeeded, so asking for write access a caller does
/// not need turns a working read into an error — and asking for read-only access and then trying to
/// save turns a working write into one.
///
/// [MS-OXCMSG] §2.2.3.1.1 — `OpenModeFlags`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum MessageMode {
    /// `0x00` — read the message and change nothing.
    #[default]
    ReadOnly,
    /// `0x01` — read and write. Required before `RopSaveChangesMessage` will commit anything.
    ReadWrite,
    /// `0x03` — read/write where the folder's permissions allow it, read-only where they do not.
    ///
    /// The open succeeds either way, so what a caller gets is not knowable from the response — the
    /// refusal arrives at the save instead. Offered because it is what a client that does not know
    /// in advance whether it may write should ask for.
    BestAccess,
}

impl MessageMode {
    /// The `OpenModeFlags` byte this is written as.
    const fn flags(self) -> u8 {
        match self {
            Self::ReadOnly => 0x00,
            Self::ReadWrite => 0x01,
            Self::BestAccess => 0x03,
        }
    }

    /// Whether a message opened this way is one the server has agreed to let this client write.
    ///
    /// `false` for [`BestAccess`](Self::BestAccess), which is a request rather than an answer.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::ReadWrite)
    }
}

/// `OpenAttachmentFlags`: read-only, as [`MessageMode::ReadOnly`].
///
/// Nothing in this crate opens an *existing* attachment to change it — an attachment is created,
/// filled and saved in one go, so the write path never passes through here.
///
/// [MS-OXCMSG] §2.2.3.12.1 — `OpenAttachmentFlags`
const OPEN_ATTACHMENT_READ_ONLY: u8 = 0x00;

/// `TableFlags`: `Unicode` — string columns come back as `PtypString`.
///
/// The attachment table's only flag worth setting. Without it a file name arrives in the session's
/// code page, which is a lossy round trip for a name this crate would then hand to a caller.
///
/// [MS-OXCMSG] §2.2.3.17.1 — `TableFlags`
const ATTACHMENT_TABLE_UNICODE: u8 = 0x40;

/// One row of the recipient table a message open answers with.
///
/// **The `RecipientRow` itself is not decoded.** [MS-OXCDATA] §2.8.3.2's grammar is a bitfield
/// whose every field is conditional, and nothing in reading a message needs it —
/// `PidTagDisplayTo` is a computed property that answers "who is this addressed to" as an ordinary
/// column. The bytes are kept rather than dropped so that a caller who does need them has them, and
/// so that writing recipients in a later phase has real examples to encode against.
///
/// [MS-OXCROPS] §2.2.6.1.2.1 — `OpenRecipientRow`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRecipient {
    recipient_type: RecipientType,
    code_page: u16,
    row: Vec<u8>,
}

impl OpenRecipient {
    /// Whether this is a To, Cc or Bcc recipient.
    #[must_use]
    pub const fn recipient_type(&self) -> RecipientType {
        self.recipient_type
    }

    /// The code page this recipient's 8-bit strings are in.
    #[must_use]
    pub const fn code_page(&self) -> u16 {
        self.code_page
    }

    /// The undecoded `RecipientRow`, exactly as many bytes as `RecipientRowSize` claimed.
    #[must_use]
    pub fn row_bytes(&self) -> &[u8] {
        &self.row
    }

    /// Reads one `OpenRecipientRow`.
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let recipient_type = RecipientType::new(r.u8()?);
        let code_page = r.u16()?;
        let _reserved = r.u16()?;
        let size = usize::from(r.u16()?);
        Ok(Self {
            recipient_type,
            code_page,
            row: r.bytes(size)?.to_vec(),
        })
    }
}

/// What opening a message reports about it.
///
/// [MS-OXCROPS] §2.2.6.1.2 — success response buffer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenMessageResponse {
    rop: RopId,
    embedded_id: Option<MessageId>,
    has_named_properties: bool,
    subject_prefix: Option<String>,
    normalized_subject: Option<String>,
    recipient_count: u16,
    recipients: Vec<OpenRecipient>,
}

impl OpenMessageResponse {
    /// Which ROP produced this — `RopOpenMessage` or `RopOpenEmbeddedMessage`.
    ///
    /// Not decoration. Reaching an embedded message opens the message it is attached to first, so
    /// a batch that opens one carries **two** of these responses, and picking the first reports the
    /// outer message's subject as the inner one's — a wrong answer that looks entirely plausible.
    /// Measured against Exchange Server SE `15.02.2562.045`, where exactly that reported the
    /// parent's subject for an attachment named `forwarded.msg`.
    #[must_use]
    pub const fn rop(&self) -> RopId {
        self.rop
    }

    /// The message's own id, for a message reached through `RopOpenEmbeddedMessage`.
    ///
    /// `None` for an ordinary `RopOpenMessage`, whose caller already supplied the id.
    ///
    /// **Exchange answers zero here**, which is not what [MS-OXCMSG] §2.2.3.16.2's "8 bytes
    /// containing the MID for the Message object" leads a reader to expect. Measured on Exchange
    /// Server SE `15.02.2562.045` against both lab mailboxes: an `afEmbeddedMessage` attachment
    /// opened as a message reports `0x0000000000000000`. That is consistent with an embedded
    /// message having no identity in the store of its own — it is reached through its attachment
    /// and by no other route — but it means the value cannot be used to re-open the message later.
    ///
    /// Reported as the zero it is rather than folded into `None`: "the server sent zero" and "this
    /// was not an embedded open" are different facts, and hiding the first would hide the finding.
    ///
    /// [MS-OXCMSG] §2.2.3.16.2 — `MessageId`
    #[must_use]
    pub const fn embedded_id(&self) -> Option<MessageId> {
        self.embedded_id
    }

    /// Whether the message holds named properties.
    ///
    /// A calendar entry always does; an ordinary mail usually does not. Worth looking at before
    /// spending a `RopGetPropertyIdsFromNames` round trip on a message that has none.
    #[must_use]
    pub const fn has_named_properties(&self) -> bool {
        self.has_named_properties
    }

    /// The `RE:`/`FW:` part of the subject, if the server sent one.
    ///
    /// `None` means the field carried `StringType` `0x00` — no string at all — which is not the
    /// same as an empty one.
    #[must_use]
    pub fn subject_prefix(&self) -> Option<&str> {
        self.subject_prefix.as_deref()
    }

    /// The subject with its prefix removed.
    #[must_use]
    pub fn normalized_subject(&self) -> Option<&str> {
        self.normalized_subject.as_deref()
    }

    /// How many recipients the message has.
    ///
    /// Not necessarily how many rows arrived: `RowCount` is documented as no greater than this, so
    /// a message with more recipients than fit the buffer reports the total here and fewer rows.
    #[must_use]
    pub const fn recipient_count(&self) -> u16 {
        self.recipient_count
    }

    /// The recipient rows that fitted in the response.
    #[must_use]
    pub fn recipients(&self) -> &[OpenRecipient] {
        &self.recipients
    }

    /// Whether the server sent fewer rows than it said there were recipients.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        usize::from(self.recipient_count) > self.recipients.len()
    }

    /// Reads a `RopOpenMessage` body, after `RopId`, `OutputHandleIndex` and a zero `ReturnValue`.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Self::read_body(r, RopId::OPEN_MESSAGE, None)
    }

    /// Reads a `RopOpenEmbeddedMessage` body, whose only difference is a `Reserved` byte and the
    /// `MessageId` in front of the rest.
    ///
    /// [MS-OXCROPS] §2.2.6.16.2 — success response buffer
    pub(crate) fn read_embedded(r: &mut Reader<'_>) -> Result<Self> {
        let _reserved = r.u8()?;
        let id = MessageId::new(r.u64()?);
        Self::read_body(r, RopId::OPEN_EMBEDDED_MESSAGE, Some(id))
    }

    fn read_body(r: &mut Reader<'_>, rop: RopId, embedded_id: Option<MessageId>) -> Result<Self> {
        let has_named_properties = r.u8()? != 0;
        let subject_prefix = typed_string(r)?;
        let normalized_subject = typed_string(r)?;
        let recipient_count = r.u16()?;

        // The column set is read and dropped: it describes the RecipientProperties inside each
        // RecipientRow, which is the part deliberately left undecoded. Consuming it is not
        // optional — the rows come after it.
        let column_count = r.u16()?;
        for _ in 0..column_count {
            let _tag = r.u32()?;
        }

        let row_count = r.u8()?;
        let mut recipients = Vec::new();
        for _ in 0..row_count {
            recipients.push(OpenRecipient::read(r)?);
        }

        Ok(Self {
            rop,
            embedded_id,
            has_named_properties,
            subject_prefix,
            normalized_subject,
            recipient_count,
            recipients,
        })
    }
}

/// Reads a `TypedString`, whose leading byte says both whether a string follows and how it is
/// encoded.
///
/// `0x03` is the one worth knowing about: a *reduced* Unicode string, which is a UTF-16LE string
/// whose every unit had a zero high byte, sent with those bytes removed. Reading it as 8-bit text
/// happens to give the right characters only because the rule that produced it is exactly "every
/// codepoint is below 0x100" — so this decodes byte-by-byte to a `char`, which is that rule stated
/// forwards rather than a lucky coincidence.
///
/// [MS-OXCDATA] §2.11.7 — `TypedString` structure
fn typed_string(r: &mut Reader<'_>) -> Result<Option<String>> {
    let at = r.position();
    Ok(match r.u8()? {
        0x00 => None,
        0x01 => Some(String::new()),
        0x02 => Some(r.ascii_z()?),
        0x03 => Some(r.bytes_z()?.iter().copied().map(char::from).collect()),
        0x04 => Some(r.utf16_z()?),
        kind => {
            return Err(Error::InvalidStringType { kind, at });
        }
    })
}

/// Encodes a `RopOpenMessage` request.
///
/// [MS-OXCROPS] §2.2.6.1.1 — request buffer
pub(crate) fn encode_open_message(
    w: &mut Writer,
    input: u8,
    output: u8,
    folder: FolderId,
    message: MessageId,
    mode: MessageMode,
) {
    w.u8(RopId::OPEN_MESSAGE.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(output)
        .u16(CODE_PAGE_FROM_LOGON)
        .u64(folder.as_u64())
        .u8(mode.flags())
        .u64(message.as_u64());
}

/// Encodes a `RopGetAttachmentTable` request.
///
/// [MS-OXCROPS] §2.2.6.17.1 — request buffer
pub(crate) fn encode_get_attachment_table(w: &mut Writer, input: u8, output: u8) {
    w.u8(RopId::GET_ATTACHMENT_TABLE.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(output)
        .u8(ATTACHMENT_TABLE_UNICODE);
}

/// Encodes a `RopOpenAttachment` request.
///
/// [MS-OXCROPS] §2.2.6.12.1 — request buffer
pub(crate) fn encode_open_attachment(w: &mut Writer, input: u8, output: u8, number: u32) {
    w.u8(RopId::OPEN_ATTACHMENT.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(output)
        .u8(OPEN_ATTACHMENT_READ_ONLY)
        .u32(number);
}

/// Encodes a `RopOpenEmbeddedMessage` request.
///
/// Read-only, and not parameterised: an embedded message is reached through its attachment and by
/// no other route, so changing one means saving the attachment and then the message that holds it —
/// a chain nothing in this crate offers.
///
/// [MS-OXCROPS] §2.2.6.16.1 — request buffer
pub(crate) fn encode_open_embedded_message(w: &mut Writer, input: u8, output: u8) {
    w.u8(RopId::OPEN_EMBEDDED_MESSAGE.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(output)
        .u16(CODE_PAGE_FROM_LOGON)
        .u8(MessageMode::ReadOnly.flags());
}

#[cfg(test)]
mod tests;
