//! The ROPs of an incremental download: configuring one, uploading the state it starts from, and
//! fetching the stream it produces.
//!
//! A download is four kinds of ROP in a fixed order. `RopSynchronizationConfigure` opens a download
//! context on a folder; the client uploads its ICS state into that context one property at a time,
//! each as `RopSynchronizationUploadStateStreamBegin`, `…Continue` and `…End`; then
//! `RopFastTransferSourceGetBuffer` is sent until the server reports the stream done.
//!
//! **Configuration is a type, not a set of flag words.** Most of the bits are not choices at all
//! for a client that wants a correct answer — `Eid` and `CN` are what client-side checkpointing
//! needs, `NoForeignIdentifiers` is a SHOULD, and `Unicode` with `ForceUnicode` is what keeps
//! strings out of the session's code page — so [`ContentsDownload`] always sets those and exposes
//! the rest as named choices.
//!
//! [MS-OXCROPS] §2.2.12.4 — `RopFastTransferSourceGetBuffer`
//! [MS-OXCROPS] §2.2.13 — the ICS ROPs
//! [MS-OXCFXICS] §2.2.3.2.1.1.1 — `RopSynchronizationConfigure` request buffer

use crate::error::{Error, ErrorCode, Result};
use crate::ics::SyncKind;
use crate::oxcdata::{PropertyTag, Restriction, ValueContext};
use crate::rop::batch::LOGON_ID;
use crate::rop::{RopId, RopResponse};
use crate::wire::{Reader, Writer};

/// `SendOptions`: `Unicode`, `RecoverMode` and `ForceUnicode`. [MS-OXCFXICS] §2.2.3.1.1.1.1
///
/// `RecoverMode` is what makes the server report an object it cannot produce with `errorInfo`
/// instead of failing the whole download (§2.2.4.3.4).
const SEND_OPTIONS: u8 = 0x01 | 0x04 | 0x08;
/// `SendOptions` `PartialItem`. [MS-OXCFXICS] §2.2.3.1.1.1.1
const PARTIAL_ITEM: u8 = 0x10;

/// `SynchronizationFlags` always set: `Unicode` (which MUST match the send option) and
/// `NoForeignIdentifiers`, which "Clients SHOULD set". [MS-OXCFXICS] §2.2.3.2.1.1.1
const SYNC_FLAGS: u16 = 0x0001 | 0x0100;
/// `SynchronizationFlags` `ReadState`.
const READ_STATE: u16 = 0x0008;
/// `SynchronizationFlags` `FAI`.
const FAI: u16 = 0x0010;
/// `SynchronizationFlags` `Normal`.
const NORMAL: u16 = 0x0020;
/// `SynchronizationFlags` `OnlySpecifiedProperties`.
const ONLY_SPECIFIED_PROPERTIES: u16 = 0x0080;
/// `SynchronizationFlags` `Progress`.
const PROGRESS: u16 = 0x8000;

/// `SynchronizationExtraFlags` always set: `Eid`, `MessageSize` and `CN`. [MS-OXCFXICS]
/// §2.2.3.2.1.1.1 — `Eid` and `CN` are what client-side checkpointing reads (§3.3.5.6).
const EXTRA_FLAGS: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
/// `SynchronizationExtraFlags` `OrderByDeliveryTime`.
const ORDER_BY_DELIVERY_TIME: u32 = 0x0000_0008;

/// `BufferSize` sentinel: let the server size the buffer. [MS-OXCFXICS] §3.3.5.7.1 — "Clients
/// SHOULD set the value of the `BufferSize` field in the ROP request to a sentinel value of 0xBABE"
const SERVER_SIZED: u16 = 0xBABE;

/// `MaximumBufferSize`. The server answers with "the residual size of the output buffer minus
/// result structure overhead, or [...] `MaximumBufferSize`, whichever is smaller"
/// ([MS-OXCFXICS] §3.2.5.8.1.5), so the largest value leaves the choice to the residual.
const MAXIMUM_BUFFER_SIZE: u16 = 0xFFFF;

/// Which messages a download covers.
///
/// Not part of the synchronization scope: §3.3.5.5 says these flags "do not modify the
/// synchronization scope; they just filter the output".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MessageKinds {
    /// Normal messages only — mail, calendar items, contacts.
    #[default]
    Normal,
    /// FAI messages only — the hidden configuration messages a folder carries.
    Associated,
    /// Both.
    Both,
}

impl MessageKinds {
    const fn flags(self) -> u16 {
        match self {
            Self::Normal => NORMAL,
            Self::Associated => FAI,
            Self::Both => NORMAL | FAI,
        }
    }
}

/// Which properties a download carries.
///
/// [MS-OXCFXICS] §3.2.5.9.1.1 — `PropertyTags`, and the `OnlySpecifiedProperties` flag that
/// decides whether they are an inclusion list or an exclusion list
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PropertyFilter {
    /// Everything except these. Empty, the default, is everything.
    #[default]
    All,
    /// Everything except the properties named.
    Except(Vec<PropertyTag>),
    /// Only the properties named.
    ///
    /// **Subobjects are properties here.** Recipients come only if
    /// [`PropertyTag::MESSAGE_RECIPIENTS`] is listed and attachments only if
    /// [`PropertyTag::MESSAGE_ATTACHMENTS`] is ([MS-OXCFXICS] §2.2.1.7), so a metadata pass that
    /// wants the recipients has to say so.
    Only(Vec<PropertyTag>),
}

/// A content synchronization download, as `RopSynchronizationConfigure` describes it.
///
/// What is always on, and why: `Unicode` and `ForceUnicode`, so every string arrives as
/// `PtypString`; `RecoverMode`, so an object the server cannot produce is reported in place
/// rather than failing the download; `NoForeignIdentifiers`, which "Clients SHOULD set"; and `Eid`,
/// `CN` and `MessageSize`, so every change carries the MID and change number checkpointing folds
/// and the size an adapter reports. `BestBody` is never set: note `<16>` says Exchange 2013 and
/// later do not support it.
///
/// [MS-OXCFXICS] §2.2.3.2.1.1.1 — `RopSynchronizationConfigure` request buffer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentsDownload {
    restriction: Option<Restriction>,
    properties: PropertyFilter,
    messages: MessageKinds,
    /// `SendOptions`, `SynchronizationFlags` and `SynchronizationExtraFlags`, less the bits that
    /// follow from `properties` and `messages`.
    send: u8,
    sync: u16,
    extra: u32,
}

impl Default for ContentsDownload {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentsDownload {
    /// Every normal message in the folder, whole, in no particular order, with read-state changes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            restriction: None,
            properties: PropertyFilter::All,
            messages: MessageKinds::Normal,
            send: SEND_OPTIONS,
            sync: SYNC_FLAGS | READ_STATE,
            extra: EXTRA_FLAGS,
        }
    }

    /// Only the messages this restriction matches — a date floor, typically.
    ///
    /// **The restriction is part of the synchronization scope**, so a state obtained under one
    /// cannot be used under another; see [`SyncScope`](crate::SyncScope).
    #[must_use]
    pub fn restriction(mut self, restriction: Restriction) -> Self {
        self.restriction = Some(restriction);
        self
    }

    /// Which properties to carry.
    #[must_use]
    pub fn properties(mut self, filter: PropertyFilter) -> Self {
        self.properties = filter;
        self
    }

    /// Which messages to cover.
    #[must_use]
    pub const fn messages(mut self, kinds: MessageKinds) -> Self {
        self.messages = kinds;
        self
    }

    /// Whether to report read-state changes. On by default.
    #[must_use]
    pub const fn read_state(mut self, report: bool) -> Self {
        self.sync = set(self.sync, READ_STATE, report);
        self
    }

    /// Whether a changed message may arrive as only the property groups that changed.
    ///
    /// [MS-OXCFXICS] §2.2.4.3.15 — `messageChangePartial`
    #[must_use]
    pub const fn partial_items(mut self, allow: bool) -> Self {
        self.send = if allow {
            self.send | PARTIAL_ITEM
        } else {
            self.send & !PARTIAL_ITEM
        };
        self
    }

    /// Whether to report how much is coming.
    #[must_use]
    pub const fn progress(mut self, report: bool) -> Self {
        self.sync = set(self.sync, PROGRESS, report);
        self
    }

    /// Whether messages arrive newest first, by delivery time.
    ///
    /// [MS-OXCFXICS] §3.2.5.9.1.1 — "the client receives the newest messages first"
    #[must_use]
    pub const fn newest_first(mut self, newest_first: bool) -> Self {
        self.extra = if newest_first {
            self.extra | ORDER_BY_DELIVERY_TIME
        } else {
            self.extra & !ORDER_BY_DELIVERY_TIME
        };
        self
    }

    /// The restriction, if one was given.
    #[must_use]
    pub const fn restriction_ref(&self) -> Option<&Restriction> {
        self.restriction.as_ref()
    }

    /// The three option words, as the request carries them.
    const fn flags(&self) -> (u8, u16, u32) {
        let mut sync = self.sync | self.messages.flags();
        if matches!(self.properties, PropertyFilter::Only(_)) {
            sync |= ONLY_SPECIFIED_PROPERTIES;
        }
        (self.send, sync, self.extra)
    }
}

/// `flags` with `bit` set or cleared.
const fn set(flags: u16, bit: u16, on: bool) -> u16 {
    if on { flags | bit } else { flags & !bit }
}

/// Encodes a `RopSynchronizationConfigure` request for a contents download.
///
/// # Errors
///
/// Whatever the restriction refused to encode, and [`Error::RopBufferTooLarge`] for a restriction
/// or a property list past what its 16-bit count can describe.
///
/// [MS-OXCROPS] §2.2.13.1.1 — request buffer
pub(crate) fn encode_configure(
    w: &mut Writer,
    input: u8,
    output: u8,
    download: &ContentsDownload,
) -> Result<()> {
    let mut restriction = Writer::new();
    if let Some(filter) = &download.restriction {
        filter.write(&mut restriction, ValueContext::Object)?;
    }
    let restriction = restriction.finish();
    let tags: &[PropertyTag] = match &download.properties {
        PropertyFilter::All => &[],
        PropertyFilter::Except(tags) | PropertyFilter::Only(tags) => tags,
    };
    let (send, sync, extra) = download.flags();

    w.u8(RopId::SYNCHRONIZATION_CONFIGURE.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(output)
        .u8(SyncKind::Contents.as_u8())
        .u8(send)
        .u16(sync)
        .u16(short(restriction.len())?)
        .bytes(&restriction)
        .u32(extra)
        .u16(short(tags.len())?);
    for tag in tags {
        w.u32(tag.as_u32());
    }
    Ok(())
}

/// Encodes a `RopSynchronizationUploadStateStreamBegin` request.
///
/// [MS-OXCROPS] §2.2.13.9.1 — request buffer
pub(crate) fn encode_upload_state_begin(w: &mut Writer, input: u8, tag: PropertyTag, size: u32) {
    w.u8(RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_BEGIN.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u32(tag.as_u32())
        .u32(size);
}

/// Encodes a `RopSynchronizationUploadStateStreamContinue` request.
///
/// [MS-OXCROPS] §2.2.13.10.1 — request buffer
pub(crate) fn encode_upload_state_continue(w: &mut Writer, input: u8, data: &[u8]) -> Result<()> {
    let size = u32::try_from(data.len()).map_err(|_| Error::RopBufferTooLarge {
        bytes: data.len(),
        limit: 0xFFFF_FFFF,
    })?;
    w.u8(RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_CONTINUE.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u32(size)
        .bytes(data);
    Ok(())
}

/// Encodes a `RopSynchronizationUploadStateStreamEnd` request.
///
/// [MS-OXCROPS] §2.2.13.11.1 — request buffer
pub(crate) fn encode_upload_state_end(w: &mut Writer, input: u8) {
    w.u8(RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_END.as_u8())
        .u8(LOGON_ID)
        .u8(input);
}

/// Encodes a `RopSynchronizationGetTransferState` request.
///
/// [MS-OXCROPS] §2.2.13.8.1 — request buffer
pub(crate) fn encode_get_transfer_state(w: &mut Writer, input: u8, output: u8) {
    w.u8(RopId::SYNCHRONIZATION_GET_TRANSFER_STATE.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(output);
}

/// Encodes a `RopFastTransferSourceGetBuffer` request, letting the server size the buffer.
///
/// [MS-OXCROPS] §2.2.12.4.1 — request buffer
pub(crate) fn encode_get_buffer(w: &mut Writer, input: u8) {
    w.u8(RopId::FAST_TRANSFER_SOURCE_GET_BUFFER.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u16(SERVER_SIZED)
        .u16(MAXIMUM_BUFFER_SIZE);
}

/// A count for a 16-bit field, or the refusal.
fn short(count: usize) -> Result<u16> {
    u16::try_from(count).map_err(|_| Error::RopBufferTooLarge {
        bytes: count,
        limit: usize::from(u16::MAX),
    })
}

/// Where a download stands after a buffer.
///
/// [MS-OXCFXICS] §2.2.3.1.1.5.2 — `TransferStatus`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransferStatus {
    /// `Error`, `0x0000` — the download stopped; `ReturnValue` says why.
    Error,
    /// `Partial`, `0x0001` — more is coming.
    Partial,
    /// `NoRoom`, `0x0002` — more is coming. Note `<8>`: Exchange 2010 and later do not send it.
    NoRoom,
    /// `Done`, `0x0003` — that was the last buffer.
    Done,
    /// A value the document does not define, as received.
    Other(u16),
}

impl TransferStatus {
    const fn from_u16(raw: u16) -> Self {
        match raw {
            0x0000 => Self::Error,
            0x0001 => Self::Partial,
            0x0002 => Self::NoRoom,
            0x0003 => Self::Done,
            other => Self::Other(other),
        }
    }

    /// Whether the stream is over, one way or the other: a client "MUST stop sending this ROP on a
    /// download context as soon as it receives `TransferStatus` field values of Done or Error"
    /// ([MS-OXCFXICS] §3.3.5.7.1).
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Done | Self::Error)
    }
}

/// One buffer of a `FastTransfer` stream.
///
/// [MS-OXCROPS] §2.2.12.4.2 — response buffer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetBufferResponse {
    status: TransferStatus,
    in_progress: u16,
    total_steps: u16,
    data: Vec<u8>,
}

impl GetBufferResponse {
    /// Where the download stands.
    #[must_use]
    pub const fn status(&self) -> TransferStatus {
        self.status
    }

    /// Steps done so far, for display only.
    #[must_use]
    pub const fn in_progress(&self) -> u16 {
        self.in_progress
    }

    /// Approximate steps in all. Note `<11>`: Exchange 2010 and later send `0x0001`.
    #[must_use]
    pub const fn total_steps(&self) -> u16 {
        self.total_steps
    }

    /// The bytes of the stream this buffer carries.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Takes the bytes out.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Reads a successful response, after `ReturnValue`.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let (status, in_progress, total_steps, size) = read_head(r)?;
        Ok(Self {
            status,
            in_progress,
            total_steps,
            data: r.bytes(usize::from(size))?.to_vec(),
        })
    }
}

/// The fields every `RopFastTransferSourceGetBuffer` response carries after `ReturnValue`,
/// `TransferBufferSize` last.
fn read_head(r: &mut Reader<'_>) -> Result<(TransferStatus, u16, u16, u16)> {
    let status = TransferStatus::from_u16(r.u16()?);
    let in_progress = r.u16()?;
    let total_steps = r.u16()?;
    let _reserved = r.u8()?;
    let size = r.u16()?;
    Ok((status, in_progress, total_steps, size))
}

/// A refused `RopFastTransferSourceGetBuffer`, after `ReturnValue`: unlike almost every other ROP's
/// refusal, it goes on.
///
/// [MS-OXCROPS] §2.2.12.4.2 gives this ROP one response layout and no failure layout. The transfer
/// fields always follow `ReturnValue`; `TransferBuffer` is "present if the `ReturnValue` is not
/// 0x00000480", and `BackoffTime` only when it is. So `ServerBusy` is the milliseconds to wait, and
/// any other refusal is the transfer fields and a buffer, skipped. [MS-OXCFXICS] §2.2.3.1.1.5.2
/// says otherwise of the buffer — it "SHOULD only exist if the value of the `ReturnValue` field is
/// Success" — and a `TransferBufferSize` of zero satisfies both readings.
///
/// Measured on Exchange Server SE `15.02.2562.056`: a `GetBuffer` aimed at a folder handle was
/// refused with `ecNotSupported`, followed by the nine bytes of the transfer fields, all zero, an
/// empty buffer, and then the next ROP's response.
pub(crate) fn read_refusal(r: &mut Reader<'_>, code: ErrorCode) -> Result<RopResponse> {
    let (_, _, _, size) = read_head(r)?;
    if code == ErrorCode::SERVER_BUSY {
        return Ok(RopResponse::FastTransferBusy {
            backoff_ms: r.u32()?,
        });
    }
    let _ = r.bytes(usize::from(size))?;
    Ok(RopResponse::Failed {
        rop: RopId::FAST_TRANSFER_SOURCE_GET_BUFFER,
        code,
    })
}

#[cfg(test)]
mod tests;
