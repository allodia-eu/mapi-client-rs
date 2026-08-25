//! Decoding a stream of ROP responses.
//!
//! Responses are read by **taking each `RopId` off the stream**, never positionally against the
//! request list. Three reasons, each of which breaks a positional decoder:
//!
//! * `RopRelease` produces no response at all when it succeeds, so the counts do not line up.
//! * The server may substitute `RopBackoff` or `RopBufferTooSmall` for a response that was asked
//!   for.
//! * A failing ROP's response stops right after `ReturnValue`, so its success fields are simply
//!   absent — which is why that field is read before anything else. With one exception: `RopLogon`
//!   answering `ecWrongServer` appends a redirect naming the server to use instead, and skipping it
//!   desynchronises the rest of the buffer.
//!
//! [MS-OXCROPS] §2.2.1 — ROP output buffers

use crate::error::{Error, ErrorCode, Result};
use crate::oxcdata::{LongTermId, PropertySet, PropertyTag, ShortTermId};
use crate::rop::{
    CreateAttachmentResponse, CreateMessageResponse, DeleteMessagesResponse, GetPropertiesResponse,
    GetTableResponse, IdFromLongTermIdResponse, LogonResponse, LongTermIdFromIdResponse,
    OpenFolderResponse, OpenMessageResponse, PropertyIdsResponse, PropertyNamesResponse,
    PropertyProblemsResponse, QueryRowsResponse, ReadStreamResponse, RopId, SaveChangesResponse,
    SetColumnsResponse, StreamSizeResponse, TableStatusResponse, WriteStreamResponse,
};
use crate::wire::Reader;

/// One decoded ROP response.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RopResponse {
    /// A successful `RopLogon`.
    Logon(LogonResponse),
    /// A successful `RopOpenFolder`.
    OpenFolder(OpenFolderResponse),
    /// A successful `RopGetHierarchyTable` or `RopGetContentsTable`.
    GetTable(GetTableResponse),
    /// A successful `RopSetColumns`.
    SetColumns(SetColumnsResponse),
    /// A successful `RopSortTable` or `RopRestrict`.
    ///
    /// Neither reports how many rows are left, so a restricted table's size is only knowable by
    /// reading it.
    TableStatus(TableStatusResponse),
    /// A successful `RopQueryRows`, with its rows already decoded.
    QueryRows(QueryRowsResponse),
    /// A successful `RopOpenMessage` or `RopOpenEmbeddedMessage`.
    OpenMessage(OpenMessageResponse),
    /// A successful `RopOpenStream` or `RopGetStreamSize`, reporting the stream's length.
    StreamSize(StreamSizeResponse),
    /// A successful `RopReadStream`. Empty data is how the end of the stream is reported.
    ReadStream(ReadStreamResponse),
    /// A ROP that succeeded and had nothing to report.
    ///
    /// `RopOpenAttachment`, `RopGetAttachmentTable`, `RopModifyRecipients`,
    /// `RopSaveChangesAttachment` and `RopCommitStream` all answer with a bare `ReturnValue`: what
    /// they did is in the handle table or in the store, and there is no body at all. The `RopId` is
    /// kept so a batch issuing several can still tell which succeeded.
    Succeeded {
        /// Which ROP.
        rop: RopId,
    },
    /// A successful `RopCreateMessage`.
    ///
    /// **Nothing exists yet.** The message is committed by `RopSaveChangesMessage` and by nothing
    /// else, so this response on its own means a handle was opened.
    CreateMessage(CreateMessageResponse),
    /// A successful `RopSaveChangesMessage`, carrying the id the message now has.
    SaveChanges(SaveChangesResponse),
    /// A successful `RopCreateAttachment`, carrying the number the new attachment was given.
    CreateAttachment(CreateAttachmentResponse),
    /// A successful `RopWriteStream`, saying how many bytes reached the stream.
    WriteStream(WriteStreamResponse),
    /// A successful `RopDeleteMessages`.
    ///
    /// Success here is about the ROP: the response says separately whether every message named was
    /// actually deleted.
    DeleteMessages(DeleteMessagesResponse),
    /// A successful `RopGetPropertiesSpecific` or `RopGetPropertiesAll`.
    GetProperties(GetPropertiesResponse),
    /// A successful `RopSetProperties` or `RopDeleteProperties`.
    ///
    /// Success here is about the ROP, not about the properties: individual ones can have been
    /// refused and are named in the response.
    PropertyProblems(PropertyProblemsResponse),
    /// A successful `RopGetPropertyIdsFromNames`.
    ///
    /// Its ids are positional against the names that were asked for, and this response carries no
    /// record of what those were.
    PropertyIds(PropertyIdsResponse),
    /// A successful `RopGetNamesFromPropertyIds`.
    PropertyNames(PropertyNamesResponse),
    /// A successful `RopIdFromLongTermId`.
    IdFromLongTermId(IdFromLongTermIdResponse),
    /// A successful `RopLongTermIdFromId`.
    LongTermIdFromId(LongTermIdFromIdResponse),
    /// A ROP the server refused. Its body stopped after `ReturnValue`.
    Failed {
        /// Which ROP failed.
        rop: RopId,
        /// Why.
        code: ErrorCode,
    },
    /// The mailbox is not on this server; log on again at `server_name`.
    ///
    /// The one refusal whose body does *not* stop after `ReturnValue`: `RopLogon` answering
    /// `ecWrongServer` appends `LogonFlags`, `ServerNameSize` and `ServerName`. Reading it as a
    /// bare failure would leave those bytes in the stream and decode every later response against
    /// them.
    ///
    /// [MS-OXCSTOR] §2.2.1.1.2 — `RopLogon` redirect response buffer
    /// [MS-OXCSTOR] §3.1.5.1 — create a Session Context with the named server and log on again
    LogonRedirect {
        /// The ESSDN of the server holding the mailbox.
        server_name: String,
    },
    /// The response did not fit in the `MaxRopOut` the request allowed.
    ///
    /// Everything from this point in the ROP list was not executed. Retrying with at least
    /// `size_needed` bytes is the documented remedy.
    ///
    /// [MS-OXCROPS] §2.2.15.1 — `RopBufferTooSmall`
    BufferTooSmall {
        /// The output buffer size the server needs.
        size_needed: u16,
    },
    /// The server is busy and is asking for a retry later.
    ///
    /// [MS-OXCROPS] §2.2.15.2 — `RopBackoff`
    Backoff {
        /// How long to wait before logging on again, in milliseconds.
        duration_ms: u32,
    },
}

impl RopResponse {
    /// The rows, if this is a `RopQueryRows` response.
    #[must_use]
    pub const fn as_query_rows(&self) -> Option<&QueryRowsResponse> {
        match self {
            Self::QueryRows(rows) => Some(rows),
            _ => None,
        }
    }

    /// The opened message, if this is a response to the ROP named.
    ///
    /// The ROP is a parameter rather than implied because reaching an embedded message opens its
    /// parent first, so one batch carries a response to each — and `RopOpenMessage`'s arrives
    /// first, so a caller taking whichever came first gets the wrong message.
    #[must_use]
    pub fn as_open_message(&self, rop: RopId) -> Option<&OpenMessageResponse> {
        match self {
            Self::OpenMessage(response) if response.rop() == rop => Some(response),
            _ => None,
        }
    }

    /// The new message, if this is a `RopCreateMessage` response.
    #[must_use]
    pub const fn as_created_message(&self) -> Option<CreateMessageResponse> {
        match self {
            Self::CreateMessage(response) => Some(*response),
            _ => None,
        }
    }

    /// The committed message, if this is a `RopSaveChangesMessage` response.
    ///
    /// The id it carries is the one that names the message from then on.
    #[must_use]
    pub const fn as_saved_message(&self) -> Option<SaveChangesResponse> {
        match self {
            Self::SaveChanges(response) => Some(*response),
            _ => None,
        }
    }

    /// The new attachment, if this is a `RopCreateAttachment` response.
    #[must_use]
    pub const fn as_created_attachment(&self) -> Option<CreateAttachmentResponse> {
        match self {
            Self::CreateAttachment(response) => Some(*response),
            _ => None,
        }
    }

    /// How many bytes landed, if this is a `RopWriteStream` response.
    #[must_use]
    pub const fn as_written(&self) -> Option<WriteStreamResponse> {
        match self {
            Self::WriteStream(response) => Some(*response),
            _ => None,
        }
    }

    /// The outcome, if this is a `RopDeleteMessages` response.
    #[must_use]
    pub const fn as_deleted_messages(&self) -> Option<DeleteMessagesResponse> {
        match self {
            Self::DeleteMessages(response) => Some(*response),
            _ => None,
        }
    }

    /// The stream's length, if this is a `RopOpenStream` or `RopGetStreamSize` response.
    #[must_use]
    pub const fn as_stream_size(&self) -> Option<StreamSizeResponse> {
        match self {
            Self::StreamSize(response) => Some(*response),
            _ => None,
        }
    }

    /// The bytes, if this is a `RopReadStream` response.
    #[must_use]
    pub const fn as_stream_data(&self) -> Option<&ReadStreamResponse> {
        match self {
            Self::ReadStream(response) => Some(response),
            _ => None,
        }
    }

    /// The table's status, if this is a `RopSortTable` or `RopRestrict` response.
    #[must_use]
    pub const fn as_table_status(&self) -> Option<TableStatusResponse> {
        match self {
            Self::TableStatus(response) => Some(*response),
            _ => None,
        }
    }

    /// The logon, if this is a `RopLogon` response.
    #[must_use]
    pub const fn as_logon(&self) -> Option<&LogonResponse> {
        match self {
            Self::Logon(logon) => Some(logon),
            _ => None,
        }
    }

    /// The properties, if this is a response to either of the property-reading ROPs.
    #[must_use]
    pub const fn as_properties(&self) -> Option<&PropertySet> {
        match self {
            Self::GetProperties(response) => Some(response.properties()),
            _ => None,
        }
    }

    /// The per-property outcomes, if this is a response to either of the property-writing ROPs.
    #[must_use]
    pub const fn as_property_problems(&self) -> Option<&PropertyProblemsResponse> {
        match self {
            Self::PropertyProblems(response) => Some(response),
            _ => None,
        }
    }

    /// The resolved ids, if this is a `RopGetPropertyIdsFromNames` response.
    #[must_use]
    pub const fn as_property_ids(&self) -> Option<&PropertyIdsResponse> {
        match self {
            Self::PropertyIds(response) => Some(response),
            _ => None,
        }
    }

    /// The names, if this is a `RopGetNamesFromPropertyIds` response.
    #[must_use]
    pub const fn as_property_names(&self) -> Option<&PropertyNamesResponse> {
        match self {
            Self::PropertyNames(response) => Some(response),
            _ => None,
        }
    }

    /// The converted identifier, if this is a `RopIdFromLongTermId` response.
    #[must_use]
    pub const fn as_short_term_id(&self) -> Option<ShortTermId> {
        match self {
            Self::IdFromLongTermId(response) => Some(response.id()),
            _ => None,
        }
    }

    /// The converted identifier, if this is a `RopLongTermIdFromId` response.
    #[must_use]
    pub const fn as_long_term_id(&self) -> Option<LongTermId> {
        match self {
            Self::LongTermIdFromId(response) => Some(response.id()),
            _ => None,
        }
    }

    /// The error code, if the server refused this ROP.
    ///
    /// A redirect is a refusal too: it reports [`ErrorCode::WRONG_SERVER`], so a caller that only
    /// looks here is not told the logon succeeded.
    #[must_use]
    pub const fn failure(&self) -> Option<ErrorCode> {
        match self {
            Self::Failed { code, .. } => Some(*code),
            Self::LogonRedirect { .. } => Some(ErrorCode::WRONG_SERVER),
            _ => None,
        }
    }

    /// The server to log on to instead, if the logon was redirected.
    #[must_use]
    pub fn redirect_server(&self) -> Option<&str> {
        match self {
            Self::LogonRedirect { server_name } => Some(server_name),
            _ => None,
        }
    }
}

/// What a response stream cannot supply for itself.
///
/// Both of these are facts about the *request*, and neither appears anywhere in the bytes coming
/// back. Grouping them makes it obvious that decoding a buffer in isolation is not something this
/// layer can do.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Decoding<'a> {
    /// The column set each handle slot's table was given, indexed by slot. Supplies the types a
    /// `RopQueryRows` response is encoded against.
    pub(crate) columns: &'a [Option<Vec<PropertyTag>>],
    /// The tag list of each `RopGetPropertiesSpecific` in the batch, in the order they were
    /// issued. Consumed in that order, because a response says nothing about which request it
    /// answers.
    pub(crate) property_tags: &'a [Vec<PropertyTag>],
}

/// Decodes every response in a ROP output buffer.
pub(crate) fn decode_all(rops: &[u8], context: Decoding<'_>) -> Result<Vec<RopResponse>> {
    let mut r = Reader::new(rops);
    let mut out = Vec::new();
    let mut property_tags = context.property_tags.iter();

    while !r.is_empty() {
        let rop = RopId::new(r.u8()?);

        match rop {
            RopId::BUFFER_TOO_SMALL => {
                let size_needed = r.u16()?;
                // The rest of the buffer echoes the ROP requests that were not executed.
                r.rest();
                out.push(RopResponse::BufferTooSmall { size_needed });
                break;
            }
            RopId::BACKOFF => {
                out.push(read_backoff(&mut r)?);
                continue;
            }
            _ => {}
        }

        // Taken whether the ROP succeeded or not: a refused fetch consumed its request's tags all
        // the same, and leaving them in the queue would decode the *next* fetch against them.
        let requested = if rop == RopId::GET_PROPERTIES_SPECIFIC {
            property_tags.next()
        } else {
            None
        };

        let handle_index = r.u8()?;
        let code = ErrorCode::new(r.u32()?);
        if !code.is_success() {
            // The single exception to "a failing ROP stops after ReturnValue".
            out.push(if rop == RopId::LOGON && code == ErrorCode::WRONG_SERVER {
                read_logon_redirect(&mut r)?
            } else {
                RopResponse::Failed { rop, code }
            });
            continue;
        }

        out.push(decode_success(
            &mut r,
            rop,
            handle_index,
            requested,
            context,
        )?);
    }

    Ok(out)
}

/// Decodes one successful response body, after `RopId`, the handle index and a zero `ReturnValue`.
///
/// Split out of [`decode_all`] because the loop around it is the part with the rules — the ROPs
/// that answer out of turn, the tag queue, the one refusal that carries a body — and a match arm
/// per ROP buries them.
fn decode_success(
    r: &mut Reader<'_>,
    rop: RopId,
    handle_index: u8,
    requested: Option<&Vec<PropertyTag>>,
    context: Decoding<'_>,
) -> Result<RopResponse> {
    Ok(match rop {
        RopId::LOGON => RopResponse::Logon(LogonResponse::read(r)?),
        RopId::OPEN_FOLDER => RopResponse::OpenFolder(OpenFolderResponse::read(r)?),
        RopId::GET_HIERARCHY_TABLE | RopId::GET_CONTENTS_TABLE => {
            RopResponse::GetTable(GetTableResponse::read(r)?)
        }
        RopId::SET_COLUMNS => RopResponse::SetColumns(SetColumnsResponse::read(r)?),
        RopId::SORT_TABLE | RopId::RESTRICT => {
            RopResponse::TableStatus(TableStatusResponse::read(r, rop)?)
        }
        // None of these has a response body at all: what each did is in the handle table or
        // in the store, and the buffer moves straight on to the next ROP.
        RopId::OPEN_ATTACHMENT
        | RopId::GET_ATTACHMENT_TABLE
        | RopId::MODIFY_RECIPIENTS
        | RopId::SAVE_CHANGES_ATTACHMENT
        | RopId::COMMIT_STREAM => RopResponse::Succeeded { rop },
        RopId::CREATE_MESSAGE => RopResponse::CreateMessage(CreateMessageResponse::read(r)?),
        RopId::SAVE_CHANGES_MESSAGE => RopResponse::SaveChanges(SaveChangesResponse::read(r)?),
        RopId::CREATE_ATTACHMENT => {
            RopResponse::CreateAttachment(CreateAttachmentResponse::read(r)?)
        }
        RopId::WRITE_STREAM => RopResponse::WriteStream(WriteStreamResponse::read(r)?),
        RopId::DELETE_MESSAGES => RopResponse::DeleteMessages(DeleteMessagesResponse::read(r)?),
        RopId::OPEN_MESSAGE => RopResponse::OpenMessage(OpenMessageResponse::read(r)?),
        RopId::OPEN_EMBEDDED_MESSAGE => {
            RopResponse::OpenMessage(OpenMessageResponse::read_embedded(r)?)
        }
        RopId::OPEN_STREAM | RopId::GET_STREAM_SIZE => {
            RopResponse::StreamSize(StreamSizeResponse::read(r, rop)?)
        }
        RopId::READ_STREAM => RopResponse::ReadStream(ReadStreamResponse::read(r)?),
        RopId::QUERY_ROWS => {
            let columns = context
                .columns
                .get(usize::from(handle_index))
                .and_then(Option::as_deref)
                .ok_or(Error::UnknownColumns { handle_index })?;
            RopResponse::QueryRows(QueryRowsResponse::read(r, columns)?)
        }
        RopId::GET_PROPERTIES_SPECIFIC => {
            let tags = requested.ok_or(Error::UnrequestedProperties { at: r.position() })?;
            RopResponse::GetProperties(GetPropertiesResponse::read_row(r, rop, tags)?)
        }
        RopId::GET_PROPERTIES_ALL => {
            RopResponse::GetProperties(GetPropertiesResponse::read_all(r, rop)?)
        }
        RopId::SET_PROPERTIES | RopId::DELETE_PROPERTIES => {
            RopResponse::PropertyProblems(PropertyProblemsResponse::read(r, rop)?)
        }
        RopId::GET_PROPERTY_IDS_FROM_NAMES => {
            RopResponse::PropertyIds(PropertyIdsResponse::read(r)?)
        }
        RopId::GET_NAMES_FROM_PROPERTY_IDS => {
            RopResponse::PropertyNames(PropertyNamesResponse::read(r)?)
        }
        RopId::ID_FROM_LONG_TERM_ID => {
            RopResponse::IdFromLongTermId(IdFromLongTermIdResponse::read(r)?)
        }
        RopId::LONG_TERM_ID_FROM_ID => {
            RopResponse::LongTermIdFromId(LongTermIdFromIdResponse::read(r)?)
        }
        // Every response is variable-length and none is self-describing, so there is no honest
        // way to skip one whose layout is unknown.
        _ => {
            return Err(Error::UnmodelledRop {
                rop,
                at: r.position(),
            });
        }
    })
}

/// Reads the tail of a `RopLogon` redirect, after `ReturnValue` of `ecWrongServer`.
///
/// `ServerNameSize` counts the terminating NUL, so the bytes are consumed by that count and the
/// name is taken from before the NUL. Consuming exactly `ServerNameSize` bytes is what keeps the
/// next ROP's response aligned.
///
/// [MS-OXCSTOR] §2.2.1.1.2 — `RopLogon` redirect response buffer
/// [MS-OXCROPS] §2.2.3.1.4 — field layout
fn read_logon_redirect(r: &mut Reader<'_>) -> Result<RopResponse> {
    let _logon_flags = r.u8()?;
    let size = usize::from(r.u8()?);
    let raw = r.bytes(size)?;
    let name = raw.split(|&b| b == 0).next().unwrap_or_default();
    Ok(RopResponse::LogonRedirect {
        server_name: String::from_utf8_lossy(name).into_owned(),
    })
}

/// [MS-OXCROPS] §2.2.15.2.1 — `RopBackoff` response buffer
fn read_backoff(r: &mut Reader<'_>) -> Result<RopResponse> {
    let _logon_id = r.u8()?;
    let duration_ms = r.u32()?;
    let rop_count = r.u8()?;
    // Each BackoffRop is a RopId and a duration. [MS-OXCROPS] §2.2.15.2.1.1
    for _ in 0..rop_count {
        r.bytes(5)?;
    }
    let additional = usize::from(r.u16()?);
    r.bytes(additional)?;
    Ok(RopResponse::Backoff { duration_ms })
}

#[cfg(test)]
mod tests;
