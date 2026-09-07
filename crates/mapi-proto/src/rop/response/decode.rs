//! Turning a ROP output buffer into a list of decoded responses.
//!
//! Split from the [`RopResponse`] enum next door because the two answer different questions: that
//! file says what a response *is*, and this one says how a buffer becomes a list of them. The
//! rules that make the second hard all live here.
//!
//! Responses are read by **taking each `RopId` off the stream**, never positionally against the
//! request list. Four reasons, each of which breaks a positional decoder:
//!
//! * `RopRelease` produces no response at all when it succeeds, so the counts do not line up.
//! * The server may substitute `RopBackoff` or `RopBufferTooSmall` for a response that was asked
//!   for, or `RopProgress` for one it chose to run asynchronously.
//! * A failing ROP's response stops right after `ReturnValue`, so its success fields are simply
//!   absent — which is why that field is read before anything else.
//! * Two refusals are exceptions to the line above, and both would desynchronise everything after
//!   them. `RopLogon` answering `ecWrongServer` appends a redirect naming the server to use
//!   instead; `RopMoveCopyMessages` answering `ecDstNullObject` appends a four-byte
//!   `DestHandleIndex` and a `PartialCompletion`.
//!
//! [MS-OXCROPS] §2.2.1 — ROP output buffers

use crate::error::{Error, ErrorCode, Result};
use crate::oxcdata::PropertyTag;
use crate::rop::send::is_null_destination;
use crate::rop::{
    CreateAttachmentResponse, CreateMessageResponse, DeleteMessagesResponse, GetPropertiesResponse,
    GetTableResponse, IdFromLongTermIdResponse, LogonResponse, LongTermIdFromIdResponse,
    MoveCopyMessagesResponse, OpenFolderResponse, OpenMessageResponse, ProgressResponse,
    PropertyIdsResponse, PropertyNamesResponse, PropertyProblemsResponse, QueryRowsResponse,
    ReadStreamResponse, RopId, RopResponse, SaveChangesResponse, SetColumnsResponse,
    SetReadFlagsResponse, StreamSizeResponse, TableStatusResponse, WriteStreamResponse,
};
use crate::wire::Reader;

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
            // The two exceptions to "a failing ROP stops after ReturnValue". Both append fields,
            // and reading either as a bare failure leaves those bytes in the stream — so the next
            // RopId is taken from the middle of a field and every later response is nonsense.
            out.push(if rop == RopId::LOGON && code == ErrorCode::WRONG_SERVER {
                read_logon_redirect(&mut r)?
            } else if rop == RopId::MOVE_COPY_MESSAGES && is_null_destination(code) {
                RopResponse::MoveCopyMessages(MoveCopyMessagesResponse::read_null_destination(
                    &mut r,
                )?)
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
        | RopId::REMOVE_ALL_RECIPIENTS
        | RopId::SAVE_CHANGES_ATTACHMENT
        | RopId::SUBMIT_MESSAGE
        | RopId::COMMIT_STREAM => RopResponse::Succeeded { rop },
        RopId::MOVE_COPY_MESSAGES => {
            RopResponse::MoveCopyMessages(MoveCopyMessagesResponse::read(r)?)
        }
        RopId::SET_READ_FLAGS => RopResponse::SetReadFlags(SetReadFlagsResponse::read(r)?),
        RopId::PROGRESS => RopResponse::Progress(ProgressResponse::read(r)?),
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
