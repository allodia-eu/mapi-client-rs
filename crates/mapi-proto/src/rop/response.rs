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
    GetPropertiesResponse, GetTableResponse, IdFromLongTermIdResponse, LogonResponse,
    LongTermIdFromIdResponse, OpenFolderResponse, PropertyProblemsResponse, QueryRowsResponse,
    RopId, SetColumnsResponse,
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
    /// A successful `RopQueryRows`, with its rows already decoded.
    QueryRows(QueryRowsResponse),
    /// A successful `RopGetPropertiesSpecific` or `RopGetPropertiesAll`.
    GetProperties(GetPropertiesResponse),
    /// A successful `RopSetProperties` or `RopDeleteProperties`.
    ///
    /// Success here is about the ROP, not about the properties: individual ones can have been
    /// refused and are named in the response.
    PropertyProblems(PropertyProblemsResponse),
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

        out.push(match rop {
            RopId::LOGON => RopResponse::Logon(LogonResponse::read(&mut r)?),
            RopId::OPEN_FOLDER => RopResponse::OpenFolder(OpenFolderResponse::read(&mut r)?),
            RopId::GET_HIERARCHY_TABLE | RopId::GET_CONTENTS_TABLE => {
                RopResponse::GetTable(GetTableResponse::read(&mut r)?)
            }
            RopId::SET_COLUMNS => RopResponse::SetColumns(SetColumnsResponse::read(&mut r)?),
            RopId::QUERY_ROWS => {
                let columns = context
                    .columns
                    .get(usize::from(handle_index))
                    .and_then(Option::as_deref)
                    .ok_or(Error::UnknownColumns { handle_index })?;
                RopResponse::QueryRows(QueryRowsResponse::read(&mut r, columns)?)
            }
            RopId::GET_PROPERTIES_SPECIFIC => {
                let tags = requested.ok_or(Error::UnrequestedProperties { at: r.position() })?;
                RopResponse::GetProperties(GetPropertiesResponse::read_row(&mut r, rop, tags)?)
            }
            RopId::GET_PROPERTIES_ALL => {
                RopResponse::GetProperties(GetPropertiesResponse::read_all(&mut r, rop)?)
            }
            RopId::SET_PROPERTIES | RopId::DELETE_PROPERTIES => {
                RopResponse::PropertyProblems(PropertyProblemsResponse::read(&mut r, rop)?)
            }
            RopId::ID_FROM_LONG_TERM_ID => {
                RopResponse::IdFromLongTermId(IdFromLongTermIdResponse::read(&mut r)?)
            }
            RopId::LONG_TERM_ID_FROM_ID => {
                RopResponse::LongTermIdFromId(LongTermIdFromIdResponse::read(&mut r)?)
            }
            // Every response is variable-length and none is self-describing, so there is no
            // honest way to skip one whose layout is unknown.
            _ => {
                return Err(Error::UnmodelledRop {
                    rop,
                    at: r.position(),
                });
            }
        });
    }

    Ok(out)
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
