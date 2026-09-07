//! What one decoded ROP response is, and the questions a caller can ask of it.
//!
//! The buffer that produces these is [`decode`]'s business; this file is the shape of the answer.
//! The one thing worth knowing here is that **success is not the same question as "did it do what
//! I asked"**. Four of these variants carry a flag saying the server did part of the work, and the
//! ROP returned success in every one of those cases.
//!
//! [MS-OXCROPS] §2.2.1 — ROP output buffers

use crate::error::ErrorCode;
use crate::oxcdata::{LongTermId, PropertySet, ShortTermId};
use crate::rop::{
    CreateAttachmentResponse, CreateMessageResponse, DeleteMessagesResponse, GetPropertiesResponse,
    GetTableResponse, IdFromLongTermIdResponse, LogonResponse, LongTermIdFromIdResponse,
    MoveCopyMessagesResponse, OpenFolderResponse, OpenMessageResponse, ProgressResponse,
    PropertyIdsResponse, PropertyNamesResponse, PropertyProblemsResponse, QueryRowsResponse,
    ReadStreamResponse, RopId, SaveChangesResponse, SetColumnsResponse, SetReadFlagsResponse,
    StreamSizeResponse, TableStatusResponse, WriteStreamResponse,
};

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
    /// `RopRemoveAllRecipients`, `RopSaveChangesAttachment`, `RopCommitStream` and
    /// `RopSubmitMessage` all answer with a bare `ReturnValue`: what they did is in the handle
    /// table, in the store or on its way to a transport, and there is no body at all. The `RopId`
    /// is kept so a batch issuing several can still tell which succeeded.
    ///
    /// **For `RopSubmitMessage` this is the whole answer.** The message was accepted for sending;
    /// whether it is delivered is not something any response can say.
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
    /// A successful `RopMoveCopyMessages`, or the null-destination refusal that also carries a
    /// body.
    ///
    /// As for the delete: the return value says the ROP ran, and the response says separately how
    /// much of it happened.
    MoveCopyMessages(MoveCopyMessagesResponse),
    /// A successful `RopSetReadFlags`.
    ///
    /// And again: `PartialCompletion` is where "some of those messages are unchanged" is reported.
    SetReadFlags(SetReadFlagsResponse),
    /// The server chose to run an operation asynchronously and answered with its progress.
    ///
    /// **Nothing in this crate asks for one.** Every ROP that could is sent with
    /// `WantAsynchronous = 0`, which [MS-OXCROPS] §2.2.4.6.1 makes a request flag rather than a
    /// server decision. This variant exists so that a server which sends one anyway is reported —
    /// the alternative is nine unread bytes and a decoder that reads the rest of the buffer as
    /// nonsense.
    ///
    /// [MS-OXCROPS] §2.2.8.13 — `RopProgress`
    Progress(ProgressResponse),
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

    /// The outcome, if this is a `RopMoveCopyMessages` response.
    #[must_use]
    pub const fn as_moved_messages(&self) -> Option<MoveCopyMessagesResponse> {
        match self {
            Self::MoveCopyMessages(response) => Some(*response),
            _ => None,
        }
    }

    /// The outcome, if this is a `RopSetReadFlags` response.
    #[must_use]
    pub const fn as_read_flags(&self) -> Option<SetReadFlagsResponse> {
        match self {
            Self::SetReadFlags(response) => Some(*response),
            _ => None,
        }
    }

    /// How far the server has got, if it answered asynchronously.
    #[must_use]
    pub const fn as_progress(&self) -> Option<ProgressResponse> {
        match self {
            Self::Progress(response) => Some(*response),
            _ => None,
        }
    }

    /// Whether this is a bare success for the ROP named.
    ///
    /// The only way to read a `RopSubmitMessage` response, which has no body at all.
    #[must_use]
    pub fn succeeded(&self, rop: RopId) -> bool {
        matches!(self, Self::Succeeded { rop: answered } if *answered == rop)
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

mod decode;

pub(crate) use decode::{Decoding, decode_all};

#[cfg(test)]
mod tests;
