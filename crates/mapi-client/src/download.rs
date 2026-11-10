//! An incremental download: what changed in a folder since a state, one event at a time.
//!
//! **Pull-driven.** Nothing is fetched until [`Download::try_next`] needs it, and nothing is
//! fetched once the caller stops asking, so a consumer that stops reading stops the download. Each
//! fetch is one `RopFastTransferSourceGetBuffer` round trip; the first also configures the download
//! and uploads the state it starts from.
//!
//! **Checkpointed as it goes.** Exchange answers `RopSynchronizationGetTransferState` with the
//! *initial* state until a download's stream has ended ([MS-OXCFXICS] notes `<2>` and `<42>`), so
//! the only way to resume one that was cut short is the client's own: every message delivered is
//! folded into [`Download::checkpoint`] by its MID and change number (§3.3.5.6), and the server's
//! final state replaces the checkpoint when the stream ends, being "a much more efficient version".
//! Persist the checkpoint whenever the events up to it are committed, and a killed process resumes
//! where it stopped.
//!
//! [MS-OXCFXICS] §3.3.4.1 — client behaviour for a synchronization download
//! [MS-OXCFXICS] §3.3.5.6 — client-side checkpointing

use mapi_proto::fasttransfer::{ContentsSync, SyncEvent};
use mapi_proto::{
    ContentsDownload, Execution, FolderId, HandleSlot, IcsState, ObjectHandle, PropertyTag,
    RopBatch, RopId, RopResponse, SyncScope, TransferStatus,
};

use crate::connection::{self, Connection};
use crate::error::{Error, Result};

/// The most state bytes one request uploads.
///
/// [MS-OXCRPC] §3.1.4.2.1.2.1 caps a request's ROP data at 32 KB; this leaves room for the ROPs
/// that travel with the upload in the first request — the folder open, the configure with its
/// restriction and property list, and the first `GetBuffer`.
const UPLOAD_CHUNK: usize = 16 * 1024;

/// One step of uploading the starting state.
#[derive(Clone, Debug)]
enum Upload {
    Begin(PropertyTag, u32),
    Part(Vec<u8>),
    End,
}

/// A content synchronization download in progress: pull-driven, one `GetBuffer` per fetch, and
/// checkpointed as each message is handed over. See [`Logon::download`](crate::Logon::download).
#[derive(Debug)]
pub struct Download<'a> {
    connection: &'a mut Connection,
    logon: ObjectHandle,
    folder: FolderId,
    configuration: ContentsDownload,
    checkpoint: IcsState,
    /// The upload of the starting state, and how far it has got.
    upload: Vec<Upload>,
    uploaded: usize,
    /// The download context, once the server has opened one.
    context: Option<ObjectHandle>,
    /// The folder, when a refused opening left it open: opened, then refused at or before the
    /// configure, so the release after it never ran. The next opening uses it rather than opening
    /// it again, and closing releases it. A refusal after the configure always comes after the
    /// release too: [MS-OXCROPS] §3.2.4.2 substitutes a `RopBackoff` "in place of the response for
    /// the delayed ROP request", and a `RopRelease` has no response to substitute.
    left_open: Option<ObjectHandle>,
    parser: ContentsSync,
    /// Whether the server has reported the stream `Done`.
    transferred: bool,
}

impl<'a> Download<'a> {
    pub(crate) fn new(
        connection: &'a mut Connection,
        logon: ObjectHandle,
        folder: FolderId,
        configuration: ContentsDownload,
        state: IcsState,
    ) -> Result<Self> {
        let upload = upload_steps(&state)?;
        Ok(Self {
            connection,
            logon,
            folder,
            configuration,
            checkpoint: state,
            upload,
            uploaded: 0,
            context: None,
            left_open: None,
            parser: ContentsSync::new(),
            transferred: false,
        })
    }

    /// The next event, fetching another buffer when the ones in hand are used up; `None` once the
    /// download has ended.
    ///
    /// # Errors
    ///
    /// Whatever a round trip failed with. [`Error::Backoff`] when the server is too busy to send
    /// the next buffer: nothing has been lost, and calling again after the wait carries on.
    /// [`Error::Protocol`] for a stream that could not be split into elements at all — one
    /// unreadable *object* is an event, [`SyncEvent::Unreadable`] or [`SyncEvent::Failed`], and
    /// never an error.
    pub async fn try_next(&mut self) -> Result<Option<SyncEvent>> {
        loop {
            if let Some(event) = self.parser.next_event()? {
                self.fold(&event);
                return Ok(Some(event));
            }
            // `Done` first: a stream that reached `IncrSyncEnd` is checked for bytes after it.
            if self.transferred {
                self.parser.finish()?;
                return Ok(None);
            }
            if self.parser.is_finished() {
                return Ok(None);
            }
            self.fetch().await?;
        }
    }

    /// The state to resume from: the starting state with every message delivered so far folded
    /// in, or the server's final state once the stream has ended.
    ///
    /// A message is folded in when [`try_next`](Self::try_next) hands it over, so persisting this
    /// after committing an event covers that event and every one before it.
    #[must_use]
    pub const fn checkpoint(&self) -> &IcsState {
        &self.checkpoint
    }

    /// Releases the server's download context and hands back the state to resume from.
    ///
    /// Dropping a download instead is not an error: the context then lives until the Session
    /// Context ends, which matters only for a long-lived session that downloads many folders.
    ///
    /// # Errors
    ///
    /// Whatever the round trip failed with; the state is lost with it only in the sense that it was
    /// never persisted — call [`checkpoint`](Self::checkpoint) first if that matters.
    ///
    /// [MS-OXCROPS] §2.2.15.3 — `RopRelease`
    pub async fn close(self) -> Result<IcsState> {
        let held: Vec<ObjectHandle> = self.context.into_iter().chain(self.left_open).collect();
        if !held.is_empty() {
            let mut batch = RopBatch::new();
            for handle in held {
                let slot = batch.bind(handle);
                batch.release(slot);
            }
            self.connection
                .execute(batch, "releasing the download context")
                .await?;
        }
        Ok(self.checkpoint)
    }

    /// Folds an event into the checkpoint.
    fn fold(&mut self, event: &SyncEvent) {
        match event {
            SyncEvent::Message(change) => {
                let header = change.header();
                if let (Some(id), Some(change_number)) = (header.id(), header.change_number()) {
                    self.checkpoint
                        .record_message(id, change_number, header.is_associated());
                }
            }
            SyncEvent::State(state) => self.checkpoint.complete(state.clone()),
            _ => {}
        }
    }

    /// One round trip: the next part of the starting state, then the next buffer once that is all
    /// uploaded.
    ///
    /// The download's own position moves only once the answer is in hand, so a fetch abandoned part
    /// way leaves it where it was — and the connection [poisoned](Error::Poisoned), which is what
    /// says the server's side is unknown.
    async fn fetch(&mut self) -> Result<()> {
        let mut batch = RopBatch::new();
        let configuring = self.context.is_none();
        let (context, opened) = if let Some(handle) = self.context {
            (batch.bind(handle), None)
        } else {
            let logon = batch.bind(self.logon);
            // The folder's long-term id names the replica its messages are numbered in, which is
            // the mapping checkpointing needs; see `IcsState::map_replica`.
            batch.long_term_id_from_id(logon, self.folder.into());
            let folder = match self.left_open.take() {
                Some(handle) => batch.bind(handle),
                None => batch.open_folder(logon, self.folder),
            };
            let context = batch.synchronization_configure(folder, &self.configuration);
            // The context is a Server object of its own, as a table is, so the folder handle is not
            // kept open for it.
            batch.release(folder);
            (context, Some(folder))
        };
        let next = self.add_upload(&mut batch, context);
        let fetching = next == self.upload.len();
        if fetching {
            batch.fast_transfer_get_buffer(context);
        }

        let execution = self.connection.execute_allowing_refusals(batch).await?;
        if configuring {
            self.context = execution.handle(context).filter(|handle| !handle.is_none());
            if let Some(long_term) = execution
                .responses()
                .iter()
                .find_map(RopResponse::as_long_term_id)
            {
                self.checkpoint
                    .map_replica(self.folder.replica_id(), long_term.database_guid());
            }
            let configured = execution.responses().iter().any(|response| {
                matches!(response, RopResponse::Succeeded { rop } | RopResponse::Failed { rop, .. }
                    if *rop == RopId::SYNCHRONIZATION_CONFIGURE)
            });
            self.left_open = opened
                .filter(|_| !configured)
                .and_then(|folder| execution.handle(folder))
                .filter(|handle| !handle.is_none());
        }
        // The upload moves on by exactly what the server carried out, refused batch or not. A busy
        // `GetBuffer` comes after the whole upload; a `RopBackoff` or `RopBufferTooSmall` can stop
        // the batch part way through it, and "all subsequent ROP requests SHOULD NOT be processed"
        // ([MS-OXCROPS] §3.2.4.2, §3.2.4.3). A retry that sent a carried-out step again would hand
        // the context that part of its state twice.
        let carried = execution
            .responses()
            .iter()
            .filter_map(upload_outcome)
            .take_while(|succeeded| *succeeded)
            .count();
        self.uploaded = self.uploaded.saturating_add(carried).min(next);
        if let Some(error) = execution.responses().iter().find_map(refusal) {
            return Err(error);
        }
        if fetching {
            self.absorb(&execution)?;
        }
        Ok(())
    }

    /// Adds as much of the remaining upload as one request carries, handing back where it stops.
    ///
    /// Parts are packed by size, so a state of several small properties — every resumed download's
    /// — goes up in the same request as the configure and the first `GetBuffer`.
    fn add_upload(&self, batch: &mut RopBatch, context: HandleSlot) -> usize {
        let mut bytes = 0_usize;
        let mut next = self.uploaded;
        for step in self.upload.iter().skip(self.uploaded) {
            match step {
                Upload::Begin(tag, size) => {
                    batch.upload_state_begin(context, *tag, *size);
                }
                Upload::Part(part) => {
                    let total = bytes.saturating_add(part.len());
                    if bytes > 0 && total > UPLOAD_CHUNK {
                        break;
                    }
                    bytes = total;
                    batch.upload_state_continue(context, part);
                }
                Upload::End => {
                    batch.upload_state_end(context);
                }
            }
            next = next.saturating_add(1);
        }
        next
    }

    /// Takes a buffer out of the answer and feeds it to the parser.
    fn absorb(&mut self, execution: &Execution) -> Result<()> {
        let buffer = execution
            .responses()
            .iter()
            .find_map(RopResponse::as_fast_transfer_buffer)
            .ok_or(Error::Unexpected {
                expected: "a RopFastTransferSourceGetBuffer response",
                found: "no buffer in the batch's responses",
            })?;
        // [MS-OXCFXICS] §2.2.3.1.1.5.2: `Error` is "a nonrecoverable error" and "the ReturnValue
        // field ... contains a code for that error", which `refusal` has already reported. Beside a
        // successful `ReturnValue` it is the server failing without saying why, and not a stream
        // that ended early.
        if buffer.status() == TransferStatus::Error {
            return Err(Error::Unexpected {
                expected: "an error code beside a TransferStatus of Error",
                found: "a successful ReturnValue",
            });
        }
        self.parser.feed(buffer.data());
        if buffer.status().is_final() {
            self.transferred = true;
        }
        Ok(())
    }
}

/// The steps that upload a state's properties: for each, a begin, its bytes in parts, and an end.
///
/// A first synchronization uploads nothing, which is how the server knows it is one.
///
/// [MS-OXCFXICS] §3.3.4.3.1 — uploading the initial ICS state
fn upload_steps(state: &IcsState) -> Result<Vec<Upload>> {
    let mut steps = Vec::new();
    for (tag, bytes) in state.state_properties() {
        let size = u32::try_from(bytes.len()).map_err(|_| {
            Error::Protocol(mapi_proto::Error::RopBufferTooLarge {
                bytes: bytes.len(),
                limit: 0xFFFF_FFFF,
            })
        })?;
        steps.push(Upload::Begin(tag, size));
        for part in bytes.chunks(UPLOAD_CHUNK) {
            steps.push(Upload::Part(part.to_vec()));
        }
        steps.push(Upload::End);
    }
    Ok(steps)
}

/// Turns a refusal in a download's batch into the error that says what to do about it, or `None`
/// for a response that is not one.
///
/// A busy server is the refusal a caller simply waits out: [MS-OXCFXICS] §3.3.5.9.1 has the
/// client "wait at least the period of time specified in `BackoffTime` before retrying the ROP".
/// Every other refusal — a whole-batch `RopBackoff` among them — is the one every batch can meet.
fn refusal(response: &RopResponse) -> Option<Error> {
    match response {
        RopResponse::FastTransferBusy { backoff_ms } => Some(Error::Backoff {
            duration_ms: *backoff_ms,
        }),
        RopResponse::Failed { rop, .. } => connection::refusal(response, during(*rop)),
        _ => connection::refusal(response, "the download"),
    }
}

/// Whether one of the upload's ROPs succeeded, or `None` for a response to any other ROP.
fn upload_outcome(response: &RopResponse) -> Option<bool> {
    let (rop, succeeded) = match response {
        RopResponse::Succeeded { rop } => (*rop, true),
        RopResponse::Failed { rop, .. } => (*rop, false),
        _ => return None,
    };
    matches!(
        rop,
        RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_BEGIN
            | RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_CONTINUE
            | RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_END
    )
    .then_some(succeeded)
}

/// What a refused ROP of a download was doing, in the caller's terms.
fn during(rop: RopId) -> &'static str {
    match rop {
        RopId::OPEN_FOLDER => "opening the folder to download",
        RopId::LONG_TERM_ID_FROM_ID => "naming the folder's replica",
        RopId::SYNCHRONIZATION_CONFIGURE => "configuring the download",
        RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_BEGIN
        | RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_CONTINUE
        | RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_END => "uploading the starting state",
        RopId::FAST_TRANSFER_SOURCE_GET_BUFFER => "fetching the next buffer",
        _ => "the download",
    }
}

/// The scope a download of `folder` covers, for checking a state against.
pub(crate) fn scope(
    mailbox: mapi_proto::Guid,
    folder: FolderId,
    configuration: &ContentsDownload,
) -> Result<SyncScope> {
    Ok(SyncScope::contents(
        mailbox,
        folder,
        configuration.restriction_ref(),
    )?)
}
