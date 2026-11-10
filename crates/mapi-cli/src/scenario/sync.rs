//! An incremental download of the Inbox, and the one after it.
//!
//! The first download is a first synchronization: every message, the deletions there are none of,
//! the final state. It spans several `RopFastTransferSourceGetBuffer` responses, which is what puts
//! a stream split across buffers into the corpus. The second resumes from a checkpoint and reports
//! nothing.
//!
//! **The second download does not start from the server's final state**, and that is deliberate.
//! A final state's `MetaTagCnsetSeen` runs up to the highest change number in the whole *mailbox* —
//! measured on Exchange Server SE `15.02.2562.056`, it moved when a draft was created and deleted
//! in another folder — so a request uploading it would differ on every capture after any other
//! scenario had written. It starts from the checkpoint the first download kept as it went, taken
//! as the last message was handed over and before the final state replaced it: only the Inbox's
//! own messages' ids and change numbers, which move only when the Inbox does. The final states the
//! server sends back still carry the mailbox-wide bound; capture rewrites that one value (see
//! `normalise`).
//!
//! **Both download a metadata set, not whole messages.** A whole message brings every property it
//! has, and Exchange writes a fresh GUID into several of them — the `Message-ID`, the
//! `X-MS-Exchange-Organization-Network-Message-Id` header, the conversation-tracking string — which
//! no scrub rule derived from the lab can know in advance and `Assert-NoSecrets.ps1` rightly
//! refuses. A metadata pass is also what a sync engine sends first, and it puts
//! `OnlySpecifiedProperties` into the corpus; the HTML body is in the set so that the seeded large
//! message still splits the stream across buffers. `mapi-client`'s live suite downloads whole
//! messages.
//!
//! [MS-OXCFXICS] §3.3.5.6 — client-side checkpointing

use mapi_client::mapi_proto::fasttransfer::SyncEvent;
use mapi_client::{ContentsDownload, MapiClient, PropertyFilter, PropertyTag, WellKnownFolder};

use crate::Failure;
use crate::capture::Recorder;

/// The metadata set both downloads ask for.
pub(crate) const METADATA: [PropertyTag; 5] = [
    PropertyTag::SUBJECT,
    PropertyTag::MESSAGE_CLASS,
    PropertyTag::MESSAGE_DELIVERY_TIME,
    PropertyTag::MESSAGE_FLAGS,
    PropertyTag::BODY_HTML,
];

/// The download configuration both downloads use.
fn configuration() -> ContentsDownload {
    ContentsDownload::new().properties(PropertyFilter::Only(METADATA.to_vec()))
}

/// Two downloads of the Inbox, the second from a checkpoint of the first.
pub(super) async fn sync(client: &MapiClient, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("");
    let connection = client.connect().await?;
    recorder.label("logon");
    let mut logon = connection.logon().await?;
    let inbox = logon.folder_id(WellKnownFolder::Inbox)?;

    recorder.label("download");
    let mut download = logon.download(inbox, configuration(), None)?;
    let mut delivered = 0_usize;
    let mut checkpoint = None;
    while let Some(event) = download.try_next().await? {
        if matches!(event, SyncEvent::Message(_)) {
            delivered = delivered.saturating_add(1);
            checkpoint = Some(download.checkpoint().clone());
        }
    }
    recorder.label("download-release");
    download.close().await?;
    println!("  {delivered} message(s) in the first download");
    let checkpoint = checkpoint.ok_or_else(|| {
        Failure::from("the first download delivered no message to checkpoint".to_owned())
    })?;

    recorder.label("resume");
    let mut resumed = logon.download(inbox, configuration(), Some(checkpoint))?;
    let mut changes = 0_usize;
    while let Some(event) = resumed.try_next().await? {
        if matches!(event, SyncEvent::Message(_)) {
            changes = changes.saturating_add(1);
        }
    }
    recorder.label("resume-release");
    resumed.close().await?;
    if changes > 0 {
        return Err(Failure::from(format!(
            "the download resumed from the checkpoint reported {changes} change(s). The Inbox \
             changed between the two downloads, or the checkpoint is wrong — either way the \
             capture would not be one a re-capture reproduces."
        )));
    }

    recorder.label("");
    logon.disconnect().await?;
    Ok(())
}
