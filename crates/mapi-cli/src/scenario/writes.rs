//! The write conversation: a draft created, filled, read back and deleted.
//!
//! Its own scenario, and the first in the corpus that is not a read. Three assumptions the other
//! two rest on stop holding here, and this file is where each is dealt with:
//!
//! * **Re-capture mutates the mailbox.** `Verify-Fixtures.ps1` re-captures against the live lab and
//!   diffs, so a create-message scenario run twice would leave two messages and the lab would drift
//!   one item per run. This one deletes what it made, and the delete is the last thing it does
//!   before the `Disconnect`.
//! * **The server assigns an identifier that differs every run.** The message id is minted by the
//!   save and then travels in two later *request* bodies, which the replay tests compare byte for
//!   byte. The scenario declares it to the recorder — see [`Recorder::server_assigned`] — and the
//!   capture zeroes it wherever it appears, in requests and responses alike. On replay the client
//!   reads the zero back out of the fake server's answer and sends the same zero, so the bytes
//!   match.
//! * **Content is a redaction surface.** Everything written here is fixed text and a fixed byte
//!   pattern, chosen so that nothing in it could be mistaken for a scrub needle and so that two
//!   captures of an unchanged server agree.
//!
//! What this is evidence for, none of which the read scenarios carry:
//!
//! * `RopCreateMessage`, whose response commits nothing at all.
//! * `RopSetProperties` on a Message object rather than on the Store — the one place the existing
//!   corpus exercises a write, and there the server refused it.
//! * `RopModifyRecipients`, with a `RecipientRow` built from a one-off entry id.
//! * `RopCreateAttachment`, `RopOpenStream` in `Create` mode, `RopWriteStream` more than once,
//!   `RopCommitStream` and `RopSaveChangesAttachment` — in the order that does not lose the
//!   attachment.
//! * `RopSaveChangesMessage`, and the identifier it mints.
//! * `RopDeleteMessages`, and its `PartialCompletion` flag.

use mapi_client::{
    ATTACHMENT_COLUMNS, AttachMethod, AttachmentNumber, Logon, MessageClass, MessageId,
    NewAttachment, PropertyTag, PropertyValue, Recipient, SpecialFolder, TableString, TaggedValue,
};

use crate::Failure;
use crate::capture::Recorder;

/// The subject the draft carries.
///
/// Fixed text at a fixed length, because a length-preserving scrub cannot cope with content that
/// changes size between captures — and because anything this scenario leaves behind after a crash
/// should be identifiable by eye.
const SUBJECT: &str = "mapi-client-rs write scenario";

/// The body.
const BODY: &str = "Written by mapi-cli capture, and deleted again in the same session.\n";

/// The address the draft is sent to, which exists nowhere.
///
/// `example.test` is reserved by [RFC 6761] and names no real host, so a scenario that one day
/// grows a `RopSubmitMessage` cannot deliver anywhere by accident.
const RECIPIENT: &str = "ada@example.test";

/// How many bytes the attachment holds.
///
/// Past the 16 KiB this client writes and reads per round trip, so the corpus carries more than one
/// `RopWriteStream` and more than one `RopReadStream` for a single value. One chunk would leave
/// both loops with no evidence behind them — which is exactly how the read loop shipped a bug that
/// only a second chunk could find.
const ATTACHMENT_BYTES: usize = 24_000;

/// The file name the attachment carries.
const ATTACHMENT_NAME: &str = "capture.bin";

/// A fixed byte pattern, so two captures of an unchanged server agree byte for byte.
///
/// `index % 251` rather than a repeated block: a repeat would let a chunk boundary land in the
/// wrong place without changing the bytes, and 251 is prime so the period does not divide the
/// 16 KiB chunk.
fn attachment_content() -> Vec<u8> {
    (0..ATTACHMENT_BYTES)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

/// The whole write conversation, in one Session Context.
pub(super) async fn writes(
    client: &mapi_client::MapiClient,
    recorder: &Recorder,
) -> Result<(), Failure> {
    recorder.label("");
    let connection = client.connect().await?;

    recorder.label("logon");
    let mut logon = connection.logon().await?;

    recorder.label("drafts-folder");
    let drafts = logon.special_folder(SpecialFolder::Drafts).await?;

    let content = attachment_content();
    recorder.label("create-draft");
    let saved = logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([
            TaggedValue::new(PropertyTag::SUBJECT, PropertyValue::String(SUBJECT.into()))?,
            TaggedValue::new(PropertyTag::BODY, PropertyValue::String(BODY.into()))?,
        ])
        .to([Recipient::to(RECIPIENT, RECIPIENT)?])
        .attach([NewAttachment::by_value(ATTACHMENT_NAME, content.clone())?])
        .save()
        .await?;

    // Declared before anything else in the capture is written out. The identifier is the server's,
    // it differs every run, and it travels in the *request* bodies of the read and the delete
    // below — which the replay tests compare byte for byte.
    recorder.server_assigned(
        "the message id RopSaveChangesMessage minted",
        &saved.id().as_u64().to_le_bytes(),
    );

    println!(
        "  created {:#018x} with {} attachment(s)",
        saved.id().as_u64(),
        saved.attachments().len()
    );
    for problem in saved.problems() {
        println!("  the server refused {problem}");
    }
    if saved.attachments() != [AttachmentNumber::new(0)] {
        return Err(Failure::from(format!(
            "the attachment came back as {:?} rather than as #0, so the capture would carry an \
             attachment number nothing predicts.",
            saved.attachments()
        )));
    }

    let outcome = read_back(&mut logon, recorder, drafts, saved.id(), &content).await;

    // The cleanup runs whatever the read said, and its result is reported afterwards: a lab that
    // drifts one message per failed run is a worse problem than the failure that caused it.
    recorder.label("delete-draft");
    let deleted = logon.folder(drafts).delete_messages(&[saved.id()]).await;

    recorder.label("");
    logon.disconnect().await?;

    outcome?;
    if !deleted? {
        return Err(Failure::from(
            "the server reported partial completion on the delete, so the draft this scenario \
             created is still in the mailbox. Remove it before capturing again."
                .to_owned(),
        ));
    }
    println!("  deleted, so the mailbox is as it was found");
    Ok(())
}

/// Reads the draft back through the ordinary read path, which is what makes the capture a claim
/// about the write rather than about the request bytes alone.
async fn read_back(
    logon: &mut Logon,
    recorder: &Recorder,
    folder: mapi_client::FolderId,
    id: MessageId,
    content: &[u8],
) -> Result<(), Failure> {
    recorder.label("read-draft");
    let opened = logon.message(folder, id).open().await?;
    println!(
        "  read back {:?}, {} recipient(s)",
        opened.normalized_subject().unwrap_or_default(),
        opened.recipient_count()
    );
    if opened.normalized_subject() != Some(SUBJECT) || opened.recipient_count() != 1 {
        return Err(Failure::from(
            "the draft did not read back with the subject and the one recipient it was written \
             with, so the capture would record a write that did not do what it says."
                .to_owned(),
        ));
    }

    // A deliberately narrow set. `MESSAGE_PROPERTIES` carries `PidTagLastModificationTime`, which
    // is the moment of the capture and would differ on every run — and the whole value of this
    // corpus is that a difference means something.
    recorder.label("draft-properties");
    let properties = logon
        .message(folder, id)
        .properties()
        .read([
            PropertyTag::MESSAGE_CLASS,
            PropertyTag::SUBJECT,
            PropertyTag::HAS_ATTACHMENTS,
        ])
        .await?;
    let class = properties
        .string(PropertyTag::MESSAGE_CLASS)
        .map(TableString::as_str)
        .map(MessageClass::new);
    if class != Some(MessageClass::Note) {
        return Err(Failure::from(format!(
            "the draft's class is {class:?} rather than IPM.Note."
        )));
    }

    recorder.label("attachment-table");
    let rows = logon
        .message(folder, id)
        .attachments()
        .columns(ATTACHMENT_COLUMNS)
        .collect()
        .await?;
    let method = rows
        .first()
        .and_then(|row| row.get(PropertyTag::ATTACH_METHOD))
        .and_then(PropertyValue::as_u32)
        .map(AttachMethod::new);
    if method != Some(AttachMethod::ByValue) {
        return Err(Failure::from(format!(
            "{} attachment(s), method {method:?} rather than afByValue.",
            rows.len()
        )));
    }

    recorder.label("attachment-content");
    let read = logon
        .message(folder, id)
        .attachment(AttachmentNumber::new(0))
        .content()
        .read()
        .await?;
    println!("  attachment read back as {} byte(s)", read.len());
    if read.as_bytes() != content {
        return Err(Failure::from(format!(
            "the attachment came back as {} bytes rather than the {} that were written.",
            read.len(),
            content.len()
        )));
    }
    Ok(())
}
