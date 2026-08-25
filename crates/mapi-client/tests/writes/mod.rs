//! Creating items in a real mailbox, reading them back, and taking them out again.
//!
//! Every test here is **self-cleaning**: it creates, asserts and deletes, and it deletes on the way
//! out of a failure too. That is not tidiness — the calendar and contact counts the `items` suite
//! asserts are exact, so a test that leaves an item behind breaks a different test on the next run,
//! which is the most confusing way for a suite to fail.
//!
//! What these prove that no fixture can: that a message this crate wrote is a message *Exchange*
//! agrees is a message. A replay proves the request bytes match what a server once accepted; only a
//! live run proves the server then produced the item the request described.
//!
//! [MS-OXCMSG] §3.1.4.2 — creating a Message object

use mapi_client::{
    ATTACHMENT_COLUMNS, AttachMethod, AttachmentNumber, FolderId, Logon, MessageClass, MessageId,
    NewAttachment, PropertyTag, PropertyValue, Recipient, SpecialFolder, TaggedValue,
    WellKnownFolder,
};

use crate::client;

/// Contacts, and the one-off entry id a usable address needs.
mod contacts;

/// A single-instance appointment, and the update that changes one.
mod events;

/// The subject every item this suite creates carries, so that anything it leaves behind after a
/// crash is identifiable by eye rather than by date.
pub(crate) const MARKER: &str = "mapi-client-rs write test";

/// The attachment content, sized to cross the 16 KiB write chunk twice.
///
/// A single-chunk attachment would leave the loop in `NewAttachment::write` with no evidence
/// behind it, which is the write-side twin of a body that fits one read.
fn attachment_bytes() -> Vec<u8> {
    (0..40_000_u32)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

pub(crate) fn string(value: &str) -> PropertyValue {
    PropertyValue::String(value.into())
}

/// A draft with a body, a recipient and an attachment larger than one stream write.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_draft_survives_being_written_and_read_back() {
    let mut logon = client()
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let drafts = logon
        .special_folder(SpecialFolder::Drafts)
        .await
        .expect("a Drafts folder");
    let content = attachment_bytes();

    let saved = logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([
            TaggedValue::new(PropertyTag::SUBJECT, string(MARKER)).expect("a string tag"),
            TaggedValue::new(PropertyTag::BODY, string("Written by the live suite.\n"))
                .expect("a string tag"),
        ])
        .to([Recipient::to("Ada Lovelace", "ada@example.test").expect("a recipient")])
        .attach([NewAttachment::by_value("probe.bin", content.clone())
            .expect("a file name with no NUL in it")])
        .save()
        .await
        .expect("the draft saves");

    println!(
        "created {:#018x} with {} attachment(s), {} refused propert(y/ies)",
        saved.id().as_u64(),
        saved.attachments().len(),
        saved.problems().len()
    );
    for problem in saved.problems() {
        println!("  refused: {problem}");
    }
    assert_eq!(saved.attachments(), [AttachmentNumber::new(0)]);

    // Reported before the cleanup runs: a read that failed usually poisons the connection, and a
    // panic from the delete would then bury the failure that caused it.
    let outcome = check_draft(&mut logon, drafts, saved.id(), &content).await;
    if let Err(reason) = &outcome {
        println!("  the draft did not read back: {reason}");
    }

    let deleted = logon.folder(drafts).delete_messages(&[saved.id()]).await;
    outcome.expect("the draft reads back as it was written");
    assert!(
        deleted.expect("the draft deletes"),
        "the draft this test created is still in Drafts"
    );
    logon.disconnect().await.expect("Disconnect");
}

/// Reads the draft back, without unwinding — the caller deletes first and reports afterwards.
async fn check_draft(
    logon: &mut Logon,
    folder: FolderId,
    id: MessageId,
    content: &[u8],
) -> Result<(), String> {
    let opened = logon
        .message(folder, id)
        .open()
        .await
        .map_err(|error| format!("opening the draft: {error}"))?;
    if opened.normalized_subject() != Some(MARKER) {
        return Err(format!(
            "subject is {:?}, not {MARKER:?}",
            opened.normalized_subject()
        ));
    }
    if opened.recipient_count() != 1 {
        return Err(format!(
            "{} recipient(s), not the one that was written",
            opened.recipient_count()
        ));
    }
    println!(
        "read back {:?} with {} recipient(s)",
        opened.normalized_subject().unwrap_or_default(),
        opened.recipient_count()
    );

    let rows = logon
        .message(folder, id)
        .attachments()
        .columns(ATTACHMENT_COLUMNS)
        .collect()
        .await
        .map_err(|error| format!("reading the attachment table: {error}"))?;
    let method = rows
        .first()
        .and_then(|row| row.get(PropertyTag::ATTACH_METHOD))
        .and_then(PropertyValue::as_u32)
        .map(AttachMethod::new);
    if method != Some(AttachMethod::ByValue) {
        return Err(format!("{} attachment(s), method {method:?}", rows.len()));
    }

    let details = logon
        .message(folder, id)
        .attachment(AttachmentNumber::new(0))
        .properties()
        .read(mapi_client::ATTACHMENT_PROPERTIES)
        .await
        .map_err(|error| format!("reading the attachment's properties: {error}"))?;
    println!(
        "  attachment properties: size {:?}, name {:?}",
        details.get(PropertyTag::ATTACH_SIZE),
        details.string(PropertyTag::ATTACH_LONG_FILENAME)
    );

    // The whole point of a 40 KB attachment: it took three `RopWriteStream`s to get there, and
    // this is the only thing that says all three landed in the right order.
    let read_back = logon
        .message(folder, id)
        .attachment(AttachmentNumber::new(0))
        .content()
        .read()
        .await
        .map_err(|error| format!("reading the attachment: {error}"))?;
    if read_back.as_bytes() != content {
        return Err(format!(
            "the attachment came back as {} bytes, not the {} that were written",
            read_back.len(),
            content.len()
        ));
    }
    println!("attachment round-tripped {} byte(s)", read_back.len());
    Ok(())
}

/// A draft written into the Inbox and taken out again, which is what a fixture scenario does.
///
/// Separate from the first test because it asserts the *deletion*: `RopDeleteMessages` succeeds
/// whether or not it deleted anything, so the only proof is that the folder's contents table stops
/// naming the message.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_deleted_message_leaves_the_contents_table() {
    let mut logon = client()
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let inbox = logon.folder_id(WellKnownFolder::Inbox).expect("an Inbox");

    let saved = logon
        .folder(inbox)
        .create_message(MessageClass::Note)
        .set([TaggedValue::new(PropertyTag::SUBJECT, string(MARKER)).expect("a string tag")])
        .save()
        .await
        .expect("the message saves");

    assert!(
        contains(&mut logon, inbox, saved.id()).await,
        "the message this test created is not in the Inbox it was created in"
    );

    let deleted = logon
        .folder(inbox)
        .delete_messages(&[saved.id()])
        .await
        .expect("the message deletes");
    assert!(deleted, "the delete reported partial completion");
    assert!(
        !contains(&mut logon, inbox, saved.id()).await,
        "the message is still in the Inbox after a successful delete"
    );

    logon.disconnect().await.expect("Disconnect");
    println!("{:#018x} was created and removed", saved.id().as_u64());
}

/// Whether a folder's contents table still names a message.
async fn contains(logon: &mut Logon, folder: FolderId, id: MessageId) -> bool {
    logon
        .folder(folder)
        .contents()
        .columns([PropertyTag::MID])
        .collect()
        .await
        .expect("a contents table")
        .iter()
        .filter_map(mapi_client::PropertyRow::message_id)
        .any(|found| found == id)
}
