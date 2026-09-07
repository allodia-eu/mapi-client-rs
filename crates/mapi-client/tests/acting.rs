//! Sending, moving and flagging against a scripted server: what goes on the wire, and what the
//! client does when the server says it did only part of the job.
//!
//! Every operation here **succeeds as a ROP while doing less than it was asked to**, and reports
//! the difference in a byte a caller has to look at. A live server will not produce one of those
//! on request and the captured corpus cannot hold one, so a server a test writes itself is the
//! only way to see the client's answer to a partial move, a partial read-flag change, a
//! destination handle that resolved to nothing, and an operation the server decided to run
//! asynchronously after being asked not to.
//!
//! [MS-OXCROPS] §2.2.7.1 — `RopSubmitMessage`
//! [MS-OXCROPS] §2.2.4.6 — `RopMoveCopyMessages`
//! [MS-OXCROPS] §2.2.6.10 — `RopSetReadFlags`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use mapi_client::{
    ErrorCode, FolderId, Logon, MessageClass, MessageId, PropertyTag, PropertyValue, ReadFlags,
    Recipient, TaggedValue,
};
use support::writes::{
    MESSAGE_HANDLE, NEW_MESSAGE_ID, create_message_response, modify_recipients_response,
    move_copy_messages_response, move_copy_null_destination, open_message_response,
    progress_response, remove_all_recipients_response, save_changes_response,
    set_properties_response, set_read_flags_response, submit_message_response,
};
use support::{
    LOGON_HANDLE, MapiServer, connect_ok, execute_body, logon_response, opcodes,
    open_folder_response,
};

/// The folder every test here works in, and the one a move sends things to.
const FOLDER: u64 = 0x0D00_0000_0000_0042;
const ARCHIVE: u64 = 0x0D00_0000_0000_0099;

/// The slots a batch fills. Slot 0 is always the handle it was bound to.
const MADE: u8 = 1;
const SECOND: u8 = 2;

/// The handles the two `RopOpenFolder`s in a move produce.
const SOURCE_HANDLE: u32 = 0x0000_0001;
const DESTINATION_HANDLE: u32 = 0x0000_0002;

/// The message every test here acts on.
const MESSAGES: [MessageId; 1] = [MessageId::new(NEW_MESSAGE_ID)];

/// A logged-on connection, with the two round trips that get there already answered.
async fn logged_on(server: &MapiServer) -> Logon {
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));
    server
        .client()
        .connect()
        .await
        .unwrap()
        .logon()
        .await
        .unwrap()
}

/// The handle table a batch leaves behind when it opened two folders off the bound logon.
const TWO_FOLDERS: [u32; 3] = [LOGON_HANDLE, SOURCE_HANDLE, DESTINATION_HANDLE];

/// Both folders open in the same buffer as the move, so archiving is one round trip.
#[tokio::test]
async fn a_move_opens_both_folders_and_the_move_in_one_round_trip() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_folder_response(MADE);
    answers.extend(open_folder_response(SECOND));
    answers.extend(move_copy_messages_response(MADE, false));
    server.reply_ok(execute_body(&answers, &TWO_FOLDERS));

    let complete = logon
        .folder(FolderId::new(FOLDER))
        .move_messages(&MESSAGES, FolderId::new(ARCHIVE))
        .await
        .unwrap();
    assert!(complete);

    let rops = server.rops(2).await;
    assert_eq!(opcodes(&rops), [0x02, 0x02, 0x33, 0x01, 0x01]);
    // The move reads slot 1 and writes into slot 2. Getting those the same way round would move
    // the message into the folder it is already in, and report success.
    let start = rops.iter().position(|&byte| byte == 0x33).unwrap();
    assert_eq!(rops[start..start + 4], [0x33, 0x00, MADE, SECOND]);
    // RopId, LogonId, two handle indices, a two-byte count, one id, then the two trailing flags.
    assert_eq!(rops[start + 14], 0x00, "WantAsynchronous stays zero");
    assert_eq!(rops[start + 15], 0x00, "WantCopy is clear for a move");
}

/// A copy differs from a move by the one byte the server reads as `WantCopy`.
#[tokio::test]
async fn a_copy_differs_from_a_move_by_one_byte_on_the_wire() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_folder_response(MADE);
    answers.extend(open_folder_response(SECOND));
    answers.extend(move_copy_messages_response(MADE, false));
    server.reply_ok(execute_body(&answers, &TWO_FOLDERS));

    logon
        .folder(FolderId::new(FOLDER))
        .copy_messages(&MESSAGES, FolderId::new(ARCHIVE))
        .await
        .unwrap();

    let rops = server.rops(2).await;
    let start = rops.iter().position(|&byte| byte == 0x33).unwrap();
    // RopId, LogonId, two handle indices, a two-byte count, one id, WantAsynchronous, WantCopy.
    assert_eq!(rops[start + 14], 0x00, "WantAsynchronous stays zero");
    assert_eq!(rops[start + 15], 0x01, "WantCopy is set for a copy");
}

/// `PartialCompletion` is the only place "some of those messages are still where they were" is
/// said, and the ROP succeeds either way.
#[tokio::test]
async fn a_partial_move_is_reported_rather_than_read_as_success() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_folder_response(MADE);
    answers.extend(open_folder_response(SECOND));
    answers.extend(move_copy_messages_response(MADE, true));
    server.reply_ok(execute_body(&answers, &TWO_FOLDERS));

    let complete = logon
        .folder(FolderId::new(FOLDER))
        .move_messages(&MESSAGES, FolderId::new(ARCHIVE))
        .await
        .unwrap();
    assert!(!complete, "the flag said the move was incomplete");
}

/// The refusal that carries a body. Its four-byte `DestHandleIndex` is what a decoder reading it
/// as an ordinary failure would leave in the stream — so the release after it has to still decode.
#[tokio::test]
async fn a_null_destination_refusal_is_decoded_rather_than_desynchronising() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_folder_response(MADE);
    answers.extend(open_folder_response(SECOND));
    answers.extend(move_copy_null_destination(MADE, u32::from(SECOND), true));
    server.reply_ok(execute_body(&answers, &TWO_FOLDERS));

    let complete = logon
        .folder(FolderId::new(FOLDER))
        .move_messages(&MESSAGES, FolderId::new(ARCHIVE))
        .await
        .unwrap();
    assert!(!complete);
}

/// Every one of these ROPs is sent with `WantAsynchronous = 0`. A server that answers `RopProgress`
/// anyway has not reported the flag the client is reading, so this is an error rather than a
/// silently confident `true`.
#[tokio::test]
async fn a_progress_response_is_refused_rather_than_read_as_completion() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_folder_response(MADE);
    answers.extend(open_folder_response(SECOND));
    answers.extend(progress_response(MADE, 0, 3));
    server.reply_ok(execute_body(&answers, &TWO_FOLDERS));

    let refused = logon
        .folder(FolderId::new(FOLDER))
        .move_messages(&MESSAGES, FolderId::new(ARCHIVE))
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("asynchronously"),
        "the failure names what the server did: {refused}"
    );
}

/// The read state is a folder-level operation over a list of ids, so a page of a contents table is
/// one ROP — and the flags byte is where the read receipt is suppressed.
#[tokio::test]
async fn marking_messages_read_sends_the_flags_byte_that_suppresses_the_receipt() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_folder_response(MADE);
    answers.extend(set_read_flags_response(MADE, false));
    server.reply_ok(execute_body(&answers, &[LOGON_HANDLE, SOURCE_HANDLE]));

    let complete = logon
        .folder(FolderId::new(FOLDER))
        .set_read(&MESSAGES, ReadFlags::ReadQuietly)
        .await
        .unwrap();
    assert!(complete);

    let rops = server.rops(2).await;
    assert_eq!(opcodes(&rops), [0x02, 0x66, 0x01]);
    let start = rops.iter().position(|&byte| byte == 0x66).unwrap();
    assert_eq!(rops[start + 3], 0x00, "WantAsynchronous stays zero");
    assert_eq!(rops[start + 4], 0x01, "rfSuppressReceipt");
}

/// [MS-OXCMSG] §2.2.3.10.1: "the client MUST include the rfSuppressReceipt bit with this flag".
/// Sending `0x04` alone is what the type makes unwritable, and this is the wire proof of it.
#[tokio::test]
async fn marking_messages_unread_never_sends_the_clear_bit_alone() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_folder_response(MADE);
    answers.extend(set_read_flags_response(MADE, true));
    server.reply_ok(execute_body(&answers, &[LOGON_HANDLE, SOURCE_HANDLE]));

    let complete = logon
        .folder(FolderId::new(FOLDER))
        .set_read(&MESSAGES, ReadFlags::Unread)
        .await
        .unwrap();
    assert!(!complete, "the flag said some messages were unchanged");

    let rops = server.rops(2).await;
    let start = rops.iter().position(|&byte| byte == 0x66).unwrap();
    assert_eq!(rops[start + 4], 0x05, "rfClearReadFlag | rfSuppressReceipt");
}

/// A send is the save batch with one more ROP in it, and the order is the whole of the correctness:
/// `RopSubmitMessage` acts on what is in the store, so a submit before the save would send an
/// empty message and succeed.
#[tokio::test]
async fn a_send_submits_after_the_save_and_in_the_same_buffer() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut created = create_message_response(MADE);
    created.extend(set_properties_response(MADE, &[]));
    created.extend(modify_recipients_response(MADE));
    server.reply_ok(execute_body(&created, &[LOGON_HANDLE, MESSAGE_HANDLE]));

    let mut sent = save_changes_response(MADE, NEW_MESSAGE_ID);
    sent.extend(submit_message_response(MADE));
    server.reply_ok(execute_body(&sent, &[MESSAGE_HANDLE]));

    let saved = logon
        .folder(FolderId::new(FOLDER))
        .create_message(MessageClass::Note)
        .set([TaggedValue::new(
            PropertyTag::SUBJECT,
            PropertyValue::String("Sent by a test".into()),
        )
        .unwrap()])
        .to([Recipient::to("Ada", "ada@example.test").unwrap()])
        .keep_copy_in(FolderId::new(ARCHIVE))
        .deleting_the_original()
        .send()
        .await
        .unwrap();

    assert_eq!(saved.id(), MessageId::new(NEW_MESSAGE_ID));
    assert!(saved.is_sent());

    // The first buffer carries the two properties that decide what happens to the message after
    // it goes: without PidTagSentMailSvrEID nothing records the send, and without
    // PidTagDeleteAfterSubmit the draft stays behind for good.
    let created = server.rops(2).await;
    assert!(
        contains_tag(&created, PropertyTag::SENT_MAIL_SVR_EID.as_u32()),
        "PidTagSentMailSvrEID is in the property write"
    );
    assert!(
        contains_tag(&created, PropertyTag::DELETE_AFTER_SUBMIT.as_u32()),
        "PidTagDeleteAfterSubmit is in the property write"
    );

    assert_eq!(opcodes(&server.rops(3).await), [0x0C, 0x32, 0x01]);
}

/// A save is the same batch without the submit. The two paths differ by one ROP, and nothing else
/// about them may differ — least of all whether the message was created.
#[tokio::test]
async fn a_save_sends_no_submit_at_all() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut created = create_message_response(MADE);
    created.extend(set_properties_response(MADE, &[]));
    server.reply_ok(execute_body(&created, &[LOGON_HANDLE, MESSAGE_HANDLE]));

    let saved = save_changes_response(MADE, NEW_MESSAGE_ID);
    server.reply_ok(execute_body(&saved, &[MESSAGE_HANDLE]));

    let saved = logon
        .folder(FolderId::new(FOLDER))
        .create_message(MessageClass::Note)
        .save()
        .await
        .unwrap();
    assert!(!saved.is_sent());
    assert_eq!(opcodes(&server.rops(3).await), [0x0C, 0x01]);
}

/// Replacing a recipient list is two ROPs and not one. `RopModifyRecipients` addresses rows by
/// position and can never shorten a list, so a draft cut from three recipients to two keeps the
/// third — and the only place that shows up is in whose mailbox the message lands.
#[tokio::test]
async fn replacing_recipients_clears_the_list_before_writing_the_new_one() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_message_response(MADE);
    answers.extend(set_properties_response(MADE, &[]));
    answers.extend(remove_all_recipients_response(MADE));
    answers.extend(modify_recipients_response(MADE));
    answers.extend(save_changes_response(MADE, NEW_MESSAGE_ID));
    answers.extend(submit_message_response(MADE));
    server.reply_ok(execute_body(&answers, &[LOGON_HANDLE, MESSAGE_HANDLE]));

    logon
        .folder(FolderId::new(FOLDER))
        .message(MessageId::new(NEW_MESSAGE_ID))
        .update()
        .replacing_recipients()
        .to([Recipient::to("Grace", "grace@example.test").unwrap()])
        .and_send()
        .save()
        .await
        .unwrap();

    // Open, properties, clear, add, save, submit, release — the clear before the add, and the
    // submit after the save.
    assert_eq!(
        opcodes(&server.rops(2).await),
        [0x03, 0x0A, 0x0D, 0x0E, 0x0C, 0x32, 0x01]
    );
}

/// A refused submit is reported rather than swallowed, and the message is still saved: only the
/// sending did not happen, so what is left behind is an ordinary draft.
#[tokio::test]
async fn a_refused_submit_is_reported() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_message_response(MADE);
    answers.extend(support::rop_failed(
        0x32,
        MADE,
        ErrorCode::TOO_MANY_RECIPIENTS.as_u32(),
    ));
    server.reply_ok(execute_body(&answers, &[LOGON_HANDLE, MESSAGE_HANDLE]));

    let refused = logon
        .folder(FolderId::new(FOLDER))
        .message(MessageId::new(NEW_MESSAGE_ID))
        .send()
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("TooManyRecips"),
        "the refusal names the code: {refused}"
    );
}

/// Whether a property write in a ROP buffer names a tag. The buffer is not parsed here — a
/// contains check is enough to say the property was sent at all, which is the claim.
fn contains_tag(rops: &[u8], tag: u32) -> bool {
    rops.windows(4).any(|window| window == tag.to_le_bytes())
}
