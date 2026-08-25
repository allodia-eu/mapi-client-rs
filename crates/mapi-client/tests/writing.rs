//! The write path against a scripted server: what it puts on the wire, and what it does when the
//! server answers something other than "all of it landed".
//!
//! The failures are the point. A short `RopWriteStream`, a `RopCreateAttachment` whose handle
//! never arrives and a `RopSetProperties` report that goes missing all **succeed** as ROPs, so a
//! live server will not produce one on request and the captured corpus cannot hold one. Only a
//! server a test writes itself can.
//!
//! [MS-OXCMSG] §3.1.4.3 — saving changes on a Message object
//! [MS-OXCPRPT] §3.1.4.16 — persisting a stream

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use mapi_client::{
    ErrorCode, FolderId, Logon, MessageClass, MessageId, NewAttachment, PropertyTag, PropertyValue,
    Recipient, TaggedValue,
};
use support::writes::{
    ATTACHMENT_HANDLE, MESSAGE_HANDLE, NEW_MESSAGE_ID, STREAM_HANDLE, create_attachment_response,
    create_message_response, delete_messages_response, modify_recipients_response,
    open_message_response, save_changes_response, set_properties_response, write_stream_response,
};
use support::{
    LOGON_HANDLE, MapiServer, connect_ok, execute_body, logon_response, opcodes,
    open_folder_response, open_stream_response,
};

/// The folder every test here writes into.
const FOLDER: u64 = 0x0D00_0000_0000_0042;

/// The slot a write batch makes its object in. Slot 0 is always the handle it was bound to.
const MADE: u8 = 1;

/// The handle a `RopOpenFolder` produces, for the one batch here that opens a folder.
const FOLDER_HANDLE: u32 = 0x0000_0001;

/// `ecAccessDenied`, which a server reports per property rather than per ROP.
const ACCESS_DENIED: u32 = 0x8000_4005;

/// The handle table a batch leaves behind when it made one object off the bound logon.
const MADE_MESSAGE: [u32; 2] = [LOGON_HANDLE, MESSAGE_HANDLE];

/// The attachment this crate writes in two of the tests below, and its length.
const CONTENT: &[u8] = b"one line\n";

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

/// One `PidTagImportance`, for the tests whose subject is the round trip rather than the value.
fn importance() -> TaggedValue {
    TaggedValue::new(PropertyTag::IMPORTANCE, PropertyValue::Integer32(1)).unwrap()
}

/// An update opens, writes, saves and releases in one `Execute` — and reports the properties the
/// server refused, which it names alongside a ROP that succeeded.
#[tokio::test]
async fn an_update_writes_and_saves_in_one_round_trip() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_message_response(MADE);
    answers.extend(set_properties_response(
        MADE,
        &[(0, PropertyTag::SUBJECT.as_u32(), ACCESS_DENIED)],
    ));
    answers.extend(modify_recipients_response(MADE));
    answers.extend(save_changes_response(MADE, NEW_MESSAGE_ID));
    server.reply_ok(execute_body(&answers, &MADE_MESSAGE));

    let message = logon
        .folder(FolderId::new(FOLDER))
        .message(MessageId::new(NEW_MESSAGE_ID));
    assert_eq!(message.id(), MessageId::new(NEW_MESSAGE_ID));
    assert_eq!(message.folder(), FolderId::new(FOLDER));

    let subject = TaggedValue::new(
        PropertyTag::SUBJECT,
        PropertyValue::String("Rewritten".into()),
    )
    .unwrap();
    let problems = message
        .update()
        .set([subject])
        .to([Recipient::to("Ada", "ada@example.test").unwrap()])
        .save()
        .await
        .unwrap();

    assert_eq!(problems.len(), 1);
    assert_eq!(problems[0].tag(), PropertyTag::SUBJECT);
    assert_eq!(problems[0].code(), ErrorCode::new(ACCESS_DENIED));

    // Open, write, recipients, save, release — in that order, in one buffer.
    assert_eq!(
        opcodes(&server.rops(2).await),
        [0x03, 0x0A, 0x0E, 0x0C, 0x01]
    );
}

/// An update with no recipients sends no `RopModifyRecipients` at all. An empty list is not the
/// same request as no list: [MS-OXCMSG] §3.1.5.5 addresses rows by position, so sending one would
/// be a modification of nothing that still costs a ROP.
#[tokio::test]
async fn an_update_with_no_recipients_sends_no_recipient_rop() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_message_response(MADE);
    answers.extend(set_properties_response(MADE, &[]));
    answers.extend(save_changes_response(MADE, NEW_MESSAGE_ID));
    server.reply_ok(execute_body(&answers, &MADE_MESSAGE));

    let problems = logon
        .folder(FolderId::new(FOLDER))
        .message(MessageId::new(NEW_MESSAGE_ID))
        .update()
        .set([importance()])
        .save()
        .await
        .unwrap();

    assert!(problems.is_empty());
    assert_eq!(opcodes(&server.rops(2).await), [0x03, 0x0A, 0x0C, 0x01]);

    // The open asked for write access, which is the byte a server refuses where it would have
    // allowed a read. `OpenModeFlags` sits between the two ids, fourteen bytes in.
    // [MS-OXCMSG] §2.2.3.1.1
    assert_eq!(server.rops(2).await[14], 0x01);
}

/// A batch that came back without the property report is not a write that went through. An empty
/// problem list and a missing one read identically to a caller, and only one of them means the
/// server considered the properties at all.
#[tokio::test]
async fn an_update_whose_property_report_never_arrives_is_not_reported_as_clean() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_message_response(MADE);
    answers.extend(save_changes_response(MADE, NEW_MESSAGE_ID));
    server.reply_ok(execute_body(&answers, &MADE_MESSAGE));

    let error = logon
        .folder(FolderId::new(FOLDER))
        .message(MessageId::new(NEW_MESSAGE_ID))
        .update()
        .set([importance()])
        .save()
        .await
        .unwrap_err();

    assert!(
        error.to_string().contains("a property write response"),
        "{error}"
    );
}

/// A `RopWriteStream` that took fewer bytes than it was sent **succeeded**, and the attachment it
/// left behind is truncated. The client refuses it — and gives back every handle it opened on the
/// way out, the message's included, because the connection is still perfectly usable.
#[tokio::test]
async fn a_short_write_is_refused_and_every_handle_is_given_back() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut created = create_message_response(MADE);
    created.extend(set_properties_response(MADE, &[]));
    server.reply_ok(execute_body(&created, &MADE_MESSAGE));

    // The attachment, its properties, its stream — and a write that took three of nine bytes.
    let mut attached = create_attachment_response(MADE, 0);
    attached.extend(set_properties_response(MADE, &[]));
    attached.extend(open_stream_response(2, 0));
    attached.extend(write_stream_response(2, 3));
    server.reply_ok(execute_body(
        &attached,
        &[MESSAGE_HANDLE, ATTACHMENT_HANDLE, STREAM_HANDLE],
    ));

    // The two releases the failure still owes, and then the message's own.
    server.reply_ok(execute_body(&[], &[STREAM_HANDLE, ATTACHMENT_HANDLE]));
    server.reply_ok(execute_body(&[], &[MESSAGE_HANDLE]));

    let error = logon
        .folder(FolderId::new(FOLDER))
        .create_message(MessageClass::Note)
        .attach([NewAttachment::by_value("notes.txt", CONTENT).unwrap()])
        .save()
        .await
        .unwrap_err();

    assert!(error.to_string().contains("a short write"), "{error}");

    // The attachment batch created, wrote and opened a stream on it, all in one buffer.
    assert_eq!(opcodes(&server.rops(3).await), [0x23, 0x0A, 0x2B, 0x2D]);
    // Nothing was committed: two releases, and neither a RopCommitStream nor a save among them.
    assert_eq!(opcodes(&server.rops(4).await), [0x01, 0x01]);
    // And the message handle went back on its own, in a buffer of exactly one RopRelease.
    assert_eq!(opcodes(&server.rops(5).await), [0x01]);
}

/// A create whose handle never arrives is refused before anything is written to it. The handle
/// table is where a slot's answer lives, so `0xFFFFFFFF` there is a ROP that reported success and
/// produced no object — and filling slot 1 anyway would write to whatever the server has in it.
#[tokio::test]
async fn an_attachment_with_no_handle_is_refused_before_it_is_filled() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut created = create_message_response(MADE);
    created.extend(set_properties_response(MADE, &[]));
    server.reply_ok(execute_body(&created, &MADE_MESSAGE));

    // Every ROP succeeded. Only the handle table says otherwise.
    let mut attached = create_attachment_response(MADE, 0);
    attached.extend(set_properties_response(MADE, &[]));
    attached.extend(open_stream_response(2, 0));
    attached.extend(write_stream_response(2, 9));
    server.reply_ok(execute_body(
        &attached,
        &[MESSAGE_HANDLE, 0xFFFF_FFFF, 0xFFFF_FFFF],
    ));

    // Only the message's release: there is nothing else to give back.
    server.reply_ok(execute_body(&[], &[MESSAGE_HANDLE]));

    let error = logon
        .folder(FolderId::new(FOLDER))
        .create_message(MessageClass::Note)
        .attach([NewAttachment::by_value("notes.txt", CONTENT).unwrap()])
        .save()
        .await
        .unwrap_err();

    assert!(
        error.to_string().contains("handles for the new attachment"),
        "{error}"
    );
    assert_eq!(opcodes(&server.rops(4).await), [0x01]);
}

/// A delete that deleted some of what it was given reports so, and the ROP still succeeds. Only
/// `PartialCompletion` says which of the two happened.
#[tokio::test]
async fn a_partial_delete_is_reported_rather_than_read_as_success() {
    let server = MapiServer::start().await;
    let mut logon = logged_on(&server).await;

    let mut answers = open_folder_response(MADE);
    answers.extend(delete_messages_response(MADE, true));
    server.reply_ok(execute_body(&answers, &[LOGON_HANDLE, FOLDER_HANDLE]));

    let complete = logon
        .folder(FolderId::new(FOLDER))
        .delete_messages(&[MessageId::new(NEW_MESSAGE_ID)])
        .await
        .unwrap();

    assert!(!complete, "the PartialCompletion flag was set");
    assert_eq!(opcodes(&server.rops(2).await), [0x02, 0x1E, 0x01]);
}
