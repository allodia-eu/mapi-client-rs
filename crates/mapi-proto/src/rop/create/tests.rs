use super::*;
use crate::oxcdata::RecipientType;

#[test]
fn the_create_requests_match_the_spec_layouts() {
    let mut w = Writer::new();
    encode_create_message(&mut w, 0, 1, FolderId::new(0x0D01_0000_0000_0001));
    #[rustfmt::skip]
    let expected = vec![
        0x06,                                           // RopId
        0x00,                                           // LogonId
        0x00,                                           // InputHandleIndex: the logon
        0x01,                                           // OutputHandleIndex: the new message
        0xFF, 0x0F,                                     // CodePageId: the Logon object's
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0D, // FolderId
        0x00,                                           // AssociatedFlag: not an FAI message
    ];
    assert_eq!(w.finish(), expected);

    let mut w = Writer::new();
    encode_create_attachment(&mut w, 1, 2);
    assert_eq!(w.finish(), vec![0x23, 0x00, 0x01, 0x02]);

    let mut w = Writer::new();
    encode_save_changes_attachment(&mut w, 2);
    assert_eq!(w.finish(), vec![0x25, 0x00, 0x02, 0x02, 0x02]);
}

/// [MS-OXCMSG] §4.8.1's worked example is `0c 00 00 01 0a`, whose `SaveFlags` is `0x0A` where
/// §2.2.3.3.1's table gives `KeepOpenReadWrite` as `0x02`. The documented value is what goes on the
/// wire here; the rest of the layout is the example's.
#[test]
fn a_message_save_sends_the_save_flag_the_table_documents() {
    let mut w = Writer::new();
    encode_save_changes_message(&mut w, 1);
    assert_eq!(w.finish(), vec![0x0C, 0x00, 0x01, 0x01, 0x02]);
    assert_eq!(
        KEEP_OPEN_READ_WRITE & 0x0A,
        KEEP_OPEN_READ_WRITE,
        "the example's 0x0A is this flag with an undocumented bit set"
    );
}

/// `RowId` is an identity, not an ordinal: two rows get 0 and 1, and sending the same list again
/// modifies the same two recipients rather than adding two more.
#[test]
fn recipients_are_numbered_from_zero_and_carry_no_columns() {
    let recipients = [
        Recipient::to("Ada", "ada@example.test").expect("a recipient"),
        Recipient::cc("Grace", "grace@example.test").expect("a recipient"),
    ];

    let mut w = Writer::new();
    encode_modify_recipients(&mut w, 3, &recipients).expect("two short rows");
    let bytes = w.finish();

    assert_eq!(bytes[0], 0x0E, "RopId");
    assert_eq!(bytes[1], 0x00, "LogonId");
    assert_eq!(bytes[2], 3, "InputHandleIndex");
    assert_eq!(&bytes[3..5], [0x00, 0x00], "ColumnCount is zero");
    assert_eq!(&bytes[5..7], [0x02, 0x00], "RowCount");

    let mut row = Writer::new();
    recipients[0].write_row(&mut row);
    let first = row.finish();
    let size = u16::try_from(first.len()).expect("a short row");

    assert_eq!(&bytes[7..11], [0x00, 0x00, 0x00, 0x00], "the first RowId");
    assert_eq!(bytes[11], RecipientType::PRIMARY.as_u8());
    assert_eq!(bytes[12..14], size.to_le_bytes());
    assert_eq!(&bytes[14..14 + first.len()], first.as_slice());

    let second = 14 + first.len();
    assert_eq!(
        &bytes[second..second + 4],
        [0x01, 0x00, 0x00, 0x00],
        "the second RowId"
    );
    assert_eq!(bytes[second + 4], RecipientType::CARBON_COPY.as_u8());
}

#[test]
fn an_empty_recipient_list_is_a_well_formed_request() {
    let mut w = Writer::new();
    encode_modify_recipients(&mut w, 1, &[]).expect("no rows");
    assert_eq!(w.finish(), vec![0x0E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn a_delete_names_every_message_it_is_given() {
    let mut w = Writer::new();
    encode_delete_messages(&mut w, 1, &[MessageId::new(0x0100), MessageId::new(0x0200)])
        .expect("two ids");

    #[rustfmt::skip]
    let expected = vec![
        0x1E,                                           // RopId
        0x00,                                           // LogonId
        0x01,                                           // InputHandleIndex: the folder
        0x00,                                           // WantAsynchronous: no RopProgress
        0x00,                                           // NotifyNonRead
        0x02, 0x00,                                     // MessageIdCount
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(w.finish(), expected);
}

/// `HasMessageId` is a Boolean and the buffer ends there when it is zero, so a decoder that always
/// read eight more bytes would run off the end of a conforming response.
#[test]
fn a_create_response_may_carry_no_id_at_all() {
    let none = CreateMessageResponse::read(&mut Reader::new(&[0x00])).expect("no id");
    assert_eq!(none.message_id(), None);

    let some = CreateMessageResponse::read(&mut Reader::new(&[
        0x01, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0D,
    ]))
    .expect("an id");
    assert_eq!(
        some.message_id(),
        Some(MessageId::new(0x0D01_0000_0000_0042))
    );
}

/// The one success body in the crate that begins with a second handle index. Reading the id from
/// the front instead would report a message id one byte out — a plausible-looking wrong answer.
#[test]
fn a_save_response_reports_the_id_after_the_input_handle_index() {
    let saved = SaveChangesResponse::read(&mut Reader::new(&[
        0x01, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0D,
    ]))
    .expect("an id");
    assert_eq!(saved.message_id(), MessageId::new(0x0D01_0000_0000_0042));
}

#[test]
fn an_attachment_is_named_by_the_number_its_creation_reported() {
    let created = CreateAttachmentResponse::read(&mut Reader::new(&[0x02, 0x00, 0x00, 0x00]))
        .expect("a number");
    assert_eq!(created.number(), AttachmentNumber::new(2));
}

/// A delete that deleted nothing still succeeds. Only this byte says so.
#[test]
fn a_partial_delete_is_reported_rather_than_folded_into_success() {
    assert!(
        DeleteMessagesResponse::read(&mut Reader::new(&[0x01]))
            .expect("a flag")
            .is_partial()
    );
    assert!(
        !DeleteMessagesResponse::read(&mut Reader::new(&[0x00]))
            .expect("a flag")
            .is_partial()
    );
}

#[test]
fn truncated_create_responses_never_panic() {
    for buf in [&b""[..], &[0x01][..], &[0x01, 0x02, 0x03][..]] {
        let _ = CreateMessageResponse::read(&mut Reader::new(buf));
        let _ = SaveChangesResponse::read(&mut Reader::new(buf));
        let _ = CreateAttachmentResponse::read(&mut Reader::new(buf));
        let _ = DeleteMessagesResponse::read(&mut Reader::new(buf));
    }
}

/// `RowCount` is two bytes. A list longer than it can express is refused rather than truncated,
/// because a count that wrapped would describe a shorter list than the rows that follow it — and
/// the server would then read the surplus rows as the next ROP.
#[test]
fn a_recipient_list_no_row_count_can_express_is_refused() {
    let one = Recipient::to("Ada", "ada@example.test").expect("a recipient");
    let recipients = vec![one; 65_536];

    let mut w = Writer::new();
    assert_eq!(
        encode_modify_recipients(&mut w, 1, &recipients),
        Err(Error::RopBufferTooLarge {
            bytes: 65_536,
            limit: 65_535,
        })
    );
}

/// `RecipientRowSize` is two bytes as well, and one row is enough to overrun it: every character
/// of a display name is two bytes of UTF-16 inside the row.
#[test]
fn a_recipient_row_no_size_field_can_express_is_refused() {
    let name = "a".repeat(40_000);
    let recipients = [Recipient::to(name, "ada@example.test").expect("a recipient")];

    let mut w = Writer::new();
    assert!(matches!(
        encode_modify_recipients(&mut w, 1, &recipients),
        Err(Error::RopBufferTooLarge { .. })
    ));
}

/// `MessageIdCount` is two bytes, and the ids that follow it are eight each — so a wrapped count
/// here would have the server delete a few messages and read the rest as ROPs.
#[test]
fn a_delete_list_no_id_count_can_express_is_refused() {
    let messages = vec![MessageId::new(0x0100); 65_536];

    let mut w = Writer::new();
    assert_eq!(
        encode_delete_messages(&mut w, 1, &messages),
        Err(Error::RopBufferTooLarge {
            bytes: 65_536,
            limit: 65_535,
        })
    );
}
