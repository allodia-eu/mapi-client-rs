use super::*;

#[test]
fn open_message_request_matches_the_spec_layout() {
    let mut w = Writer::new();
    encode_open_message(
        &mut w,
        0,
        1,
        FolderId::new(0x0D01_0000_0000_0001),
        MessageId::new(0x0D01_0000_0000_0042),
    );

    #[rustfmt::skip]
    let expected = vec![
        0x03,                                           // RopId
        0x00,                                           // LogonId
        0x00,                                           // InputHandleIndex
        0x01,                                           // OutputHandleIndex
        0xFF, 0x0F,                                     // CodePageId: the Logon object's
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0D, // FolderId
        0x00,                                           // OpenModeFlags: ReadOnly
        0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0D, // MessageId
    ];
    assert_eq!(w.finish(), expected);
}

/// The three attachment-side requests, each of which is short enough that a transposed field would
/// still parse as *something* on the server.
#[test]
fn the_attachment_requests_match_the_spec_layouts() {
    let mut w = Writer::new();
    encode_get_attachment_table(&mut w, 2, 3);
    assert_eq!(w.finish(), vec![0x21, 0x00, 0x02, 0x03, 0x40]);

    let mut w = Writer::new();
    encode_open_attachment(&mut w, 3, 4, 0x0000_0001);
    assert_eq!(
        w.finish(),
        vec![0x22, 0x00, 0x03, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00]
    );

    let mut w = Writer::new();
    encode_open_embedded_message(&mut w, 4, 5);
    assert_eq!(w.finish(), vec![0x46, 0x00, 0x04, 0x05, 0xFF, 0x0F, 0x00]);
}

/// Every `StringType` [MS-OXCDATA] §2.11.7 lists. `0x00` and `0x01` are the pair that matter: one
/// is "no string" and the other is "a string of length zero", and folding them together would
/// report a message with an empty prefix as one with no prefix at all.
#[test]
fn every_typed_string_form_decodes_and_consumes_exactly_its_own_bytes() {
    let cases: [(&[u8], Option<&str>); 5] = [
        (&[0x00], None),
        (&[0x01], Some("")),
        (&[0x02, b'R', b'E', b':', 0x00], Some("RE:")),
        (&[0x03, b'F', b'W', b':', 0x00], Some("FW:")),
        (
            &[0x04, b'R', 0x00, b'E', 0x00, b':', 0x00, 0x00, 0x00],
            Some("RE:"),
        ),
    ];

    for (bytes, expected) in cases {
        let mut buf = bytes.to_vec();
        buf.push(0xEE); // whatever follows the field
        let mut r = Reader::new(&buf);
        assert_eq!(
            typed_string(&mut r).unwrap().as_deref(),
            expected,
            "{bytes:?}"
        );
        assert_eq!(r.rest(), &[0xEE], "{bytes:?} consumed the wrong length");
    }
}

/// A reduced Unicode string is a UTF-16LE string whose high bytes were all zero and were removed,
/// so a byte of `0xE9` is `é` — not the second half of a UTF-8 sequence, which is what a naive
/// `String::from_utf8` would make of it.
#[test]
fn a_reduced_unicode_string_widens_each_byte_to_a_codepoint() {
    let mut r = Reader::new(&[0x03, b'c', b'a', b'f', 0xE9, 0x00]);
    assert_eq!(typed_string(&mut r).unwrap().as_deref(), Some("caf\u{E9}"));
}

/// An unrecognised `StringType` has no length, so decoding stops rather than continuing into the
/// recipient table from the wrong offset.
#[test]
fn an_unknown_string_type_stops_the_decode() {
    let mut r = Reader::new(&[0x05, 0x00]);
    assert!(matches!(
        typed_string(&mut r),
        Err(Error::InvalidStringType { kind: 0x05, at: 0 })
    ));
}

/// Built the way the server sends it, then read back — including the trailing byte that proves the
/// recipient table was consumed to exactly its own end.
#[test]
fn an_open_message_response_reads_its_recipient_table_whole() {
    let mut w = Writer::new();
    w.u8(0x01); // HasNamedProperties
    w.u8(0x02).ascii_z("RE: "); // SubjectPrefix
    w.u8(0x04).utf16_z("quarterly report"); // NormalizedSubject
    w.u16(2); // RecipientCount
    w.u16(2).u32(0x0037_001F).u32(0x3001_001F); // ColumnCount, RecipientColumns
    w.u8(2); // RowCount
    w.u8(0x01)
        .u16(1252)
        .u16(0)
        .u16(3)
        .bytes(&[0xAA, 0xBB, 0xCC]);
    w.u8(0x12).u16(1252).u16(0).u16(1).bytes(&[0xDD]);
    w.u8(0xEE); // the next ROP response starts here
    let buf = w.finish();

    let mut r = Reader::new(&buf);
    let response = OpenMessageResponse::read(&mut r).unwrap();

    assert!(response.has_named_properties());
    assert_eq!(response.subject_prefix(), Some("RE: "));
    assert_eq!(response.normalized_subject(), Some("quarterly report"));
    assert_eq!(response.recipient_count(), 2);
    assert!(!response.is_truncated());
    assert_eq!(response.embedded_id(), None);

    let recipients = response.recipients();
    assert_eq!(recipients.len(), 2);
    assert_eq!(
        recipients.first().map(OpenRecipient::recipient_type),
        Some(RecipientType::PRIMARY)
    );
    assert_eq!(
        recipients.first().map(OpenRecipient::row_bytes),
        Some(&[0xAA, 0xBB, 0xCC][..])
    );
    assert_eq!(recipients.first().map(OpenRecipient::code_page), Some(1252));

    // 0x12 is a Cc recipient carrying the "did not receive it last time" flag.
    let resent = recipients.get(1).expect("a second recipient");
    assert_eq!(resent.recipient_type().as_u8(), 0x12);
    assert_eq!(resent.recipient_type().kind(), RecipientType::CARBON_COPY);
    assert_eq!(resent.recipient_type().to_string(), "Cc");

    assert_eq!(
        r.rest(),
        &[0xEE],
        "the recipient table was not consumed exactly"
    );
}

/// The embedded form differs by a reserved byte and the id the caller could not have known.
#[test]
fn an_embedded_message_response_reports_the_id_it_was_given() {
    let mut w = Writer::new();
    w.u8(0x00).u64(0x0D01_0000_0000_00FF); // Reserved, MessageId
    w.u8(0x00); // HasNamedProperties
    w.u8(0x00); // SubjectPrefix: absent
    w.u8(0x01); // NormalizedSubject: empty
    w.u16(0).u16(0).u8(0); // no recipients at all
    let buf = w.finish();

    let response = OpenMessageResponse::read_embedded(&mut Reader::new(&buf)).unwrap();
    assert_eq!(
        response.embedded_id(),
        Some(MessageId::new(0x0D01_0000_0000_00FF))
    );
    assert!(!response.has_named_properties());
    assert_eq!(response.subject_prefix(), None);
    assert_eq!(response.normalized_subject(), Some(""));
    assert!(response.recipients().is_empty());
}

/// `RowCount` is documented as no greater than `RecipientCount`, so the two disagreeing is a fact
/// about the answer rather than a decode failure — and a caller that reported "2 recipients" from a
/// response carrying one would be wrong about the message.
#[test]
fn fewer_rows_than_recipients_is_reported_rather_than_hidden() {
    let mut w = Writer::new();
    w.u8(0x00).u8(0x01).u8(0x01);
    w.u16(9).u16(0).u8(0);
    let buf = w.finish();

    let response = OpenMessageResponse::read(&mut Reader::new(&buf)).unwrap();
    assert_eq!(response.recipient_count(), 9);
    assert!(response.recipients().is_empty());
    assert!(response.is_truncated());
}

#[test]
fn a_recipient_type_outside_the_table_still_prints() {
    let odd = RecipientType::new(0x07);
    assert_eq!(odd.name(), None);
    assert_eq!(odd.to_string(), "recipient type 0x07");
    assert_eq!(RecipientType::BLIND_CARBON_COPY.to_string(), "Bcc");
    assert_eq!(format!("{:<4}", RecipientType::PRIMARY), "To  ");
}

#[test]
fn truncated_message_responses_never_panic() {
    for length in 0..24 {
        let buf = vec![0x02; length];
        let _ = OpenMessageResponse::read(&mut Reader::new(&buf));
        let _ = OpenMessageResponse::read_embedded(&mut Reader::new(&buf));
    }
}
