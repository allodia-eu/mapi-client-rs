use super::*;

#[test]
fn the_requests_match_the_spec_layouts() {
    let mut w = Writer::new();
    encode_submit_message(&mut w, 1, SubmitFlags::None);
    #[rustfmt::skip]
    let expected = vec![
        0x32, // RopId
        0x00, // LogonId
        0x01, // InputHandleIndex: the message
        0x00, // SubmitFlags: None
    ];
    assert_eq!(w.finish(), expected);

    let mut w = Writer::new();
    encode_move_copy_messages(
        &mut w,
        1,
        2,
        &[MessageId::new(0x0C01_0000_0000_0042)],
        false,
    )
    .expect("one id fits the count");
    #[rustfmt::skip]
    let expected = vec![
        0x33,                                           // RopId
        0x00,                                           // LogonId
        0x01,                                           // SourceHandleIndex
        0x02,                                           // DestHandleIndex
        0x01, 0x00,                                     // MessageIdCount
        0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0C, // MessageIds
        0x00,                                           // WantAsynchronous: no
        0x00,                                           // WantCopy: a move
    ];
    assert_eq!(w.finish(), expected);

    let mut w = Writer::new();
    encode_set_read_flags(
        &mut w,
        1,
        ReadFlags::ReadQuietly,
        &[MessageId::new(0x0C01_0000_0000_0042)],
    )
    .expect("one id fits the count");
    #[rustfmt::skip]
    let expected = vec![
        0x66,                                           // RopId
        0x00,                                           // LogonId
        0x01,                                           // InputHandleIndex: the folder
        0x00,                                           // WantAsynchronous: no
        0x01,                                           // ReadFlags: rfSuppressReceipt
        0x01, 0x00,                                     // MessageIdCount
        0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0C, // MessageIds
    ];
    assert_eq!(w.finish(), expected);

    let mut w = Writer::new();
    encode_remove_all_recipients(&mut w, 1);
    assert_eq!(w.finish(), vec![0x0D, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
}

/// `WantCopy` is the only difference between the two operations, so the one byte is worth its own
/// assertion: a move that copies leaves the message in both folders and reports success.
#[test]
fn a_copy_differs_from_a_move_by_one_byte() {
    let mut moved = Writer::new();
    encode_move_copy_messages(&mut moved, 1, 2, &[MessageId::new(1)], false).expect("a move");
    let mut copied = Writer::new();
    encode_move_copy_messages(&mut copied, 1, 2, &[MessageId::new(1)], true).expect("a copy");

    let (moved, copied) = (moved.finish(), copied.finish());
    assert_eq!(moved.len(), copied.len());
    assert_eq!(
        moved.split_last().map(|(_, rest)| rest),
        copied.split_last().map(|(_, rest)| rest)
    );
    assert_eq!(moved.last(), Some(&0x00));
    assert_eq!(copied.last(), Some(&0x01));
}

/// [MS-OXCMSG] §2.2.3.10.1's table, and the sentence under it that makes one of the four
/// combinations mandatory rather than optional: "the client MUST include the rfSuppressReceipt bit
/// with this flag". Sending `0x04` alone is the bug this type exists to make unwritable.
#[test]
fn clearing_the_read_flag_always_carries_the_suppress_bit() {
    assert_eq!(ReadFlags::Unread.as_u8(), 0x05);
    assert_eq!(
        ReadFlags::Unread.as_u8() & ReadFlags::SUPPRESS_RECEIPT,
        ReadFlags::SUPPRESS_RECEIPT
    );
    assert_eq!(
        ReadFlags::Unread.as_u8() & ReadFlags::CLEAR_READ_FLAG,
        ReadFlags::CLEAR_READ_FLAG
    );

    assert_eq!(ReadFlags::Read.as_u8(), 0x00);
    assert_eq!(ReadFlags::ReadQuietly.as_u8(), 0x01);
    assert_eq!(ReadFlags::ReceiptOnly.as_u8(), 0x10);
    assert_eq!(ReadFlags::default(), ReadFlags::Read);

    assert_eq!(ReadFlags::Read.read_afterwards(), Some(true));
    assert_eq!(ReadFlags::ReadQuietly.read_afterwards(), Some(true));
    assert_eq!(ReadFlags::Unread.read_afterwards(), Some(false));
    // The one request that changes no read state at all, which is why this is an Option.
    assert_eq!(ReadFlags::ReceiptOnly.read_afterwards(), None);
}

/// [MS-OXOMSG] §2.2.4.1.1's three values, and the one that means the server does *not* send.
#[test]
fn only_the_spooler_flag_stops_the_server_sending() {
    assert_eq!(SubmitFlags::None.as_u8(), 0x00);
    assert_eq!(SubmitFlags::PreProcess.as_u8(), 0x01);
    assert_eq!(SubmitFlags::NeedsSpooler.as_u8(), 0x02);
    assert_eq!(SubmitFlags::default(), SubmitFlags::None);

    assert!(SubmitFlags::None.sends());
    assert!(SubmitFlags::PreProcess.sends());
    assert!(!SubmitFlags::NeedsSpooler.sends());
}

/// Both of these succeed while doing less than they were asked, and the flag is the only place it
/// is said.
#[test]
fn partial_completion_is_read_from_the_byte_after_the_return_value() {
    for (body, partial) in [([0x00_u8], false), ([0x01], true)] {
        let mut r = Reader::new(&body);
        assert_eq!(
            MoveCopyMessagesResponse::read(&mut r)
                .expect("a body")
                .is_partial(),
            partial
        );

        let mut r = Reader::new(&body);
        assert_eq!(
            SetReadFlagsResponse::read(&mut r)
                .expect("a body")
                .is_partial(),
            partial
        );
    }
}

/// [MS-OXCROPS] §2.2.4.6.3. The refusal that does not stop after `ReturnValue`, and whose
/// `DestHandleIndex` is four bytes where the request's is one. Reading it as an ordinary failure
/// leaves five bytes in the stream — so this checks the reader consumed exactly the five.
#[test]
fn the_null_destination_refusal_carries_a_four_byte_handle_index_and_a_flag() {
    let body = [
        0x02, 0x00, 0x00, 0x00, // DestHandleIndex, four bytes
        0x01, // PartialCompletion
    ];
    let mut r = Reader::new(&body);
    let response = MoveCopyMessagesResponse::read_null_destination(&mut r).expect("a body");
    assert!(response.is_partial());
    assert!(r.is_empty(), "the whole body was consumed");

    assert!(is_null_destination(ErrorCode::NULL_DESTINATION_OBJECT));
    // ecNullObject, four codes earlier, is about a *source* handle and stops where failures stop.
    assert!(!is_null_destination(ErrorCode::new(0x0000_04B9)));
    assert!(!is_null_destination(ErrorCode::ACCESS_DENIED));
}

/// Nothing here asks for an asynchronous run, so this is about not desynchronising the buffer when
/// one arrives anyway: nine bytes in, nothing left over.
#[test]
fn a_progress_response_is_consumed_whole() {
    let body = [
        0x00, // LogonId
        0x03, 0x00, 0x00, 0x00, // CompletedTaskCount
        0x07, 0x00, 0x00, 0x00, // TotalTaskCount
    ];
    let mut r = Reader::new(&body);
    let progress = ProgressResponse::read(&mut r).expect("a body");
    assert_eq!(progress.completed(), 3);
    assert_eq!(progress.total(), 7);
    assert!(r.is_empty());
}

/// `MessageIdCount` is two bytes, so a longer list is refused rather than truncated — a truncated
/// list moves some of the messages and reports success.
#[test]
fn a_list_longer_than_the_count_is_refused() {
    let too_many = vec![MessageId::new(1); usize::from(u16::MAX).saturating_add(1)];

    let mut w = Writer::new();
    let refused = encode_move_copy_messages(&mut w, 1, 2, &too_many, false);
    assert!(matches!(refused, Err(Error::RopBufferTooLarge { .. })));

    let mut w = Writer::new();
    let refused = encode_set_read_flags(&mut w, 1, ReadFlags::Read, &too_many);
    assert!(matches!(refused, Err(Error::RopBufferTooLarge { .. })));
}
