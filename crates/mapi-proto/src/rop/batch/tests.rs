use super::*;
use crate::oxcdata::{
    CONTENTS_COLUMNS, FolderId, Guid, HIERARCHY_COLUMNS, LongTermId, MessageId, PropertyName,
    Restriction, ShortTermId, SortOrder, SortOrderSet,
};
use crate::rop::message::MessageMode;
use crate::rop::named::NameRegistration;
use crate::rop::stream::StreamMode;
use crate::rop::table::FolderDepth;

fn dn() -> LegacyDn {
    LegacyDn::new("/o=First/ou=Exchange Administrative Group/cn=alice").unwrap()
}

/// The chain is one round trip only if each ROP's input index is the previous ROP's output index,
/// within the same buffer. Nothing here writes an index by hand.
#[test]
fn the_chain_threads_slots_not_handles() {
    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(0x2A));
    let folder = batch.open_folder(logon, FolderId::new(1));
    let table = batch.contents_table(folder);
    batch
        .set_columns(table, &HIERARCHY_COLUMNS)
        .query_rows(table, 10);

    assert_eq!(logon.index(), 0);
    assert_eq!(folder.index(), 1);
    assert_eq!(table.index(), 2);
    assert_eq!(batch.len(), 4);

    let built = batch.build().unwrap();
    let rops = built.bytes.get(10..).unwrap();

    // RopOpenFolder: RopId, LogonId, InputHandleIndex, OutputHandleIndex.
    assert_eq!(rops.get(..4), Some(&[0x02, 0x00, 0x00, 0x01][..]));
    // RopGetContentsTable reads slot 1 and writes slot 2.
    assert_eq!(rops.get(13..17), Some(&[0x05, 0x00, 0x01, 0x02][..]));
    // Both table ROPs read slot 2.
    assert_eq!(rops.get(18..21), Some(&[0x12, 0x00, 0x02][..]));
}

/// The handle table is sized by the slots used, and every slot a ROP will fill starts unowned.
///
/// [MS-OXCROPS] §3.1.4.1
#[test]
fn the_handle_table_is_sized_by_slots_and_starts_unowned() {
    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(0x2A));
    let folder = batch.open_folder(logon, FolderId::new(1));
    let _table = batch.hierarchy_table(folder, FolderDepth::Immediate);

    let built = batch.build().unwrap();
    assert_eq!(
        built.initial_handles,
        vec![
            ObjectHandle::new(0x2A),
            ObjectHandle::NONE,
            ObjectHandle::NONE
        ]
    );
}

#[test]
fn a_logon_batch_is_one_rop_and_one_unowned_slot() {
    let mut batch = RopBatch::new();
    let logon = batch.logon(&dn());

    assert_eq!(logon.index(), 0);
    let built = batch.build().unwrap();
    assert_eq!(built.initial_handles, vec![ObjectHandle::NONE]);
    assert_eq!(built.bytes.get(10), Some(&0xFE));
}

#[test]
fn columns_are_recorded_against_the_slot_that_will_carry_the_rows() {
    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(1));
    let folder = batch.open_folder(logon, FolderId::new(1));
    let table = batch.hierarchy_table(folder, FolderDepth::Immediate);
    batch.set_columns(table, &HIERARCHY_COLUMNS);

    let built = batch.build().unwrap();
    assert_eq!(built.columns.first(), Some(&None));
    assert_eq!(
        built.columns.get(usize::from(table.index())),
        Some(&Some(HIERARCHY_COLUMNS.to_vec()))
    );
}

#[test]
fn release_frees_a_slot_the_server_is_holding() {
    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(0x2A));
    batch.release(logon);

    let built = batch.build().unwrap();
    assert_eq!(built.bytes.get(10..13), Some(&[0x01, 0x00, 0x00][..]));
}

/// A slot from another batch would address an unrelated handle, so it is refused rather than
/// silently sent.
#[test]
fn a_slot_from_another_batch_is_refused() {
    let mut other = RopBatch::new();
    let stranger = other.bind(ObjectHandle::new(7));

    let mut batch = RopBatch::new();
    let folder = batch.open_folder(stranger, FolderId::new(1));
    batch.query_rows(folder, 1);

    assert_eq!(
        batch.build().unwrap_err(),
        Error::UnknownHandleSlot { index: 0 }
    );
}

#[test]
fn the_first_failure_is_the_one_reported() {
    let mut other = RopBatch::new();
    let stranger_a = other.bind(ObjectHandle::new(7));
    let stranger_b = other.bind(ObjectHandle::new(8));

    let mut batch = RopBatch::new();
    batch.query_rows(stranger_b, 1);
    batch.query_rows(stranger_a, 1);

    assert_eq!(
        batch.build().unwrap_err(),
        Error::UnknownHandleSlot { index: 1 }
    );
}

/// A ROP addresses the table with one byte, so slot 256 cannot exist.
#[test]
fn a_batch_cannot_outgrow_a_one_byte_handle_index() {
    let mut batch = RopBatch::new();
    for _ in 0..256 {
        batch.bind(ObjectHandle::NONE);
    }
    assert!(batch.build().is_ok(), "256 slots is the limit, not past it");

    let mut batch = RopBatch::new();
    for _ in 0..257 {
        batch.bind(ObjectHandle::NONE);
    }
    assert_eq!(
        batch.build().unwrap_err(),
        Error::TooManyHandles { limit: 256 }
    );
}

#[test]
fn a_batch_past_the_length_field_is_refused() {
    let mut batch = RopBatch::new();
    let table = batch.bind(ObjectHandle::new(1));
    // Each RopQueryRows is 7 bytes; 10,000 of them is well past what RopSize can describe.
    for _ in 0..10_000 {
        batch.query_rows(table, 1);
    }
    assert!(matches!(
        batch.build(),
        Err(Error::RopBufferTooLarge { .. })
    ));
}

#[test]
fn an_empty_batch_is_still_a_valid_buffer() {
    let batch = RopBatch::new();
    assert!(batch.is_empty());
    assert_eq!(batch.len(), 0);

    let built = RopBatch::default().build().unwrap();
    assert_eq!(built.bytes.len(), 10, "just the framing");
    assert!(built.columns.is_empty());
}

/// A conversion ROP answers *for the store the logon named*, so one addressed at a handle from
/// another batch would return a plausible folder id for the wrong mailbox — an answer that looks
/// entirely right. The slot is checked before the ROP is written rather than after the id comes
/// back, because by then there is nothing left to check it against.
#[test]
fn a_conversion_refuses_a_slot_from_another_batch() {
    let mut other = RopBatch::new();
    let stranger = other.bind(ObjectHandle::new(7));
    let long_term = LongTermId::new(Guid::from_bytes([0; 16]), [1, 0, 0, 0, 0, 0]);

    let mut from_long = RopBatch::new();
    from_long.id_from_long_term_id(stranger, &long_term);
    assert_eq!(
        from_long.build().unwrap_err(),
        Error::UnknownHandleSlot { index: 0 }
    );

    let mut from_short = RopBatch::new();
    from_short.long_term_id_from_id(stranger, ShortTermId::new(1));
    assert_eq!(
        from_short.build().unwrap_err(),
        Error::UnknownHandleSlot { index: 0 }
    );
}

/// Both name ROPs travel in one buffer against one object, which is what keeps resolving ten named
/// properties at the cost of resolving one.
#[test]
fn both_name_ropes_ride_the_same_logon_slot() {
    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(0x2A));
    batch
        .property_ids_from_names(
            logon,
            &[PropertyName::lid(
                crate::oxcdata::PropertySetId::APPOINTMENT,
                0x0000_8208,
            )],
            NameRegistration::Existing,
        )
        .names_from_property_ids(logon, &[0x8005]);

    assert_eq!(batch.len(), 2);
    let built = batch.build().unwrap();
    let rops = built.bytes.get(10..).unwrap();

    // RopGetPropertyIdsFromNames: RopId, LogonId, InputHandleIndex, Flags, then the count.
    assert_eq!(rops.get(..5), Some(&[0x56, 0x00, 0x00, 0x00, 0x01][..]));
    // RopGetNamesFromPropertyIds picks up right after the one 21-byte PropertyName, same slot.
    assert_eq!(
        rops.get(27..34),
        Some(&[0x55, 0x00, 0x00, 0x01, 0x00, 0x05, 0x80][..])
    );
    assert!(built.property_tags.is_empty(), "neither ROP needs the tags");
}

/// Neither takes a slot this batch never allocated, for the same reason a conversion does not: the
/// mapping table belongs to one store, and an id resolved against another one reads a different
/// property and reports nothing.
#[test]
fn a_name_lookup_refuses_a_slot_from_another_batch() {
    let mut other = RopBatch::new();
    let stranger = other.bind(ObjectHandle::new(7));

    let mut forward = RopBatch::new();
    forward.property_ids_from_names(stranger, &[], NameRegistration::Existing);
    assert_eq!(
        forward.build().unwrap_err(),
        Error::UnknownHandleSlot { index: 0 }
    );

    let mut inverse = RopBatch::new();
    inverse.names_from_property_ids(stranger, &[0x8005]);
    assert_eq!(
        inverse.build().unwrap_err(),
        Error::UnknownHandleSlot { index: 0 }
    );
}

#[test]
fn handles_and_slots_render_for_humans() {
    assert_eq!(ObjectHandle::NONE.to_string(), "<none>");
    assert!(ObjectHandle::NONE.is_none());
    assert_eq!(ObjectHandle::new(0x2A).to_string(), "0x0000002A");
    assert!(!ObjectHandle::new(0x2A).is_none());
    assert_eq!(ObjectHandle::new(0x2A).as_u32(), 0x2A);

    let mut batch = RopBatch::new();
    assert_eq!(batch.bind(ObjectHandle::NONE).to_string(), "slot 0");
}

/// The whole of *"extract an attachment's bytes"* in one buffer: open the message, open its
/// attachment, open the attachment's data as a stream, read it. Four handles, and not one index
/// written by hand.
#[test]
fn a_message_attachment_and_stream_chain_through_one_buffer() {
    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(0x2A));
    let message = batch.open_message(
        logon,
        FolderId::new(1),
        MessageId::new(2),
        MessageMode::ReadOnly,
    );
    let attachment = batch.open_attachment(message, 0);
    let stream = batch.open_stream(
        attachment,
        PropertyTag::ATTACH_DATA_BINARY,
        StreamMode::ReadOnly,
    );
    batch.read_stream(stream, 4096).release(stream);

    assert_eq!(message.index(), 1);
    assert_eq!(attachment.index(), 2);
    assert_eq!(stream.index(), 3);
    assert_eq!(batch.len(), 5);

    let built = batch.build().unwrap();
    let rops = built.bytes.get(10..).unwrap();
    // RopOpenMessage reads slot 0 and writes slot 1.
    assert_eq!(rops.get(..4), Some(&[0x03, 0x00, 0x00, 0x01][..]));
    // RopOpenAttachment reads slot 1 and writes slot 2, 23 bytes later — the length of a
    // RopOpenMessage request, which carries two 8-byte ids.
    assert_eq!(rops.get(23..27), Some(&[0x22, 0x00, 0x01, 0x02][..]));
    // RopOpenStream reads slot 2 and writes slot 3, 9 bytes after that.
    assert_eq!(rops.get(32..36), Some(&[0x2B, 0x00, 0x02, 0x03][..]));
}

/// An attachment table hangs off a message, not off a folder — and a message that turns out to be
/// an embedded one hangs off an attachment. Both are chains this layer has to allow.
#[test]
fn an_embedded_message_hangs_off_the_attachment_it_is() {
    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(0x2A));
    let message = batch.open_message(
        logon,
        FolderId::new(1),
        MessageId::new(2),
        MessageMode::ReadOnly,
    );
    let table = batch.attachment_table(message);
    let attachment = batch.open_attachment(message, 3);
    let embedded = batch.open_embedded_message(attachment);
    batch.get_properties(embedded, &[PropertyTag::SUBJECT]);

    assert_eq!(table.index(), 2);
    assert_eq!(attachment.index(), 3);
    assert_eq!(embedded.index(), 4);
    assert!(batch.build().is_ok());
}

/// [MS-OXCTABL] §2.2.2.3 requires the sort key to be among the columns. The server's refusal does
/// not name the column, so the batch does — and it does it before spending the round trip.
#[test]
fn sorting_on_a_column_the_table_was_not_given_is_refused_by_name() {
    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(0x2A));
    let folder = batch.open_folder(logon, FolderId::new(1));
    let table = batch.contents_table(folder);
    batch.set_columns(table, &[PropertyTag::MID]).sort_table(
        table,
        &SortOrderSet::new([SortOrder::descending(PropertyTag::MESSAGE_DELIVERY_TIME)]),
    );

    assert!(matches!(
        batch.build(),
        Err(Error::SortColumnNotSet {
            tag: PropertyTag::MESSAGE_DELIVERY_TIME
        })
    ));
}

/// The same sort against a column set that does carry it goes out, and a table whose columns this
/// batch never saw is left to the server rather than refused.
#[test]
fn a_sort_whose_column_is_present_or_unknown_is_sent() {
    let orders = SortOrderSet::new([SortOrder::descending(PropertyTag::MESSAGE_DELIVERY_TIME)]);

    let mut batch = RopBatch::new();
    let logon = batch.bind(ObjectHandle::new(0x2A));
    let folder = batch.open_folder(logon, FolderId::new(1));
    let table = batch.contents_table(folder);
    batch
        .set_columns(table, &CONTENTS_COLUMNS)
        .sort_table(table, &orders);
    assert!(batch.build().is_ok());

    // A table bound from an earlier round trip carries no recorded column set here.
    let mut later = RopBatch::new();
    let bound = later.bind(ObjectHandle::new(0x30));
    later.sort_table(bound, &orders);
    assert!(later.build().is_ok());
}

/// A restriction goes out with its own length in front of it, and the packet is what
/// [MS-OXCDATA] §2.12.9.1 describes.
#[test]
fn a_restriction_is_sent_with_its_own_size() {
    let mut batch = RopBatch::new();
    let table = batch.bind(ObjectHandle::new(0x30));
    batch.restrict(table, &Restriction::exists(PropertyTag::SUBJECT));

    let built = batch.build().unwrap();
    #[rustfmt::skip]
    let expected = &[
        0x14, 0x00, 0x00,       // RopRestrict, LogonId, InputHandleIndex
        0x00,                   // RestrictFlags: synchronous
        0x05, 0x00,             // RestrictionDataSize
        0x08, 0x1F, 0x00, 0x37, 0x00, // ExistRestriction on PidTagSubject
    ][..];
    // After the RPC_HEADER_EXT and RopSize, and before the one-entry handle table.
    assert_eq!(built.bytes.get(10..21), Some(expected));
}

/// `DataSize` is two bytes, so a larger read could not be answered in full — and a short answer is
/// how the end of a stream is reported, which is why this is refused rather than clamped.
#[test]
fn a_stream_read_past_what_one_response_holds_fails_the_batch() {
    let mut batch = RopBatch::new();
    let stream = batch.bind(ObjectHandle::new(0x40));
    batch.read_stream(stream, 0x1_0000);

    assert!(matches!(
        batch.build(),
        Err(Error::StreamReadTooLarge {
            wanted: 0x1_0000,
            ..
        })
    ));
}

/// One write call, named, so a failure says which ROP let the slot through.
type Attempt = (&'static str, fn(&mut RopBatch, HandleSlot));

/// Every write ROP refuses a slot this batch never allocated, for the reason the reads do and with
/// more at stake: a create, a save or a delete addressed at a handle-table entry that does not
/// exist is a change to whatever the server has in that slot, and the ROP that made it reports
/// success.
#[test]
fn a_write_refuses_a_slot_from_another_batch() {
    let mut other = RopBatch::new();
    let stranger = other.bind(ObjectHandle::new(7));

    let attempts: [Attempt; 8] = [
        ("create_message", |batch, slot| {
            batch.create_message(slot, FolderId::new(1));
        }),
        ("save_message", |batch, slot| {
            batch.save_message(slot);
        }),
        ("modify_recipients", |batch, slot| {
            batch.modify_recipients(slot, &[]);
        }),
        ("create_attachment", |batch, slot| {
            batch.create_attachment(slot);
        }),
        ("save_attachment", |batch, slot| {
            batch.save_attachment(slot);
        }),
        ("write_stream", |batch, slot| {
            batch.write_stream(slot, &[0x00]);
        }),
        ("commit_stream", |batch, slot| {
            batch.commit_stream(slot);
        }),
        ("delete_messages", |batch, slot| {
            batch.delete_messages(slot, &[MessageId::new(0x0100)]);
        }),
    ];

    for (name, attempt) in attempts {
        let mut batch = RopBatch::new();
        attempt(&mut batch, stranger);
        assert_eq!(
            batch.build().unwrap_err(),
            Error::UnknownHandleSlot { index: 0 },
            "{name} sent a ROP against a slot it does not have"
        );
    }
}
