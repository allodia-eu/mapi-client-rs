use super::*;
use crate::oxcdata::{Guid, HIERARCHY_COLUMNS};

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
