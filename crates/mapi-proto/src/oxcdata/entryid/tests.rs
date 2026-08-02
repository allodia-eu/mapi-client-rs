use super::*;

/// The Calendar folder's `PidTagIpmAppointmentEntryId`, transcribed byte for byte from
/// [MS-OXOSFLD] §4.2.1's worked example. Using the document's own bytes rather than ones this
/// crate encoded means the decoder is checked against the specification and not against itself.
#[rustfmt::skip]
const SPEC_EXAMPLE: [u8; 46] = [
    0x00, 0x00, 0x00, 0x00,                         // Flags
    0x6A, 0x3C, 0xB8, 0xFA, 0x3B, 0xA9, 0xF0, 0x46, // ProviderUID
    0xB4, 0xF4, 0xE4, 0xB6, 0xC7, 0x74, 0x45, 0x09,
    0x01, 0x00,                                     // FolderType: PrivateFolder
    0x02, 0x27, 0x39, 0x56, 0x14, 0x8B, 0xEF, 0x4F, // DatabaseGuid
    0x98, 0x14, 0x81, 0x7E, 0x2C, 0x82, 0xBD, 0xC2,
    0x00, 0x00, 0x01, 0x50, 0x4D, 0xF6,             // GlobalCounter
    0x00, 0x00,                                     // Pad
];

#[test]
fn the_specifications_own_example_decodes_field_for_field() {
    let entry_id = FolderEntryId::parse(&SPEC_EXAMPLE).expect("the document's own bytes");

    assert_eq!(
        entry_id.provider_uid().to_string(),
        "{fab83c6a-a93b-46f0-b4f4-e4b6c7744509}"
    );
    assert_eq!(entry_id.object_type(), StoreObjectType::PRIVATE_FOLDER);
    assert!(entry_id.object_type().is_folder());
    assert_eq!(
        entry_id.long_term_id().database_guid().to_string(),
        "{56392702-8b14-4fef-9814-817e2c82bdc2}"
    );
    assert_eq!(
        entry_id.long_term_id().global_counter_bytes(),
        [0x00, 0x00, 0x01, 0x50, 0x4D, 0xF6]
    );
}

/// The example's own `RopCreateFolder` response reports the FID as `0001-000001504df6`, which is
/// the replica id and then the six counter bytes in wire order. The counter this crate reads back
/// must be those same six bytes: getting the order wrong here would produce a long-term id that
/// converts to a plausible folder id for a folder nobody asked for.
///
/// [MS-OXOSFLD] §4.2.2 — `FolderId: 0001-000001504df6`
#[test]
fn the_counter_bytes_are_the_ones_the_examples_fid_notation_shows() {
    let entry_id = FolderEntryId::parse(&SPEC_EXAMPLE).expect("the document's own bytes");
    let counter = entry_id.long_term_id().global_counter_bytes().iter().fold(
        String::new(),
        |mut text, byte| {
            use core::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        },
    );
    assert_eq!(counter, "000001504df6");
}

#[test]
fn an_entry_id_round_trips_through_its_bytes() {
    let entry_id = FolderEntryId::parse(&SPEC_EXAMPLE).expect("the document's own bytes");
    assert_eq!(entry_id.to_bytes(), SPEC_EXAMPLE);
    assert_eq!(
        FolderEntryId::parse(&entry_id.to_bytes()),
        Ok(entry_id),
        "encoding and decoding disagree"
    );
}

/// The check that keeps an entry id from one mailbox out of another: for a private-mailbox folder
/// the provider is the `MailboxGuid` the logon reported.
///
/// [MS-OXCDATA] §2.2.4.1 — `Provider UID`
#[test]
fn an_entry_id_knows_which_mailbox_issued_it() {
    let entry_id = FolderEntryId::parse(&SPEC_EXAMPLE).expect("the document's own bytes");
    assert!(entry_id.belongs_to(entry_id.provider_uid()));
    assert!(!entry_id.belongs_to(Guid::from_bytes([0xFF; 16])));

    // Printed as the folder it names *and* the mailbox that issued it, because the second half is
    // the only thing that tells two mailboxes' identical-looking folders apart.
    //
    // The counter prints as the number [`LongTermId::global_counter`] reads, which is the six wire
    // bytes little-endian — **not** the `0001-000001504df6` notation the specification's own
    // example and Exchange's own logs use for the same value. Recorded here so that a reader
    // comparing a line of this crate's output against a server log knows the digits are reversed.
    assert_eq!(
        entry_id.to_string(),
        "{56392702-8b14-4fef-9814-817e2c82bdc2}-F64D50010000 in \
         {fab83c6a-a93b-46f0-b4f4-e4b6c7744509}"
    );
}

/// Each of the three refusals, and what makes each worth having. The object-type one especially:
/// a message entry id differs from a folder's in that field alone.
#[test]
fn a_value_that_is_not_a_folder_entry_id_is_refused_with_the_reason() {
    let reason = |bytes: &[u8]| match FolderEntryId::parse(bytes) {
        Err(Error::InvalidEntryId { reason, length }) => {
            assert_eq!(length, bytes.len());
            reason
        }
        other => panic!("{other:?}"),
    };

    assert!(reason(&[]).contains("46 bytes"));
    assert!(reason(&SPEC_EXAMPLE[..45]).contains("46 bytes"));

    let mut short_term = SPEC_EXAMPLE;
    short_term[0] = 0x01;
    assert!(reason(&short_term).contains("short-term"));

    // The same 46 bytes with PrivateMessage in the type field.
    let mut message = SPEC_EXAMPLE;
    message[20] = 0x07;
    assert!(reason(&message).contains("neither PrivateFolder nor PublicFolder"));

    // And with MappedPublicFolder, which the same reason has to cover truthfully: it is a folder
    // type that this crate refuses, so a message saying "a message rather than a folder" would be
    // a false statement about the bytes in hand.
    let mut wacky = SPEC_EXAMPLE;
    wacky[20] = 0x05;
    assert!(reason(&wacky).contains("neither PrivateFolder nor PublicFolder"));
}

/// A long-term id is the last 24 bytes of a folder entry id, which is the whole reason the
/// conversion ROP takes one: the property's tail goes straight onto the wire.
#[test]
fn a_long_term_id_is_the_tail_of_the_entry_id() {
    let entry_id = FolderEntryId::parse(&SPEC_EXAMPLE).expect("the document's own bytes");

    let mut w = Writer::new();
    entry_id.long_term_id().write(&mut w);
    let written = w.finish();

    assert_eq!(written.len(), LongTermId::SIZE);
    assert_eq!(
        written,
        SPEC_EXAMPLE[FolderEntryId::SIZE - LongTermId::SIZE..]
    );
    assert_eq!(
        LongTermId::read(&mut Reader::new(&written)),
        Ok(entry_id.long_term_id())
    );
}

#[test]
fn a_long_term_id_is_built_and_printed_from_its_parts() {
    let guid = Guid::from_bytes([0x11; 16]);
    let id = LongTermId::new(guid, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    assert_eq!(id.database_guid(), guid);
    assert_eq!(id.global_counter(), 0x0605_0403_0201);
    assert_eq!(
        id.to_string(),
        "{11111111-1111-1111-1111-111111111111}-060504030201"
    );
}

#[test]
fn a_truncated_long_term_id_errors_rather_than_panicking() {
    for length in 0..LongTermId::SIZE {
        let buf = vec![0_u8; length];
        assert!(
            LongTermId::read(&mut Reader::new(&buf)).is_err(),
            "{length}"
        );
    }
}

#[test]
fn store_object_types_carry_the_values_the_table_gives_them() {
    for (kind, raw, name, folder) in [
        (
            StoreObjectType::PRIVATE_FOLDER,
            0x0001,
            "PrivateFolder",
            true,
        ),
        (StoreObjectType::PUBLIC_FOLDER, 0x0003, "PublicFolder", true),
        (
            StoreObjectType::PRIVATE_MESSAGE,
            0x0007,
            "PrivateMessage",
            false,
        ),
        (
            StoreObjectType::PUBLIC_MESSAGE,
            0x0009,
            "PublicMessage",
            false,
        ),
    ] {
        assert_eq!(kind.as_u16(), raw);
        assert_eq!(StoreObjectType::new(raw), kind);
        assert_eq!(kind.name(), Some(name));
        assert_eq!(kind.is_folder(), folder);
        assert_eq!(kind.to_string(), format!("{name} (0x{raw:04X})"));
    }

    // MappedPublicFolder: a folder type by name, and still not a folder by this crate's reckoning.
    // [MS-OXCDATA] §2.2.4 endnote <2> says the server neither reads nor writes it, so one arriving
    // from Exchange means the bytes are not an entry id. Refusing it is the point, not an
    // oversight.
    let wacky = StoreObjectType::new(0x0005);
    assert_eq!(wacky.name(), None);
    assert!(!wacky.is_folder());
    assert_eq!(wacky.to_string(), "0x0005");
}

/// The point of the newtype: the same eight bytes are a folder id or a message id depending on
/// what was converted, and nothing in them says which.
#[test]
fn a_short_term_id_is_read_as_whichever_was_converted() {
    let id = ShortTermId::new(0x0001_0000_0150_4DF6);
    assert_eq!(id.as_u64(), 0x0001_0000_0150_4DF6);
    assert_eq!(id.as_folder_id(), FolderId::new(0x0001_0000_0150_4DF6));
    assert_eq!(id.as_message_id(), MessageId::new(0x0001_0000_0150_4DF6));
    assert_eq!(id.to_string(), "0x0001000001504DF6");

    assert_eq!(ShortTermId::from(FolderId::new(7)).as_u64(), 7);
    assert_eq!(ShortTermId::from(MessageId::new(7)).as_u64(), 7);
}
