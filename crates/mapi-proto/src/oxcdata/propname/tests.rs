use super::*;

/// The exact bytes [MS-OXCPRPT] §4.1.1 puts on the wire for the two names in its worked example.
///
/// Everything after the `RopId`, `LogonId`, `InputHandleIndex`, `Flags` and `PropertyNameCount`
/// prefix, which the ROP encoder writes and this structure does not.
const WORKED_EXAMPLE: [u8; 76] = [
    0x01, 0x02, 0x20, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x46, 0x14, 0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00,
    0x70, 0x00, 0x31, 0x00, 0x00, 0x00, 0x01, 0x02, 0x20, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x14, 0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00,
    0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x70, 0x00, 0x32, 0x00, 0x00, 0x00,
];

fn encode(name: &PropertyName) -> Vec<u8> {
    let mut w = Writer::new();
    name.write(&mut w);
    w.finish()
}

/// The worked example is the only place a `PropertyName` appears as bytes in the whole corpus, so
/// it is the only independent check that this encoder is right rather than merely self-consistent.
#[test]
fn a_string_name_matches_the_worked_example_byte_for_byte() {
    let first = PropertyName::named(PropertySetId::APPOINTMENT, "TestProp1").expect("a name");
    let second = PropertyName::named(PropertySetId::APPOINTMENT, "TestProp2").expect("a name");

    let mut written = encode(&first);
    written.extend_from_slice(&encode(&second));
    assert_eq!(written, WORKED_EXAMPLE);
}

/// `NameSize` is `0x14` — twenty — for a nine-character name. Eighteen bytes of UTF-16 plus the
/// two-byte terminator, and writing eighteen would shift every field after it.
#[test]
fn name_size_counts_the_terminator() {
    let name = PropertyName::named(PropertySetId::APPOINTMENT, "TestProp1").expect("a name");
    let bytes = encode(&name);
    assert_eq!(bytes.get(17), Some(&0x14));
    assert_eq!(bytes.len(), 1 + 16 + 1 + 20);
}

#[test]
fn a_lid_name_is_kind_zero_and_four_bytes() {
    let location = PropertyName::lid(PropertySetId::APPOINTMENT, 0x0000_8208);
    let bytes = encode(&location);

    assert_eq!(bytes.len(), 1 + 16 + 4);
    assert_eq!(bytes.first(), Some(&0x00));
    assert_eq!(
        bytes.get(17..),
        Some(&[0x08, 0x82, 0x00, 0x00][..]),
        "the LID is little-endian like every other integer"
    );
    assert_eq!(location.as_lid(), Some(0x0000_8208));
    assert_eq!(location.as_name(), None);
    assert_eq!(location.set(), PropertySetId::APPOINTMENT);
}

#[test]
fn every_kind_round_trips_through_its_own_encoding() {
    let names = [
        PropertyName::lid(PropertySetId::APPOINTMENT, 0x0000_820D),
        PropertyName::named(PropertySetId::PUBLIC_STRINGS, "x-custom").expect("a name"),
        PropertyName::named(PropertySetId::PUBLIC_STRINGS, "").expect("an empty name"),
        // Outside the basic multilingual plane, so the encoded length is not the character count.
        PropertyName::named(PropertySetId::PUBLIC_STRINGS, "caf\u{e9}\u{1F600}").expect("a name"),
    ];

    for name in names {
        let bytes = encode(&name);
        let mut r = Reader::new(&bytes);
        assert_eq!(PropertyName::read(&mut r), Ok(Some(name.clone())), "{name}");
        assert!(r.is_empty(), "{name} left bytes behind");
    }
}

/// **The one place the layout is specified in a different document from the structure.**
///
/// [MS-OXCDATA] §2.6.1's diagram marks `LID`, `NameSize` and `Name` optional and `GUID` not, so a
/// reading confined to that section has a `Kind` of `0xFF` still carrying sixteen bytes of property
/// set. [MS-OXCPRPT] §3.2.5.9 step 3 governs this ROP and says there is no other return data for
/// the entry; Exchange Server SE `15.02.2562.045` agrees with it, framing a 30-byte ROP whose last
/// byte is the `0xFF`. Reading §2.6.1's sixteen bytes eats whatever comes next.
#[test]
fn an_id_with_no_name_is_the_kind_byte_and_nothing_else() {
    let bytes = [0xFF, 0xEE];
    let mut r = Reader::new(&bytes);

    assert_eq!(PropertyName::read(&mut r), Ok(None));
    assert_eq!(r.rest(), &[0xEE], "nothing follows the kind byte");

    // And at the very end of a buffer, which is how the lab sends it.
    let mut r = Reader::new(&[0xFF]);
    assert_eq!(PropertyName::read(&mut r), Ok(None));
    assert!(r.is_empty());
}

#[test]
fn a_name_this_crate_cannot_carry_is_refused_rather_than_truncated() {
    let interior_nul = PropertyName::named(PropertySetId::PUBLIC_STRINGS, "a\0b");
    assert!(matches!(
        interior_nul,
        Err(Error::UnencodableValue {
            value: "a property name",
            ..
        })
    ));

    // 126 UTF-16 units plus the terminator is 254 bytes, which fits; 127 is 256, which does not.
    assert!(PropertyName::named(PropertySetId::PUBLIC_STRINGS, "a".repeat(126)).is_ok());
    assert!(PropertyName::named(PropertySetId::PUBLIC_STRINGS, "a".repeat(127)).is_err());

    // A surrogate pair is two units, so 63 of them is the same 252 bytes as 126 ASCII characters.
    assert!(PropertyName::named(PropertySetId::PUBLIC_STRINGS, "\u{1F600}".repeat(63)).is_ok());
    assert!(PropertyName::named(PropertySetId::PUBLIC_STRINGS, "\u{1F600}".repeat(64)).is_err());
}

#[test]
fn an_unrecognised_kind_stops_rather_than_guessing_a_length() {
    let mut bytes = vec![0x02];
    bytes.extend_from_slice(PropertySetId::APPOINTMENT.as_guid().as_bytes());
    bytes.extend_from_slice(&[0x00; 8]);

    assert_eq!(
        PropertyName::read(&mut Reader::new(&bytes)),
        Err(Error::InvalidPropertyNameKind { kind: 0x02, at: 0 })
    );
}

#[test]
fn a_truncated_structure_never_panics() {
    for length in 0..WORKED_EXAMPLE.len() / 2 {
        let buf = WORKED_EXAMPLE.get(..length).expect("a prefix");
        let _ = PropertyName::read(&mut Reader::new(buf));
    }

    // A NameSize longer than the bytes that follow it.
    let mut lying = vec![0x01];
    lying.extend_from_slice(PropertySetId::APPOINTMENT.as_guid().as_bytes());
    lying.extend_from_slice(&[0xFE, 0x41, 0x00]);
    assert!(PropertyName::read(&mut Reader::new(&lying)).is_err());
}

/// A `NameSize` of 254 with no terminator inside it is 127 UTF-16 units — one more than this crate
/// can write back, because `NameSize` counts the terminator and is one byte. Refused on the way in
/// rather than accepted and clamped on the way out: a clamped `NameSize` of 255 followed by 256
/// bytes of name would have the server read the next `PropertyName` as part of this one's.
#[test]
fn a_name_too_long_to_write_back_is_refused_on_the_way_in() {
    let mut unterminated = vec![0x01];
    unterminated.extend_from_slice(PropertySetId::PUBLIC_STRINGS.as_guid().as_bytes());
    unterminated.push(0xFE);
    unterminated.extend(core::iter::repeat_n([0x41, 0x00], 127).flatten());

    assert!(matches!(
        PropertyName::read(&mut Reader::new(&unterminated)),
        Err(Error::UnencodableValue {
            value: "a property name",
            ..
        })
    ));

    // One unit shorter — 126 characters and a terminator — is the longest that does round-trip.
    let mut longest = vec![0x01];
    longest.extend_from_slice(PropertySetId::PUBLIC_STRINGS.as_guid().as_bytes());
    longest.push(0xFE);
    longest.extend(core::iter::repeat_n([0x41, 0x00], 126).flatten());
    longest.extend_from_slice(&[0x00, 0x00]);

    let name = PropertyName::read(&mut Reader::new(&longest)).expect("a 126-character name");
    assert_eq!(
        name.as_ref().and_then(PropertyName::as_name).map(str::len),
        Some(126)
    );
    assert_eq!(encode(&name.expect("a name")), longest);
}

/// An odd `NameSize` cannot be a UTF-16 string. It is reported rather than rounded down, because
/// rounding down would hand back a name one character short of the one that was stored — which
/// resolves to a different property and says nothing.
#[test]
fn an_odd_name_size_is_an_error() {
    let mut odd = vec![0x01];
    odd.extend_from_slice(PropertySetId::PUBLIC_STRINGS.as_guid().as_bytes());
    odd.extend_from_slice(&[0x03, 0x41, 0x00, 0x00]);

    assert!(matches!(
        PropertyName::read(&mut Reader::new(&odd)),
        Err(Error::InvalidUtf16 { .. })
    ));
}

#[test]
fn an_unpaired_surrogate_in_a_name_is_an_error() {
    let mut bad = vec![0x01];
    bad.extend_from_slice(PropertySetId::PUBLIC_STRINGS.as_guid().as_bytes());
    bad.extend_from_slice(&[0x04, 0x00, 0xD8, 0x00, 0x00]);

    assert!(matches!(
        PropertyName::read(&mut Reader::new(&bad)),
        Err(Error::InvalidUtf16 { .. })
    ));
}

#[test]
fn a_name_prints_its_set_and_what_identifies_it_inside_it() {
    let lid = PropertyName::lid(PropertySetId::APPOINTMENT, 0x0000_8208);
    assert_eq!(
        lid.to_string(),
        "PSETID_Appointment {00062002-0000-0000-c000-000000000046}/0x00008208"
    );

    let named = PropertyName::named(PropertySetId::INTERNET_HEADERS, "x-spam").expect("a name");
    assert!(named.to_string().ends_with("/x-spam"), "{named}");
}

/// The whole reason the id is a type and not a `u16`: the same number in two mailboxes is two
/// different properties, and nothing on the wire says so.
#[test]
fn an_id_knows_which_store_issued_it() {
    let developer = Guid::from_bytes([0x01; 16]);
    let developer2 = Guid::from_bytes([0x02; 16]);

    let resolved = NamedPropertyId::new(developer, 0x8205);
    assert!(resolved.belongs_to(developer));
    assert!(!resolved.belongs_to(developer2));
    assert_eq!(resolved.store(), developer);
    assert_eq!(resolved.as_u16(), 0x8205);
    assert_eq!(resolved.to_string(), "0x8205");

    // Same number, different store: equal ids, unequal values.
    assert_ne!(resolved, NamedPropertyId::new(developer2, 0x8205));
}

/// The type is supplied by the caller because the id carries none, and the tag that results is a
/// named tag like any other.
#[test]
fn an_id_becomes_a_tag_only_when_a_type_is_supplied() {
    let id = NamedPropertyId::new(Guid::from_bytes([0x01; 16]), 0x8205);
    let tag = id.tag(PropertyType::Integer32);

    assert_eq!(tag, PropertyTag::new(0x8205_0003));
    assert_eq!(tag.id(), 0x8205);
    assert!(tag.is_named());
    assert_eq!(tag.property_type(), PropertyType::Integer32);
    assert_eq!(id.tag(PropertyType::Time), PropertyTag::new(0x8205_0040));
}
