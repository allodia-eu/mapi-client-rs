use super::*;
use crate::oxcdata::PropertySetId;

/// [MS-OXCPRPT] §4.1.1's complete request buffer, byte for byte.
///
/// A worked example is worth more than any amount of self-consistency here: it is the only
/// statement in the corpus of what this ROP looks like on the wire that this crate did not write.
#[rustfmt::skip]
const EXAMPLE_REQUEST: [u8; 82] = [
    0x56, 0x00, 0x00,
    0x02, 0x02, 0x00,
    0x01,
    0x02, 0x20, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    0x14,
    0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x70, 0x00,
    0x31, 0x00, 0x00, 0x00,
    0x01,
    0x02, 0x20, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    0x14,
    0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x50, 0x00, 0x72, 0x00, 0x6F, 0x00, 0x70, 0x00,
    0x32, 0x00, 0x00, 0x00,
];

/// [MS-OXCPRPT] §4.1.2's complete response buffer.
///
/// Note the two-byte ids. §4.1.2's own prose calls each entry "four-byte property ID" and its own
/// bytes disagree: `3E 86 3F 86` is two ids, not one. [MS-OXCROPS] §2.2.8.1.2 says unsigned 16-bit
/// integers, the bytes agree with it, and that is what this decodes.
const EXAMPLE_RESPONSE: [u8; 12] = [
    0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3E, 0x86, 0x3F, 0x86,
];

fn test_props() -> Vec<PropertyName> {
    vec![
        PropertyName::named(PropertySetId::APPOINTMENT, "TestProp1").expect("a name"),
        PropertyName::named(PropertySetId::APPOINTMENT, "TestProp2").expect("a name"),
    ]
}

#[test]
fn the_request_matches_the_worked_example_byte_for_byte() {
    let mut w = Writer::new();
    encode_property_ids_from_names(&mut w, 0, &test_props(), NameRegistration::CreateIfMissing);
    assert_eq!(w.finish(), EXAMPLE_REQUEST);
}

#[test]
fn the_response_matches_the_worked_example() {
    // Past RopId, InputHandleIndex and ReturnValue, which the response decoder consumes.
    let body = EXAMPLE_RESPONSE.get(6..).expect("the response body");
    let mut r = Reader::new(body);
    let response = PropertyIdsResponse::read(&mut r).expect("two ids");

    assert_eq!(response.ids(), &[0x863E, 0x863F]);
    assert!(r.is_empty());
}

/// `Flags` is the difference between a lookup and a write to the store's mapping table, so it gets
/// a test of its own rather than riding along in the example above.
///
/// [MS-OXCPRPT] §2.2.12.1
#[test]
fn the_create_flag_is_the_only_thing_that_differs_between_the_two_registrations() {
    let names = [PropertyName::lid(PropertySetId::APPOINTMENT, 0x0000_8208)];

    let mut existing = Writer::new();
    encode_property_ids_from_names(&mut existing, 0, &names, NameRegistration::Existing);
    let existing = existing.finish();

    let mut creating = Writer::new();
    encode_property_ids_from_names(&mut creating, 0, &names, NameRegistration::CreateIfMissing);
    let creating = creating.finish();

    assert_eq!(existing.get(3), Some(&0x00));
    assert_eq!(creating.get(3), Some(&0x02));
    assert_eq!(existing.get(4..), creating.get(4..));
    assert_eq!(NameRegistration::default(), NameRegistration::Existing);
}

/// A count of zero is a question rather than an empty request: [MS-OXCPRPT] §3.2.5.10 has a server
/// answer it, on a Logon object, with every named property id registered in the store.
#[test]
fn no_names_at_all_asks_for_the_whole_mapping_table() {
    let mut w = Writer::new();
    encode_property_ids_from_names(&mut w, 3, &[], NameRegistration::Existing);
    assert_eq!(w.finish(), vec![0x56, 0x00, 0x03, 0x00, 0x00, 0x00]);
}

#[test]
fn the_inverse_rop_carries_two_byte_ids() {
    let mut w = Writer::new();
    encode_names_from_property_ids(&mut w, 1, &[0x8205, 0x0037]);

    #[rustfmt::skip]
    assert_eq!(
        w.finish(),
        vec![
            0x55, 0x00, 0x01,
            0x02, 0x00,
            0x05, 0x82,
            0x37, 0x00,
        ]
    );
}

/// The inverse ROP's answer round-trips through the structure the forward one writes, which is what
/// makes the two a matched pair rather than two encoders that happen to agree with themselves.
#[test]
fn the_inverse_response_decodes_the_names_the_forward_request_wrote() {
    let mut body = Writer::new();
    body.u16(2);
    for name in test_props() {
        name.write(&mut body);
    }
    let body = body.finish();

    let mut r = Reader::new(&body);
    let response = PropertyNamesResponse::read(&mut r).expect("two names");
    let expected: Vec<Option<PropertyName>> = test_props().into_iter().map(Some).collect();
    assert_eq!(response.names(), expected.as_slice());
    assert!(r.is_empty());
}

/// An id a store has no name for. It keeps its place, so the answer to the fourth id asked about is
/// still the fourth entry — and it is **one byte**, per [MS-OXCPRPT] §3.2.5.9 rather than the
/// seventeen [MS-OXCDATA] §2.6.1's diagram implies on its own.
#[test]
fn an_unnamed_id_keeps_its_place_and_costs_one_byte() {
    let mut body = Writer::new();
    body.u16(2).u8(0xFF);
    PropertyName::lid(PropertySetId::APPOINTMENT, 0x0000_8205).write(&mut body);
    let body = body.finish();

    let mut r = Reader::new(&body);
    let response = PropertyNamesResponse::read(&mut r).expect("an unnamed id and a named one");
    assert_eq!(response.names().len(), 2);
    assert_eq!(response.names().first(), Some(&None));
    assert_eq!(
        response
            .names()
            .get(1)
            .and_then(|name| name.as_ref()?.as_lid()),
        Some(0x0000_8205)
    );
    assert!(r.is_empty(), "a 0xFF entry consumed bytes it should not");
}

/// A count that promises more than the buffer holds is a server's number, not this crate's.
#[test]
fn a_lying_count_errors_rather_than_allocating() {
    let ids = [0xFF_u8, 0xFF, 0x01, 0x00];
    assert!(PropertyIdsResponse::read(&mut Reader::new(&ids)).is_err());

    let names = [0xFF_u8, 0xFF];
    assert!(PropertyNamesResponse::read(&mut Reader::new(&names)).is_err());
}

#[test]
fn a_truncated_response_never_panics() {
    for length in 0..EXAMPLE_RESPONSE.len() {
        let buf = EXAMPLE_RESPONSE.get(6..length).unwrap_or_default();
        let _ = PropertyIdsResponse::read(&mut Reader::new(buf));
    }
    assert_eq!(
        PropertyIdsResponse::read(&mut Reader::new(&[0x00, 0x00])),
        Ok(PropertyIdsResponse::default())
    );
    assert!(PropertyNamesResponse::default().names().is_empty());
}
