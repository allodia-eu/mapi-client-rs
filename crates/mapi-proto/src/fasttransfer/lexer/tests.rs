use super::*;
use crate::oxcdata::{PropertyNameKind, ServerEntryId};

/// Lexes one whole element from `bytes`, asserting nothing is left over.
fn element(bytes: &[u8]) -> Element {
    let mut lexer = Lexer::new();
    lexer.feed(bytes);
    let element = lexer.next_element().unwrap().expect("a whole element");
    assert_eq!(
        lexer.pending(),
        0,
        "the element consumed exactly its own bytes"
    );
    element
}

fn property(tag: u32, value: &[u8]) -> StreamProperty {
    let mut bytes = tag.to_le_bytes().to_vec();
    bytes.extend_from_slice(value);
    match element(&bytes) {
        Element::Property(property) => property,
        Element::Marker(marker) => panic!("{marker:?} is not a property"),
    }
}

fn counted(bytes: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(bytes.len()).unwrap().to_le_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn utf16_z(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// Every fixed-width type in the stream's own encoding — the boolean two bytes wide.
#[test]
fn every_fixed_width_type_reads_its_stream_width() {
    let cases: [(u32, &[u8], PropertyValue); 11] = [
        (0x0001_0002, &[7, 0], PropertyValue::Integer16(7)),
        (0x0001_0003, &[7, 0, 0, 0], PropertyValue::Integer32(7)),
        (
            0x0001_0004,
            &[0, 0, 0xC0, 0x3F],
            PropertyValue::Floating32(Floating32::new(1.5)),
        ),
        (
            0x0001_0005,
            &[0, 0, 0, 0, 0, 0, 0xF0, 0x3F],
            PropertyValue::Floating64(Floating64::new(1.0)),
        ),
        (
            0x0001_0006,
            &[0x39, 0x30, 0, 0, 0, 0, 0, 0],
            PropertyValue::Currency(Currency::from_scaled(12_345)),
        ),
        (
            0x0001_0007,
            &[0, 0, 0, 0, 0, 0, 0x04, 0x40],
            PropertyValue::FloatingTime(Floating64::new(2.5)),
        ),
        (
            0x0001_000A,
            &[0x0F, 0x01, 0x04, 0x80],
            PropertyValue::Error(crate::ErrorCode::new(0x8004_010F)),
        ),
        (0x0001_000B, &[0x00, 0x01], PropertyValue::Boolean(true)),
        (
            0x0001_0014,
            &[1, 0, 0, 0, 0, 0, 0, 0],
            PropertyValue::Integer64(1),
        ),
        (
            0x0001_0040,
            &[2, 0, 0, 0, 0, 0, 0, 0],
            PropertyValue::Time(FileTime::new(2)),
        ),
        (
            0x0001_0048,
            &[0xAB; 16],
            PropertyValue::Guid(Guid::from_bytes([0xAB; 16])),
        ),
    ];
    for (tag, bytes, expected) in cases {
        assert_eq!(property(tag, bytes).into_value(), expected, "0x{tag:08X}");
    }
}

/// Every variable-length type is a 32-bit length and that many bytes; a string's terminator is
/// dropped when it is there and tolerated when it is not.
#[test]
fn every_variable_length_type_is_a_long_length_then_its_bytes() {
    let text = |value: &PropertyValue| {
        value
            .as_string()
            .map(TableString::as_str)
            .map(str::to_owned)
    };

    let unicode = property(0x0037_001F, &counted(&utf16_z("Hello")));
    assert_eq!(text(unicode.value()).as_deref(), Some("Hello"));
    let unterminated: Vec<u8> = "Hi".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let bare = property(0x0037_001F, &counted(&unterminated));
    assert_eq!(text(bare.value()).as_deref(), Some("Hi"));

    let eight = property(0x0037_001E, &counted(b"abc\0"));
    assert_eq!(
        eight.value(),
        &PropertyValue::String8(TableString::from("abc"))
    );

    assert_eq!(
        property(0x0FF9_0102, &counted(&[1, 2, 3])).into_value(),
        PropertyValue::Binary(vec![1, 2, 3])
    );
    assert_eq!(
        property(0x3701_000D, &counted(&[9, 9])).into_value(),
        PropertyValue::Object(vec![9, 9])
    );
    let server_id = [1_u8; 21];
    assert_eq!(
        property(0x0001_00FB, &counted(&server_id)).into_value(),
        PropertyValue::ServerId(ServerEntryId::from_bytes(&server_id))
    );
}

/// Every list type: a 32-bit count, then the values, each variable-length one with its own length.
#[test]
fn every_list_type_is_a_count_then_its_values() {
    let two = |bytes: &[u8]| -> Vec<u8> { [&[2, 0, 0, 0][..], bytes, bytes].concat() };
    let cases: Vec<(u32, Vec<u8>, PropertyValue)> = vec![
        (
            0x0001_1002,
            two(&[1, 0]),
            PropertyValue::MultipleInteger16(vec![1, 1]),
        ),
        (
            0x0001_1003,
            two(&[1, 0, 0, 0]),
            PropertyValue::MultipleInteger32(vec![1, 1]),
        ),
        (
            0x0001_1014,
            two(&[1, 0, 0, 0, 0, 0, 0, 0]),
            PropertyValue::MultipleInteger64(vec![1, 1]),
        ),
        (
            0x0001_1004,
            two(&[1, 0, 0, 0]),
            PropertyValue::MultipleFloating32(vec![Floating32::from_bits(1); 2]),
        ),
        (
            0x0001_1005,
            two(&[1, 0, 0, 0, 0, 0, 0, 0]),
            PropertyValue::MultipleFloating64(vec![Floating64::from_bits(1); 2]),
        ),
        (
            0x0001_1007,
            two(&[1, 0, 0, 0, 0, 0, 0, 0]),
            PropertyValue::MultipleFloatingTime(vec![Floating64::from_bits(1); 2]),
        ),
        (
            0x0001_1006,
            two(&[1, 0, 0, 0, 0, 0, 0, 0]),
            PropertyValue::MultipleCurrency(vec![Currency::from_scaled(1); 2]),
        ),
        (
            0x0001_1040,
            two(&[1, 0, 0, 0, 0, 0, 0, 0]),
            PropertyValue::MultipleTime(vec![FileTime::new(1); 2]),
        ),
        (
            0x0001_1048,
            two(&[7; 16]),
            PropertyValue::MultipleGuid(vec![Guid::from_bytes([7; 16]); 2]),
        ),
        (
            0x0001_101F,
            two(&counted(&utf16_z("x"))),
            PropertyValue::MultipleString(vec![TableString::from("x"); 2]),
        ),
        (
            0x0001_101E,
            two(&counted(b"y\0")),
            PropertyValue::MultipleString8(vec![TableString::from("y"); 2]),
        ),
        (
            0x0001_1102,
            two(&counted(&[5])),
            PropertyValue::MultipleBinary(vec![vec![5]; 2]),
        ),
    ];
    for (tag, bytes, expected) in cases {
        assert_eq!(property(tag, &bytes).into_value(), expected, "0x{tag:08X}");
    }
}

/// A named property brings its property set and LID or name inline, after the tag.
#[test]
fn a_named_property_carries_its_name_inline() {
    let set = PropertySetId::COMMON;
    let mut by_lid = set.as_guid().as_bytes().to_vec();
    by_lid.push(0x00);
    by_lid.extend_from_slice(&0x8503_u32.to_le_bytes());
    by_lid.extend_from_slice(&[0x00, 0x00]);
    let reminder = property(0x8008_000B, &by_lid);
    assert_eq!(reminder.name().and_then(PropertyName::as_lid), Some(0x8503));
    assert_eq!(reminder.value(), &PropertyValue::Boolean(false));

    let mut by_name = PropertySetId::PUBLIC_STRINGS.as_guid().as_bytes().to_vec();
    by_name.push(0x01);
    by_name.extend_from_slice(&utf16_z("Keywords"));
    by_name.extend_from_slice(&[0, 0, 0, 0]);
    let keywords = property(0x800C_101F, &by_name);
    assert!(matches!(
        keywords.name().map(PropertyName::kind),
        Some(PropertyNameKind::Name(name)) if name == "Keywords"
    ));
    assert_eq!(keywords.value(), &PropertyValue::MultipleString(Vec::new()));

    let mut unknown = set.as_guid().as_bytes().to_vec();
    unknown.push(0x02);
    let mut bytes = 0x8008_000B_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&unknown);
    let mut lexer = Lexer::new();
    lexer.feed(&bytes);
    assert!(matches!(
        lexer.next_element(),
        Err(Error::InvalidPropertyNameKind { kind: 0x02, .. })
    ));
}

/// A string under a code-page type is reported under the ordinary string type: UTF-16 for code
/// page 1200, 8-bit for anything else, the code page kept either way.
#[test]
fn a_code_page_string_is_reported_under_the_ordinary_string_type() {
    let western = property(0x0037_84E4, &counted(b"cafe "));
    assert_eq!(western.tag(), PropertyTag::new(0x0037_001E));
    assert_eq!(western.code_page(), Some(1252));
    assert_eq!(
        western.value(),
        &PropertyValue::String8(TableString::from("cafe"))
    );
    assert_eq!(
        property(0x0037_001F, &counted(&utf16_z("u"))).code_page(),
        None
    );
}

/// [MS-OXCFXICS] §3.2.5.2.1: tagged `PtypInteger32`, carried and read as `PtypBinary`.
#[test]
fn idset_given_is_read_as_binary_despite_its_tag() {
    let given = property(0x4017_0003, &counted(&[1, 2, 3, 4, 5]));
    assert_eq!(given.tag(), PropertyTag::META_TAG_IDSET_GIVEN);
    assert_eq!(
        given.into_value(),
        PropertyValue::Binary(vec![1, 2, 3, 4, 5])
    );
}

#[test]
fn a_string_that_is_not_utf16_is_refused() {
    let mut lexer = Lexer::new();
    let mut bytes = 0x0037_001F_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&counted(&[0x00, 0xD8]));
    lexer.feed(&bytes);
    assert!(matches!(
        lexer.next_element(),
        Err(Error::InvalidUtf16 { .. })
    ));
}

/// A value split across buffers waits for the rest, and a lexer fed a short read does not try
/// again until the bytes it needs are there.
#[test]
fn a_split_value_waits_for_the_bytes_it_needs() {
    let mut bytes = 0x0FF9_0102_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&counted(&[0xEE; 100]));
    let mut lexer = Lexer::new();
    lexer.feed(&bytes[..10]);
    assert_eq!(lexer.next_element().unwrap(), None);
    assert_eq!(lexer.pending(), 10);
    lexer.feed(&bytes[10..50]);
    assert_eq!(
        lexer.next_element().unwrap(),
        None,
        "still short of the length it named"
    );
    lexer.feed(&bytes[50..]);
    assert!(matches!(
        lexer.next_element().unwrap(),
        Some(Element::Property(_))
    ));
    assert_eq!(lexer.next_element().unwrap(), None);
}

/// A name whose terminator is in the next buffer is waited on, not refused.
#[test]
fn a_named_property_split_inside_its_name_waits() {
    let mut bytes = 0x800C_101F_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(PropertySetId::PUBLIC_STRINGS.as_guid().as_bytes());
    bytes.push(0x01);
    bytes.extend_from_slice(&utf16_z("Keywords"));
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    let mut lexer = Lexer::new();
    lexer.feed(&bytes[..25]);
    assert_eq!(lexer.next_element().unwrap(), None);
    lexer.feed(&bytes[25..]);
    assert!(lexer.next_element().unwrap().is_some());
}
