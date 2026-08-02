use super::*;
use crate::error::Error;
use crate::oxcdata::kind::ValueContext;
use crate::wire::{Reader, Writer};

fn utf16_z(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

fn read(bytes: &[u8], property_type: PropertyType) -> Result<PropertyValue, Error> {
    PropertyValue::read(&mut Reader::new(bytes), property_type, ValueContext::Object)
}

fn write(value: &PropertyValue) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    value.write(&mut w, ValueContext::Object)?;
    Ok(w.finish())
}

/// Every fixed-width type, with the width [MS-OXCDATA] §2.11.1 gives it. The assertion that the
/// reader is empty afterwards is the one that matters: a value read one byte short or one byte
/// long shifts every property after it, with no error anywhere.
#[test]
fn each_fixed_width_type_reads_exactly_its_own_width() {
    let cases: [(PropertyType, &[u8], PropertyValue); 8] = [
        (
            PropertyType::Integer16,
            &[0x07, 0x00],
            PropertyValue::Integer16(7),
        ),
        (
            PropertyType::Integer32,
            &[0x07, 0x00, 0x00, 0x00],
            PropertyValue::Integer32(7),
        ),
        (
            PropertyType::Integer64,
            &[0x01, 0, 0, 0, 0, 0, 0, 0x0D],
            PropertyValue::Integer64(0x0D00_0000_0000_0001),
        ),
        (
            PropertyType::Floating64,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F],
            PropertyValue::Floating64(Floating64::new(1.0)),
        ),
        (PropertyType::Boolean, &[0x01], PropertyValue::Boolean(true)),
        (
            PropertyType::Time,
            &[0x9E, 0x71, 0x1A, 0x36, 0x5E, 0xD8, 0xDD, 0x01],
            PropertyValue::Time(FileTime::new(0x01DD_D85E_361A_719E)),
        ),
        (
            PropertyType::Guid,
            &[
                0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
                0x9A, 0xBC,
            ],
            PropertyValue::Guid(Guid::from_bytes([
                0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78,
                0x9A, 0xBC,
            ])),
        ),
        (
            PropertyType::ErrorCode,
            &[0x05, 0x03, 0x04, 0x80],
            PropertyValue::Error(ErrorCode::TOO_BIG),
        ),
    ];

    for (property_type, bytes, expected) in cases {
        let mut r = Reader::new(bytes);
        assert_eq!(
            PropertyValue::read(&mut r, property_type, ValueContext::Object).unwrap(),
            expected
        );
        assert!(r.is_empty(), "{property_type} left bytes behind");
        assert_eq!(expected.property_type(), Some(property_type));
    }
}

/// A `PtypBinary` value is a COUNT of bytes and then those bytes; in a ROP buffer that COUNT is
/// 16 bits. Reading it as 32 would swallow the first two bytes of the value and every property
/// after it would decode against the wrong offset.
///
/// [MS-OXCDATA] §2.11.1.1
#[test]
fn a_binary_value_is_a_sixteen_bit_count_then_that_many_bytes() {
    let bytes = [0x03, 0x00, 0xAA, 0xBB, 0xCC];
    let mut r = Reader::new(&bytes);
    let value = PropertyValue::read(&mut r, PropertyType::Binary, ValueContext::Object).unwrap();

    assert_eq!(value.as_binary(), Some(&[0xAA, 0xBB, 0xCC][..]));
    assert!(r.is_empty());
    assert_eq!(write(&value).unwrap(), bytes);
}

#[test]
fn an_empty_binary_value_is_a_count_of_zero() {
    let value = read(&[0x00, 0x00], PropertyType::Binary).unwrap();
    assert_eq!(value, PropertyValue::Binary(Vec::new()));
    assert_eq!(write(&value).unwrap(), vec![0x00, 0x00]);
}

/// A `PtypMultiple` COUNT is 32 bits in a ROP buffer, unlike a `PtypBinary` byte count in the very
/// same buffer. That asymmetry is the whole reason the width is a parameter.
///
/// [MS-OXCDATA] §2.11.1.1
#[test]
fn a_multivalued_count_is_thirty_two_bits_in_the_same_buffer() {
    let bytes = [
        0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0, 0, 0,
    ];
    let mut r = Reader::new(&bytes);
    let value = PropertyValue::read(
        &mut r,
        PropertyType::MultipleInteger32,
        ValueContext::Object,
    )
    .unwrap();

    assert_eq!(value, PropertyValue::MultipleInteger32(vec![1, 2]));
    assert!(r.is_empty());
    assert_eq!(write(&value).unwrap(), bytes);
}

/// A multiple-binary carries both widths at once: a 32-bit value count, and a 16-bit byte count
/// inside each element.
#[test]
fn a_multiple_binary_nests_a_short_count_inside_a_long_one() {
    let mut w = Writer::new();
    w.u32(2).u16(1).u8(0xAA).u16(0);
    let bytes = w.finish();

    let value = read(&bytes, PropertyType::MultipleBinary).unwrap();
    assert_eq!(
        value,
        PropertyValue::MultipleBinary(vec![vec![0xAA], Vec::new()])
    );
    assert_eq!(write(&value).unwrap(), bytes);
}

#[test]
fn a_multiple_string_is_a_count_then_that_many_terminated_strings() {
    let mut bytes = vec![0x02, 0x00, 0x00, 0x00];
    bytes.extend(utf16_z("one"));
    bytes.extend(utf16_z("two"));

    let value = read(&bytes, PropertyType::MultipleString).unwrap();
    assert_eq!(
        value,
        PropertyValue::MultipleString(vec![
            TableString::from("one"),
            TableString::from("two".to_owned())
        ])
    );
    assert_eq!(write(&value).unwrap(), bytes);
}

#[test]
fn a_string8_value_is_terminated_by_one_zero_byte() {
    let value = read(b"Inbox\0", PropertyType::String8).unwrap();
    assert_eq!(
        value.as_string().map(TableString::as_str),
        Some("Inbox"),
        "as_string answers for either width"
    );
    assert_eq!(value.property_type(), Some(PropertyType::String8));
}

#[test]
fn accessors_answer_only_for_their_own_type() {
    let value = PropertyValue::Integer32(7);
    assert_eq!(value.as_u32(), Some(7));
    assert_eq!(value.as_u16(), None);
    assert_eq!(value.as_u64(), None);
    assert_eq!(value.as_bool(), None);
    assert_eq!(value.as_string(), None);
    assert_eq!(value.as_time(), None);
    assert_eq!(value.as_guid(), None);
    assert_eq!(value.as_binary(), None);
    assert_eq!(value.as_error(), None);
    assert_eq!(value.as_f64(), None);

    assert_eq!(PropertyValue::Integer16(3).as_u16(), Some(3));
    assert_eq!(PropertyValue::Boolean(true).as_bool(), Some(true));
    assert_eq!(PropertyValue::Integer64(9).as_u64(), Some(9));
    assert_eq!(
        PropertyValue::Floating64(Floating64::new(0.5)).as_f64(),
        Some(0.5)
    );
    assert_eq!(
        PropertyValue::Time(FileTime::new(4)).as_time(),
        Some(FileTime::new(4))
    );
    assert_eq!(
        PropertyValue::Error(ErrorCode::NOT_FOUND).as_error(),
        Some(ErrorCode::NOT_FOUND)
    );
    assert_eq!(PropertyValue::Absent.as_u32(), None);
    assert_eq!(PropertyValue::Absent.property_type(), None);
}

/// [MS-OXCSTOR] documents a quota of `-1` as "no limit" in a `PtypInteger32` field, so the same
/// four bytes are a count in one property and a sentinel in another. Both readings are offered
/// rather than one being picked for the caller.
#[test]
fn an_integer32_reads_as_signed_or_unsigned() {
    let no_limit = PropertyValue::Integer32(0xFFFF_FFFF);
    assert_eq!(no_limit.as_i32(), Some(-1));
    assert_eq!(no_limit.as_u32(), Some(4_294_967_295));
    assert_eq!(PropertyValue::Integer16(1).as_i32(), None);
}

#[test]
fn a_short_string_is_complete() {
    let bytes = utf16_z("Inbox");
    let value = PropertyValue::read(
        &mut Reader::new(&bytes),
        PropertyType::String,
        ValueContext::TableRow,
    )
    .unwrap();
    let text = value.as_string().unwrap();
    assert!(!text.is_truncated());
    assert_eq!(text.complete(), Some("Inbox"));
    assert_eq!(text.as_str(), "Inbox");
    assert_eq!(value.to_string(), "\"Inbox\"");
}

/// Exchange truncates a table string at 255 characters and appends a literal `...`, with no
/// error code and no flag. The only signal is the length, so the decoder has to act on it.
#[test]
fn a_string_at_the_table_limit_is_reported_as_truncated() {
    let long = format!("{}...", "x".repeat(252));
    assert_eq!(long.chars().count(), 255);

    let bytes = utf16_z(&long);
    let value = PropertyValue::read(
        &mut Reader::new(&bytes),
        PropertyType::String,
        ValueContext::TableRow,
    )
    .unwrap();
    let text = value.as_string().unwrap();

    assert!(text.is_truncated());
    assert_eq!(text.complete(), None, "a truncated value is not the value");
    assert_eq!(
        text.as_str(),
        long,
        "the bytes received are still available"
    );
    assert!(value.to_string().ends_with("(truncated)"));
}

#[test]
fn one_character_short_of_the_limit_is_still_complete() {
    let text = TableString::from_table("y".repeat(254));
    assert!(!text.is_truncated());
    assert_eq!(text.into_string().chars().count(), 254);
}

/// Counted in characters, not bytes: 255 emoji are four bytes each in UTF-8 and two units
/// each in UTF-16, and none of those numbers is the one the specification talks about.
#[test]
fn the_limit_counts_characters_not_bytes() {
    assert!(TableString::from_table("é".repeat(255)).is_truncated());
    assert!(!TableString::from_table("é".repeat(200)).is_truncated());
}

/// A `PtypObject` has no value bytes at all: its content is another Server object. Reading the
/// next property's bytes as this one's is exactly what a "skip it" would do.
///
/// [MS-OXCDATA] §2.11.1.5
#[test]
fn a_ptypobject_says_to_open_a_stream_rather_than_decoding() {
    assert_eq!(
        read(&[0u8; 8], PropertyType::Object),
        Err(Error::ObjectPropertyValue { at: 0 })
    );
}

#[test]
fn an_unmodelled_type_stops_rather_than_guessing_a_length() {
    assert_eq!(
        read(&[0u8; 8], PropertyType::new(0x0006)),
        Err(Error::UnsupportedPropertyType {
            property_type: 0x0006,
            at: 0
        })
    );
}

/// The values that exist as decoding outcomes and are not things a client may send. Each is
/// refused rather than approximated, because a buffer the server reads as something else sets a
/// silently wrong property.
#[test]
fn the_values_a_client_cannot_send_are_refused_by_name() {
    for value in [
        PropertyValue::Absent,
        PropertyValue::Error(ErrorCode::NOT_FOUND),
        PropertyValue::String8(TableString::from("x")),
    ] {
        assert!(
            matches!(write(&value), Err(Error::UnencodableValue { .. })),
            "{value:?} was encoded"
        );
    }
}

/// A NUL inside a string would terminate its own field and shift every field after it — which the
/// server parses as a different property rather than reporting as an error.
#[test]
fn a_string_with_an_interior_nul_is_refused() {
    let value = PropertyValue::String(TableString::from("before\0after"));
    assert!(matches!(write(&value), Err(Error::UnencodableValue { .. })));

    let multi = PropertyValue::MultipleString(vec![
        TableString::from("ok"),
        value.as_string().unwrap().clone(),
    ]);
    assert!(matches!(write(&multi), Err(Error::UnencodableValue { .. })));
}

/// A binary value's COUNT is 16 bits inside a ROP buffer, so 64 KiB is the ceiling. Writing the
/// low half of the length would produce a buffer the server reads happily and wrongly.
#[test]
fn a_binary_value_past_what_its_count_can_express_is_refused() {
    let value = PropertyValue::Binary(vec![0u8; 0x1_0000]);
    assert_eq!(
        write(&value),
        Err(Error::ValueTooLarge {
            property_type: PropertyType::Binary,
            count: 0x1_0000,
            limit: 0xFFFF,
        })
    );

    // One byte less fits exactly.
    assert!(write(&PropertyValue::Binary(vec![0u8; 0xFFFF])).is_ok());
}

#[test]
fn round_trips_every_value_a_client_may_send() {
    let values = [
        PropertyValue::Integer16(0xBEEF),
        PropertyValue::Integer32(0xDEAD_BEEF),
        PropertyValue::Integer64(u64::MAX),
        PropertyValue::Floating64(Floating64::new(-2.5)),
        PropertyValue::Boolean(false),
        PropertyValue::String(TableString::from("Mailbox comment")),
        PropertyValue::Time(FileTime::new(134_300_850_968_907_102)),
        PropertyValue::Guid(Guid::from_bytes([0x11; 16])),
        PropertyValue::Binary(vec![0x00, 0xFF, 0x7F]),
        PropertyValue::MultipleInteger32(vec![1, 2, 3]),
        PropertyValue::MultipleString(vec![TableString::from("a"), TableString::from("")]),
        PropertyValue::MultipleBinary(vec![vec![0x01], vec![]]),
    ];

    for value in values {
        let property_type = value.property_type().unwrap();
        let bytes = write(&value).unwrap_or_else(|e| panic!("{property_type} did not encode: {e}"));
        let mut r = Reader::new(&bytes);
        let back = PropertyValue::read(&mut r, property_type, ValueContext::Object).unwrap();
        assert_eq!(back, value, "{property_type} did not round-trip");
        assert!(r.is_empty(), "{property_type} left bytes behind");
    }
}

/// A float carried as its bits so that `PropertyValue` can stay `Eq` and `Hash`. Two NaNs with
/// the same bit pattern therefore compare equal, which `f64` would not.
#[test]
fn a_float_is_compared_by_the_bytes_the_server_sent() {
    let nan = Floating64::new(f64::NAN);
    assert_eq!(nan, Floating64::from_bits(f64::NAN.to_bits()));
    assert!(nan.as_f64().is_nan());
    assert_eq!(Floating64::new(1.5).to_bits(), 1.5_f64.to_bits());
    assert_eq!(Floating64::new(1.5).to_string(), "1.5");
}

#[test]
fn truncated_buffers_never_panic() {
    let types = [
        PropertyType::Integer16,
        PropertyType::Integer32,
        PropertyType::Integer64,
        PropertyType::Floating64,
        PropertyType::Boolean,
        PropertyType::String,
        PropertyType::String8,
        PropertyType::Time,
        PropertyType::Guid,
        PropertyType::Binary,
        PropertyType::MultipleInteger32,
        PropertyType::MultipleString,
        PropertyType::MultipleBinary,
        PropertyType::ErrorCode,
    ];

    for property_type in types {
        for bytes in [
            &b""[..],
            &[0x01][..],
            &[0xFF, 0xFF, 0xFF][..],
            // A length prefix claiming far more than the buffer holds, which is the shape a
            // hostile or damaged packet takes.
            &[0xFF, 0xFF, 0xFF, 0xFF, 0x00][..],
        ] {
            for context in [ValueContext::TableRow, ValueContext::Object] {
                let _ = PropertyValue::read(&mut Reader::new(bytes), property_type, context);
            }
        }
    }
}

#[test]
fn values_render_for_humans() {
    assert_eq!(PropertyValue::Integer32(42).to_string(), "42");
    assert_eq!(PropertyValue::Integer16(42).to_string(), "42");
    assert_eq!(
        PropertyValue::Integer64(0x0D00_0000_0000_0001).to_string(),
        "0x0D00000000000001"
    );
    assert_eq!(PropertyValue::Boolean(false).to_string(), "false");
    assert_eq!(
        PropertyValue::Time(FileTime::new(5)).to_string(),
        "FILETIME(5)"
    );
    assert_eq!(
        PropertyValue::Error(ErrorCode::TOO_BIG).to_string(),
        "<TooBig (0x80040305)>"
    );
    assert_eq!(PropertyValue::Absent.to_string(), "<absent>");
    assert_eq!(
        PropertyValue::Binary(vec![1, 2, 3]).to_string(),
        "3 byte(s)"
    );
    assert_eq!(
        PropertyValue::MultipleInteger32(vec![1, 2]).to_string(),
        "[1, 2]"
    );
    assert_eq!(
        PropertyValue::MultipleString(vec![
            TableString::from("a"),
            TableString::Truncated("b".to_owned())
        ])
        .to_string(),
        "[\"a\", \"b\" (truncated)]"
    );
    assert_eq!(
        PropertyValue::MultipleBinary(vec![vec![1], vec![2, 3]]).to_string(),
        "2 value(s), 3 byte(s)"
    );
    assert_eq!(
        PropertyValue::Guid(Guid::from_bytes([0x00; 16])).to_string(),
        "{00000000-0000-0000-0000-000000000000}"
    );
}
