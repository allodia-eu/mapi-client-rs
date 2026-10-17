//! The types an ICS stream can carry that a contents table never had to: every remaining scalar and
//! list type of [MS-OXCDATA] §2.11.1.
//!
//! A contents table lets the caller choose its columns, so an unmodelled type could be left out.
//! An incremental download sends whatever properties an item has, so one unmodelled type anywhere
//! would fail the whole response.

use super::*;

/// The three remaining scalars, each with the width §2.11.1 gives it and nothing after it.
#[test]
fn the_remaining_scalars_read_exactly_their_own_width() {
    let cases: [(PropertyType, &[u8], PropertyValue); 3] = [
        (
            PropertyType::Floating32,
            &[0x00, 0x00, 0xC0, 0x3F],
            PropertyValue::Floating32(Floating32::new(1.5)),
        ),
        (
            PropertyType::Currency,
            &[0x39, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            PropertyValue::Currency(Currency::from_scaled(12_345)),
        ),
        (
            // 2.5 days after 30 December 1899: noon on 1 January 1900.
            PropertyType::FloatingTime,
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x40],
            PropertyValue::FloatingTime(Floating64::new(2.5)),
        ),
    ];
    for (property_type, bytes, expected) in cases {
        let mut r = Reader::new(bytes);
        let value = PropertyValue::read(&mut r, property_type, ValueContext::Object).unwrap();
        assert_eq!(value, expected, "{property_type}");
        assert!(r.is_empty(), "{property_type} left bytes unread");
        assert_eq!(value.property_type(), Some(property_type));
        assert_eq!(write(&value).unwrap(), bytes, "{property_type}");
    }
}

/// A negative currency is a negative count, not a large positive one.
#[test]
fn a_currency_is_signed() {
    let value = read(&(-1_i64).to_le_bytes(), PropertyType::Currency).unwrap();
    assert_eq!(value, PropertyValue::Currency(Currency::from_scaled(-1)));
    assert_eq!(value.to_string(), "-0.0001");
}

/// Every list type, as a 32-bit COUNT of values in a ROP buffer and then the values themselves.
#[test]
fn every_list_type_is_a_long_count_then_its_values() {
    let one_two = |width: usize| -> Vec<u8> {
        let mut bytes = vec![0x02, 0x00, 0x00, 0x00];
        for value in [1_u8, 2] {
            bytes.push(value);
            bytes.extend(core::iter::repeat_n(0, width - 1));
        }
        bytes
    };
    let guid = |byte: u8| Guid::from_bytes([byte; 16]);

    let cases: Vec<(PropertyType, Vec<u8>, PropertyValue)> = vec![
        (
            PropertyType::MultipleInteger16,
            one_two(2),
            PropertyValue::MultipleInteger16(vec![1, 2]),
        ),
        (
            PropertyType::MultipleInteger64,
            one_two(8),
            PropertyValue::MultipleInteger64(vec![1, 2]),
        ),
        (
            PropertyType::MultipleFloating32,
            one_two(4),
            PropertyValue::MultipleFloating32(vec![
                Floating32::from_bits(1),
                Floating32::from_bits(2),
            ]),
        ),
        (
            PropertyType::MultipleFloating64,
            one_two(8),
            PropertyValue::MultipleFloating64(vec![
                Floating64::from_bits(1),
                Floating64::from_bits(2),
            ]),
        ),
        (
            PropertyType::MultipleFloatingTime,
            one_two(8),
            PropertyValue::MultipleFloatingTime(vec![
                Floating64::from_bits(1),
                Floating64::from_bits(2),
            ]),
        ),
        (
            PropertyType::MultipleCurrency,
            one_two(8),
            PropertyValue::MultipleCurrency(vec![
                Currency::from_scaled(1),
                Currency::from_scaled(2),
            ]),
        ),
        (
            PropertyType::MultipleTime,
            one_two(8),
            PropertyValue::MultipleTime(vec![FileTime::new(1), FileTime::new(2)]),
        ),
        (
            PropertyType::MultipleGuid,
            [&[0x02, 0x00, 0x00, 0x00][..], &[0xAA; 16], &[0xBB; 16]].concat(),
            PropertyValue::MultipleGuid(vec![guid(0xAA), guid(0xBB)]),
        ),
    ];

    for (property_type, bytes, expected) in cases {
        let mut r = Reader::new(&bytes);
        let value = PropertyValue::read(&mut r, property_type, ValueContext::Object).unwrap();
        assert_eq!(value, expected, "{property_type}");
        assert!(r.is_empty(), "{property_type} left bytes unread");
        assert_eq!(value.property_type(), Some(property_type));
        assert_eq!(write(&value).unwrap(), bytes, "{property_type}");

        let mut r = Reader::new(&bytes);
        let in_a_row = PropertyValue::read(&mut r, property_type, ValueContext::TableRow).unwrap();
        assert_eq!(in_a_row, expected, "a table row counts values the same way");
    }
}

/// `PtypMultipleString8` decodes as `PtypString8` does, and like it is never sent: its code page is
/// the session's, which this crate never sets.
#[test]
fn a_multiple_string8_reads_but_is_never_written() {
    let bytes = [0x02, 0x00, 0x00, 0x00, b'a', 0x00, b'b', b'c', 0x00];
    let value = read(&bytes, PropertyType::MultipleString8).unwrap();
    assert_eq!(
        value,
        PropertyValue::MultipleString8(vec![TableString::from("a"), TableString::from("bc")])
    );
    assert_eq!(value.to_string(), "[\"a\", \"bc\"]");
    assert!(matches!(write(&value), Err(Error::UnencodableValue { .. })));
}

/// A claimed count no buffer could hold costs one failed read, not that many allocations.
#[test]
fn a_lying_count_on_a_new_list_type_fails_cleanly() {
    for property_type in [
        PropertyType::MultipleInteger16,
        PropertyType::MultipleGuid,
        PropertyType::MultipleString8,
    ] {
        assert!(
            read(&[0xFF, 0xFF, 0xFF, 0xFF, 0x01], property_type).is_err(),
            "{property_type}"
        );
    }
}

#[test]
fn the_new_types_render_for_humans() {
    assert_eq!(
        PropertyValue::FloatingTime(Floating64::new(2.5)).to_string(),
        "2.5 day(s) since 1899-12-30"
    );
    assert_eq!(
        PropertyValue::MultipleCurrency(vec![Currency::from_scaled(10_000)]).to_string(),
        "[1.0000]"
    );
    assert_eq!(
        PropertyValue::MultipleTime(vec![FileTime::new(0)]).to_string(),
        "1 time(s)"
    );
    assert_eq!(
        PropertyValue::MultipleInteger16(vec![3, 4]).to_string(),
        "[3, 4]"
    );
}
