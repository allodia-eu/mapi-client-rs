//! 8-bit strings in a ROP buffer, which are in the code page the session connected with.
//!
//! [MS-OXCDATA] §2.11.1.2 — string property values

use super::*;
use crate::oxcdata::{CodePage, PropertyTag};

fn read_in(bytes: &[u8], tag: PropertyTag, code_page: u16) -> Result<PropertyValue, Error> {
    let mut r = Reader::new(bytes);
    let value = PropertyValue::read(
        &mut r,
        tag,
        ValueContext::Object,
        CodePage::new(code_page).unwrap(),
    );
    assert!(
        value.is_err() || r.is_empty(),
        "the value consumed its own bytes"
    );
    value
}

const SUBJECT_A: PropertyTag = PropertyTag::new(0x0037_001E);

/// The subject Exchange Server SE `15.02.2562.056` sent under a session connected with 1252 —
/// `0x80` is `€` there, which Latin-1 would have made a control character — and the same subject
/// under 1251.
#[test]
fn a_string8_is_read_in_the_sessions_code_page() {
    assert_eq!(
        read_in(b"Caf\xE9 \x80 \x9E\0", SUBJECT_A, 1252).unwrap(),
        PropertyValue::String8(TableString::from("Caf\u{E9} \u{20AC} \u{17E}"))
    );
    assert_eq!(
        read_in(b"\xCF\xF0\xE8 \x88\0", SUBJECT_A, 1251).unwrap(),
        PropertyValue::String8(TableString::from("\u{41F}\u{440}\u{438} \u{20AC}"))
    );
    assert_eq!(
        read_in(b"\x93\xFA\x96\x7B\0", SUBJECT_A, 932).unwrap(),
        PropertyValue::String8(TableString::from("\u{65E5}\u{672C}"))
    );
}

/// Every value of a list is decoded the same way.
#[test]
fn a_multiple_string8_is_read_in_the_sessions_code_page() {
    let tag = PropertyTag::new(0x6700_101E);
    let bytes = [0x02, 0x00, 0x00, 0x00, 0xCF, 0x00, 0xF0, 0xE8, 0x00];
    assert_eq!(
        read_in(&bytes, tag, 1251).unwrap(),
        PropertyValue::MultipleString8(vec![
            TableString::from("\u{41F}"),
            TableString::from("\u{440}\u{438}"),
        ])
    );
}

/// Bytes that are not text in the code page are refused with the property named, never patched
/// with replacement characters.
#[test]
fn a_string8_that_is_not_text_names_its_property() {
    assert_eq!(
        read_in(b"\x93\0", SUBJECT_A, 932),
        Err(Error::UndecodableString {
            tag: SUBJECT_A,
            code_page: 932,
            reason: "the bytes are not text in that code page",
        })
    );
    let tag = PropertyTag::new(0x6700_101E);
    assert!(matches!(
        read_in(&[0x01, 0x00, 0x00, 0x00, 0x93, 0x00], tag, 932),
        Err(Error::UndecodableString { code_page: 932, .. })
    ));
}

/// A table cuts an 8-bit string at 255 whole characters, the last three a literal `...`, as
/// Exchange Server SE `15.02.2562.056` did in a 932 session: that reads as truncated. A value whose
/// last character is short a byte is not a cut the server makes, so it is refused in a row as it
/// is anywhere else — never passed off as truncation.
#[test]
fn a_table_string_is_cut_by_characters_and_anything_else_is_refused() {
    let mut bytes = Vec::new();
    for _ in 0..252 {
        bytes.extend_from_slice(&[0x93, 0xFA]);
    }
    bytes.extend_from_slice(b"...\0");
    let mut r = Reader::new(&bytes);
    let value = PropertyValue::read(
        &mut r,
        SUBJECT_A,
        ValueContext::TableRow,
        CodePage::new(932).unwrap(),
    )
    .unwrap();
    let PropertyValue::String8(text) = value else {
        panic!("a string")
    };
    assert!(text.is_truncated());
    assert_eq!(text.as_str().chars().count(), 255);
    assert!(text.as_str().ends_with("\u{65E5}..."));
    assert!(r.is_empty());

    let mut r = Reader::new(&[0x41, 0x81, 0x00]);
    assert!(matches!(
        PropertyValue::read(
            &mut r,
            SUBJECT_A,
            ValueContext::TableRow,
            CodePage::new(932).unwrap(),
        ),
        Err(Error::UndecodableString { code_page: 932, .. })
    ));
}
