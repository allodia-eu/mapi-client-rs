use super::*;
use crate::error::ErrorCode;
use crate::oxcdata::{CONTENTS_COLUMNS, HIERARCHY_COLUMNS, PropertyType};
use crate::wire::Writer;

fn utf16_z(w: &mut Writer, text: &str) {
    for unit in text.encode_utf16() {
        w.u16(unit);
    }
    w.u16(0);
}

/// Every row in this file comes off a table, which is the context that decides COUNT widths and
/// the 255-character truncation rule.
fn read(buf: &[u8], columns: &[PropertyTag]) -> Result<PropertyRow> {
    PropertyRow::read(
        &mut Reader::new(buf),
        columns,
        ValueContext::TableRow,
        CodePage::WINDOWS_1252,
    )
}

/// A hierarchy row exactly as the live Exchange lab sends one: standard form, the six columns of
/// [`HIERARCHY_COLUMNS`] in order.
fn standard_hierarchy_row(folder_id: u64, name: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(0x00).u64(folder_id).u64(0x0D00_0000_0000_0001);
    utf16_z(&mut w, name);
    utf16_z(&mut w, "IPF.Note");
    w.u32(7).u8(1);
    w.finish()
}

#[test]
fn decodes_a_standard_property_row() {
    let buf = standard_hierarchy_row(0x0D00_0000_0000_0001, "Inbox");
    let mut r = Reader::new(&buf);
    let row = PropertyRow::read(
        &mut r,
        &HIERARCHY_COLUMNS,
        ValueContext::TableRow,
        CodePage::WINDOWS_1252,
    )
    .unwrap();

    assert_eq!(row.form(), RowForm::Standard);
    assert_eq!(row.folder_id(), Some(FolderId::new(0x0D00_0000_0000_0001)));
    assert_eq!(
        row.cells().first().map(Cell::tag),
        Some(PropertyTag::FOLDER_ID)
    );
    assert_eq!(
        row.string(PropertyTag::DISPLAY_NAME).unwrap().as_str(),
        "Inbox"
    );
    assert_eq!(
        row.get(PropertyTag::CONTENT_COUNT)
            .and_then(PropertyValue::as_u32),
        Some(7)
    );
    assert_eq!(
        row.get(PropertyTag::SUBFOLDERS)
            .and_then(PropertyValue::as_bool),
        Some(true)
    );
    assert!(r.is_empty());
}

/// Flag `0x01` means the value is absent **and consumes no bytes**. Getting that wrong
/// desynchronises every later column in the row rather than failing where the mistake is.
#[test]
fn a_flagged_row_handles_present_absent_and_error() {
    let mut w = Writer::new();
    w.u8(0x01);
    w.u8(0x00).u64(0x1234);
    w.u8(0x00).u64(0x0D00_0000_0000_0001);
    w.u8(0x0A).u32(ErrorCode::TOO_BIG.as_u32());
    w.u8(0x01);
    w.u8(0x01);
    w.u8(0x00).u8(0);
    let buf = w.finish();

    let row = read(&buf, &HIERARCHY_COLUMNS).unwrap();

    assert_eq!(row.form(), RowForm::Flagged);
    assert_eq!(row.folder_id(), Some(FolderId::new(0x1234)));
    assert_eq!(
        row.get(PropertyTag::PARENT_FOLDER_ID)
            .and_then(PropertyValue::as_u64),
        Some(0x0D00_0000_0000_0001)
    );
    assert_eq!(
        row.get(PropertyTag::DISPLAY_NAME),
        Some(&PropertyValue::Error(ErrorCode::TOO_BIG))
    );
    assert_eq!(
        row.get(PropertyTag::CONTAINER_CLASS),
        Some(&PropertyValue::Absent)
    );
    assert_eq!(
        row.get(PropertyTag::CONTENT_COUNT),
        Some(&PropertyValue::Absent)
    );
    assert_eq!(
        row.get(PropertyTag::SUBFOLDERS),
        Some(&PropertyValue::Boolean(false))
    );
}

/// The form is the server's choice per row, so the decoder reports it instead of normalising it
/// away. Both rows below carry the same six values.
#[test]
fn the_row_form_is_reported_not_normalised_away() {
    let standard = standard_hierarchy_row(1, "");
    let standard = read(&standard, &HIERARCHY_COLUMNS).unwrap();

    let mut w = Writer::new();
    w.u8(0x01);
    w.u8(0x00).u64(1);
    w.u8(0x00).u64(0x0D00_0000_0000_0001);
    w.u8(0x00);
    utf16_z(&mut w, "");
    w.u8(0x00);
    utf16_z(&mut w, "IPF.Note");
    w.u8(0x00).u32(7);
    w.u8(0x00).u8(1);
    let flagged = read(&w.finish(), &HIERARCHY_COLUMNS).unwrap();

    assert_eq!(standard.form(), RowForm::Standard);
    assert_eq!(flagged.form(), RowForm::Flagged);
    assert_eq!(
        standard.cells().iter().map(Cell::value).collect::<Vec<_>>(),
        flagged.cells().iter().map(Cell::value).collect::<Vec<_>>(),
        "the values alone cannot tell the two forms apart"
    );
}

/// The clearest demonstration that rows are not self-describing: identical bytes, different
/// columns, different values — and no error either way.
#[test]
fn identical_bytes_decode_differently_per_column_set() {
    let mut w = Writer::new();
    w.u8(0x00).u32(1).u32(2);
    let buf = w.finish();

    let two_i32 = [PropertyTag::MESSAGE_FLAGS, PropertyTag::CONTENT_COUNT];
    let row = read(&buf, &two_i32).unwrap();
    assert_eq!(
        row.cells().iter().map(Cell::value).collect::<Vec<_>>(),
        vec![&PropertyValue::Integer32(1), &PropertyValue::Integer32(2)]
    );

    let one_i64 = [PropertyTag::MID];
    let row = read(&buf, &one_i64).unwrap();
    assert_eq!(
        row.message_id(),
        Some(MessageId::new(0x0000_0002_0000_0001))
    );
}

#[test]
fn a_column_that_was_not_requested_is_absent_from_the_row() {
    let buf = standard_hierarchy_row(1, "Inbox");
    let row = read(&buf, &HIERARCHY_COLUMNS).unwrap();

    assert_eq!(row.get(PropertyTag::SUBJECT), None);
    assert_eq!(row.string(PropertyTag::SUBJECT), None);
    assert_eq!(row.message_id(), None);
    assert_eq!(row.cells().len(), HIERARCHY_COLUMNS.len());
}

#[test]
fn a_contents_row_yields_a_message_id_and_a_subject() {
    let mut w = Writer::new();
    w.u8(0x00).u64(0x0D00_0000_0000_00AA);
    utf16_z(&mut w, "Seeded test message");
    w.u64(134_300_850_968_907_102).u32(1);

    let row = read(&w.finish(), &CONTENTS_COLUMNS).unwrap();
    assert_eq!(
        row.message_id(),
        Some(MessageId::new(0x0D00_0000_0000_00AA))
    );
    assert_eq!(
        row.string(PropertyTag::SUBJECT).unwrap().complete(),
        Some("Seeded test message")
    );
    assert_eq!(
        row.get(PropertyTag::MESSAGE_DELIVERY_TIME)
            .and_then(PropertyValue::as_time)
            .and_then(crate::oxcdata::FileTime::to_unix_seconds),
        Some(1_785_611_496)
    );
}

/// The same bytes, read as a table row and as an object's answer. Only the table's reading
/// classifies a 255-character value as cut short, because only a table cuts one.
///
/// [MS-OXCDATA] §2.8.2 — table values can be truncated
/// [MS-OXCPRPT] §2.2.3.2 — a property fetch answers `NotEnoughMemory` instead
#[test]
fn the_context_decides_whether_a_long_string_counts_as_truncated() {
    let long = "x".repeat(255);
    let mut w = Writer::new();
    w.u8(0x00);
    utf16_z(&mut w, &long);
    let buf = w.finish();

    let columns = [PropertyTag::DISPLAY_NAME];
    let from_table = PropertyRow::read(
        &mut Reader::new(&buf),
        &columns,
        ValueContext::TableRow,
        CodePage::WINDOWS_1252,
    )
    .unwrap();
    let from_object = PropertyRow::read(
        &mut Reader::new(&buf),
        &columns,
        ValueContext::Object,
        CodePage::WINDOWS_1252,
    )
    .unwrap();

    assert!(
        from_table
            .string(PropertyTag::DISPLAY_NAME)
            .unwrap()
            .is_truncated()
    );
    assert!(
        !from_object
            .string(PropertyTag::DISPLAY_NAME)
            .unwrap()
            .is_truncated(),
        "a property fetch does not truncate, so the whole value arrived"
    );
}

/// A row read from an object is the shape `RopGetPropertiesSpecific` answers in, and a caller
/// wants it in the same form `RopGetPropertiesAll` produces.
#[test]
fn a_row_converts_to_the_property_set_both_fetches_share() {
    let buf = standard_hierarchy_row(0x0D00_0000_0000_0001, "Inbox");
    let set = read(&buf, &HIERARCHY_COLUMNS).unwrap().into_property_set();

    assert_eq!(set.len(), HIERARCHY_COLUMNS.len());
    assert_eq!(
        set.string(PropertyTag::DISPLAY_NAME)
            .map(TableString::as_str),
        Some("Inbox")
    );
}

#[test]
fn an_unknown_value_flag_is_an_error_rather_than_a_guess() {
    let mut w = Writer::new();
    w.u8(0x01).u8(0x07);
    assert_eq!(
        read(&w.finish(), &HIERARCHY_COLUMNS),
        Err(Error::InvalidValueFlag { flag: 0x07, at: 1 })
    );
}

/// `PtypRestriction` has a width only its own parser knows, and a type whose width is not
/// modelled has to stop the row rather than be stepped over.
#[test]
fn a_column_of_an_unmodelled_type_stops_the_row() {
    let restriction = PropertyTag::from_parts(0x0FF9, PropertyType::new(0x00FD));
    let buf = [0x00, 0x01, 0x02, 0x03, 0x04];
    assert!(matches!(
        read(&buf, &[restriction]),
        Err(Error::UnsupportedPropertyType { tag, .. }) if tag == restriction
    ));
}

#[test]
fn truncated_rows_never_panic() {
    for buf in [
        &b""[..],
        &[0x00][..],
        &[0x00, 0x01, 0x02][..],
        &[0x01, 0x0A][..],
        &[0xFF; 12][..],
    ] {
        let _ = read(buf, &HIERARCHY_COLUMNS);
        let _ = read(buf, &CONTENTS_COLUMNS);
    }
}

/// A column asked for as `PtypUnspecified` arrives with its type in front of its value, and is
/// reported under that type. The bytes are what Exchange Server SE `15.02.2562.056` sent for
/// `PidTagSubject` and `PidTagMessageFlags` asked for that way: a standard row, a type, a value.
///
/// [MS-OXCDATA] §2.8.1.1 — a `TypedPropertyValue` where the column was asked for as
/// `PtypUnspecified`
#[test]
fn an_unspecified_column_is_read_under_the_type_it_arrives_with() {
    let subject = PropertyTag::from_parts(0x0037, PropertyType::Unspecified);
    let flags = PropertyTag::from_parts(0x0E07, PropertyType::Unspecified);
    let mut w = Writer::new();
    w.u8(0x00).u16(0x001F);
    utf16_z(&mut w, "Hi");
    w.u16(0x0003).u32(0x0409);
    let row = read(&w.finish(), &[subject, flags]).unwrap();

    assert_eq!(row.form(), RowForm::Standard);
    let tags: Vec<PropertyTag> = row.cells().iter().map(Cell::tag).collect();
    assert_eq!(tags, [PropertyTag::SUBJECT, PropertyTag::MESSAGE_FLAGS]);
    assert_eq!(
        row.string(PropertyTag::SUBJECT),
        Some(&TableString::from("Hi"))
    );
    assert_eq!(
        row.get(PropertyTag::MESSAGE_FLAGS),
        Some(&PropertyValue::Integer32(0x0409))
    );
}

/// [MS-OXCDATA] §3.2's worked example: a flagged row whose second column was asked for without a
/// type, so it carries a `FlaggedPropertyValueWithType` — type, then flag, then value — between
/// two ordinary flagged values. The example lists that column as `00370001`, which is
/// `PtypNull`; its bytes and its prose are about `PtypUnspecified`, `0x0000`, which is what is
/// asked for here.
#[test]
fn the_documents_flagged_row_with_a_typed_value_reads_as_described() {
    let columns = [
        PropertyTag::MESSAGE_FLAGS,
        PropertyTag::from_parts(0x0037, PropertyType::Unspecified),
        PropertyTag::BODY,
    ];
    #[rustfmt::skip]
    let bytes = [
        0x01,                                   // a flagged row
        0x00, 0x13, 0x00, 0x00, 0x00,           // PidTagMessageFlags, present
        0x1F, 0x00, 0x00,                       // PtypString, present
        0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00, 0x00, 0x00,
        0x0A, 0x0E, 0x00, 0x07, 0x80,           // PidTagBody: NotEnoughMemory
    ];
    let row = read(&bytes, &columns).unwrap();

    assert_eq!(row.form(), RowForm::Flagged);
    assert_eq!(
        row.get(PropertyTag::MESSAGE_FLAGS),
        Some(&PropertyValue::Integer32(0x13))
    );
    assert_eq!(
        row.string(PropertyTag::SUBJECT),
        Some(&TableString::from("Hello"))
    );
    assert_eq!(
        row.get(PropertyTag::BODY).and_then(PropertyValue::as_error),
        Some(ErrorCode::new(0x8007_000E))
    );
}

/// A column asked for without a type, answered with one that is not a value's type either, is
/// refused with the property named rather than read as something else.
#[test]
fn an_unspecified_column_answered_without_a_type_is_refused() {
    let subject = PropertyTag::from_parts(0x0037, PropertyType::Unspecified);
    assert!(matches!(
        read(&[0x00, 0x00, 0x00, 0x41], &[subject]),
        Err(Error::UnsupportedPropertyType { tag, at: 3 }) if tag == subject
    ));
}

/// A column asked for without a type is found by the tag it was asked for as, and one the server
/// could not return — which arrives typed `PtypErrorCode` — by its usual tag too.
#[test]
fn an_unspecified_column_is_found_by_the_tag_it_was_asked_for_as() {
    let subject = PropertyTag::from_parts(0x0037, PropertyType::Unspecified);
    let absent = PropertyTag::from_parts(0x6FFE, PropertyType::Unspecified);
    let mut w = Writer::new();
    w.u8(0x01).u16(0x001F).u8(0x00);
    utf16_z(&mut w, "Hi");
    w.u16(0x000A).u8(0x0A).u32(0x8004_010F);
    let row = read(&w.finish(), &[subject, absent]).unwrap();

    assert_eq!(row.string(subject), Some(&TableString::from("Hi")));
    let not_found = Some(ErrorCode::new(0x8004_010F));
    assert_eq!(row.get(absent).and_then(PropertyValue::as_error), not_found);
    let usual = PropertyTag::from_parts(0x6FFE, PropertyType::String);
    assert_eq!(row.get(usual).and_then(PropertyValue::as_error), not_found);
    assert_eq!(row.clone().into_property_set().error(absent), not_found);
    // A value of another type under the same id is not an error, and is not handed back for it.
    assert_eq!(
        row.get(PropertyTag::from_parts(0x0037, PropertyType::Binary)),
        None
    );
}
