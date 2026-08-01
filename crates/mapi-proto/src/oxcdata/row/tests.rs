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

/// A hierarchy row exactly as the live Exchange lab sends one: standard form, four columns.
fn standard_hierarchy_row(folder_id: u64, name: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(0x00).u64(folder_id);
    utf16_z(&mut w, name);
    w.u32(7).u8(1);
    w.finish()
}

#[test]
fn decodes_a_standard_property_row() {
    let buf = standard_hierarchy_row(0x0D00_0000_0000_0001, "Inbox");
    let mut r = Reader::new(&buf);
    let row = PropertyRow::read(&mut r, &HIERARCHY_COLUMNS).unwrap();

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
    w.u8(0x0A).u32(ErrorCode::TOO_BIG.as_u32());
    w.u8(0x01);
    w.u8(0x00).u8(0);
    let buf = w.finish();

    let mut r = Reader::new(&buf);
    let row = PropertyRow::read(&mut r, &HIERARCHY_COLUMNS).unwrap();

    assert_eq!(row.form(), RowForm::Flagged);
    assert_eq!(row.folder_id(), Some(FolderId::new(0x1234)));
    assert_eq!(
        row.get(PropertyTag::DISPLAY_NAME),
        Some(&PropertyValue::Error(ErrorCode::TOO_BIG))
    );
    assert_eq!(
        row.get(PropertyTag::CONTENT_COUNT),
        Some(&PropertyValue::Absent)
    );
    assert_eq!(
        row.get(PropertyTag::SUBFOLDERS),
        Some(&PropertyValue::Boolean(false))
    );
    assert!(r.is_empty(), "an absent value must consume nothing");
}

/// The form is the server's choice per row, so the decoder reports it instead of normalising it
/// away. Both rows below carry the same four values.
#[test]
fn the_row_form_is_reported_not_normalised_away() {
    let standard = standard_hierarchy_row(1, "");
    let standard = PropertyRow::read(&mut Reader::new(&standard), &HIERARCHY_COLUMNS).unwrap();

    let mut w = Writer::new();
    w.u8(0x01);
    w.u8(0x00).u64(1);
    w.u8(0x00);
    utf16_z(&mut w, "");
    w.u8(0x00).u32(7);
    w.u8(0x00).u8(1);
    let flagged = w.finish();
    let flagged = PropertyRow::read(&mut Reader::new(&flagged), &HIERARCHY_COLUMNS).unwrap();

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
    let row = PropertyRow::read(&mut Reader::new(&buf), &two_i32).unwrap();
    assert_eq!(
        row.cells().iter().map(Cell::value).collect::<Vec<_>>(),
        vec![&PropertyValue::Integer32(1), &PropertyValue::Integer32(2)]
    );

    let one_i64 = [PropertyTag::MID];
    let row = PropertyRow::read(&mut Reader::new(&buf), &one_i64).unwrap();
    assert_eq!(
        row.message_id(),
        Some(MessageId::new(0x0000_0002_0000_0001))
    );
}

#[test]
fn a_column_that_was_not_requested_is_absent_from_the_row() {
    let buf = standard_hierarchy_row(1, "Inbox");
    let row = PropertyRow::read(&mut Reader::new(&buf), &HIERARCHY_COLUMNS).unwrap();

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
    let buf = w.finish();

    let row = PropertyRow::read(&mut Reader::new(&buf), &CONTENTS_COLUMNS).unwrap();
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

#[test]
fn an_unknown_value_flag_is_an_error_rather_than_a_guess() {
    let mut w = Writer::new();
    w.u8(0x01).u8(0x07);
    let buf = w.finish();
    assert_eq!(
        PropertyRow::read(&mut Reader::new(&buf), &HIERARCHY_COLUMNS),
        Err(Error::InvalidValueFlag { flag: 0x07, at: 1 })
    );
}

#[test]
fn a_column_of_an_unmodelled_type_stops_the_row() {
    let binary = PropertyTag::from_parts(0x0FF9, PropertyType::new(0x0102));
    let buf = [0x00, 0x01, 0x02, 0x03, 0x04];
    assert!(matches!(
        PropertyRow::read(&mut Reader::new(&buf), &[binary]),
        Err(Error::UnsupportedPropertyType { .. })
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
        let _ = PropertyRow::read(&mut Reader::new(buf), &HIERARCHY_COLUMNS);
        let _ = PropertyRow::read(&mut Reader::new(buf), &CONTENTS_COLUMNS);
    }
}
