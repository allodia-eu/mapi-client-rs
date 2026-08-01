use super::*;
use crate::error::Error;
use crate::oxcdata::{HIERARCHY_COLUMNS, PropertyTag, PropertyValue};

fn hierarchy_row(w: &mut Writer, folder_id: u64, name: &str) {
    w.u8(0x00).u64(folder_id);
    for unit in name.encode_utf16() {
        w.u16(unit);
    }
    w.u16(0);
    w.u32(3).u8(0);
}

#[test]
fn get_table_requests_differ_only_in_their_opcode() {
    let mut hierarchy = Writer::new();
    encode_get_table(&mut hierarchy, RopId::GET_HIERARCHY_TABLE, 1, 2);
    assert_eq!(hierarchy.finish(), vec![0x04, 0x00, 0x01, 0x02, 0x00]);

    let mut contents = Writer::new();
    encode_get_table(&mut contents, RopId::GET_CONTENTS_TABLE, 1, 2);
    assert_eq!(contents.finish(), vec![0x05, 0x00, 0x01, 0x02, 0x00]);
}

#[test]
fn set_columns_is_a_counted_array_of_tags() {
    let mut w = Writer::new();
    encode_set_columns(&mut w, 2, &HIERARCHY_COLUMNS);
    let bytes = w.finish();

    assert_eq!(bytes.get(..4), Some(&[0x12, 0x00, 0x02, 0x00][..]));
    assert_eq!(bytes.get(4..6), Some(&[0x04, 0x00][..]), "PropertyTagCount");
    assert_eq!(bytes.len(), 4 + 2 + 4 * 4);
    assert_eq!(
        bytes.get(6..10),
        Some(&PropertyTag::FOLDER_ID.as_u32().to_le_bytes()[..])
    );
}

#[test]
fn query_rows_asks_for_a_forward_read_that_advances_the_cursor() {
    let mut w = Writer::new();
    encode_query_rows(&mut w, 2, 25);
    assert_eq!(w.finish(), vec![0x15, 0x00, 0x02, 0x00, 0x01, 0x19, 0x00]);
}

#[test]
fn decodes_query_rows_with_two_rows() {
    let mut w = Writer::new();
    w.u8(Bookmark::Beginning.as_u8()).u16(2);
    hierarchy_row(&mut w, 0x11, "Inbox");
    hierarchy_row(&mut w, 0x22, "Sent Items");
    let buf = w.finish();

    let mut r = Reader::new(&buf);
    let response = QueryRowsResponse::read(&mut r, &HIERARCHY_COLUMNS).unwrap();

    assert_eq!(response.bookmark(), Bookmark::Beginning);
    assert_eq!(response.rows().len(), 2);
    assert_eq!(
        response
            .rows()
            .first()
            .unwrap()
            .string(PropertyTag::DISPLAY_NAME)
            .unwrap()
            .as_str(),
        "Inbox"
    );
    assert_eq!(
        response
            .rows()
            .get(1)
            .unwrap()
            .string(PropertyTag::DISPLAY_NAME)
            .unwrap()
            .as_str(),
        "Sent Items"
    );
    assert_eq!(response.form_counts(), (2, 0));
    assert!(r.is_empty());
}

/// Every row of every table on the live Exchange lab came back in standard form. The counts are
/// reported rather than assumed, because the choice belongs to the server.
#[test]
fn form_counts_report_what_the_server_chose() {
    let mut w = Writer::new();
    w.u8(Bookmark::Current.as_u8()).u16(2);
    hierarchy_row(&mut w, 0x11, "Standard");
    w.u8(0x01);
    w.u8(0x00).u64(0x22);
    w.u8(0x01);
    w.u8(0x00).u32(0);
    w.u8(0x00).u8(1);
    let buf = w.finish();

    let response = QueryRowsResponse::read(&mut Reader::new(&buf), &HIERARCHY_COLUMNS).unwrap();
    assert_eq!(response.form_counts(), (1, 1));
    assert_eq!(response.bookmark(), Bookmark::Current);
}

#[test]
fn zero_rows_is_an_answer_not_an_error() {
    let mut w = Writer::new();
    w.u8(Bookmark::End.as_u8()).u16(0);
    let buf = w.finish();

    let response = QueryRowsResponse::read(&mut Reader::new(&buf), &HIERARCHY_COLUMNS).unwrap();
    assert!(response.rows().is_empty());
    assert_eq!(response.bookmark(), Bookmark::End);
    assert_eq!(response.form_counts(), (0, 0));
}

/// A `RowCount` that lies must error rather than allocate 65,535 rows of nothing.
#[test]
fn a_lying_row_count_errors_rather_than_over_reading() {
    let mut w = Writer::new();
    w.u8(0x00).u16(0xFFFF);
    let buf = w.finish();
    assert!(matches!(
        QueryRowsResponse::read(&mut Reader::new(&buf), &HIERARCHY_COLUMNS),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn a_table_reports_how_many_rows_it_holds() {
    let mut r = Reader::new(&[0x0F, 0x00, 0x00, 0x00]);
    assert_eq!(GetTableResponse::read(&mut r).unwrap().row_count(), 15);
}

#[test]
fn set_columns_reports_the_table_status() {
    let mut r = Reader::new(&[0x00]);
    let response = SetColumnsResponse::read(&mut r).unwrap();
    assert!(response.status().is_complete());
    assert_eq!(response.status(), TableStatus::COMPLETE);

    let mut r = Reader::new(&[0x0B]);
    let status = SetColumnsResponse::read(&mut r).unwrap().status();
    assert!(!status.is_complete());
    assert_eq!(status, TableStatus::SETTING_COLUMNS);
    assert_eq!(status.as_u8(), 0x0B);
}

#[test]
fn bookmarks_and_statuses_round_trip_through_their_raw_values() {
    for (bookmark, raw) in [
        (Bookmark::Beginning, 0x00),
        (Bookmark::Current, 0x01),
        (Bookmark::End, 0x02),
        (Bookmark::Other(0x7F), 0x7F),
    ] {
        assert_eq!(Bookmark::new(raw), bookmark);
        assert_eq!(bookmark.as_u8(), raw);
    }

    for status in [
        TableStatus::SORTING,
        TableStatus::SORT_ERROR,
        TableStatus::SET_COLUMNS_ERROR,
        TableStatus::RESTRICTING,
        TableStatus::RESTRICT_ERROR,
    ] {
        assert!(!status.is_complete());
        assert_eq!(TableStatus::new(status.as_u8()), status);
    }
}

#[test]
fn truncated_table_responses_never_panic() {
    for buf in [&b""[..], &[0x00][..], &[0x00, 0x02][..], &[0xFF; 16][..]] {
        let _ = QueryRowsResponse::read(&mut Reader::new(buf), &HIERARCHY_COLUMNS);
        let _ = GetTableResponse::read(&mut Reader::new(buf));
        let _ = SetColumnsResponse::read(&mut Reader::new(buf));
    }
}

#[test]
fn rows_expose_their_values_by_tag() {
    let mut w = Writer::new();
    w.u8(0x00).u16(1);
    hierarchy_row(&mut w, 0x0D00_0000_0000_0004, "Inbox");
    let buf = w.finish();

    let response = QueryRowsResponse::read(&mut Reader::new(&buf), &HIERARCHY_COLUMNS).unwrap();
    let row = response.rows().first().unwrap();
    assert_eq!(
        row.get(PropertyTag::CONTENT_COUNT),
        Some(&PropertyValue::Integer32(3))
    );
    assert_eq!(
        row.get(PropertyTag::SUBFOLDERS),
        Some(&PropertyValue::Boolean(false))
    );
}
