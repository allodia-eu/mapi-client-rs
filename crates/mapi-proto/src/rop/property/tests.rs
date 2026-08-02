use super::*;
use crate::error::ErrorCode;
use crate::oxcdata::{MAILBOX_PROPERTIES, PropertyValue, TableString};

fn encoded(encode: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut w = Writer::new();
    encode(&mut w);
    w.finish()
}

/// The request layout, field by field, against [MS-OXCROPS] §2.2.8.3.1: `RopId`, `LogonId`,
/// `InputHandleIndex`, `PropertySizeLimit`, `WantUnicode`, `PropertyTagCount`, then the tags.
#[test]
fn get_properties_specific_matches_its_documented_layout() {
    let tags = [PropertyTag::DISPLAY_NAME, PropertyTag::CONTENT_COUNT];
    let bytes = encoded(|w| encode_get_properties_specific(w, 3, &tags));

    assert_eq!(
        bytes,
        vec![
            0x07, // RopId
            0x00, // LogonId
            0x03, // InputHandleIndex
            0x00, 0x00, // PropertySizeLimit: no limit beyond the buffer's own
            0x01, 0x00, // WantUnicode
            0x02, 0x00, // PropertyTagCount
            0x1F, 0x00, 0x01, 0x30, // PidTagDisplayName, type first
            0x03, 0x00, 0x02, 0x36, // PidTagContentCount
        ]
    );
}

/// [MS-OXCROPS] §2.2.8.4.1 — no tag list at all, which is the point of the ROP.
#[test]
fn get_properties_all_names_no_tags() {
    let bytes = encoded(|w| encode_get_properties_all(w, 0));
    assert_eq!(bytes, vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
}

/// [MS-OXCROPS] §2.2.8.8.1
#[test]
fn delete_properties_is_a_tag_list() {
    let bytes = encoded(|w| encode_delete_properties(w, 1, &[PropertyTag::COMMENT]));
    assert_eq!(
        bytes,
        vec![0x0B, 0x00, 0x01, 0x01, 0x00, 0x1F, 0x00, 0x04, 0x30]
    );
}

/// `PropertyValueSize` counts `PropertyValueCount` as well as the values themselves — the one
/// field here that cannot be predicted from the value list, because every string is a different
/// length.
///
/// [MS-OXCROPS] §2.2.8.6.1
#[test]
fn set_properties_measures_the_values_and_the_count_field_together() {
    let values = [TaggedValue::new(
        PropertyTag::COMMENT,
        PropertyValue::String(TableString::from("hi")),
    )
    .unwrap()];

    let mut w = Writer::new();
    encode_set_properties(&mut w, 2, &values).unwrap();
    let bytes = w.finish();

    assert_eq!(
        bytes,
        vec![
            0x0A, // RopId
            0x00, // LogonId
            0x02, // InputHandleIndex
            0x0C, 0x00, // PropertyValueSize: 2 for the count field + 10 for the value
            0x01, 0x00, // PropertyValueCount
            0x1F, 0x00, 0x04, 0x30, // PidTagComment
            0x68, 0x00, 0x69, 0x00, 0x00, 0x00, // "hi", NUL-terminated UTF-16LE
        ]
    );

    // The claim the field makes, checked against the bytes that follow it rather than restated.
    let declared = usize::from(u16::from_le_bytes([bytes[3], bytes[4]]));
    assert_eq!(declared, bytes.len() - 5);
}

#[test]
fn setting_nothing_is_a_well_formed_request_that_sets_nothing() {
    let mut w = Writer::new();
    encode_set_properties(&mut w, 0, &[]).unwrap();
    assert_eq!(
        w.finish(),
        vec![0x0A, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
        "PropertyValueSize is the two bytes of PropertyValueCount and nothing else"
    );
}

/// A value the encoder refuses stops the whole ROP rather than producing a shorter one. The
/// alternative — writing what could be written — is a request the server accepts and misreads.
#[test]
fn a_value_that_cannot_be_encoded_fails_the_whole_rop() {
    let values = [TaggedValue::new(
        PropertyTag::COMMENT,
        PropertyValue::String(TableString::from("before\0after")),
    )
    .unwrap()];

    let mut w = Writer::new();
    assert!(matches!(
        encode_set_properties(&mut w, 0, &values),
        Err(Error::UnencodableValue { .. })
    ));
}

/// `PropertyValueSize` is 16 bits, so a set of values past 64 KiB cannot be described by its own
/// request. Refused here rather than wrapping, which would name a length the server then reads
/// the wrong number of bytes against.
#[test]
fn values_past_what_the_size_field_can_express_are_refused() {
    let big = TaggedValue::new(
        PropertyTag::MAILBOX_OWNER_ENTRY_ID,
        PropertyValue::Binary(vec![0u8; 0xFFF0]),
    )
    .unwrap();
    let values = [big.clone(), big];

    let mut w = Writer::new();
    assert!(matches!(
        encode_set_properties(&mut w, 0, &values),
        Err(Error::RopBufferTooLarge { .. })
    ));
}

/// The response to `RopGetPropertiesSpecific` is a `PropertyRow` — values and no tags — decoded
/// against the tags of the request that asked for them.
#[test]
fn a_specific_fetch_decodes_its_row_against_the_tags_that_were_asked_for() {
    let mut w = Writer::new();
    w.u8(0x00).utf16_z("Developer").u32(12);
    let bytes = w.finish();

    let tags = [PropertyTag::DISPLAY_NAME, PropertyTag::CONTENT_COUNT];
    let mut r = Reader::new(&bytes);
    let response =
        GetPropertiesResponse::read_row(&mut r, RopId::GET_PROPERTIES_SPECIFIC, &tags).unwrap();

    assert!(r.is_empty());
    assert_eq!(response.rop(), RopId::GET_PROPERTIES_SPECIFIC);
    assert_eq!(
        response
            .properties()
            .string(PropertyTag::DISPLAY_NAME)
            .map(TableString::as_str),
        Some("Developer")
    );
    assert_eq!(response.into_properties().len(), 2);
}

#[test]
fn an_all_fetch_reads_its_count_and_then_the_tagged_values() {
    let mut w = Writer::new();
    w.u16(1).u32(PropertyTag::CONTENT_COUNT.as_u32()).u32(5);
    let bytes = w.finish();

    let mut r = Reader::new(&bytes);
    let response = GetPropertiesResponse::read_all(&mut r, RopId::GET_PROPERTIES_ALL).unwrap();

    assert!(r.is_empty());
    assert_eq!(response.rop(), RopId::GET_PROPERTIES_ALL);
    assert_eq!(
        response.properties().get(PropertyTag::CONTENT_COUNT),
        Some(&PropertyValue::Integer32(5))
    );
}

/// Both write ROPs report per-property failures **alongside a successful `ReturnValue`**, so a
/// caller that only looked at the return value would report a write that did not happen as done.
#[test]
fn a_write_reports_its_refusals_next_to_a_successful_return_value() {
    let mut w = Writer::new();
    w.u16(1)
        .u16(0)
        .u32(PropertyTag::DISPLAY_NAME.as_u32())
        .u32(ErrorCode::ACCESS_DENIED.as_u32());
    let bytes = w.finish();

    let mut r = Reader::new(&bytes);
    let response = PropertyProblemsResponse::read(&mut r, RopId::SET_PROPERTIES).unwrap();

    assert!(r.is_empty());
    assert_eq!(response.rop(), RopId::SET_PROPERTIES);
    assert!(!response.is_clean());
    assert_eq!(response.problems().len(), 1);
    assert_eq!(
        response.problems().first().map(|problem| problem.code()),
        Some(ErrorCode::ACCESS_DENIED)
    );
}

#[test]
fn a_write_with_nothing_to_report_is_clean() {
    let mut r = Reader::new(&[0x00, 0x00]);
    let response = PropertyProblemsResponse::read(&mut r, RopId::DELETE_PROPERTIES).unwrap();
    assert!(response.is_clean());
    assert!(response.problems().is_empty());
    assert_eq!(response.rop(), RopId::DELETE_PROPERTIES);
}

#[test]
fn truncated_responses_never_panic() {
    for bytes in [
        &b""[..],
        &[0x01][..],
        &[0xFF, 0xFF][..],
        &[0xFF, 0xFF, 0xFF, 0xFF][..],
    ] {
        let _ = GetPropertiesResponse::read_all(&mut Reader::new(bytes), RopId::GET_PROPERTIES_ALL);
        let _ = GetPropertiesResponse::read_row(
            &mut Reader::new(bytes),
            RopId::GET_PROPERTIES_SPECIFIC,
            &MAILBOX_PROPERTIES,
        );
        let _ = PropertyProblemsResponse::read(&mut Reader::new(bytes), RopId::SET_PROPERTIES);
    }
}
