use super::*;
use crate::oxcdata::{PropertyType, TableString};
use crate::wire::Writer;

fn set(cells: &[(PropertyTag, PropertyValue)]) -> PropertySet {
    PropertySet::from_cells(
        cells
            .iter()
            .map(|(tag, value)| Cell::new(*tag, value.clone()))
            .collect(),
    )
}

/// `RopGetPropertiesAll` answers with tag/value pairs, so the tags come off the wire and nothing
/// has to be known in advance. That is what makes "dump every property" possible at all.
#[test]
fn tagged_values_carry_their_own_tags() {
    let mut w = Writer::new();
    w.u32(PropertyTag::CONTENT_COUNT.as_u32()).u32(42);
    w.u32(PropertyTag::DISPLAY_NAME.as_u32()).utf16_z("Mailbox");
    let bytes = w.finish();

    let mut r = Reader::new(&bytes);
    let properties = PropertySet::read_tagged(&mut r, 2).unwrap();

    assert!(r.is_empty());
    assert_eq!(properties.len(), 2);
    assert!(!properties.is_empty());
    assert_eq!(
        properties.get(PropertyTag::CONTENT_COUNT),
        Some(&PropertyValue::Integer32(42))
    );
    assert_eq!(
        properties
            .string(PropertyTag::DISPLAY_NAME)
            .map(TableString::as_str),
        Some("Mailbox")
    );
    assert_eq!(properties.get(PropertyTag::SUBJECT), None);
}

/// **The trap this type exists to close.** A value too large for the response buffer comes back
/// under its own property id with the type changed to `PtypErrorCode`, so a lookup that insisted
/// on both halves of the tag would report "the server could not fit this" as "not set" — which is
/// a different fact, and the one a caller would act on wrongly.
///
/// [MS-OXCPRPT] §2.2.3.2 — an oversized value becomes `NotEnoughMemory`
#[test]
fn a_value_the_server_could_not_fit_is_found_under_the_tag_that_was_asked_for() {
    let as_error = PropertyTag::from_parts(PropertyTag::DISPLAY_NAME.id(), PropertyType::ErrorCode);
    let properties = set(&[(as_error, PropertyValue::Error(ErrorCode::TOO_BIG))]);

    assert_eq!(
        properties.error(PropertyTag::DISPLAY_NAME),
        Some(ErrorCode::TOO_BIG),
        "the refusal has to be reachable under the tag the caller knows"
    );
    assert_eq!(
        properties.string(PropertyTag::DISPLAY_NAME),
        None,
        "and it is still not a value"
    );
}

/// The fallback above is confined to errors on purpose. `PidTagMessageSize` and
/// `PidTagMessageSizeExtended` are one property id and two real properties, so matching on the id
/// alone would hand back the wrong one.
#[test]
fn one_id_with_two_real_types_does_not_cross() {
    let thirty_two = PropertyTag::from_parts(
        PropertyTag::MESSAGE_SIZE_EXTENDED.id(),
        PropertyType::Integer32,
    );
    let properties = set(&[(thirty_two, PropertyValue::Integer32(1024))]);

    assert_eq!(
        properties.get(PropertyTag::MESSAGE_SIZE_EXTENDED),
        None,
        "a 32-bit size is not the 64-bit property that was asked for"
    );
    assert_eq!(
        properties.get(thirty_two),
        Some(&PropertyValue::Integer32(1024))
    );
}

#[test]
fn an_absent_property_is_told_apart_from_a_refused_one() {
    let properties = set(&[
        (PropertyTag::COMMENT, PropertyValue::Absent),
        (
            PropertyTag::DISPLAY_NAME,
            PropertyValue::Error(ErrorCode::ACCESS_DENIED),
        ),
    ]);

    assert_eq!(
        properties.get(PropertyTag::COMMENT),
        Some(&PropertyValue::Absent)
    );
    assert_eq!(properties.error(PropertyTag::COMMENT), None);
    assert_eq!(
        properties.error(PropertyTag::DISPLAY_NAME),
        Some(ErrorCode::ACCESS_DENIED)
    );
    assert_eq!(properties.error(PropertyTag::SUBJECT), None);
}

#[test]
fn a_property_set_iterates_in_the_order_the_server_sent() {
    let properties = set(&[
        (PropertyTag::DISPLAY_NAME, PropertyValue::Absent),
        (PropertyTag::CONTENT_COUNT, PropertyValue::Integer32(1)),
    ]);

    let tags: Vec<PropertyTag> = properties.iter().map(Cell::tag).collect();
    assert_eq!(
        tags,
        vec![PropertyTag::DISPLAY_NAME, PropertyTag::CONTENT_COUNT]
    );
    assert_eq!(properties.iter().len(), 2);
    assert_eq!(
        properties.iter().next_back().map(Cell::tag),
        Some(PropertyTag::CONTENT_COUNT)
    );
    assert_eq!((&properties).into_iter().count(), 2);
    assert_eq!(properties.cells().len(), 2);
    assert!(PropertySet::default().is_empty());
}

#[test]
fn a_cell_renders_as_its_tag_and_value() {
    let cell = Cell::new(PropertyTag::CONTENT_COUNT, PropertyValue::Integer32(7));
    assert_eq!(cell.to_string(), "PidTagContentCount (0x36020003) = 7");
}

/// The check that makes a wrong pairing impossible to build. The type half of a tag is what tells
/// the server how to parse the bytes that follow, so a mismatch does not set a wrong value — it
/// makes the server read the rest of the buffer as a different shape.
#[test]
fn a_value_cannot_be_paired_with_a_tag_of_another_type() {
    assert!(
        TaggedValue::new(
            PropertyTag::COMMENT,
            PropertyValue::String(TableString::from("hello"))
        )
        .is_ok()
    );

    let wrong = TaggedValue::new(PropertyTag::COMMENT, PropertyValue::Integer32(1))
        .expect_err("a string tag cannot carry an integer");
    assert_eq!(
        wrong,
        Error::PropertyTypeMismatch {
            tag: PropertyTag::COMMENT,
            value_type: Some(PropertyType::Integer32),
        }
    );
    assert!(wrong.to_string().contains("PtypString"), "{wrong}");
    assert!(wrong.to_string().contains("PtypInteger32"), "{wrong}");

    let absent = TaggedValue::new(PropertyTag::COMMENT, PropertyValue::Absent)
        .expect_err("an absent value is not a value");
    assert!(absent.to_string().contains("an absent value"), "{absent}");
}

#[test]
fn a_tagged_value_writes_its_tag_and_then_its_value() {
    let value = TaggedValue::new(
        PropertyTag::COMMENT,
        PropertyValue::String(TableString::from("hi")),
    )
    .unwrap();
    assert_eq!(value.tag(), PropertyTag::COMMENT);
    assert_eq!(
        value.value(),
        &PropertyValue::String(TableString::from("hi"))
    );

    let mut w = Writer::new();
    value.write(&mut w, ValueContext::Object).unwrap();
    assert_eq!(
        w.finish(),
        vec![0x1F, 0x00, 0x04, 0x30, 0x68, 0x00, 0x69, 0x00, 0x00, 0x00]
    );
}

/// A `PropertyProblem` names the entry it refers to as well as the tag, because the request may
/// hold the same tag twice and "which one" is the actionable half.
///
/// [MS-OXCDATA] §2.7
#[test]
fn a_property_problem_names_the_entry_the_tag_and_the_code() {
    let mut w = Writer::new();
    w.u16(1)
        .u32(PropertyTag::DISPLAY_NAME.as_u32())
        .u32(ErrorCode::ACCESS_DENIED.as_u32());
    let bytes = w.finish();

    let mut r = Reader::new(&bytes);
    let problem = PropertyProblem::read(&mut r).unwrap();

    assert!(r.is_empty());
    assert_eq!(problem.index(), 1);
    assert_eq!(problem.tag(), PropertyTag::DISPLAY_NAME);
    assert_eq!(problem.code(), ErrorCode::ACCESS_DENIED);
    assert_eq!(
        problem.to_string(),
        "PidTagDisplayName (0x3001001F) (entry 1): AccessDenied (0x80070005)"
    );
}

/// A count from a server nobody here controls: nothing may be pre-allocated from it, and a claim
/// larger than the buffer has to cost one failed read.
#[test]
fn a_lying_count_errors_rather_than_allocating() {
    let bytes = [0xFF, 0xFF, 0xFF, 0xFF];
    assert!(PropertySet::read_tagged(&mut Reader::new(&bytes), 0xFFFF_FFFF).is_err());
    assert!(PropertySet::read_tagged(&mut Reader::new(&[]), 1).is_err());
}
