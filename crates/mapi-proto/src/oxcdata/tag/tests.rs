mod catalogue;

use catalogue::CATALOGUE;

use super::*;
use crate::oxcdata::columns::{
    APPOINTMENT_COLUMNS, ATTACHMENT_COLUMNS, ATTACHMENT_PROPERTIES, CONTACT_COLUMNS,
    CONTENTS_COLUMNS, FOLDER_PROPERTIES, HIERARCHY_COLUMNS, MAILBOX_PROPERTIES, MESSAGE_PROPERTIES,
};

/// The canonical constant, little-endian, *is* the wire form: type first, then id.
#[test]
fn a_tag_is_type_then_id_on_the_wire() {
    assert_eq!(
        PropertyTag::SUBJECT.as_u32().to_le_bytes(),
        [0x1F, 0x00, 0x37, 0x00]
    );
    assert_eq!(PropertyTag::SUBJECT.id(), 0x0037);
    assert_eq!(PropertyTag::SUBJECT.property_type(), PropertyType::String);
}

#[test]
fn every_named_tag_carries_the_id_and_type_its_document_gives_it() {
    for (tag, id, property_type, name) in CATALOGUE {
        assert_eq!(tag.id(), id, "{name}");
        assert_eq!(tag.property_type(), property_type, "{name}");
        assert_eq!(tag.name(), Some(name));
        assert_eq!(PropertyTag::from_parts(id, property_type), tag, "{name}");
        assert_eq!(tag.to_string(), format!("{name} (0x{:08X})", tag.as_u32()));
    }
}

/// No two constants may name the same tag, which a copied-and-edited block makes easy to do and
/// impossible to see: the duplicate would simply shadow the first arm of `name`.
#[test]
fn no_two_constants_are_the_same_tag() {
    let mut seen: Vec<u32> = CATALOGUE.iter().map(|(tag, ..)| tag.as_u32()).collect();
    seen.sort_unstable();
    let count = seen.len();
    seen.dedup();
    assert_eq!(seen.len(), count, "two constants share one tag value");
}

/// `PidTagMessageSize` and `PidTagMessageSizeExtended` are one id and two types. A tag is both
/// halves, so they are different tags — and asking for the wrong one gets a value documented as
/// undefined past 4 GB.
#[test]
fn one_property_id_can_carry_two_types() {
    assert_eq!(
        PropertyTag::MESSAGE_SIZE.id(),
        PropertyTag::MESSAGE_SIZE_EXTENDED.id()
    );
    assert_ne!(
        PropertyTag::MESSAGE_SIZE,
        PropertyTag::MESSAGE_SIZE_EXTENDED
    );
}

/// Streaming a body means asking for the same property under a different type — `PtypBinary` for
/// the raw bytes rather than `PtypString` for the text. The id has to survive that.
#[test]
fn changing_a_tags_type_keeps_its_property() {
    let raw = PropertyTag::BODY.with_type(PropertyType::Binary);
    assert_eq!(raw.id(), PropertyTag::BODY.id());
    assert_eq!(raw.property_type(), PropertyType::Binary);
    assert_eq!(
        PropertyTag::BODY.with_type(PropertyType::String),
        PropertyTag::BODY
    );
}

#[test]
fn every_tag_this_crate_sends_has_a_type_it_can_decode() {
    let sent = HIERARCHY_COLUMNS
        .iter()
        .chain(&CONTENTS_COLUMNS)
        .chain(&ATTACHMENT_COLUMNS)
        .chain(&MAILBOX_PROPERTIES)
        .chain(&FOLDER_PROPERTIES)
        .chain(&MESSAGE_PROPERTIES)
        .chain(&ATTACHMENT_PROPERTIES)
        .chain(&CONTACT_COLUMNS)
        .chain(&APPOINTMENT_COLUMNS)
        .chain(&crate::oxcdata::SPECIAL_FOLDER_PROPERTIES);

    for tag in sent {
        assert!(tag.name().is_some(), "{tag} has no name");
        assert!(
            !matches!(tag.property_type(), PropertyType::Unsupported(_)),
            "{tag} has a type the decoder cannot read"
        );
        assert!(
            !tag.is_named(),
            "{tag} is a named-property id, which is not stable between mailboxes"
        );
    }
}

/// Ids from `0x8000` up are allocated per store, so the same number means a different property in
/// a different mailbox. Recognising one is what stops a diagnostic printing it as though it were a
/// constant.
#[test]
fn named_property_ids_are_recognisable_from_the_id_alone() {
    assert!(PropertyTag::new(0x8005_001F).is_named());
    assert!(PropertyTag::new(0xFFFF_0003).is_named());
    assert!(!PropertyTag::new(0x7FFF_0003).is_named());
    assert!(!PropertyTag::SUBJECT.is_named());
}

#[test]
fn an_unknown_tag_still_prints_usefully() {
    let unknown = PropertyTag::new(0x1234_001F);
    assert_eq!(unknown.name(), None);
    assert_eq!(unknown.to_string(), "0x1234001F");
}

/// The catalogue is what checks the constants, so a constant it does not mention is a constant
/// nothing checks — and the way that happens is somebody adding an arm to `names.rs` and stopping
/// there, which is exactly what the four properties this file gained last did.
///
/// Counting the arms in the source is the only thing that can notice. There is no way to enumerate
/// a type's associated constants at run time, and `name` returning `Some` for a tag proves only
/// that the arm exists — not that anybody transcribed its id and its type from the document.
#[test]
fn the_catalogue_names_every_tag_the_crate_has_a_constant_for() {
    let arms = include_str!("names.rs")
        .lines()
        .filter(|line| line.contains("=> ") && line.contains("PidTag"))
        .count();

    assert_eq!(
        arms,
        CATALOGUE.len(),
        "names.rs has {arms} arms and the catalogue {}: nothing checks the id or the type of a \
         constant the catalogue does not name",
        CATALOGUE.len()
    );
}
