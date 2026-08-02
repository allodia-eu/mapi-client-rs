use super::*;

/// Every named tag, with the id and type its defining document gives it — transcribed from the
/// specification rather than derived from the constant, so a mistyped constant is not confirmed by
/// the test that checks it.
const CATALOGUE: [(PropertyTag, u16, PropertyType, &str); 39] = [
    (
        PropertyTag::ADDITIONAL_REN_ENTRY_IDS,
        0x36D8,
        PropertyType::MultipleBinary,
        "PidTagAdditionalRenEntryIds",
    ),
    (
        PropertyTag::ATTRIBUTE_HIDDEN,
        0x10F4,
        PropertyType::Boolean,
        "PidTagAttributeHidden",
    ),
    (
        PropertyTag::CODE_PAGE_ID,
        0x66C3,
        PropertyType::Integer32,
        "PidTagCodePageId",
    ),
    (
        PropertyTag::COMMENT,
        0x3004,
        PropertyType::String,
        "PidTagComment",
    ),
    (
        PropertyTag::CONTAINER_CLASS,
        0x3613,
        PropertyType::String,
        "PidTagContainerClass",
    ),
    (
        PropertyTag::CONTENT_COUNT,
        0x3602,
        PropertyType::Integer32,
        "PidTagContentCount",
    ),
    (
        PropertyTag::CONTENT_UNREAD_COUNT,
        0x3603,
        PropertyType::Integer32,
        "PidTagContentUnreadCount",
    ),
    (
        PropertyTag::DELETE_AFTER_SUBMIT,
        0x0E01,
        PropertyType::Boolean,
        "PidTagDeleteAfterSubmit",
    ),
    (
        PropertyTag::DISPLAY_NAME,
        0x3001,
        PropertyType::String,
        "PidTagDisplayName",
    ),
    (
        PropertyTag::EXTENDED_RULE_SIZE_LIMIT,
        0x0E9B,
        PropertyType::Integer32,
        "PidTagExtendedRuleSizeLimit",
    ),
    (
        PropertyTag::FOLDER_FLAGS,
        0x66A8,
        PropertyType::Integer32,
        "PidTagFolderFlags",
    ),
    (
        PropertyTag::FOLDER_ID,
        0x6748,
        PropertyType::Integer64,
        "PidTagFolderId",
    ),
    (
        PropertyTag::FOLDER_TYPE,
        0x3601,
        PropertyType::Integer32,
        "PidTagFolderType",
    ),
    (
        PropertyTag::IPM_APPOINTMENT_ENTRY_ID,
        0x36D0,
        PropertyType::Binary,
        "PidTagIpmAppointmentEntryId",
    ),
    (
        PropertyTag::IPM_ARCHIVE_ENTRY_ID,
        0x35FF,
        PropertyType::Binary,
        "PidTagIpmArchiveEntryId",
    ),
    (
        PropertyTag::IPM_CONTACT_ENTRY_ID,
        0x36D1,
        PropertyType::Binary,
        "PidTagIpmContactEntryId",
    ),
    (
        PropertyTag::IPM_DRAFTS_ENTRY_ID,
        0x36D7,
        PropertyType::Binary,
        "PidTagIpmDraftsEntryId",
    ),
    (
        PropertyTag::IPM_JOURNAL_ENTRY_ID,
        0x36D2,
        PropertyType::Binary,
        "PidTagIpmJournalEntryId",
    ),
    (
        PropertyTag::IPM_NOTE_ENTRY_ID,
        0x36D3,
        PropertyType::Binary,
        "PidTagIpmNoteEntryId",
    ),
    (
        PropertyTag::IPM_TASK_ENTRY_ID,
        0x36D4,
        PropertyType::Binary,
        "PidTagIpmTaskEntryId",
    ),
    (
        PropertyTag::LOCALE_ID,
        0x66A1,
        PropertyType::Integer32,
        "PidTagLocaleId",
    ),
    (
        PropertyTag::MAILBOX_OWNER_ENTRY_ID,
        0x661B,
        PropertyType::Binary,
        "PidTagMailboxOwnerEntryId",
    ),
    (
        PropertyTag::MAILBOX_OWNER_NAME,
        0x661C,
        PropertyType::String,
        "PidTagMailboxOwnerName",
    ),
    (
        PropertyTag::MAXIMUM_SUBMIT_MESSAGE_SIZE,
        0x666D,
        PropertyType::Integer32,
        "PidTagMaximumSubmitMessageSize",
    ),
    (
        PropertyTag::MESSAGE_DELIVERY_TIME,
        0x0E06,
        PropertyType::Time,
        "PidTagMessageDeliveryTime",
    ),
    (
        PropertyTag::MESSAGE_FLAGS,
        0x0E07,
        PropertyType::Integer32,
        "PidTagMessageFlags",
    ),
    (
        PropertyTag::MESSAGE_SIZE_EXTENDED,
        0x0E08,
        PropertyType::Integer64,
        "PidTagMessageSizeExtended",
    ),
    (
        PropertyTag::MID,
        0x674A,
        PropertyType::Integer64,
        "PidTagMid",
    ),
    (
        PropertyTag::OUT_OF_OFFICE_STATE,
        0x661D,
        PropertyType::Boolean,
        "PidTagOutOfOfficeState",
    ),
    (
        PropertyTag::PARENT_FOLDER_ID,
        0x6749,
        PropertyType::Integer64,
        "PidTagParentFolderId",
    ),
    (
        PropertyTag::PROHIBIT_RECEIVE_QUOTA,
        0x666A,
        PropertyType::Integer32,
        "PidTagProhibitReceiveQuota",
    ),
    (
        PropertyTag::PROHIBIT_SEND_QUOTA,
        0x666E,
        PropertyType::Integer32,
        "PidTagProhibitSendQuota",
    ),
    (
        PropertyTag::REMINDERS_ONLINE_ENTRY_ID,
        0x36D5,
        PropertyType::Binary,
        "PidTagRemindersOnlineEntryId",
    ),
    (
        PropertyTag::SERIALIZED_REPLID_GUID_MAP,
        0x6638,
        PropertyType::Binary,
        "PidTagSerializedReplidGuidMap",
    ),
    (
        PropertyTag::SORT_LOCALE_ID,
        0x6705,
        PropertyType::Integer32,
        "PidTagSortLocaleId",
    ),
    (
        PropertyTag::STORE_STATE,
        0x340E,
        PropertyType::Integer32,
        "PidTagStoreState",
    ),
    (
        PropertyTag::SUBFOLDERS,
        0x360A,
        PropertyType::Boolean,
        "PidTagSubfolders",
    ),
    (
        PropertyTag::SUBJECT,
        0x0037,
        PropertyType::String,
        "PidTagSubject",
    ),
    (
        PropertyTag::USER_ENTRY_ID,
        0x6619,
        PropertyType::Binary,
        "PidTagUserEntryId",
    ),
];

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
    let thirty_two = PropertyTag::from_parts(0x0E08, PropertyType::Integer32);
    assert_eq!(thirty_two.id(), PropertyTag::MESSAGE_SIZE_EXTENDED.id());
    assert_ne!(thirty_two, PropertyTag::MESSAGE_SIZE_EXTENDED);
}

#[test]
fn every_tag_this_crate_sends_has_a_type_it_can_decode() {
    let sent = HIERARCHY_COLUMNS
        .iter()
        .chain(&CONTENTS_COLUMNS)
        .chain(&MAILBOX_PROPERTIES)
        .chain(&FOLDER_PROPERTIES)
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
/// a different mailbox. Nothing resolves them yet; recognising one is what stops a diagnostic
/// printing it as though it were a constant.
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
