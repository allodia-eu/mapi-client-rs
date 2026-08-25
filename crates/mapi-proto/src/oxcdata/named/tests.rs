use super::*;

/// Every named property this crate catalogues, with the set, LID and type [MS-OXPROPS] §2 gives it.
///
/// Transcribed from the document rather than from the code that would use it, so a transposed digit
/// is not confirmed by the thing it would break — and hoisted out of the test below because the
/// table grows with every phase and the assertions do not.
const MASTER_LIST: [(NamedProperty, PropertySetId, u32, PropertyType, &str);
    NamedProperty::ALL.len()] = [
    (
        NamedProperty::AppointmentStartWhole,
        PropertySetId::APPOINTMENT,
        0x0000_820D,
        PropertyType::Time,
        "PidLidAppointmentStartWhole",
    ),
    (
        NamedProperty::AppointmentEndWhole,
        PropertySetId::APPOINTMENT,
        0x0000_820E,
        PropertyType::Time,
        "PidLidAppointmentEndWhole",
    ),
    (
        NamedProperty::Location,
        PropertySetId::APPOINTMENT,
        0x0000_8208,
        PropertyType::String,
        "PidLidLocation",
    ),
    (
        NamedProperty::BusyStatus,
        PropertySetId::APPOINTMENT,
        0x0000_8205,
        PropertyType::Integer32,
        "PidLidBusyStatus",
    ),
    (
        NamedProperty::AppointmentSubType,
        PropertySetId::APPOINTMENT,
        0x0000_8215,
        PropertyType::Boolean,
        "PidLidAppointmentSubType",
    ),
    (
        NamedProperty::Recurring,
        PropertySetId::APPOINTMENT,
        0x0000_8223,
        PropertyType::Boolean,
        "PidLidRecurring",
    ),
    (
        NamedProperty::AppointmentRecur,
        PropertySetId::APPOINTMENT,
        0x0000_8216,
        PropertyType::Binary,
        "PidLidAppointmentRecur",
    ),
    (
        NamedProperty::Email1DisplayName,
        PropertySetId::ADDRESS,
        0x0000_8080,
        PropertyType::String,
        "PidLidEmail1DisplayName",
    ),
    (
        NamedProperty::Email1AddressType,
        PropertySetId::ADDRESS,
        0x0000_8082,
        PropertyType::String,
        "PidLidEmail1AddressType",
    ),
    (
        NamedProperty::Email1EmailAddress,
        PropertySetId::ADDRESS,
        0x0000_8083,
        PropertyType::String,
        "PidLidEmail1EmailAddress",
    ),
    (
        NamedProperty::ResponseStatus,
        PropertySetId::APPOINTMENT,
        0x0000_8218,
        PropertyType::Integer32,
        "PidLidResponseStatus",
    ),
    (
        NamedProperty::AppointmentStateFlags,
        PropertySetId::APPOINTMENT,
        0x0000_8217,
        PropertyType::Integer32,
        "PidLidAppointmentStateFlags",
    ),
    (
        NamedProperty::SideEffects,
        PropertySetId::COMMON,
        0x0000_8510,
        PropertyType::Integer32,
        "PidLidSideEffects",
    ),
    (
        NamedProperty::Email1OriginalDisplayName,
        PropertySetId::ADDRESS,
        0x0000_8084,
        PropertyType::String,
        "PidLidEmail1OriginalDisplayName",
    ),
    (
        NamedProperty::Email1OriginalEntryId,
        PropertySetId::ADDRESS,
        0x0000_8085,
        PropertyType::Binary,
        "PidLidEmail1OriginalEntryId",
    ),
    (
        NamedProperty::FileUnder,
        PropertySetId::ADDRESS,
        0x0000_8005,
        PropertyType::String,
        "PidLidFileUnder",
    ),
];

#[test]
fn each_property_matches_the_master_list() {
    for (property, set, lid, property_type, name) in MASTER_LIST {
        assert_eq!(property.set(), set, "{name}");
        assert_eq!(property.lid(), lid, "{name}");
        assert_eq!(property.property_type(), property_type, "{name}");
        assert_eq!(property.canonical_name(), name);
        assert_eq!(property.to_string(), name);
        assert_eq!(PropertyName::from(property), PropertyName::lid(set, lid));
        // A column of these is printed with a width, and `write_str` would ignore it.
        assert_eq!(format!("{property:<32}").len(), 32, "{name}");
    }
}

/// The two write sets partition the catalogue, and no property appears twice. A duplicate LID
/// would resolve two entries to one id and quietly halve a fetch.
#[test]
fn the_two_write_sets_are_the_whole_catalogue_and_share_nothing() {
    let mut grouped: Vec<NamedProperty> = NEW_APPOINTMENT_PROPERTIES.to_vec();
    grouped.extend_from_slice(&NEW_CONTACT_PROPERTIES);
    grouped.sort_unstable();

    let mut all = NamedProperty::ALL.to_vec();
    all.sort_unstable();
    assert_eq!(grouped, all);

    let mut names: Vec<PropertyName> = all.iter().copied().map(NamedProperty::name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), NamedProperty::ALL.len());
}

/// A read set is a prefix of the write set for its kind. Not tidiness: `Logon::resolve_names`
/// caches by name, so a listing that has already resolved its columns pays for three more
/// properties when it goes on to create one, rather than for ten.
#[test]
fn each_read_set_is_the_front_of_its_write_set() {
    assert_eq!(
        NEW_APPOINTMENT_PROPERTIES.get(..APPOINTMENT_PROPERTIES.len()),
        Some(&APPOINTMENT_PROPERTIES[..])
    );
    assert_eq!(
        NEW_CONTACT_PROPERTIES.get(..CONTACT_PROPERTIES.len()),
        Some(&CONTACT_PROPERTIES[..])
    );
}

/// Every appointment property is in `PSETID_Appointment` and every contact one in
/// `PSETID_Address` — with one exception, which is the point of checking. Resolving a name
/// against the wrong set answers `0x0000` at best and a different property at worst.
#[test]
fn each_group_stays_inside_its_own_set() {
    for property in APPOINTMENT_PROPERTIES {
        assert_eq!(property.set(), PropertySetId::APPOINTMENT, "{property}");
    }
    for property in CONTACT_PROPERTIES {
        assert_eq!(property.set(), PropertySetId::ADDRESS, "{property}");
    }
    for property in NEW_CONTACT_PROPERTIES {
        assert_eq!(property.set(), PropertySetId::ADDRESS, "{property}");
    }
    // `PidLidSideEffects` is shared across item types and lives in `PSETID_Common`, so the
    // appointment write set is the one group that spans two sets.
    for property in NEW_APPOINTMENT_PROPERTIES {
        let expected = if property == NamedProperty::SideEffects {
            PropertySetId::COMMON
        } else {
            PropertySetId::APPOINTMENT
        };
        assert_eq!(property.set(), expected, "{property}");
    }
}
