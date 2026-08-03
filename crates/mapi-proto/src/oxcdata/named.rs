//! The named properties this crate knows by name.
//!
//! A catalogue rather than a mechanism: [`PropertyName`] can name anything, and this is the list of
//! the ones the requested operations need — the seven that make a calendar entry mean something and
//! the three that carry a contact's email address. Every one of them is a `PidLid` with a
//! documented set, LID and data type, and none of them has a fixed property id.
//!
//! The type matters as much as the id. A named property's id says nothing about how its value is
//! encoded, so a caller that resolved an id and then guessed `PtypString` for
//! `PidLidAppointmentStartWhole` would ask the server to read eight bytes of `PtypTime` as a
//! null-terminated string. Pairing the two here is what stops that.
//!
//! [MS-OXPROPS] §2 — every `PidLid`, with its set, its LID and its type
//! [MS-OXOCAL] §2.2.1 — the appointment properties
//! [MS-OXOCNTC] §2.2.1.2 — the electronic address properties

use crate::oxcdata::{PropertyName, PropertySetId, PropertyType};

/// How many appointment properties are catalogued here.
const APPOINTMENT_COUNT: usize = 7;

/// How many contact properties are catalogued here.
const CONTACT_COUNT: usize = 3;

/// A named property [MS-OXPROPS] gives a canonical name, a set, a LID and a type.
///
/// Reaching one takes a round trip that a `PidTag` does not: the id has to be asked for, per store,
/// before any property ROP can name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum NamedProperty {
    /// `PidLidAppointmentEndWhole`, `PSETID_Appointment/0x820E`, `PtypTime`.
    ///
    /// [MS-OXOCAL] §2.2.1.6
    AppointmentEndWhole,
    /// `PidLidAppointmentRecur`, `PSETID_Appointment/0x8216`, `PtypBinary`.
    ///
    /// The recurrence pattern as its own grammar — pattern, exceptions, deleted instances and
    /// embedded timezone rules. This crate reads the blob and does not expand it into occurrences;
    /// that calculation's failure mode is an event reported at the wrong time with no error
    /// anywhere.
    ///
    /// [MS-OXOCAL] §2.2.1.44
    AppointmentRecur,
    /// `PidLidAppointmentStartWhole`, `PSETID_Appointment/0x820D`, `PtypTime`.
    ///
    /// [MS-OXOCAL] §2.2.1.5
    AppointmentStartWhole,
    /// `PidLidAppointmentSubType`, `PSETID_Appointment/0x8215`, `PtypBoolean` — whether the event
    /// is an all-day event.
    ///
    /// [MS-OXOCAL] §2.2.1.9
    AppointmentSubType,
    /// `PidLidBusyStatus`, `PSETID_Appointment/0x8205`, `PtypInteger32`.
    ///
    /// [MS-OXOCAL] §2.2.1.2
    BusyStatus,
    /// `PidLidEmail1AddressType`, `PSETID_Address/0x8082`, `PtypString`.
    ///
    /// [MS-OXOCNTC] §2.2.1.2.2
    Email1AddressType,
    /// `PidLidEmail1DisplayName`, `PSETID_Address/0x8080`, `PtypString`.
    ///
    /// [MS-OXOCNTC] §2.2.1.2.1
    Email1DisplayName,
    /// `PidLidEmail1EmailAddress`, `PSETID_Address/0x8083`, `PtypString`.
    ///
    /// The property *"list contacts"* is really asking for.
    ///
    /// [MS-OXOCNTC] §2.2.1.2.3
    Email1EmailAddress,
    /// `PidLidLocation`, `PSETID_Appointment/0x8208`, `PtypString`.
    ///
    /// [MS-OXOCAL] §2.2.1.4
    Location,
    /// `PidLidRecurring`, `PSETID_Appointment/0x8223`, `PtypBoolean` — whether this object is a
    /// recurring series.
    ///
    /// [MS-OXOCAL] §2.2.1.12
    Recurring,
}

impl NamedProperty {
    /// Every one of them, appointment properties first.
    pub const ALL: [Self; APPOINTMENT_COUNT + CONTACT_COUNT] = [
        Self::AppointmentStartWhole,
        Self::AppointmentEndWhole,
        Self::Location,
        Self::BusyStatus,
        Self::AppointmentSubType,
        Self::Recurring,
        Self::AppointmentRecur,
        Self::Email1DisplayName,
        Self::Email1AddressType,
        Self::Email1EmailAddress,
    ];

    /// The set this property is named in.
    #[must_use]
    pub const fn set(self) -> PropertySetId {
        match self {
            Self::AppointmentEndWhole
            | Self::AppointmentRecur
            | Self::AppointmentStartWhole
            | Self::AppointmentSubType
            | Self::BusyStatus
            | Self::Location
            | Self::Recurring => PropertySetId::APPOINTMENT,
            Self::Email1AddressType | Self::Email1DisplayName | Self::Email1EmailAddress => {
                PropertySetId::ADDRESS
            }
        }
    }

    /// Its LID within that set, as [MS-OXPROPS] writes it.
    #[must_use]
    pub const fn lid(self) -> u32 {
        match self {
            Self::BusyStatus => 0x0000_8205,
            Self::Location => 0x0000_8208,
            Self::AppointmentStartWhole => 0x0000_820D,
            Self::AppointmentEndWhole => 0x0000_820E,
            Self::AppointmentSubType => 0x0000_8215,
            Self::AppointmentRecur => 0x0000_8216,
            Self::Recurring => 0x0000_8223,
            Self::Email1DisplayName => 0x0000_8080,
            Self::Email1AddressType => 0x0000_8082,
            Self::Email1EmailAddress => 0x0000_8083,
        }
    }

    /// The type its value is carried in.
    ///
    /// Not derivable from anything on the wire: the id a store answers with carries no type, so
    /// this is where a tag for the property gets its second half.
    #[must_use]
    pub const fn property_type(self) -> PropertyType {
        match self {
            Self::AppointmentEndWhole | Self::AppointmentStartWhole => PropertyType::Time,
            Self::AppointmentRecur => PropertyType::Binary,
            Self::AppointmentSubType | Self::Recurring => PropertyType::Boolean,
            Self::BusyStatus => PropertyType::Integer32,
            Self::Email1AddressType
            | Self::Email1DisplayName
            | Self::Email1EmailAddress
            | Self::Location => PropertyType::String,
        }
    }

    /// Its canonical `PidLidXxx` name.
    #[must_use]
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::AppointmentEndWhole => "PidLidAppointmentEndWhole",
            Self::AppointmentRecur => "PidLidAppointmentRecur",
            Self::AppointmentStartWhole => "PidLidAppointmentStartWhole",
            Self::AppointmentSubType => "PidLidAppointmentSubType",
            Self::BusyStatus => "PidLidBusyStatus",
            Self::Email1AddressType => "PidLidEmail1AddressType",
            Self::Email1DisplayName => "PidLidEmail1DisplayName",
            Self::Email1EmailAddress => "PidLidEmail1EmailAddress",
            Self::Location => "PidLidLocation",
            Self::Recurring => "PidLidRecurring",
        }
    }

    /// The portable name to resolve against a store.
    #[must_use]
    pub const fn name(self) -> PropertyName {
        PropertyName::lid(self.set(), self.lid())
    }
}

impl core::fmt::Display for NamedProperty {
    /// `pad` rather than `write_str`, so `{:<28}` lines a column of these up. `write_str` goes
    /// straight past the formatter's width and produces a listing that silently does not align.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.pad(self.canonical_name())
    }
}

impl From<NamedProperty> for PropertyName {
    fn from(property: NamedProperty) -> Self {
        property.name()
    }
}

/// The appointment properties that make a calendar row mean something.
///
/// Start, end, location and busy status are what *"list calendar events"* is asking for; the two
/// recurrence properties are here because a row without them cannot say whether the time it reports
/// is the only one.
pub const APPOINTMENT_PROPERTIES: [NamedProperty; APPOINTMENT_COUNT] = [
    NamedProperty::AppointmentStartWhole,
    NamedProperty::AppointmentEndWhole,
    NamedProperty::Location,
    NamedProperty::BusyStatus,
    NamedProperty::AppointmentSubType,
    NamedProperty::Recurring,
    NamedProperty::AppointmentRecur,
];

/// The contact properties that carry an email address.
pub const CONTACT_PROPERTIES: [NamedProperty; CONTACT_COUNT] = [
    NamedProperty::Email1DisplayName,
    NamedProperty::Email1AddressType,
    NamedProperty::Email1EmailAddress,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Each row transcribed from [MS-OXPROPS] §2 rather than from the code that would use it, so a
    /// transposed digit is not confirmed by the thing it would break.
    #[test]
    fn each_property_matches_the_master_list() {
        for (property, set, lid, property_type, name) in [
            (
                NamedProperty::AppointmentStartWhole,
                PropertySetId::APPOINTMENT,
                0x0000_820D_u32,
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
        ] {
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

    /// The two groups partition the catalogue, and no property appears twice. A duplicate LID would
    /// resolve two entries to one id and quietly halve a fetch.
    #[test]
    fn the_two_groups_are_the_whole_catalogue_and_share_nothing() {
        let mut grouped: Vec<NamedProperty> = APPOINTMENT_PROPERTIES.to_vec();
        grouped.extend_from_slice(&CONTACT_PROPERTIES);
        grouped.sort_unstable();

        let mut all = NamedProperty::ALL.to_vec();
        all.sort_unstable();
        assert_eq!(grouped, all);

        let mut names: Vec<PropertyName> = all.iter().copied().map(NamedProperty::name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), NamedProperty::ALL.len());
    }

    /// Every appointment property is in `PSETID_Appointment` and every contact one in
    /// `PSETID_Address`. Resolving a name against the wrong set answers `0x0000` at best and a
    /// different property at worst.
    #[test]
    fn each_group_stays_inside_its_own_set() {
        for property in APPOINTMENT_PROPERTIES {
            assert_eq!(property.set(), PropertySetId::APPOINTMENT, "{property}");
        }
        for property in CONTACT_PROPERTIES {
            assert_eq!(property.set(), PropertySetId::ADDRESS, "{property}");
        }
    }
}
