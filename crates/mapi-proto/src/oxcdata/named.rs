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
//! Reading and writing want different lists, which is why there are four constants rather than
//! two. [`APPOINTMENT_PROPERTIES`] and [`CONTACT_PROPERTIES`] are what a *listing* needs;
//! [`NEW_APPOINTMENT_PROPERTIES`] and [`NEW_CONTACT_PROPERTIES`] add the ones an item has to carry
//! to be a well-formed item of its kind, which a reader has no reason to fetch.
//!
//! [MS-OXPROPS] §2 — every `PidLid`, with its set, its LID and its type
//! [MS-OXOCAL] §2.2.1 — the appointment properties
//! [MS-OXOCNTC] §2.2.1.2 — the electronic address properties

use crate::oxcdata::{PropertyName, PropertySetId, PropertyType};

/// How many appointment properties a listing reads.
const APPOINTMENT_COUNT: usize = 7;

/// How many contact properties a listing reads.
const CONTACT_COUNT: usize = 3;

/// How many more an appointment has to carry to be a well-formed one.
const NEW_APPOINTMENT_COUNT: usize = 3;

/// How many more a contact has to carry to be a well-formed one.
const NEW_CONTACT_COUNT: usize = 3;

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
    /// `PidLidAppointmentStateFlags`, `PSETID_Appointment/0x8217`, `PtypInteger32` — whether the
    /// object is a meeting, was received from somebody else, or has been cancelled.
    ///
    /// Zero is an appointment nobody was invited to, which is the only kind this crate creates.
    ///
    /// [MS-OXOCAL] §2.2.1.10
    AppointmentStateFlags,
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
    /// `PidLidEmail1OriginalDisplayName`, `PSETID_Address/0x8084`, `PtypString` — the SMTP address
    /// behind the display name.
    ///
    /// [MS-OXOCNTC] §2.2.1.2.4
    Email1OriginalDisplayName,
    /// `PidLidEmail1OriginalEntryId`, `PSETID_Address/0x8085`, `PtypBinary` — the address as an
    /// identifier rather than as text.
    ///
    /// A [`OneOffEntryId`](crate::OneOffEntryId) for an address the directory does not hold, which
    /// is what every SMTP address in a contact is. A contact saved without it has an email address
    /// a client can display and cannot act on.
    ///
    /// [MS-OXOCNTC] §2.2.1.2.5
    Email1OriginalEntryId,
    /// `PidLidFileUnder`, `PSETID_Address/0x8005`, `PtypString` — the name a contact is filed
    /// under, which is not necessarily its display name.
    ///
    /// [MS-OXOCNTC] §2.2.1.1.11
    FileUnder,
    /// `PidLidLocation`, `PSETID_Appointment/0x8208`, `PtypString`.
    ///
    /// [MS-OXOCAL] §2.2.1.4
    Location,
    /// `PidLidRecurring`, `PSETID_Appointment/0x8223`, `PtypBoolean` — whether this object is a
    /// recurring series.
    ///
    /// [MS-OXOCAL] §2.2.1.12
    Recurring,
    /// `PidLidResponseStatus`, `PSETID_Appointment/0x8218`, `PtypInteger32` — an attendee's
    /// response.
    ///
    /// `respNone` (`0x0`) is the documented value for an Appointment object, as against a Meeting
    /// object, and [MS-OXOCAL] §2.2.1.11 requires the property to hold one of its six values —
    /// so an appointment that omits it is not one the document allows.
    ///
    /// [MS-OXOCAL] §2.2.1.11
    ResponseStatus,
    /// `PidLidSideEffects`, `PSETID_Common/0x8510`, `PtypInteger32` — what a client may do to the
    /// item without asking.
    ///
    /// The one property here that is not in `PSETID_Appointment` or `PSETID_Address`. [MS-OXOCAL]
    /// §2.2.2.2 has every Calendar object set five of its flags.
    ///
    /// [MS-OXCMSG] §2.2.1.16
    SideEffects,
}

impl NamedProperty {
    /// Every one of them, appointment properties first.
    pub const ALL: [Self;
        APPOINTMENT_COUNT + CONTACT_COUNT + NEW_APPOINTMENT_COUNT + NEW_CONTACT_COUNT] = [
        Self::AppointmentStartWhole,
        Self::AppointmentEndWhole,
        Self::Location,
        Self::BusyStatus,
        Self::AppointmentSubType,
        Self::Recurring,
        Self::AppointmentRecur,
        Self::ResponseStatus,
        Self::AppointmentStateFlags,
        Self::SideEffects,
        Self::Email1DisplayName,
        Self::Email1AddressType,
        Self::Email1EmailAddress,
        Self::Email1OriginalDisplayName,
        Self::Email1OriginalEntryId,
        Self::FileUnder,
    ];

    /// The set this property is named in.
    #[must_use]
    pub const fn set(self) -> PropertySetId {
        match self {
            Self::AppointmentEndWhole
            | Self::AppointmentRecur
            | Self::AppointmentStartWhole
            | Self::AppointmentStateFlags
            | Self::AppointmentSubType
            | Self::BusyStatus
            | Self::Location
            | Self::Recurring
            | Self::ResponseStatus => PropertySetId::APPOINTMENT,
            Self::Email1AddressType
            | Self::Email1DisplayName
            | Self::Email1EmailAddress
            | Self::Email1OriginalDisplayName
            | Self::Email1OriginalEntryId
            | Self::FileUnder => PropertySetId::ADDRESS,
            Self::SideEffects => PropertySetId::COMMON,
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
            Self::AppointmentStateFlags => 0x0000_8217,
            Self::ResponseStatus => 0x0000_8218,
            Self::Recurring => 0x0000_8223,
            Self::SideEffects => 0x0000_8510,
            Self::FileUnder => 0x0000_8005,
            Self::Email1DisplayName => 0x0000_8080,
            Self::Email1AddressType => 0x0000_8082,
            Self::Email1EmailAddress => 0x0000_8083,
            Self::Email1OriginalDisplayName => 0x0000_8084,
            Self::Email1OriginalEntryId => 0x0000_8085,
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
            Self::AppointmentRecur | Self::Email1OriginalEntryId => PropertyType::Binary,
            Self::AppointmentSubType | Self::Recurring => PropertyType::Boolean,
            Self::AppointmentStateFlags
            | Self::BusyStatus
            | Self::ResponseStatus
            | Self::SideEffects => PropertyType::Integer32,
            Self::Email1AddressType
            | Self::Email1DisplayName
            | Self::Email1EmailAddress
            | Self::Email1OriginalDisplayName
            | Self::FileUnder
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
            Self::AppointmentStateFlags => "PidLidAppointmentStateFlags",
            Self::AppointmentSubType => "PidLidAppointmentSubType",
            Self::BusyStatus => "PidLidBusyStatus",
            Self::Email1AddressType => "PidLidEmail1AddressType",
            Self::Email1DisplayName => "PidLidEmail1DisplayName",
            Self::Email1EmailAddress => "PidLidEmail1EmailAddress",
            Self::Email1OriginalDisplayName => "PidLidEmail1OriginalDisplayName",
            Self::Email1OriginalEntryId => "PidLidEmail1OriginalEntryId",
            Self::FileUnder => "PidLidFileUnder",
            Self::Location => "PidLidLocation",
            Self::Recurring => "PidLidRecurring",
            Self::ResponseStatus => "PidLidResponseStatus",
            Self::SideEffects => "PidLidSideEffects",
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

/// The named properties **creating** an appointment needs, which is the read set plus three.
///
/// The three are not decoration. [MS-OXOCAL] §2.2.1.11 requires `PidLidResponseStatus` to hold one
/// of six values, §2.2.2.2 has every Calendar object set five flags of `PidLidSideEffects`, and
/// `PidLidAppointmentStateFlags` is what distinguishes an appointment from a meeting. An item
/// missing them saves without complaint and is not the item the document describes.
pub const NEW_APPOINTMENT_PROPERTIES: [NamedProperty; APPOINTMENT_COUNT + NEW_APPOINTMENT_COUNT] = [
    NamedProperty::AppointmentStartWhole,
    NamedProperty::AppointmentEndWhole,
    NamedProperty::Location,
    NamedProperty::BusyStatus,
    NamedProperty::AppointmentSubType,
    NamedProperty::Recurring,
    NamedProperty::AppointmentRecur,
    NamedProperty::ResponseStatus,
    NamedProperty::AppointmentStateFlags,
    NamedProperty::SideEffects,
];

/// The named properties **creating** a contact needs, which is the read set plus three.
///
/// `PidLidEmail1OriginalEntryId` is the one that costs something to get right: it is a
/// [`OneOffEntryId`](crate::OneOffEntryId), and a contact saved without it has an address a client
/// can show and cannot use.
pub const NEW_CONTACT_PROPERTIES: [NamedProperty; CONTACT_COUNT + NEW_CONTACT_COUNT] = [
    NamedProperty::Email1DisplayName,
    NamedProperty::Email1AddressType,
    NamedProperty::Email1EmailAddress,
    NamedProperty::Email1OriginalDisplayName,
    NamedProperty::Email1OriginalEntryId,
    NamedProperty::FileUnder,
];

#[cfg(test)]
mod tests;
