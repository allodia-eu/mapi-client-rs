//! The GUIDs that scope a named property.
//!
//! A named property has no fixed id. What it has instead is a property *set* — a GUID — and either
//! a number or a string inside that set, which together name it the same way in every mailbox in
//! the world. The 16-bit id a store hands back for it is local to that store and means nothing
//! anywhere else; the pair here is the part that travels.
//!
//! [MS-OXPROPS] §1.3.2 — the commonly used property sets
//! [MS-OXCDATA] §2.6.1 — the `GUID` field of a `PropertyName`

use crate::oxcdata::Guid;

/// The GUID identifying a named property's property set.
///
/// A newtype over [`Guid`] rather than a bare one, because a property set GUID and a mailbox GUID
/// are the same sixteen bytes and are never interchangeable: comparing a resolved id's store
/// against the set it was resolved in is the check that a mistyped argument should fail rather
/// than pass.
///
/// [MS-OXCDATA] §2.6.1 — `GUID`, in little-endian order as a `FlatUID`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PropertySetId(Guid);

/// Builds a set id from the four groups the documents write a GUID in.
///
/// Written this way so that a constant below can be read against [MS-OXPROPS] §1.3.2 character by
/// character. The first three groups are little-endian on the wire and the last is byte order as
/// stored, which is exactly the transposition a hand-assembled byte array gets wrong.
const fn property_set(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> PropertySetId {
    let [a0, a1, a2, a3] = data1.to_le_bytes();
    let [b0, b1] = data2.to_le_bytes();
    let [c0, c1] = data3.to_le_bytes();
    let [d0, d1, d2, d3, d4, d5, d6, d7] = data4;
    PropertySetId(Guid::from_bytes([
        a0, a1, a2, a3, b0, b1, c0, c1, d0, d1, d2, d3, d4, d5, d6, d7,
    ]))
}

/// The trailing eight bytes every property set in [MS-OXPROPS] §1.3.2 but two shares.
const OLE_TAIL: [u8; 8] = [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];

impl PropertySetId {
    /// `PSETID_Address`, `{00062004-0000-0000-C000-000000000046}` — contact properties.
    ///
    /// Half of *"list contacts"* lives here: a contact's email addresses are
    /// `PidLidEmail1EmailAddress` and its siblings, none of which is a `PidTag` constant.
    ///
    /// [MS-OXOCNTC] §2.2.1.2 — electronic address properties
    pub const ADDRESS: Self = property_set(0x0006_2004, 0x0000, 0x0000, OLE_TAIL);
    /// `PSETID_Appointment`, `{00062002-0000-0000-C000-000000000046}` — calendar properties.
    ///
    /// The set that makes *"list calendar events"* need this whole mechanism: an appointment's
    /// start, end, location and busy status are all named properties in here, and none of them has
    /// a fixed id.
    ///
    /// [MS-OXOCAL] §2.2.1 — appointment and meeting object properties
    pub const APPOINTMENT: Self = property_set(0x0006_2002, 0x0000, 0x0000, OLE_TAIL);
    /// `PSETID_Common`, `{00062008-0000-0000-C000-000000000046}` — properties shared across item
    /// types, including the follow-up flag of [MS-OXOFLAG].
    pub const COMMON: Self = property_set(0x0006_2008, 0x0000, 0x0000, OLE_TAIL);
    /// `PS_INTERNET_HEADERS`, `{00020386-0000-0000-C000-000000000046}` — one named property per
    /// Internet message header.
    ///
    /// The one set with a documented server-side rule of its own: a string name in here is
    /// **lowercased by the server before it is matched**, so `X-Spam` and `x-spam` resolve to the
    /// same id.
    ///
    /// [MS-OXCPRPT] §3.2.5.10 — the server coerces the name to lowercase
    pub const INTERNET_HEADERS: Self = property_set(0x0002_0386, 0x0000, 0x0000, OLE_TAIL);
    /// `PS_MAPI`, `{00020328-0000-0000-C000-000000000046}` — the pseudo-set that stands for the
    /// fixed property ids.
    ///
    /// Not a set to resolve names in: a `PropertyName` naming it is answered from its own LID
    /// rather than from the store's mapping table, and one whose `Kind` is a string cannot be
    /// mapped at all. It is what `RopGetNamesFromPropertyIds` answers with for an id below
    /// `0x8000`.
    ///
    /// [MS-OXCPRPT] §2.2.13 — `PS_MAPI` is used for mapping non-named ids into names
    /// [MS-OXCPRPT] §3.2.5.10 — a `PS_MAPI` name whose `Kind` is not `0x00` cannot be mapped
    pub const MAPI: Self = property_set(0x0002_0328, 0x0000, 0x0000, OLE_TAIL);
    /// `PSETID_Meeting`, `{6ED8DA90-450B-101B-98DA-00AA003F1305}` — the meeting workflow.
    ///
    /// The one set here whose GUID is not of the `0006xxxx` family, which is why it is worth having
    /// a constant rather than being written out at each use.
    pub const MEETING: Self = property_set(
        0x6ED8_DA90,
        0x450B,
        0x101B,
        [0x98, 0xDA, 0x00, 0xAA, 0x00, 0x3F, 0x13, 0x05],
    );
    /// `PSETID_Note`, `{0006200E-0000-0000-C000-000000000046}` — sticky notes.
    pub const NOTE: Self = property_set(0x0006_200E, 0x0000, 0x0000, OLE_TAIL);
    /// `PS_PUBLIC_STRINGS`, `{00020329-0000-0000-C000-000000000046}` — the set a client puts its
    /// own string-named properties in.
    pub const PUBLIC_STRINGS: Self = property_set(0x0002_0329, 0x0000, 0x0000, OLE_TAIL);
    /// `PSETID_Task`, `{00062003-0000-0000-C000-000000000046}` — task properties.
    pub const TASK: Self = property_set(0x0006_2003, 0x0000, 0x0000, OLE_TAIL);

    /// Wraps a GUID that names a property set.
    #[must_use]
    pub const fn from_guid(guid: Guid) -> Self {
        Self(guid)
    }

    /// The GUID, in the order the wire carries it.
    #[must_use]
    pub const fn as_guid(self) -> Guid {
        self.0
    }

    /// The specification's name for this set, if it is one this crate knows.
    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::PUBLIC_STRINGS => "PS_PUBLIC_STRINGS",
            Self::MAPI => "PS_MAPI",
            Self::INTERNET_HEADERS => "PS_INTERNET_HEADERS",
            Self::APPOINTMENT => "PSETID_Appointment",
            Self::ADDRESS => "PSETID_Address",
            Self::COMMON => "PSETID_Common",
            Self::TASK => "PSETID_Task",
            Self::NOTE => "PSETID_Note",
            Self::MEETING => "PSETID_Meeting",
            _ => return None,
        })
    }
}

impl From<Guid> for PropertySetId {
    fn from(guid: Guid) -> Self {
        Self(guid)
    }
}

impl core::fmt::Display for PropertySetId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} {}", self.0),
            None => write!(f, "{}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every set, with the GUID [MS-OXPROPS] §1.3.2 prints for it — compared as the rendered
    /// string rather than as bytes, because the rendered form is the one the document gives and a
    /// byte array transcribed by hand is exactly where the endianness goes wrong.
    #[test]
    fn each_set_renders_the_guid_the_document_prints() {
        for (set, guid, name) in [
            (
                PropertySetId::PUBLIC_STRINGS,
                "{00020329-0000-0000-c000-000000000046}",
                "PS_PUBLIC_STRINGS",
            ),
            (
                PropertySetId::MAPI,
                "{00020328-0000-0000-c000-000000000046}",
                "PS_MAPI",
            ),
            (
                PropertySetId::INTERNET_HEADERS,
                "{00020386-0000-0000-c000-000000000046}",
                "PS_INTERNET_HEADERS",
            ),
            (
                PropertySetId::APPOINTMENT,
                "{00062002-0000-0000-c000-000000000046}",
                "PSETID_Appointment",
            ),
            (
                PropertySetId::ADDRESS,
                "{00062004-0000-0000-c000-000000000046}",
                "PSETID_Address",
            ),
            (
                PropertySetId::COMMON,
                "{00062008-0000-0000-c000-000000000046}",
                "PSETID_Common",
            ),
            (
                PropertySetId::TASK,
                "{00062003-0000-0000-c000-000000000046}",
                "PSETID_Task",
            ),
            (
                PropertySetId::NOTE,
                "{0006200e-0000-0000-c000-000000000046}",
                "PSETID_Note",
            ),
            (
                PropertySetId::MEETING,
                "{6ed8da90-450b-101b-98da-00aa003f1305}",
                "PSETID_Meeting",
            ),
        ] {
            assert_eq!(set.as_guid().to_string(), guid, "{name}");
            assert_eq!(set.name(), Some(name));
            assert_eq!(set.to_string(), format!("{name} {guid}"));
        }
    }

    /// The bytes of `PSETID_Appointment` as [MS-OXCPRPT] §4.1.1 shows them going onto the wire.
    /// The worked example is the only place in the corpus where a property set appears as bytes,
    /// which makes it the only check that the little-endian transposition is right.
    #[test]
    fn the_appointment_set_matches_the_bytes_in_the_worked_example() {
        assert_eq!(
            PropertySetId::APPOINTMENT.as_guid().as_bytes(),
            &[
                0x02, 0x20, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ]
        );
    }

    #[test]
    fn a_set_this_crate_does_not_know_still_prints_its_guid() {
        let unknown = PropertySetId::from(Guid::from_bytes([0xAA; 16]));
        assert_eq!(unknown.name(), None);
        assert_eq!(unknown.to_string(), unknown.as_guid().to_string());
        assert_eq!(
            PropertySetId::from_guid(Guid::from_bytes([0xAA; 16])),
            unknown
        );
    }
}
