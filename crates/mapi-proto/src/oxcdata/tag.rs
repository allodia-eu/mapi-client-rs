//! Property tags and the types they imply.
//!
//! A tag is a property id and a property type packed into one 32-bit value. Written the way the
//! documents write it — `0x0037001F` for `PidTagSubject` — the id is the high half and the type
//! the low half, and the little-endian encoding of that `u32` is exactly the wire form.
//!
//! [MS-OXCDATA] §2.9 — `PropertyTag` structure
//! [MS-OXCDATA] §2.11.1 — property data types

/// The type half of a property tag, which decides how many bytes a value occupies.
///
/// [MS-OXCDATA] §2.11.1 — property data types
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PropertyType {
    /// `PtypInteger32`, `0x0003`: 4 bytes.
    Integer32,
    /// `PtypErrorCode`, `0x000A`: 4 bytes holding an error code instead of a value.
    ErrorCode,
    /// `PtypBoolean`, `0x000B`: 1 byte, restricted to 0 or 1.
    Boolean,
    /// `PtypInteger64`, `0x0014`: 8 bytes.
    Integer64,
    /// `PtypString`, `0x001F`: null-terminated UTF-16LE.
    String,
    /// `PtypTime`, `0x0040`: 8 bytes of 100-nanosecond intervals since 1601-01-01 UTC.
    Time,
    /// A type this crate does not model. Its length is unknown, so a value of this type cannot be
    /// skipped over — decoding stops instead of guessing.
    Unsupported(u16),
}

impl PropertyType {
    /// Reads a type code as the wire carries it.
    #[must_use]
    pub const fn new(raw: u16) -> Self {
        match raw {
            0x0003 => Self::Integer32,
            0x000A => Self::ErrorCode,
            0x000B => Self::Boolean,
            0x0014 => Self::Integer64,
            0x001F => Self::String,
            0x0040 => Self::Time,
            other => Self::Unsupported(other),
        }
    }

    /// The type code as the wire carries it.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Integer32 => 0x0003,
            Self::ErrorCode => 0x000A,
            Self::Boolean => 0x000B,
            Self::Integer64 => 0x0014,
            Self::String => 0x001F,
            Self::Time => 0x0040,
            Self::Unsupported(raw) => raw,
        }
    }

    /// The specification's name for this type, if it is one this crate models.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::Integer32 => "PtypInteger32",
            Self::ErrorCode => "PtypErrorCode",
            Self::Boolean => "PtypBoolean",
            Self::Integer64 => "PtypInteger64",
            Self::String => "PtypString",
            Self::Time => "PtypTime",
            Self::Unsupported(_) => return None,
        })
    }
}

impl core::fmt::Display for PropertyType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "unmodelled type 0x{:04X}", self.as_u16()),
        }
    }
}

/// A property id paired with the type of its value.
///
/// [MS-OXCDATA] §2.9 — `PropertyTag` structure
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PropertyTag(u32);

impl PropertyTag {
    /// `PidTagContentCount`, `0x36020003` — messages in a folder, excluding FAI entries.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.1.1
    pub const CONTENT_COUNT: Self = Self(0x3602_0003);
    /// `PidTagDisplayName`, `0x3001001F` — a folder's display name.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.2.5
    pub const DISPLAY_NAME: Self = Self(0x3001_001F);
    /// `PidTagFolderId`, `0x67480014` — the folder id of a row in a hierarchy table.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.1.6
    pub const FOLDER_ID: Self = Self(0x6748_0014);
    /// `PidTagMessageDeliveryTime`, `0x0E060040` — when the server took delivery.
    ///
    /// [MS-OXOMSG] §2.2.3.9
    pub const MESSAGE_DELIVERY_TIME: Self = Self(0x0E06_0040);
    /// `PidTagMessageFlags`, `0x0E070003` — read state, attachments and so on.
    ///
    /// [MS-OXCMSG] §2.2.1.6
    pub const MESSAGE_FLAGS: Self = Self(0x0E07_0003);
    /// `PidTagMid`, `0x674A0014` — the message id of a row in a contents table.
    ///
    /// [MS-OXCFXICS] §2.2.1.2.1
    pub const MID: Self = Self(0x674A_0014);
    /// `PidTagSubfolders`, `0x360A000B` — whether a folder has children.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.1.12
    pub const SUBFOLDERS: Self = Self(0x360A_000B);
    /// `PidTagSubject`, `0x0037001F` — a message's subject line.
    ///
    /// [MS-OXPROPS] §2.1035
    pub const SUBJECT: Self = Self(0x0037_001F);

    /// Wraps a raw tag written the way the documents write it, id first.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Builds a tag from its two halves.
    #[must_use]
    pub const fn from_parts(id: u16, property_type: PropertyType) -> Self {
        let [id_low, id_high] = id.to_le_bytes();
        let [type_low, type_high] = property_type.as_u16().to_le_bytes();
        Self(u32::from_le_bytes([type_low, type_high, id_low, id_high]))
    }

    /// The tag as a `u32`, which little-endian encoded is the wire form.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// The property id — the half that names the property.
    #[must_use]
    pub const fn id(self) -> u16 {
        let [_, _, low, high] = self.0.to_le_bytes();
        u16::from_le_bytes([low, high])
    }

    /// The property type — the half that decides how the value is encoded.
    #[must_use]
    pub const fn property_type(self) -> PropertyType {
        let [low, high, ..] = self.0.to_le_bytes();
        PropertyType::new(u16::from_le_bytes([low, high]))
    }

    /// The canonical `PidTagXxx` name, if this is a tag the crate knows.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::MID => "PidTagMid",
            Self::SUBJECT => "PidTagSubject",
            Self::MESSAGE_DELIVERY_TIME => "PidTagMessageDeliveryTime",
            Self::MESSAGE_FLAGS => "PidTagMessageFlags",
            Self::FOLDER_ID => "PidTagFolderId",
            Self::DISPLAY_NAME => "PidTagDisplayName",
            Self::CONTENT_COUNT => "PidTagContentCount",
            Self::SUBFOLDERS => "PidTagSubfolders",
            _ => return None,
        })
    }
}

impl core::fmt::Display for PropertyTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (0x{:08X})", self.0),
            None => write!(f, "0x{:08X}", self.0),
        }
    }
}

/// The columns a hierarchy table is read with here: folder id, name, message count, has-children.
pub const HIERARCHY_COLUMNS: [PropertyTag; 4] = [
    PropertyTag::FOLDER_ID,
    PropertyTag::DISPLAY_NAME,
    PropertyTag::CONTENT_COUNT,
    PropertyTag::SUBFOLDERS,
];

/// The columns a contents table is read with here: message id, subject, delivery time, flags.
pub const CONTENTS_COLUMNS: [PropertyTag; 4] = [
    PropertyTag::MID,
    PropertyTag::SUBJECT,
    PropertyTag::MESSAGE_DELIVERY_TIME,
    PropertyTag::MESSAGE_FLAGS,
];

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_tag_round_trips_through_its_halves() {
        for tag in HIERARCHY_COLUMNS.iter().chain(&CONTENTS_COLUMNS) {
            assert_eq!(
                PropertyTag::from_parts(tag.id(), tag.property_type()),
                *tag,
                "{tag} did not round-trip"
            );
        }
    }

    #[test]
    fn every_column_this_crate_sends_has_a_type_it_can_decode() {
        for tag in HIERARCHY_COLUMNS.iter().chain(&CONTENTS_COLUMNS) {
            assert!(tag.name().is_some(), "{tag} has no name");
            assert!(
                !matches!(tag.property_type(), PropertyType::Unsupported(_)),
                "{tag} has a type the row decoder cannot read"
            );
        }
    }

    #[test]
    fn types_map_both_ways() {
        for (raw, expected) in [
            (0x0003, PropertyType::Integer32),
            (0x000A, PropertyType::ErrorCode),
            (0x000B, PropertyType::Boolean),
            (0x0014, PropertyType::Integer64),
            (0x001F, PropertyType::String),
            (0x0040, PropertyType::Time),
        ] {
            assert_eq!(PropertyType::new(raw), expected);
            assert_eq!(expected.as_u16(), raw);
            assert_eq!(Some(expected.to_string().as_str()), expected.name());
        }
    }

    /// `PtypBinary` is deliberately unmodelled: its count field is 2 bytes inside a ROP buffer but
    /// 4 in a `FastTransfer` stream, so "just skip it" is not a length this layer can assume.
    #[test]
    fn an_unmodelled_type_survives_being_read_and_says_so() {
        let binary = PropertyType::new(0x0102);
        assert_eq!(binary, PropertyType::Unsupported(0x0102));
        assert_eq!(binary.as_u16(), 0x0102);
        assert_eq!(binary.name(), None);
        assert_eq!(binary.to_string(), "unmodelled type 0x0102");
    }

    #[test]
    fn an_unknown_tag_still_prints_usefully() {
        let unknown = PropertyTag::new(0x1234_001F);
        assert_eq!(unknown.name(), None);
        assert_eq!(unknown.to_string(), "0x1234001F");
        assert_eq!(
            PropertyTag::SUBJECT.to_string(),
            "PidTagSubject (0x0037001F)"
        );
    }
}
