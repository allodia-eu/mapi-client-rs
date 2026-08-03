//! ROP opcodes.

/// The one-byte value that identifies a ROP, in both requests and responses.
///
/// [MS-OXCROPS] §2.2.2 — the table of `RopId` values
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RopId(u8);

impl RopId {
    /// `RopBackoff`, `0xF9` — the server is busy and is asking for a retry later.
    ///
    /// [MS-OXCROPS] §2.2.15.2
    pub const BACKOFF: Self = Self(0xF9);
    /// `RopBufferTooSmall`, `0xFF` — the response did not fit in `MaxRopOut`.
    ///
    /// [MS-OXCROPS] §2.2.15.1
    pub const BUFFER_TOO_SMALL: Self = Self(0xFF);
    /// `RopDeleteProperties`, `0x0B` — removes properties from an object.
    ///
    /// [MS-OXCROPS] §2.2.8.8
    pub const DELETE_PROPERTIES: Self = Self(0x0B);
    /// `RopGetContentsTable`, `0x05` — the messages in a folder.
    ///
    /// [MS-OXCROPS] §2.2.4.14
    pub const GET_CONTENTS_TABLE: Self = Self(0x05);
    /// `RopGetHierarchyTable`, `0x04` — the subfolders of a folder.
    ///
    /// [MS-OXCROPS] §2.2.4.13
    pub const GET_HIERARCHY_TABLE: Self = Self(0x04);
    /// `RopGetNamesFromPropertyIds`, `0x55` — what this store calls the ids it was given.
    ///
    /// [MS-OXCROPS] §2.2.8.2
    pub const GET_NAMES_FROM_PROPERTY_IDS: Self = Self(0x55);
    /// `RopGetPropertiesAll`, `0x08` — every property an object has, tags included.
    ///
    /// [MS-OXCROPS] §2.2.8.4
    pub const GET_PROPERTIES_ALL: Self = Self(0x08);
    /// `RopGetPropertiesSpecific`, `0x07` — the properties that were asked for, by tag.
    ///
    /// [MS-OXCROPS] §2.2.8.3
    pub const GET_PROPERTIES_SPECIFIC: Self = Self(0x07);
    /// `RopGetPropertyIdsFromNames`, `0x56` — what this store calls the names it was given.
    ///
    /// [MS-OXCROPS] §2.2.8.1
    pub const GET_PROPERTY_IDS_FROM_NAMES: Self = Self(0x56);
    /// `RopIdFromLongTermId`, `0x44` — a long-term id into one a ROP will take.
    ///
    /// [MS-OXCROPS] §2.2.3.9
    pub const ID_FROM_LONG_TERM_ID: Self = Self(0x44);
    /// `RopLogon`, `0xFE`.
    ///
    /// [MS-OXCROPS] §2.2.3.1
    pub const LOGON: Self = Self(0xFE);
    /// `RopLongTermIdFromId`, `0x43` — a short-term id into one that survives leaving the store.
    ///
    /// [MS-OXCROPS] §2.2.3.8
    pub const LONG_TERM_ID_FROM_ID: Self = Self(0x43);
    /// `RopOpenFolder`, `0x02`.
    ///
    /// [MS-OXCROPS] §2.2.4.1
    pub const OPEN_FOLDER: Self = Self(0x02);
    /// `RopQueryRows`, `0x15`.
    ///
    /// [MS-OXCROPS] §2.2.5.4
    pub const QUERY_ROWS: Self = Self(0x15);
    /// `RopRelease`, `0x01` — releases a Server object handle.
    ///
    /// [MS-OXCROPS] §2.2.15.3
    pub const RELEASE: Self = Self(0x01);
    /// `RopSetColumns`, `0x12` — the column set every later row is encoded against.
    ///
    /// [MS-OXCROPS] §2.2.5.1
    pub const SET_COLUMNS: Self = Self(0x12);
    /// `RopSetProperties`, `0x0A` — writes property values to an object.
    ///
    /// [MS-OXCROPS] §2.2.8.6
    pub const SET_PROPERTIES: Self = Self(0x0A);

    /// Wraps a raw opcode.
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// The opcode as the wire carries it.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// The `RopXxx` name, if this is an opcode the crate models.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::RELEASE => "RopRelease",
            Self::OPEN_FOLDER => "RopOpenFolder",
            Self::GET_HIERARCHY_TABLE => "RopGetHierarchyTable",
            Self::GET_CONTENTS_TABLE => "RopGetContentsTable",
            Self::GET_PROPERTIES_SPECIFIC => "RopGetPropertiesSpecific",
            Self::GET_PROPERTIES_ALL => "RopGetPropertiesAll",
            Self::GET_NAMES_FROM_PROPERTY_IDS => "RopGetNamesFromPropertyIds",
            Self::GET_PROPERTY_IDS_FROM_NAMES => "RopGetPropertyIdsFromNames",
            Self::SET_PROPERTIES => "RopSetProperties",
            Self::DELETE_PROPERTIES => "RopDeleteProperties",
            Self::SET_COLUMNS => "RopSetColumns",
            Self::QUERY_ROWS => "RopQueryRows",
            Self::LONG_TERM_ID_FROM_ID => "RopLongTermIdFromId",
            Self::ID_FROM_LONG_TERM_ID => "RopIdFromLongTermId",
            Self::BACKOFF => "RopBackoff",
            Self::LOGON => "RopLogon",
            Self::BUFFER_TOO_SMALL => "RopBufferTooSmall",
            _ => return None,
        })
    }
}

impl core::fmt::Display for RopId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (0x{:02X})", self.0),
            None => write!(f, "0x{:02X}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcodes_match_the_table_of_ropids() {
        for (rop, raw, name) in [
            (RopId::RELEASE, 0x01, "RopRelease"),
            (RopId::OPEN_FOLDER, 0x02, "RopOpenFolder"),
            (RopId::GET_HIERARCHY_TABLE, 0x04, "RopGetHierarchyTable"),
            (RopId::GET_CONTENTS_TABLE, 0x05, "RopGetContentsTable"),
            (
                RopId::GET_PROPERTIES_SPECIFIC,
                0x07,
                "RopGetPropertiesSpecific",
            ),
            (RopId::GET_PROPERTIES_ALL, 0x08, "RopGetPropertiesAll"),
            (RopId::SET_PROPERTIES, 0x0A, "RopSetProperties"),
            (RopId::DELETE_PROPERTIES, 0x0B, "RopDeleteProperties"),
            (RopId::SET_COLUMNS, 0x12, "RopSetColumns"),
            (RopId::QUERY_ROWS, 0x15, "RopQueryRows"),
            (RopId::LONG_TERM_ID_FROM_ID, 0x43, "RopLongTermIdFromId"),
            (RopId::ID_FROM_LONG_TERM_ID, 0x44, "RopIdFromLongTermId"),
            (
                RopId::GET_NAMES_FROM_PROPERTY_IDS,
                0x55,
                "RopGetNamesFromPropertyIds",
            ),
            (
                RopId::GET_PROPERTY_IDS_FROM_NAMES,
                0x56,
                "RopGetPropertyIdsFromNames",
            ),
            (RopId::BACKOFF, 0xF9, "RopBackoff"),
            (RopId::LOGON, 0xFE, "RopLogon"),
            (RopId::BUFFER_TOO_SMALL, 0xFF, "RopBufferTooSmall"),
        ] {
            assert_eq!(rop.as_u8(), raw);
            assert_eq!(RopId::new(raw), rop);
            assert_eq!(rop.name(), Some(name));
        }
    }

    #[test]
    fn an_unmodelled_opcode_still_prints_its_value() {
        let reserved = RopId::new(0x7A);
        assert_eq!(reserved.name(), None);
        assert_eq!(reserved.to_string(), "0x7A");
        assert_eq!(RopId::LOGON.to_string(), "RopLogon (0xFE)");
    }
}
