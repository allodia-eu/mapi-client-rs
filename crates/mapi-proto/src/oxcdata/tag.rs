//! Property tags, and the sets of them this crate asks for.
//!
//! A tag is a property id and a property type packed into one 32-bit value. Written the way the
//! documents write it — `0x0037001F` for `PidTagSubject` — the id is the high half and the type
//! the low half, and the little-endian encoding of that `u32` is exactly the wire form.
//!
//! [MS-OXCDATA] §2.9 — `PropertyTag` structure

use crate::oxcdata::PropertyType;

/// A property id paired with the type of its value.
///
/// [MS-OXCDATA] §2.9 — `PropertyTag` structure
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PropertyTag(u32);

impl PropertyTag {
    /// `PidTagCodePageId`, `0x66C30003` — the code page `PtypString8` values are encoded in.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.15
    pub const CODE_PAGE_ID: Self = Self(0x66C3_0003);
    /// `PidTagComment`, `0x3004001F` — a mailbox comment, on a Logon object.
    ///
    /// Listed as read/write and deletable, and refused in practice: [MS-OXCSTOR]'s own product
    /// note 14 says Exchange 2013 SP1 and later answer `ecAccessDenied` when a client sets it.
    /// Confirmed on Exchange Server SE `15.02.2562.045`, where both `RopSetProperties` **and**
    /// `RopDeleteProperties` come back with a successful `ReturnValue` and an `ecAccessDenied`
    /// `PropertyProblem` — the delete is the crate's own observation, which the note does not
    /// cover.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.2.1, and §7 note 14
    pub const COMMENT: Self = Self(0x3004_001F);
    /// `PidTagContentCount`, `0x36020003` — messages in a folder, excluding FAI entries.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.1.1
    pub const CONTENT_COUNT: Self = Self(0x3602_0003);
    /// `PidTagDeleteAfterSubmit`, `0x0E01000B` — whether transport deletes submitted mail.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.2.2
    pub const DELETE_AFTER_SUBMIT: Self = Self(0x0E01_000B);
    /// `PidTagDisplayName`, `0x3001001F` — a folder's display name, or a mailbox's.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.2.5, and [MS-OXCSTOR] §2.2.2.1.2.3 for the Store object
    pub const DISPLAY_NAME: Self = Self(0x3001_001F);
    /// `PidTagExtendedRuleSizeLimit`, `0x0E9B0003` — bytes allowed for one extended rule.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.1
    pub const EXTENDED_RULE_SIZE_LIMIT: Self = Self(0x0E9B_0003);
    /// `PidTagFolderId`, `0x67480014` — the folder id of a row in a hierarchy table.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.1.6
    pub const FOLDER_ID: Self = Self(0x6748_0014);
    /// `PidTagLocaleId`, `0x66A10003` — the locale system-generated messages are written in.
    ///
    /// Documented as a read-only property of every private mailbox logon; observed answering
    /// `ecNotFound` on Exchange Server SE `15.02.2562.045`, for both an en-US and an nl-NL mailbox.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.12
    pub const LOCALE_ID: Self = Self(0x66A1_0003);
    /// `PidTagMailboxOwnerEntryId`, `0x661B0102` — the owner's `EntryID` in the GAL.
    ///
    /// **Not returned by `RopGetPropertiesAll`.** Measured on Exchange Server SE
    /// `15.02.2562.045`: absent from all 113 properties that ROP answered with, and 151 bytes long
    /// when asked for by name. [MS-OXCPRPT] §3.2.5.2 has the server return the values for all
    /// properties *on the object*, while §3.2.5.1 has an explicit fetch return computed properties
    /// as well — so a computed property is not "on the object", and only the second ROP finds it.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.7
    pub const MAILBOX_OWNER_ENTRY_ID: Self = Self(0x661B_0102);
    /// `PidTagMailboxOwnerName`, `0x661C001F` — the display name of the mailbox's owner.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.8
    pub const MAILBOX_OWNER_NAME: Self = Self(0x661C_001F);
    /// `PidTagMaximumSubmitMessageSize`, `0x666D0003` — kilobytes, or `-1` for no limit.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.2
    pub const MAXIMUM_SUBMIT_MESSAGE_SIZE: Self = Self(0x666D_0003);
    /// `PidTagMessageDeliveryTime`, `0x0E060040` — when the server took delivery.
    ///
    /// [MS-OXOMSG] §2.2.3.9
    pub const MESSAGE_DELIVERY_TIME: Self = Self(0x0E06_0040);
    /// `PidTagMessageFlags`, `0x0E070003` — read state, attachments and so on.
    ///
    /// [MS-OXCMSG] §2.2.1.6
    pub const MESSAGE_FLAGS: Self = Self(0x0E07_0003);
    /// `PidTagMessageSizeExtended`, `0x0E080014` — bytes of content in the mailbox.
    ///
    /// Shares property id `0x0E08` with `PidTagMessageSize`, which is the same quantity in 32 bits
    /// and is documented as *undefined* past 4 GB. A tag is an id **and** a type, so the two are
    /// different tags; ask for this one.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.10
    pub const MESSAGE_SIZE_EXTENDED: Self = Self(0x0E08_0014);
    /// `PidTagMid`, `0x674A0014` — the message id of a row in a contents table.
    ///
    /// [MS-OXCFXICS] §2.2.1.2.1
    pub const MID: Self = Self(0x674A_0014);
    /// `PidTagOutOfOfficeState`, `0x661D000B` — whether the user is out of office.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.2.4
    pub const OUT_OF_OFFICE_STATE: Self = Self(0x661D_000B);
    /// `PidTagProhibitReceiveQuota`, `0x666A0003` — kilobytes before delivery stops.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.3
    pub const PROHIBIT_RECEIVE_QUOTA: Self = Self(0x666A_0003);
    /// `PidTagProhibitSendQuota`, `0x666E0003` — kilobytes before sending stops.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.4
    pub const PROHIBIT_SEND_QUOTA: Self = Self(0x666E_0003);
    /// `PidTagSerializedReplidGuidMap`, `0x66380102` — 18-byte REPLID/REPLGUID pairs.
    ///
    /// Whatever part of the mapping the server chose to send, which is not required to be all of
    /// it; a trailing run shorter than 18 bytes is to be ignored.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.13
    pub const SERIALIZED_REPLID_GUID_MAP: Self = Self(0x6638_0102);
    /// `PidTagSortLocaleId`, `0x67050003` — the locale table contents are sorted in.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.14
    pub const SORT_LOCALE_ID: Self = Self(0x6705_0003);
    /// `PidTagStoreState`, `0x340E0003` — `0x01000000` if the mailbox has active search folders.
    ///
    /// Documented as a read-only property of every private mailbox logon; observed answering
    /// `ecNotFound` on Exchange Server SE `15.02.2562.045`, for both lab mailboxes.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.5
    pub const STORE_STATE: Self = Self(0x340E_0003);
    /// `PidTagSubfolders`, `0x360A000B` — whether a folder has children.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.1.12
    pub const SUBFOLDERS: Self = Self(0x360A_000B);
    /// `PidTagSubject`, `0x0037001F` — a message's subject line.
    ///
    /// [MS-OXPROPS] §2.1035
    pub const SUBJECT: Self = Self(0x0037_001F);
    /// `PidTagUserEntryId`, `0x66190102` — the address book `EntryID` of the logged-on user.
    ///
    /// Not the same as [`MAILBOX_OWNER_ENTRY_ID`](Self::MAILBOX_OWNER_ENTRY_ID): they differ
    /// exactly when one account is reading another's mailbox, which is the case worth telling
    /// apart.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.11
    pub const USER_ENTRY_ID: Self = Self(0x6619_0102);

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

    /// Whether this id was allocated for a named property rather than fixed by a specification.
    ///
    /// Ids from `0x8000` upwards are handed out by each store as it first needs them, so the same
    /// id means a different property in a different mailbox. Nothing here resolves them yet; this
    /// is what lets a diagnostic say "this number is only meaningful in the store it came from"
    /// rather than printing it as though it were a constant.
    ///
    /// [MS-OXCDATA] §2.4.2 — `ecUnexpectedId`
    #[must_use]
    pub const fn is_named(self) -> bool {
        self.id() >= 0x8000
    }

    /// The canonical `PidTagXxx` name, if this is a tag the crate knows.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::CODE_PAGE_ID => "PidTagCodePageId",
            Self::COMMENT => "PidTagComment",
            Self::CONTENT_COUNT => "PidTagContentCount",
            Self::DELETE_AFTER_SUBMIT => "PidTagDeleteAfterSubmit",
            Self::DISPLAY_NAME => "PidTagDisplayName",
            Self::EXTENDED_RULE_SIZE_LIMIT => "PidTagExtendedRuleSizeLimit",
            Self::FOLDER_ID => "PidTagFolderId",
            Self::LOCALE_ID => "PidTagLocaleId",
            Self::MAILBOX_OWNER_ENTRY_ID => "PidTagMailboxOwnerEntryId",
            Self::MAILBOX_OWNER_NAME => "PidTagMailboxOwnerName",
            Self::MAXIMUM_SUBMIT_MESSAGE_SIZE => "PidTagMaximumSubmitMessageSize",
            Self::MESSAGE_DELIVERY_TIME => "PidTagMessageDeliveryTime",
            Self::MESSAGE_FLAGS => "PidTagMessageFlags",
            Self::MESSAGE_SIZE_EXTENDED => "PidTagMessageSizeExtended",
            Self::MID => "PidTagMid",
            Self::OUT_OF_OFFICE_STATE => "PidTagOutOfOfficeState",
            Self::PROHIBIT_RECEIVE_QUOTA => "PidTagProhibitReceiveQuota",
            Self::PROHIBIT_SEND_QUOTA => "PidTagProhibitSendQuota",
            Self::SERIALIZED_REPLID_GUID_MAP => "PidTagSerializedReplidGuidMap",
            Self::SORT_LOCALE_ID => "PidTagSortLocaleId",
            Self::STORE_STATE => "PidTagStoreState",
            Self::SUBFOLDERS => "PidTagSubfolders",
            Self::SUBJECT => "PidTagSubject",
            Self::USER_ENTRY_ID => "PidTagUserEntryId",
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

/// The Store object properties that answer "tell me about this mailbox".
///
/// Every one is documented as available on a private mailbox logon, so a server that omits one has
/// said something — which is why they are asked for by name rather than filtered out of everything
/// the store happens to hold.
///
/// [MS-OXCSTOR] §2.2.2.1 — private mailbox logon properties
pub const MAILBOX_PROPERTIES: [PropertyTag; 10] = [
    PropertyTag::DISPLAY_NAME,
    PropertyTag::MAILBOX_OWNER_NAME,
    PropertyTag::MESSAGE_SIZE_EXTENDED,
    PropertyTag::CONTENT_COUNT,
    PropertyTag::PROHIBIT_SEND_QUOTA,
    PropertyTag::PROHIBIT_RECEIVE_QUOTA,
    PropertyTag::MAXIMUM_SUBMIT_MESSAGE_SIZE,
    PropertyTag::STORE_STATE,
    PropertyTag::LOCALE_ID,
    PropertyTag::MAILBOX_OWNER_ENTRY_ID,
];

#[cfg(test)]
mod tests;
