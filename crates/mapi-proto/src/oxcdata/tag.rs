//! Property tags: a property id and the type of its value, packed into one 32-bit word.
//!
//! Written the way the documents write it — `0x0037001F` for `PidTagSubject` — the id is the high
//! half and the type the low half, and the little-endian encoding of that `u32` is exactly the wire
//! form.
//!
//! The catalogue is split three ways so that none of the three outgrows the file limit: the type
//! and the constants are here, the canonical names are in the `names` submodule, and the sets a
//! caller asks for are in `columns`.
//!
//! [MS-OXCDATA] §2.9 — `PropertyTag` structure

use crate::oxcdata::PropertyType;

mod names;

/// A property id paired with the type of its value.
///
/// [MS-OXCDATA] §2.9 — `PropertyTag` structure
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PropertyTag(u32);

impl PropertyTag {
    /// `PidTagAdditionalRenEntryIds`, `0x36D81102` — entry ids of five more special folders.
    ///
    /// A `PtypMultipleBinary` on the Inbox, indexed rather than named: `0x0000` Conflicts,
    /// `0x0001` Sync Issues, `0x0002` Local Failures, `0x0003` Server Failures, `0x0004` Junk
    /// E-mail. The indexed mechanism is not modelled here — [`SpecialFolder`] covers the folders
    /// that get a property each — but the tag is named because the value is this crate's evidence
    /// for the COUNT-width measurement, and because a caller can index it themselves.
    ///
    /// [MS-OXOSFLD] §2.2.4
    ///
    /// [`SpecialFolder`]: crate::SpecialFolder
    pub const ADDITIONAL_REN_ENTRY_IDS: Self = Self(0x36D8_1102);
    /// `PidTagAttachDataBinary`, `0x37010102` — an attachment's content.
    ///
    /// **Read this with `RopOpenStream`, not with a property fetch.** Anything larger than the
    /// response buffer comes back as `NotEnoughMemory` instead of as bytes, and an attachment whose
    /// [`ATTACH_METHOD`](Self::ATTACH_METHOD) is `afEmbeddedMessage` does not hold this property at
    /// all — its payload is another Message object.
    ///
    /// [MS-OXCMSG] §2.2.2.7
    pub const ATTACH_DATA_BINARY: Self = Self(0x3701_0102);
    /// `PidTagAttachFilename`, `0x3704001F` — the 8.3 form of the attachment's file name.
    ///
    /// [MS-OXCMSG] §2.2.2.11
    pub const ATTACH_FILENAME: Self = Self(0x3704_001F);
    /// `PidTagAttachLongFilename`, `0x3707001F` — the attachment's full file name.
    ///
    /// [MS-OXCMSG] §2.2.2.10
    pub const ATTACH_LONG_FILENAME: Self = Self(0x3707_001F);
    /// `PidTagAttachMethod`, `0x37050003` — how the attachment's content is reached.
    ///
    /// The column that decides which of two entirely different reads is correct. See
    /// [`AttachMethod`](crate::AttachMethod).
    ///
    /// [MS-OXCMSG] §2.2.2.9
    pub const ATTACH_METHOD: Self = Self(0x3705_0003);
    /// `PidTagAttachMimeTag`, `0x370E001F` — the attachment's MIME content type.
    ///
    /// [MS-OXCMSG] §2.2.2.29
    pub const ATTACH_MIME_TAG: Self = Self(0x370E_001F);
    /// `PidTagAttachNumber`, `0x0E210003` — identifies an attachment within its message.
    ///
    /// This is the `AttachmentID` `RopOpenAttachment` takes, and the only way to name one.
    ///
    /// [MS-OXCMSG] §2.2.2.6
    pub const ATTACH_NUMBER: Self = Self(0x0E21_0003);
    /// `PidTagAttachSize`, `0x0E200003` — bytes the attachment occupies on the server.
    ///
    /// [MS-OXCMSG] §2.2.2.5
    pub const ATTACH_SIZE: Self = Self(0x0E20_0003);
    /// `PidTagAttributeHidden`, `0x10F4000B` — whether a client hides this folder from the user.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.2.1
    pub const ATTRIBUTE_HIDDEN: Self = Self(0x10F4_000B);
    /// `PidTagBody`, `0x1000001F` — the message's plain-text body.
    ///
    /// **Read this with `RopOpenStream`.** [MS-OXCPRPT] §2.2.3.2 has a value too large for the
    /// response buffer come back as `NotEnoughMemory`, and any real body clears that bar — so a
    /// property fetch answers a long message with an error and a short one with text, which is the
    /// most misleading pair of behaviours a body reader could have.
    ///
    /// [MS-OXCMSG] §2.2.1.56.1
    pub const BODY: Self = Self(0x1000_001F);
    /// `PidTagHtml`, `0x10130102` — the message's body as HTML.
    ///
    /// `PtypBinary` rather than a string: the bytes carry their own character set, named by
    /// `PidTagInternetCodepage`. Streamed for the same reason as [`BODY`](Self::BODY).
    ///
    /// [MS-OXCMSG] §2.2.1.56.4
    pub const BODY_HTML: Self = Self(0x1013_0102);
    /// `PidTagBusinessTelephoneNumber`, `0x3A08001F` — a contact's work telephone number.
    ///
    /// [MS-OXOCNTC] §2.2.1.4.4
    pub const BUSINESS_TELEPHONE_NUMBER: Self = Self(0x3A08_001F);
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
    /// `PidTagCompanyName`, `0x3A16001F` — the company a contact works for.
    ///
    /// [MS-OXOCNTC] §2.2.1.6.2
    pub const COMPANY_NAME: Self = Self(0x3A16_001F);
    /// `PidTagContainerClass`, `0x3613001F` — the kind of item a folder holds.
    ///
    /// The whole of what makes a folder a calendar rather than a mailbox: there is no calendar
    /// object in MAPI, only a folder whose class is `IPF.Appointment`. See [`ContainerClass`].
    ///
    /// [MS-OXCFOLD] §2.2.2.2.2.3
    ///
    /// [`ContainerClass`]: crate::ContainerClass
    pub const CONTAINER_CLASS: Self = Self(0x3613_001F);
    /// `PidTagContentCount`, `0x36020003` — messages in a folder, excluding FAI entries.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.1.1
    pub const CONTENT_COUNT: Self = Self(0x3602_0003);
    /// `PidTagContentUnreadCount`, `0x36030003` — unread messages in a folder.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.1.2
    pub const CONTENT_UNREAD_COUNT: Self = Self(0x3603_0003);
    /// `PidTagDeleteAfterSubmit`, `0x0E01000B` — whether transport deletes submitted mail.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.2.2
    pub const DELETE_AFTER_SUBMIT: Self = Self(0x0E01_000B);
    /// `PidTagDisplayName`, `0x3001001F` — a folder's display name, or a mailbox's.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.2.5, and [MS-OXCSTOR] §2.2.2.1.2.3 for the Store object
    pub const DISPLAY_NAME: Self = Self(0x3001_001F);
    /// `PidTagDisplayTo`, `0x0E04001F` — the primary recipients, as one display string.
    ///
    /// A computed summary of the recipient table rather than the table itself, which is why it can
    /// be read as an ordinary column.
    ///
    /// [MS-OXOMSG] §2.2.1.9
    pub const DISPLAY_TO: Self = Self(0x0E04_001F);
    /// `PidTagExtendedRuleSizeLimit`, `0x0E9B0003` — bytes allowed for one extended rule.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.1
    pub const EXTENDED_RULE_SIZE_LIMIT: Self = Self(0x0E9B_0003);
    /// `PidTagFolderFlags`, `0x66A80003` — a computed bitfield describing the folder.
    ///
    /// `IPM` (1), `SEARCH` (2), `NORMAL` (4), `RULES` (8). The `SEARCH` bit is the one that
    /// matters to a listing: the To-Do and Reminders folders carry a container class like any
    /// other folder and hold nothing of their own, so a caller enumerating calendars or task
    /// folders by class alone will find search folders among them.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.1.5
    pub const FOLDER_FLAGS: Self = Self(0x66A8_0003);
    /// `PidTagFolderId`, `0x67480014` — the folder id of a row in a hierarchy table.
    ///
    /// [MS-OXCFOLD] §2.2.2.2.1.6
    pub const FOLDER_ID: Self = Self(0x6748_0014);
    /// `PidTagFolderType`, `0x36010003` — Root (0), Generic (1) or Search (2).
    ///
    /// [MS-OXCFOLD] §2.2.2.2.2.7
    pub const FOLDER_TYPE: Self = Self(0x3601_0003);
    /// `PidTagGivenName`, `0x3A06001F` — a contact's first name.
    ///
    /// [MS-OXOCNTC] §2.2.1.1.6
    pub const GIVEN_NAME: Self = Self(0x3A06_001F);
    /// `PidTagHasAttachments`, `0x0E1B000B` — whether the message has any attachment.
    ///
    /// Computed from `PidTagMessageFlags`' `mfHasAttach` bit, and worth asking for by name: a
    /// caller that opened an attachment table for every message would spend a round trip per
    /// message to be told there is nothing there.
    ///
    /// [MS-OXCMSG] §2.2.1.2
    pub const HAS_ATTACHMENTS: Self = Self(0x0E1B_000B);
    /// `PidTagIpmAppointmentEntryId`, `0x36D00102` — the Calendar folder's entry id.
    ///
    /// [MS-OXOSFLD] §2.2.3
    pub const IPM_APPOINTMENT_ENTRY_ID: Self = Self(0x36D0_0102);
    /// `PidTagIpmArchiveEntryId`, `0x35FF0102` — the Archive folder's entry id.
    ///
    /// [MS-OXOSFLD] §2.2.3
    pub const IPM_ARCHIVE_ENTRY_ID: Self = Self(0x35FF_0102);
    /// `PidTagIpmContactEntryId`, `0x36D10102` — the Contacts folder's entry id.
    ///
    /// [MS-OXOSFLD] §2.2.3
    pub const IPM_CONTACT_ENTRY_ID: Self = Self(0x36D1_0102);
    /// `PidTagIpmDraftsEntryId`, `0x36D70102` — the Drafts folder's entry id.
    ///
    /// [MS-OXOSFLD] §2.2.3
    pub const IPM_DRAFTS_ENTRY_ID: Self = Self(0x36D7_0102);
    /// `PidTagIpmJournalEntryId`, `0x36D20102` — the Journal folder's entry id.
    ///
    /// [MS-OXOSFLD] §2.2.3
    pub const IPM_JOURNAL_ENTRY_ID: Self = Self(0x36D2_0102);
    /// `PidTagIpmNoteEntryId`, `0x36D30102` — the Notes folder's entry id.
    ///
    /// [MS-OXOSFLD] §2.2.3
    pub const IPM_NOTE_ENTRY_ID: Self = Self(0x36D3_0102);
    /// `PidTagIpmTaskEntryId`, `0x36D40102` — the Tasks folder's entry id.
    ///
    /// [MS-OXOSFLD] §2.2.3
    pub const IPM_TASK_ENTRY_ID: Self = Self(0x36D4_0102);
    /// `PidTagLastModificationTime`, `0x30080040` — when the object last changed.
    ///
    /// [MS-OXCMSG] §2.2.2.2
    pub const LAST_MODIFICATION_TIME: Self = Self(0x3008_0040);
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
    /// `PidTagMessageClass`, `0x001A001F` — what kind of item this is.
    ///
    /// `IPM.Note` for mail, `IPM.Appointment` for a calendar entry, `IPM.Contact` for a contact.
    /// The message-level counterpart of `PidTagContainerClass`, and the only thing that
    /// distinguishes an appointment from an ordinary message sitting in the same folder.
    ///
    /// [MS-OXCMSG] §2.2.1.3
    pub const MESSAGE_CLASS: Self = Self(0x001A_001F);
    /// `PidTagMessageDeliveryTime`, `0x0E060040` — when the server took delivery.
    ///
    /// [MS-OXOMSG] §2.2.3.9
    pub const MESSAGE_DELIVERY_TIME: Self = Self(0x0E06_0040);
    /// `PidTagMessageFlags`, `0x0E070003` — read state, attachments and so on.
    ///
    /// [MS-OXCMSG] §2.2.1.6
    pub const MESSAGE_FLAGS: Self = Self(0x0E07_0003);
    /// `PidTagMessageSize`, `0x0E080003` — bytes one message occupies.
    ///
    /// Shares its property id with [`MESSAGE_SIZE_EXTENDED`](Self::MESSAGE_SIZE_EXTENDED), which
    /// is the same quantity in 64 bits. A tag is an id **and** a type, so the two are different
    /// tags; this one is the right question for a message and the other for a mailbox.
    ///
    /// [MS-OXCMSG] §2.2.1.7
    pub const MESSAGE_SIZE: Self = Self(0x0E08_0003);
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
    /// `PidTagNativeBody`, `0x10160003` — which body property is the original.
    ///
    /// Undefined (0), plain text (1), RTF (2), HTML (3), clear-signed (4). Everything else is
    /// converted from it on demand, so this says which one to stream if the un-converted text is
    /// what is wanted.
    ///
    /// [MS-OXCMSG] §2.2.1.56.7
    pub const NATIVE_BODY: Self = Self(0x1016_0003);
    /// `PidTagNormalizedSubject`, `0x0E1D001F` — the subject with its prefix removed.
    ///
    /// `PidTagSubject` is this and [`SUBJECT_PREFIX`](Self::SUBJECT_PREFIX) concatenated, which is
    /// why `RopOpenMessage` answers with the two halves rather than the whole.
    ///
    /// [MS-OXCMSG] §2.2.1.10
    pub const NORMALIZED_SUBJECT: Self = Self(0x0E1D_001F);
    /// `PidTagOutOfOfficeState`, `0x661D000B` — whether the user is out of office.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.2.4
    pub const OUT_OF_OFFICE_STATE: Self = Self(0x661D_000B);
    /// `PidTagParentFolderId`, `0x67490014` — the folder id of a row's parent.
    ///
    /// The column that turns a `Depth` hierarchy read into a tree: with `Depth` set the table
    /// lists every folder below the one asked about, at every level, and nothing else in the row
    /// says where each sits.
    ///
    /// [MS-OXPROPS] §2.861
    pub const PARENT_FOLDER_ID: Self = Self(0x6749_0014);
    /// `PidTagProhibitReceiveQuota`, `0x666A0003` — kilobytes before delivery stops.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.3
    pub const PROHIBIT_RECEIVE_QUOTA: Self = Self(0x666A_0003);
    /// `PidTagProhibitSendQuota`, `0x666E0003` — kilobytes before sending stops.
    ///
    /// [MS-OXCSTOR] §2.2.2.1.1.4
    pub const PROHIBIT_SEND_QUOTA: Self = Self(0x666E_0003);
    /// `PidTagRemindersOnlineEntryId`, `0x36D50102` — the Reminders folder's entry id.
    ///
    /// [MS-OXOSFLD] §2.2.3
    pub const REMINDERS_ONLINE_ENTRY_ID: Self = Self(0x36D5_0102);
    /// `PidTagSenderEmailAddress`, `0x0C1F001F` — the sender's address, in its own address type.
    ///
    /// [MS-OXOMSG] §2.2.1.48
    pub const SENDER_EMAIL_ADDRESS: Self = Self(0x0C1F_001F);
    /// `PidTagSenderName`, `0x0C1A001F` — the sender's display name.
    ///
    /// [MS-OXOMSG] §2.2.1.51
    pub const SENDER_NAME: Self = Self(0x0C1A_001F);
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
    /// `PidTagSubjectPrefix`, `0x003D001F` — the `RE:`/`FW:` part of a subject.
    ///
    /// [MS-OXCMSG] §2.2.1.9
    pub const SUBJECT_PREFIX: Self = Self(0x003D_001F);
    /// `PidTagSurname`, `0x3A11001F` — a contact's family name.
    ///
    /// [MS-OXOCNTC] §2.2.1.1.10
    pub const SURNAME: Self = Self(0x3A11_001F);
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

    /// The same property, carried as a different type.
    ///
    /// What `RopOpenStream` needs when a body has to be read as bytes rather than as text: the
    /// property is the same one, and only the reading changes.
    #[must_use]
    pub const fn with_type(self, property_type: PropertyType) -> Self {
        Self::from_parts(self.id(), property_type)
    }

    /// Whether this id was allocated for a named property rather than fixed by a specification.
    ///
    /// Ids from `0x8000` upwards are handed out by each store as it first needs them, so the same
    /// id means a different property in a different mailbox. Nothing here resolves them; this is
    /// what lets a diagnostic say "this number is only meaningful in the store it came from"
    /// rather than printing it as though it were a constant.
    ///
    /// [MS-OXCDATA] §2.4.2 — `ecUnexpectedId`
    #[must_use]
    pub const fn is_named(self) -> bool {
        self.id() >= 0x8000
    }

    /// The canonical `PidTagXxx` name, if this is a tag the crate knows.
    ///
    /// The table itself lives in this module's `names` submodule, so that adding a property is one
    /// constant here and one line there rather than a file that outgrows the length limit.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        names::name(self)
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

#[cfg(test)]
mod tests;
