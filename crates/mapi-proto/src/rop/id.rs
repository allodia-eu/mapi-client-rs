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
    /// `RopCommitStream`, `0x5D` — pushes what has been written into the property itself.
    ///
    /// [MS-OXCROPS] §2.2.9.5
    pub const COMMIT_STREAM: Self = Self(0x5D);
    /// `RopCreateAttachment`, `0x23` — adds an attachment to an open message.
    ///
    /// Its response carries the `PidTagAttachNumber` the new attachment was given, which is the
    /// only way to name it afterwards.
    ///
    /// [MS-OXCROPS] §2.2.6.13
    pub const CREATE_ATTACHMENT: Self = Self(0x23);
    /// `RopCreateMessage`, `0x06` — creates a Message object in a folder.
    ///
    /// **Nothing is committed until `RopSaveChangesMessage`**, so a batch that creates a message
    /// and stops leaves nothing behind.
    ///
    /// [MS-OXCROPS] §2.2.6.2
    pub const CREATE_MESSAGE: Self = Self(0x06);
    /// `RopDeleteMessages`, `0x1E` — deletes messages from a folder by id.
    ///
    /// [MS-OXCROPS] §2.2.4.11
    pub const DELETE_MESSAGES: Self = Self(0x1E);
    /// `RopDeleteProperties`, `0x0B` — removes properties from an object.
    ///
    /// [MS-OXCROPS] §2.2.8.8
    pub const DELETE_PROPERTIES: Self = Self(0x0B);
    /// `RopGetAttachmentTable`, `0x21` — the attachments on a message.
    ///
    /// Its response carries **no row count**, unlike the folder tables, so how many attachments
    /// there are is only known once rows have been read.
    ///
    /// [MS-OXCROPS] §2.2.6.17
    pub const GET_ATTACHMENT_TABLE: Self = Self(0x21);
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
    /// `RopGetStreamSize`, `0x5E` — how many bytes the stream holds now.
    ///
    /// [MS-OXCROPS] §2.2.9.6
    pub const GET_STREAM_SIZE: Self = Self(0x5E);
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
    /// `RopModifyRecipients`, `0x0E` — adds or changes the recipients of an open message.
    ///
    /// [MS-OXCROPS] §2.2.6.5
    pub const MODIFY_RECIPIENTS: Self = Self(0x0E);
    /// `RopMoveCopyMessages`, `0x33` — moves or copies messages between two folders.
    ///
    /// **Three response shapes, not two.** Besides success and an ordinary refusal there is the
    /// null-destination failure of [MS-OXCROPS] §2.2.4.6.3, whose body continues past
    /// `ReturnValue`.
    ///
    /// [MS-OXCROPS] §2.2.4.6
    pub const MOVE_COPY_MESSAGES: Self = Self(0x33);
    /// `RopOpenAttachment`, `0x22` — opens one attachment by its `PidTagAttachNumber`.
    ///
    /// [MS-OXCROPS] §2.2.6.12
    pub const OPEN_ATTACHMENT: Self = Self(0x22);
    /// `RopOpenEmbeddedMessage`, `0x46` — opens an attachment as the message it holds.
    ///
    /// The only way to reach an attachment whose `PidTagAttachMethod` is `afEmbeddedMessage`:
    /// such an attachment has no `PidTagAttachDataBinary` at all.
    ///
    /// [MS-OXCROPS] §2.2.6.16
    pub const OPEN_EMBEDDED_MESSAGE: Self = Self(0x46);
    /// `RopOpenFolder`, `0x02`.
    ///
    /// [MS-OXCROPS] §2.2.4.1
    pub const OPEN_FOLDER: Self = Self(0x02);
    /// `RopOpenMessage`, `0x03` — opens a message in a folder.
    ///
    /// [MS-OXCROPS] §2.2.6.1
    pub const OPEN_MESSAGE: Self = Self(0x03);
    /// `RopOpenStream`, `0x2B` — opens one property for streaming access.
    ///
    /// [MS-OXCROPS] §2.2.9.1
    pub const OPEN_STREAM: Self = Self(0x2B);
    /// `RopProgress`, `0x50` — how far an asynchronous operation has got.
    ///
    /// Nothing in this crate asks for one; every ROP that could is sent with
    /// `WantAsynchronous = 0`. Recognised so that a server which answers one anyway is reported
    /// rather than left to desynchronise the rest of the buffer.
    ///
    /// [MS-OXCROPS] §2.2.8.13
    pub const PROGRESS: Self = Self(0x50);
    /// `RopQueryRows`, `0x15`.
    ///
    /// [MS-OXCROPS] §2.2.5.4
    pub const QUERY_ROWS: Self = Self(0x15);
    /// `RopReadStream`, `0x2C` — reads bytes from an open stream.
    ///
    /// [MS-OXCROPS] §2.2.9.2
    pub const READ_STREAM: Self = Self(0x2C);
    /// `RopRelease`, `0x01` — releases a Server object handle.
    ///
    /// [MS-OXCROPS] §2.2.15.3
    pub const RELEASE: Self = Self(0x01);
    /// `RopRemoveAllRecipients`, `0x0D` — takes every recipient off a message.
    ///
    /// The counterpart `RopModifyRecipients` does not have: that ROP adds and modifies rows by
    /// `RowId` and can never shorten a list, so this is the only way to clear one.
    ///
    /// [MS-OXCROPS] §2.2.6.4
    pub const REMOVE_ALL_RECIPIENTS: Self = Self(0x0D);
    /// `RopRestrict`, `0x14` — establishes a filter for a table.
    ///
    /// [MS-OXCROPS] §2.2.5.3
    pub const RESTRICT: Self = Self(0x14);
    /// `RopSaveChangesAttachment`, `0x25` — commits an attachment's changes.
    ///
    /// **Before the message's own save, never after.** An attachment saved after its message is
    /// lost without anything failing.
    ///
    /// [MS-OXCROPS] §2.2.6.15
    pub const SAVE_CHANGES_ATTACHMENT: Self = Self(0x25);
    /// `RopSaveChangesMessage`, `0x0C` — commits a message's changes and reports its id.
    ///
    /// [MS-OXCROPS] §2.2.6.3
    pub const SAVE_CHANGES_MESSAGE: Self = Self(0x0C);
    /// `RopSetColumns`, `0x12` — the column set every later row is encoded against.
    ///
    /// [MS-OXCROPS] §2.2.5.1
    pub const SET_COLUMNS: Self = Self(0x12);
    /// `RopSetProperties`, `0x0A` — writes property values to an object.
    ///
    /// [MS-OXCROPS] §2.2.8.6
    pub const SET_PROPERTIES: Self = Self(0x0A);
    /// `RopSetReadFlags`, `0x66` — changes the read state of messages in a folder.
    ///
    /// Addressed at a Folder object and a list of ids, not at an open message. It also sends the
    /// read receipt the sender asked for, which is why the request carries flags rather than a
    /// boolean.
    ///
    /// [MS-OXCROPS] §2.2.6.10
    pub const SET_READ_FLAGS: Self = Self(0x66);
    /// `RopSortTable`, `0x13` — orders a table's rows by a sort key.
    ///
    /// [MS-OXCROPS] §2.2.5.2
    pub const SORT_TABLE: Self = Self(0x13);
    /// `RopSubmitMessage`, `0x32` — hands a message to the transport.
    ///
    /// **It sends real mail.** There is no dry run, and [MS-OXOMSG] §2.2.4.2's `RopAbortSubmit`
    /// only helps while the message is still queued.
    ///
    /// [MS-OXCROPS] §2.2.7.1
    pub const SUBMIT_MESSAGE: Self = Self(0x32);
    /// `RopWriteStream`, `0x2D` — writes bytes at the stream's cursor.
    ///
    /// [MS-OXCROPS] §2.2.9.3
    pub const WRITE_STREAM: Self = Self(0x2D);

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
            Self::OPEN_MESSAGE => "RopOpenMessage",
            Self::CREATE_MESSAGE => "RopCreateMessage",
            Self::SAVE_CHANGES_MESSAGE => "RopSaveChangesMessage",
            Self::MODIFY_RECIPIENTS => "RopModifyRecipients",
            Self::REMOVE_ALL_RECIPIENTS => "RopRemoveAllRecipients",
            Self::SUBMIT_MESSAGE => "RopSubmitMessage",
            Self::MOVE_COPY_MESSAGES => "RopMoveCopyMessages",
            Self::SET_READ_FLAGS => "RopSetReadFlags",
            Self::PROGRESS => "RopProgress",
            Self::CREATE_ATTACHMENT => "RopCreateAttachment",
            Self::SAVE_CHANGES_ATTACHMENT => "RopSaveChangesAttachment",
            Self::DELETE_MESSAGES => "RopDeleteMessages",
            Self::WRITE_STREAM => "RopWriteStream",
            Self::COMMIT_STREAM => "RopCommitStream",
            Self::GET_HIERARCHY_TABLE => "RopGetHierarchyTable",
            Self::GET_CONTENTS_TABLE => "RopGetContentsTable",
            Self::SORT_TABLE => "RopSortTable",
            Self::RESTRICT => "RopRestrict",
            Self::GET_ATTACHMENT_TABLE => "RopGetAttachmentTable",
            Self::OPEN_ATTACHMENT => "RopOpenAttachment",
            Self::OPEN_EMBEDDED_MESSAGE => "RopOpenEmbeddedMessage",
            Self::OPEN_STREAM => "RopOpenStream",
            Self::READ_STREAM => "RopReadStream",
            Self::GET_STREAM_SIZE => "RopGetStreamSize",
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
            (RopId::OPEN_MESSAGE, 0x03, "RopOpenMessage"),
            (RopId::CREATE_MESSAGE, 0x06, "RopCreateMessage"),
            (RopId::SAVE_CHANGES_MESSAGE, 0x0C, "RopSaveChangesMessage"),
            (RopId::MODIFY_RECIPIENTS, 0x0E, "RopModifyRecipients"),
            (RopId::REMOVE_ALL_RECIPIENTS, 0x0D, "RopRemoveAllRecipients"),
            (RopId::SUBMIT_MESSAGE, 0x32, "RopSubmitMessage"),
            (RopId::MOVE_COPY_MESSAGES, 0x33, "RopMoveCopyMessages"),
            (RopId::SET_READ_FLAGS, 0x66, "RopSetReadFlags"),
            (RopId::PROGRESS, 0x50, "RopProgress"),
            (RopId::DELETE_MESSAGES, 0x1E, "RopDeleteMessages"),
            (RopId::CREATE_ATTACHMENT, 0x23, "RopCreateAttachment"),
            (
                RopId::SAVE_CHANGES_ATTACHMENT,
                0x25,
                "RopSaveChangesAttachment",
            ),
            (RopId::WRITE_STREAM, 0x2D, "RopWriteStream"),
            (RopId::COMMIT_STREAM, 0x5D, "RopCommitStream"),
            (RopId::GET_HIERARCHY_TABLE, 0x04, "RopGetHierarchyTable"),
            (RopId::GET_CONTENTS_TABLE, 0x05, "RopGetContentsTable"),
            (RopId::SORT_TABLE, 0x13, "RopSortTable"),
            (RopId::RESTRICT, 0x14, "RopRestrict"),
            (RopId::GET_ATTACHMENT_TABLE, 0x21, "RopGetAttachmentTable"),
            (RopId::OPEN_ATTACHMENT, 0x22, "RopOpenAttachment"),
            (RopId::OPEN_STREAM, 0x2B, "RopOpenStream"),
            (RopId::READ_STREAM, 0x2C, "RopReadStream"),
            (RopId::OPEN_EMBEDDED_MESSAGE, 0x46, "RopOpenEmbeddedMessage"),
            (RopId::GET_STREAM_SIZE, 0x5E, "RopGetStreamSize"),
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
