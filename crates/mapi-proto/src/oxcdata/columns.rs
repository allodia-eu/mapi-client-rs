//! The sets of tags this crate asks for, one per question a caller can ask.
//!
//! Split out of [`tag`](super::tag) because that module is the *type* and these are the
//! vocabulary — and because a set is where a decision lives. `HIERARCHY_COLUMNS` carries
//! `PidTagParentFolderId` not for tidiness but because without it a recursive read is a flat bag;
//! `FOLDER_PROPERTIES` carries `PidTagFolderType` because a search folder answers every other
//! property exactly as a real folder does.

use crate::oxcdata::PropertyTag;

/// The columns a hierarchy table is read with here.
///
/// `PidTagParentFolderId` and `PidTagContainerClass` are what make a listing useful rather than
/// merely present: with the `Depth` flag set a hierarchy table lists every folder below the one
/// asked about and says nothing about where each sits, so without the parent id the answer is a
/// flat bag; and the class is the only thing that distinguishes a calendar from a mail folder.
pub const HIERARCHY_COLUMNS: [PropertyTag; 6] = [
    PropertyTag::FOLDER_ID,
    PropertyTag::PARENT_FOLDER_ID,
    PropertyTag::DISPLAY_NAME,
    PropertyTag::CONTAINER_CLASS,
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

/// The columns an attachment table is read with here.
///
/// `PidTagAttachMethod` is the one that cannot be left out. An attachment whose method is
/// `afEmbeddedMessage` has no `PidTagAttachDataBinary` at all — its payload is another Message
/// object reached with `RopOpenEmbeddedMessage` — so a listing without the method reports a
/// forwarded mail as an empty attachment, which is a wrong answer that looks like a right one.
///
/// [MS-OXCMSG] §2.2.2.9 — `PidTagAttachMethod`
pub const ATTACHMENT_COLUMNS: [PropertyTag; 5] = [
    PropertyTag::ATTACH_NUMBER,
    PropertyTag::ATTACH_METHOD,
    PropertyTag::ATTACH_LONG_FILENAME,
    PropertyTag::ATTACH_SIZE,
    PropertyTag::ATTACH_MIME_TAG,
];

/// The Folder object properties that answer "tell me about this folder".
///
/// This is *"get calendar details"* and *"get folder details"*: a calendar is a folder, so the two
/// are one question. `PidTagFolderType` and `PidTagFolderFlags` are in the set because a search
/// folder answers every other property exactly as a real folder does — the To-Do list reports a
/// container class of `IPF.Task` and a message count, and holds none of them.
///
/// [MS-OXCFOLD] §2.2.2.2 — Folder object properties
pub const FOLDER_PROPERTIES: [PropertyTag; 9] = [
    PropertyTag::DISPLAY_NAME,
    PropertyTag::CONTAINER_CLASS,
    PropertyTag::PARENT_FOLDER_ID,
    PropertyTag::CONTENT_COUNT,
    PropertyTag::CONTENT_UNREAD_COUNT,
    PropertyTag::MESSAGE_SIZE_EXTENDED,
    PropertyTag::SUBFOLDERS,
    PropertyTag::FOLDER_TYPE,
    PropertyTag::FOLDER_FLAGS,
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

/// The Message object properties that answer "tell me about this message".
///
/// **`PidTagBody` is deliberately absent.** A real HTML body clears the response buffer's limit,
/// and a body asked for here comes back as `NotEnoughMemory` rather than as text
/// ([MS-OXCPRPT] §2.2.3.2) — so it belongs in a stream read and not in a property fetch.
/// `PidTagNativeBody` is in the set instead, because it says which body property is the original
/// and therefore which one is worth streaming.
///
/// [MS-OXCMSG] §2.2.1 — Message object properties
pub const MESSAGE_PROPERTIES: [PropertyTag; 11] = [
    PropertyTag::MESSAGE_CLASS,
    PropertyTag::SUBJECT,
    PropertyTag::SENDER_NAME,
    PropertyTag::SENDER_EMAIL_ADDRESS,
    PropertyTag::DISPLAY_TO,
    PropertyTag::MESSAGE_DELIVERY_TIME,
    PropertyTag::LAST_MODIFICATION_TIME,
    PropertyTag::MESSAGE_SIZE,
    PropertyTag::MESSAGE_FLAGS,
    PropertyTag::HAS_ATTACHMENTS,
    PropertyTag::NATIVE_BODY,
];

/// The Attachment object properties that answer "what is this attachment".
///
/// `PidTagAttachDataBinary` is not among them for the same reason `PidTagBody` is not in
/// [`MESSAGE_PROPERTIES`]: the bytes are what a stream read is for, and an attachment of any size
/// asked for here comes back as an error instead of as content.
///
/// [MS-OXCMSG] §2.2.2 — Attachment object properties
pub const ATTACHMENT_PROPERTIES: [PropertyTag; 6] = [
    PropertyTag::ATTACH_NUMBER,
    PropertyTag::ATTACH_METHOD,
    PropertyTag::ATTACH_LONG_FILENAME,
    PropertyTag::ATTACH_FILENAME,
    PropertyTag::ATTACH_SIZE,
    PropertyTag::ATTACH_MIME_TAG,
];

/// The contact columns that have a fixed property id.
///
/// Half of *"list contacts"* and no more: an email address is a **named** property with no id of
/// its own, so a listing wanting one has to resolve
/// [`CONTACT_PROPERTIES`](crate::CONTACT_PROPERTIES) against the store and append the tags that
/// come back. These are the columns that need no round trip first.
///
/// [MS-OXOCNTC] §2.2.1 — Contact object properties
pub const CONTACT_COLUMNS: [PropertyTag; 6] = [
    PropertyTag::MID,
    PropertyTag::DISPLAY_NAME,
    PropertyTag::GIVEN_NAME,
    PropertyTag::SURNAME,
    PropertyTag::COMPANY_NAME,
    PropertyTag::BUSINESS_TELEPHONE_NUMBER,
];

/// The appointment columns that have a fixed property id.
///
/// As [`CONTACT_COLUMNS`]: start, end, location and busy status are named properties, so this is
/// what a calendar listing can ask for before it has resolved anything.
///
/// [MS-OXOCAL] §2.2.1 — Appointment object properties
pub const APPOINTMENT_COLUMNS: [PropertyTag; 3] = [
    PropertyTag::MID,
    PropertyTag::SUBJECT,
    PropertyTag::MESSAGE_CLASS,
];

/// What a message says about its own state: read or not, sent or not, flagged or not.
///
/// The three questions "flag a message" can mean, together in one fetch because a client that asks
/// only one of them gives a confidently wrong answer to the others.
/// [`PidTagMessageFlags`](PropertyTag::MESSAGE_FLAGS) carries the read bit,
/// [`PidTagFlagStatus`](PropertyTag::FLAG_STATUS) the follow-up flag, and
/// [`PidTagClientSubmitTime`](PropertyTag::CLIENT_SUBMIT_TIME) says whether it was ever submitted.
///
/// **Expect most of these to come back absent.** [MS-OXOFLAG] §2.2.1.1 has the flag properties
/// exist only on a flagged message, so a fetch of an ordinary one answers with nothing for four of
/// the six — which is the answer, not a failure.
///
/// [MS-OXOFLAG] §2.2.1 — the flagging properties
/// [MS-OXCMSG] §2.2.1.6 — `PidTagMessageFlags`
pub const STATE_PROPERTIES: [PropertyTag; 6] = [
    PropertyTag::MESSAGE_FLAGS,
    PropertyTag::FLAG_STATUS,
    PropertyTag::FOLLOWUP_ICON,
    PropertyTag::FLAG_COMPLETE_TIME,
    PropertyTag::TODO_ITEM_FLAGS,
    PropertyTag::CLIENT_SUBMIT_TIME,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// A recursive hierarchy read has to carry the parent id, or its rows are a flat bag with no
    /// way back to a tree — which is the one thing the `Depth` flag makes it easy to get wrong.
    #[test]
    fn the_hierarchy_columns_can_rebuild_a_tree() {
        assert!(HIERARCHY_COLUMNS.contains(&PropertyTag::FOLDER_ID));
        assert!(HIERARCHY_COLUMNS.contains(&PropertyTag::PARENT_FOLDER_ID));
        assert!(HIERARCHY_COLUMNS.contains(&PropertyTag::CONTAINER_CLASS));
    }

    /// Without the method, an `afEmbeddedMessage` attachment is indistinguishable from an empty
    /// one — the failure this column set exists to prevent.
    #[test]
    fn the_attachment_columns_say_how_each_attachment_is_reached() {
        assert!(ATTACHMENT_COLUMNS.contains(&PropertyTag::ATTACH_METHOD));
        assert!(ATTACHMENT_COLUMNS.contains(&PropertyTag::ATTACH_NUMBER));
        assert!(ATTACHMENT_PROPERTIES.contains(&PropertyTag::ATTACH_METHOD));
    }

    /// A body or an attachment's bytes read through a property fetch come back as an error rather
    /// than as content, so neither set may name one.
    #[test]
    fn no_set_asks_for_a_value_that_has_to_be_streamed() {
        for streamed in [
            PropertyTag::BODY,
            PropertyTag::BODY_HTML,
            PropertyTag::ATTACH_DATA_BINARY,
        ] {
            assert!(!MESSAGE_PROPERTIES.contains(&streamed), "{streamed}");
            assert!(!ATTACHMENT_PROPERTIES.contains(&streamed), "{streamed}");
            assert!(!CONTENTS_COLUMNS.contains(&streamed), "{streamed}");
            assert!(!ATTACHMENT_COLUMNS.contains(&streamed), "{streamed}");
        }
    }

    /// Every set is asked for by tag, and a repeated tag would ask the same question twice and
    /// widen the answer for nothing.
    #[test]
    fn no_set_names_the_same_tag_twice() {
        let sets: [&[PropertyTag]; 10] = [
            &HIERARCHY_COLUMNS,
            &CONTENTS_COLUMNS,
            &ATTACHMENT_COLUMNS,
            &FOLDER_PROPERTIES,
            &MAILBOX_PROPERTIES,
            &MESSAGE_PROPERTIES,
            &ATTACHMENT_PROPERTIES,
            &CONTACT_COLUMNS,
            &APPOINTMENT_COLUMNS,
            &STATE_PROPERTIES,
        ];
        for set in sets {
            let mut unique = set.to_vec();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), set.len(), "{set:?}");
        }
    }
}
