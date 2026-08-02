//! The folders a logon does not name.
//!
//! `RopLogon` returns thirteen folder ids and none of them is Calendar, Contacts, Drafts, Tasks,
//! Notes or Journal — [MS-OXCSTOR] §2.2.1.1.3. Those live behind a binary property on the Inbox
//! holding a 46-byte [`FolderEntryId`](crate::FolderEntryId), which has to be converted to a
//! folder id with `RopIdFromLongTermId` before `RopOpenFolder` will take it.
//!
//! **The property is read from the Inbox for the mailbox's owner and from the Root folder for a
//! delegate** ([MS-OXOSFLD] §2.2.3). This crate logs on as the mailbox owner, so it reads the
//! Inbox; a delegate scenario is not implemented and would need the other object.
//!
//! Not every special folder is reached this way. The Junk E-mail, Conflicts, Sync Issues, Local
//! Failures and Server Failures folders are indexed entries inside `PidTagAdditionalRenEntryIds`
//! ([MS-OXOSFLD] §2.2.4), which is a different mechanism and is not modelled here; a recursive
//! hierarchy walk still finds them, by name and by container class.
//!
//! **And not every one of them is inside the user-visible tree.** [MS-OXOSFLD] §3.1.1.1 puts
//! Reminders directly under the Root folder, a sibling of Top of Personal Folders rather than a
//! child of it — confirmed on Exchange Server SE `15.02.2562.045`, where a recursive walk of the
//! IPM subtree does not contain the folder this resolves Reminders to. A client that looked for
//! special folders by walking the tree Outlook shows would not find it at all, which is the second
//! reason this chain exists rather than a name search.
//!
//! [MS-OXOSFLD] §2.2.2 — where the identifier of a special folder comes from
//! [MS-OXOSFLD] §2.2.3 — the binary identification properties

use crate::oxcdata::{ContainerClass, PropertyTag};

/// How many folders are named by a property of their own.
const SPECIAL_COUNT: usize = 8;

/// A folder located through one of [MS-OXOSFLD] §2.2.3's binary identification properties.
///
/// [MS-OXOSFLD] §2.2.3 — one property per folder, each holding a single entry id
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SpecialFolder {
    /// The Archive folder, named by `PidTagIpmArchiveEntryId`.
    ///
    /// The one of the eight both lab mailboxes lack: Exchange creates it when an archive mailbox
    /// or a retention policy first needs it, so an ordinary mailbox carries no such property.
    Archive,
    /// The Calendar, named by `PidTagIpmAppointmentEntryId`.
    Calendar,
    /// Contacts, named by `PidTagIpmContactEntryId`.
    Contacts,
    /// Drafts, named by `PidTagIpmDraftsEntryId`.
    Drafts,
    /// Journal, named by `PidTagIpmJournalEntryId`.
    Journal,
    /// Notes, named by `PidTagIpmNoteEntryId`.
    Notes,
    /// The Reminders search folder, named by `PidTagRemindersOnlineEntryId`.
    Reminders,
    /// Tasks, named by `PidTagIpmTaskEntryId`.
    Tasks,
}

impl SpecialFolder {
    /// Every folder [MS-OXOSFLD] §2.2.3 gives a property of its own, in tag order.
    pub const ALL: [Self; SPECIAL_COUNT] = [
        Self::Archive,
        Self::Calendar,
        Self::Contacts,
        Self::Journal,
        Self::Notes,
        Self::Tasks,
        Self::Reminders,
        Self::Drafts,
    ];

    /// The property on the Inbox that holds this folder's entry id.
    #[must_use]
    pub const fn tag(self) -> PropertyTag {
        match self {
            Self::Archive => PropertyTag::IPM_ARCHIVE_ENTRY_ID,
            Self::Calendar => PropertyTag::IPM_APPOINTMENT_ENTRY_ID,
            Self::Contacts => PropertyTag::IPM_CONTACT_ENTRY_ID,
            Self::Drafts => PropertyTag::IPM_DRAFTS_ENTRY_ID,
            Self::Journal => PropertyTag::IPM_JOURNAL_ENTRY_ID,
            Self::Notes => PropertyTag::IPM_NOTE_ENTRY_ID,
            Self::Reminders => PropertyTag::REMINDERS_ONLINE_ENTRY_ID,
            Self::Tasks => PropertyTag::IPM_TASK_ENTRY_ID,
        }
    }

    /// The container class [MS-OXOSFLD] §2.2.1 says this folder carries.
    ///
    /// Documentation rather than identification: several folders share a class — Drafts and the
    /// Inbox are both `IPF.Note` — so this narrows a hierarchy listing and never settles it. The
    /// entry-id property is what identifies the folder.
    #[must_use]
    pub const fn container_class(self) -> ContainerClass {
        match self {
            Self::Archive | Self::Drafts => ContainerClass::Note,
            Self::Calendar => ContainerClass::Appointment,
            Self::Contacts => ContainerClass::Contact,
            Self::Journal => ContainerClass::Journal,
            Self::Notes => ContainerClass::StickyNote,
            Self::Reminders => ContainerClass::Reminder,
            Self::Tasks => ContainerClass::Task,
        }
    }

    /// The name [MS-OXOSFLD] §2.2.1 gives this folder.
    ///
    /// The specification's name, in English, and **not what the folder is called in a mailbox**:
    /// display names are localised to the language the mailbox was provisioned with, so a Dutch
    /// mailbox's Calendar is called `Agenda`. Addressing a folder by this string would work
    /// against one mailbox and fail against another, which is exactly why the entry-id chain
    /// exists.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Archive => "Archive",
            Self::Calendar => "Calendar",
            Self::Contacts => "Contacts",
            Self::Drafts => "Drafts",
            Self::Journal => "Journal",
            Self::Notes => "Notes",
            Self::Reminders => "Reminders",
            Self::Tasks => "Tasks",
        }
    }
}

impl core::fmt::Display for SpecialFolder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// The tags naming every special folder, in the order [`SpecialFolder::ALL`] lists them.
///
/// One `RopGetPropertiesSpecific` on the Inbox asks for all eight, which is why finding every
/// special folder in a mailbox costs two round trips rather than sixteen.
pub const SPECIAL_FOLDER_PROPERTIES: [PropertyTag; SPECIAL_COUNT] = [
    PropertyTag::IPM_ARCHIVE_ENTRY_ID,
    PropertyTag::IPM_APPOINTMENT_ENTRY_ID,
    PropertyTag::IPM_CONTACT_ENTRY_ID,
    PropertyTag::IPM_JOURNAL_ENTRY_ID,
    PropertyTag::IPM_NOTE_ENTRY_ID,
    PropertyTag::IPM_TASK_ENTRY_ID,
    PropertyTag::REMINDERS_ONLINE_ENTRY_ID,
    PropertyTag::IPM_DRAFTS_ENTRY_ID,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Each property id transcribed from [MS-OXPROPS] rather than from `tag()`, so a transposed
    /// digit is not confirmed by the code that would use it.
    #[test]
    fn each_folder_names_the_property_that_holds_its_entry_id() {
        for (folder, raw, name) in [
            (SpecialFolder::Archive, 0x35FF_0102_u32, "Archive"),
            (SpecialFolder::Calendar, 0x36D0_0102, "Calendar"),
            (SpecialFolder::Contacts, 0x36D1_0102, "Contacts"),
            (SpecialFolder::Journal, 0x36D2_0102, "Journal"),
            (SpecialFolder::Notes, 0x36D3_0102, "Notes"),
            (SpecialFolder::Tasks, 0x36D4_0102, "Tasks"),
            (SpecialFolder::Reminders, 0x36D5_0102, "Reminders"),
            (SpecialFolder::Drafts, 0x36D7_0102, "Drafts"),
        ] {
            assert_eq!(folder.tag(), PropertyTag::new(raw), "{name}");
            assert_eq!(folder.name(), name);
            assert_eq!(folder.to_string(), name);
            // Every one of them is binary, which is what makes the entry-id chain possible at all.
            assert_eq!(folder.tag().property_type(), crate::PropertyType::Binary);
        }
    }

    /// The fetch and the enum have to stay in step: a mismatch would pair each answer with the
    /// wrong folder, which is a wrong result rather than an error.
    #[test]
    fn the_property_set_is_the_enums_own_order() {
        assert_eq!(
            SpecialFolder::ALL.map(SpecialFolder::tag),
            SPECIAL_FOLDER_PROPERTIES
        );

        let mut tags = SPECIAL_FOLDER_PROPERTIES.to_vec();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), SPECIAL_COUNT, "two folders share a property");
    }

    /// The classes [MS-OXOSFLD] §2.2.1 gives, including the two that share `IPF.Note` — which is
    /// why the class narrows a search and never settles it.
    #[test]
    fn each_folder_carries_the_class_the_table_gives_it() {
        for (folder, class) in [
            (SpecialFolder::Calendar, ContainerClass::Appointment),
            (SpecialFolder::Contacts, ContainerClass::Contact),
            (SpecialFolder::Journal, ContainerClass::Journal),
            (SpecialFolder::Notes, ContainerClass::StickyNote),
            (SpecialFolder::Tasks, ContainerClass::Task),
            (SpecialFolder::Reminders, ContainerClass::Reminder),
            (SpecialFolder::Drafts, ContainerClass::Note),
            (SpecialFolder::Archive, ContainerClass::Note),
        ] {
            assert_eq!(folder.container_class(), class, "{folder}");
        }
    }
}
