//! What kind of item a folder holds — the value of `PidTagContainerClass`.
//!
//! There is no such thing as a calendar object in MAPI. A calendar *is* a folder whose container
//! class is `IPF.Appointment`, and a contacts folder one whose class is `IPF.Contact`, so this
//! string is the whole of what distinguishes them. Everything the eighteen requested operations
//! call "list calendars" or "list contact folders" is a query over this property.
//!
//! [MS-OXCFOLD] §2.2.2.2.2.3 — `PidTagContainerClass`
//! [MS-OXOSFLD] §2.2.1 — the class each special folder carries

/// The class of message a folder is meant to hold.
///
/// An open set: [MS-OXOSFLD] §2.2.1 names eleven and any deployment may invent more, so an
/// unrecognised value is carried through rather than discarded. Comparison is exact and
/// case-sensitive, which is what the property is.
///
/// **[MS-OXCFOLD] §2.2.2.2.2.3 says the value "MUST begin with `IPF.`" and both the specification
/// and a real server break that rule.** [MS-OXOSFLD] §2.2.1's own table gives the Reminders search
/// folder `Outlook.Reminder`, and a freshly provisioned mailbox on Exchange Server SE
/// `15.02.2562.045` carries a folder whose class is the bare string `IPF`, with no dot and nothing
/// after it. So the prefix is not something to validate against — [`is_ipf`](Self::is_ipf) reports
/// it instead.
///
/// The same measurement found seventeen distinct classes in an empty mailbox, eight of them
/// refinements of `IPF.Contact` — which is why [`is_a`](Self::is_a) matches on the dotted prefix
/// rather than on equality.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ContainerClass {
    /// `IPF.Appointment` — a calendar.
    Appointment,
    /// `IPF.Configuration` — folder associated information holding client settings.
    Configuration,
    /// `IPF.Contact` — contacts.
    Contact,
    /// `IPF.Contact.MOC.ImContactList` — instant-messaging contact lists.
    ImContactList,
    /// `IPF.Journal` — journal entries.
    Journal,
    /// `IPF.Note` — ordinary mail. The Inbox, Drafts, Junk E-mail and the sync-issue folders all
    /// carry this one, so it says less about a folder than the others do.
    Note,
    /// `IPF.Contact.MOC.QuickContacts` — favourite and instant-messaging contacts.
    QuickContacts,
    /// `Outlook.Reminder` — the Reminders search folder, and the one documented class that does
    /// not begin with `IPF.`.
    Reminder,
    /// `IPF.Note.OutlookHomepage` — RSS feeds.
    RssFeeds,
    /// `IPF.ShortcutFolder` — document libraries.
    ShortcutFolder,
    /// `IPF.StickyNote` — notes.
    StickyNote,
    /// `IPF.Task` — tasks.
    Task,
    /// A class this crate does not name. Deployments add their own, and a folder carrying one is
    /// still a folder.
    Other(String),
}

impl ContainerClass {
    /// Classifies the value of a `PidTagContainerClass` property.
    #[must_use]
    pub fn new(value: &str) -> Self {
        match value {
            "IPF.Appointment" => Self::Appointment,
            "IPF.Configuration" => Self::Configuration,
            "IPF.Contact" => Self::Contact,
            "IPF.Contact.MOC.ImContactList" => Self::ImContactList,
            "IPF.Contact.MOC.QuickContacts" => Self::QuickContacts,
            "IPF.Journal" => Self::Journal,
            "IPF.Note" => Self::Note,
            "IPF.Note.OutlookHomepage" => Self::RssFeeds,
            "IPF.ShortcutFolder" => Self::ShortcutFolder,
            "IPF.StickyNote" => Self::StickyNote,
            "IPF.Task" => Self::Task,
            "Outlook.Reminder" => Self::Reminder,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The string the property holds.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Appointment => "IPF.Appointment",
            Self::Configuration => "IPF.Configuration",
            Self::Contact => "IPF.Contact",
            Self::ImContactList => "IPF.Contact.MOC.ImContactList",
            Self::QuickContacts => "IPF.Contact.MOC.QuickContacts",
            Self::Journal => "IPF.Journal",
            Self::Note => "IPF.Note",
            Self::RssFeeds => "IPF.Note.OutlookHomepage",
            Self::ShortcutFolder => "IPF.ShortcutFolder",
            Self::StickyNote => "IPF.StickyNote",
            Self::Task => "IPF.Task",
            Self::Reminder => "Outlook.Reminder",
            Self::Other(value) => value,
        }
    }

    /// Whether the class follows [MS-OXCFOLD]'s `IPF.` convention.
    ///
    /// [`Reminder`](Self::Reminder) does not, which is why this is a question rather than an
    /// invariant.
    #[must_use]
    pub fn is_ipf(&self) -> bool {
        self.as_str().starts_with("IPF.")
    }

    /// Whether a folder of this class holds items of `wanted`'s kind.
    ///
    /// Classes nest: `IPF.Contact.MOC.QuickContacts` is a contacts folder, and Outlook shows it as
    /// one. Matching on equality alone would report a mailbox as having one contacts folder when
    /// it has three, so the comparison is on the dotted prefix — `IPF.Contact` matches
    /// `IPF.Contact.MOC.QuickContacts`, and does **not** match a hypothetical `IPF.Contacts`.
    #[must_use]
    pub fn is_a(&self, wanted: &Self) -> bool {
        let (mine, theirs) = (self.as_str(), wanted.as_str());
        mine == theirs
            || mine
                .strip_prefix(theirs)
                .is_some_and(|rest| rest.starts_with('.'))
    }
}

impl core::fmt::Display for ContainerClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for ContainerClass {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every class [MS-OXOSFLD] §2.2.1's table names, transcribed from the document rather than
    /// from `new`, so that a typo in one is not confirmed by the other.
    const DOCUMENTED: [(&str, ContainerClass); 12] = [
        ("IPF.Appointment", ContainerClass::Appointment),
        ("IPF.Configuration", ContainerClass::Configuration),
        ("IPF.Contact", ContainerClass::Contact),
        (
            "IPF.Contact.MOC.ImContactList",
            ContainerClass::ImContactList,
        ),
        (
            "IPF.Contact.MOC.QuickContacts",
            ContainerClass::QuickContacts,
        ),
        ("IPF.Journal", ContainerClass::Journal),
        ("IPF.Note", ContainerClass::Note),
        ("IPF.Note.OutlookHomepage", ContainerClass::RssFeeds),
        ("IPF.ShortcutFolder", ContainerClass::ShortcutFolder),
        ("IPF.StickyNote", ContainerClass::StickyNote),
        ("IPF.Task", ContainerClass::Task),
        ("Outlook.Reminder", ContainerClass::Reminder),
    ];

    #[test]
    fn each_class_carries_the_string_the_table_gives_it() {
        for (value, expected) in DOCUMENTED {
            assert_eq!(ContainerClass::new(value), expected, "{value}");
            assert_eq!(expected.as_str(), value);
            assert_eq!(expected.to_string(), value);
        }
    }

    /// Every class observed on the live lab that this crate does not name. Transcribed from the
    /// run rather than invented, because the point is that a real mailbox carries more classes
    /// than either specification lists — including `IPF`, which has no dot at all.
    #[test]
    fn a_class_this_crate_does_not_name_survives_being_read() {
        for observed in [
            "IPF",
            "IPF.Appointment.Birthday",
            "IPF.Contact.Company",
            "IPF.Contact.GalContacts",
            "IPF.Contact.OrganizationalContacts",
            "IPF.Contact.PeopleCentricConversationBuddies",
            "IPF.Contact.RecipientCache",
            "IPF.Files",
        ] {
            let class = ContainerClass::new(observed);
            assert_eq!(class, ContainerClass::Other(observed.to_owned()));
            assert_eq!(class.as_str(), observed);
        }

        // The bare `IPF` does not begin with `IPF.`, so it is not an IPF class by the rule as
        // written — and it is not a refinement of any other class either.
        assert!(!ContainerClass::new("IPF").is_ipf());
        assert!(!ContainerClass::new("IPF").is_a(&ContainerClass::Note));

        // The refinements a listing has to fold into their parents.
        for contacts in [
            "IPF.Contact.Company",
            "IPF.Contact.GalContacts",
            "IPF.Contact.RecipientCache",
        ] {
            assert!(
                ContainerClass::new(contacts).is_a(&ContainerClass::Contact),
                "{contacts}"
            );
        }
        assert!(ContainerClass::new("IPF.Appointment.Birthday").is_a(&ContainerClass::Appointment));

        let empty = ContainerClass::from("");
        assert_eq!(empty.as_str(), "");
        assert!(!empty.is_ipf());
    }

    /// The specification says the value MUST begin with `IPF.` and its own table then names one
    /// that does not. Both facts are recorded here so that neither is quietly dropped.
    #[test]
    fn the_reminders_class_breaks_the_documented_prefix_rule() {
        assert!(!ContainerClass::Reminder.is_ipf());
        for (_, class) in DOCUMENTED {
            let expected = class != ContainerClass::Reminder;
            assert_eq!(class.is_ipf(), expected, "{class}");
        }
    }

    /// Contacts folders nest, and a listing that matched only on equality would miss two of the
    /// three kinds a mailbox has.
    #[test]
    fn a_class_matches_the_kind_it_is_a_refinement_of() {
        assert!(ContainerClass::QuickContacts.is_a(&ContainerClass::Contact));
        assert!(ContainerClass::ImContactList.is_a(&ContainerClass::Contact));
        assert!(ContainerClass::Contact.is_a(&ContainerClass::Contact));
        assert!(ContainerClass::RssFeeds.is_a(&ContainerClass::Note));

        assert!(!ContainerClass::Contact.is_a(&ContainerClass::QuickContacts));
        assert!(!ContainerClass::Appointment.is_a(&ContainerClass::Contact));
        // A prefix that is not a dotted one is a different class, not a refinement.
        assert!(!ContainerClass::new("IPF.Notes").is_a(&ContainerClass::Note));
    }
}
