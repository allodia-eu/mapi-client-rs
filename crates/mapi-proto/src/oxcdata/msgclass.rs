//! What kind of item a message is — the value of `PidTagMessageClass`.
//!
//! The counterpart of [`ContainerClass`](crate::ContainerClass) one level down, and the property
//! that decides what an item *is*. A message whose class is `IPM.Note` is mail however many
//! appointment properties it carries, and one whose class is `IPM.Appointment` is an appointment
//! however few — so this is the first property a create sets and the last one worth getting wrong.
//!
//! **Matching is case-insensitive here and case-sensitive for a folder's class.** [MS-OXCMSG]
//! §2.2.1.3 says so in as many words: "Any equality or matching operations performed against the
//! value of this property MUST be case-insensitive." Nothing says that about
//! `PidTagContainerClass`, and the two are otherwise the same shape of dotted string — which is
//! exactly the sort of difference a shared helper would erase.
//!
//! [MS-OXCMSG] §2.2.1.3 — `PidTagMessageClass`
//! [MS-OXOMSG] §2.2.1.48 — `IPM.Note` on an E-mail object
//! [MS-OXOCAL] §2.2.2.1 — `IPM.Appointment`, or prefixed with `IPM.Appointment.`
//! [MS-OXOCNTC] §2.2.1.1.1 — `IPM.Contact`

use crate::error::{Error, Result};

/// The longest a class may be, in characters.
///
/// [MS-OXCMSG] §2.2.1.3 — "less than 256 characters"
const MAX_LENGTH: usize = 255;

/// The kind of item a message is.
///
/// An open set, like a folder's class: deployments and add-ins invent their own, and a message
/// carrying one is still a message.
///
/// ```
/// use mapi_proto::MessageClass;
///
/// // Matching is case-insensitive, and classes nest.
/// let response = MessageClass::new("ipm.schedule.meeting.resp.pos");
/// assert!(response.is_a(&MessageClass::new("IPM.Schedule")));
/// assert!(!response.is_a(&MessageClass::Note));
/// ```
///
/// [MS-OXCMSG] §2.2.1.3 — `PidTagMessageClass`
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum MessageClass {
    /// `IPM.Activity` — a journal entry.
    Journal,
    /// `IPM.Appointment` — a calendar entry, whether an appointment or a meeting.
    Appointment,
    /// `IPM.Contact` — a contact.
    Contact,
    /// `IPM.DistList` — a personal distribution list.
    DistributionList,
    /// `IPM.Note` — ordinary mail. What `RopCreateMessage` initialises a new message to.
    Note,
    /// `IPM.StickyNote` — a note.
    StickyNote,
    /// `IPM.Task` — a task.
    Task,
    /// A class this crate does not name, carried through as it arrived.
    Other(String),
}

impl MessageClass {
    /// The classes this crate names, in the order they are matched.
    const KNOWN: [Self; 7] = [
        Self::Journal,
        Self::Appointment,
        Self::Contact,
        Self::DistributionList,
        Self::Note,
        Self::StickyNote,
        Self::Task,
    ];

    /// Classifies the value of a `PidTagMessageClass` property.
    ///
    /// Case-insensitive, as [MS-OXCMSG] §2.2.1.3 requires — so a message stored as `ipm.contact` is
    /// a contact here, and [`as_str`](Self::as_str) then answers with the documented spelling
    /// rather than the stored one.
    #[must_use]
    pub fn new(value: &str) -> Self {
        for known in Self::KNOWN {
            if value.eq_ignore_ascii_case(known.as_str()) {
                return known;
            }
        }
        Self::Other(value.to_owned())
    }

    /// Names a class this crate does not model, checking it against the rules for the property.
    ///
    /// # Errors
    ///
    /// [`Error::UnencodableValue`] for a value [MS-OXCMSG] §2.2.1.3 forbids: empty, 256 characters
    /// or longer, ending in a period, or holding anything outside ASCII `0x20`–`0x7F`. Refused
    /// rather than sent, because a message whose class the server will not accept is a save that
    /// fails well away from the line that chose the string.
    pub fn custom(value: &str) -> Result<Self> {
        let reason = if value.is_empty() {
            Some("a message class has to be at least one character")
        } else if value.chars().count() > MAX_LENGTH {
            Some("a message class is shorter than 256 characters")
        } else if value.ends_with('.') {
            Some("a message class may not end with a period")
        } else if !value.chars().all(|c| (' '..='\u{7F}').contains(&c)) {
            Some("a message class holds only ASCII 0x20 to 0x7F")
        } else {
            None
        };

        match reason {
            Some(reason) => Err(Error::UnencodableValue {
                value: "a message class",
                reason,
            }),
            None => Ok(Self::new(value)),
        }
    }

    /// The string the property holds.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Journal => "IPM.Activity",
            Self::Appointment => "IPM.Appointment",
            Self::Contact => "IPM.Contact",
            Self::DistributionList => "IPM.DistList",
            Self::Note => "IPM.Note",
            Self::StickyNote => "IPM.StickyNote",
            Self::Task => "IPM.Task",
            Self::Other(value) => value,
        }
    }

    /// Whether this is an item of `wanted`'s kind.
    ///
    /// Classes nest in dotted groups — [MS-OXCMSG] §2.2.1.3: "The value of this property is
    /// interpreted in groups of characters separated by periods" — so `IPM.Appointment.Birthday` is
    /// an appointment and `IPM.Schedule.Meeting.Request` is not. Comparison is case-insensitive,
    /// which is the whole reason this is a method rather than a `==`.
    #[must_use]
    pub fn is_a(&self, wanted: &Self) -> bool {
        let (mine, theirs) = (self.as_str(), wanted.as_str());
        if mine.eq_ignore_ascii_case(theirs) {
            return true;
        }
        mine.get(..theirs.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(theirs))
            && mine
                .get(theirs.len()..)
                .is_some_and(|rest| rest.starts_with('.'))
    }
}

impl core::fmt::Display for MessageClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for MessageClass {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transcribed from [MS-OXCFOLD] §3.1.4.7.1's default-view rules, which name each of these as a
    /// `PidTagMessageClass` value, rather than from `as_str`.
    const DOCUMENTED: [(&str, MessageClass); 7] = [
        ("IPM.Activity", MessageClass::Journal),
        ("IPM.Appointment", MessageClass::Appointment),
        ("IPM.Contact", MessageClass::Contact),
        ("IPM.DistList", MessageClass::DistributionList),
        ("IPM.Note", MessageClass::Note),
        ("IPM.StickyNote", MessageClass::StickyNote),
        ("IPM.Task", MessageClass::Task),
    ];

    #[test]
    fn each_class_carries_the_string_the_documents_give_it() {
        for (value, expected) in DOCUMENTED {
            assert_eq!(MessageClass::new(value), expected, "{value}");
            assert_eq!(expected.as_str(), value);
            assert_eq!(expected.to_string(), value);
            assert_eq!(MessageClass::from(value), expected);
        }
    }

    /// The rule that separates this from a folder's class. A message stored in a different case is
    /// the same kind of item, and a client that compared exactly would report a contact as unknown.
    #[test]
    fn matching_ignores_case_because_the_document_requires_it() {
        assert_eq!(MessageClass::new("ipm.contact"), MessageClass::Contact);
        assert_eq!(MessageClass::new("IPM.CONTACT"), MessageClass::Contact);
        assert_eq!(
            MessageClass::new("ipm.contact").as_str(),
            "IPM.Contact",
            "the documented spelling, not the stored one"
        );
        assert!(MessageClass::new("IPM.APPOINTMENT.Birthday").is_a(&MessageClass::Appointment));
    }

    /// Classes nest in dotted groups, so a listing that matched on equality would miss the
    /// refinements — and one that matched on a bare prefix would call a meeting request a note.
    #[test]
    fn a_class_matches_the_kind_it_is_a_refinement_of() {
        let birthday = MessageClass::new("IPM.Appointment.Birthday");
        assert!(birthday.is_a(&MessageClass::Appointment));
        assert!(!birthday.is_a(&MessageClass::Note));

        let request = MessageClass::new("IPM.Schedule.Meeting.Request");
        assert!(request.is_a(&MessageClass::new("IPM.Schedule.Meeting")));
        assert!(!request.is_a(&MessageClass::Note));

        // A prefix that is not a dotted one is a different class, not a refinement.
        assert!(!MessageClass::new("IPM.Notebook").is_a(&MessageClass::Note));
        assert!(MessageClass::Note.is_a(&MessageClass::Note));
        // A header message object, whose class is prefixed rather than suffixed.
        assert!(!MessageClass::new("Remote.IPM.Note").is_a(&MessageClass::Note));
    }

    #[test]
    fn a_class_this_crate_does_not_name_survives_being_read() {
        for observed in ["IPM.Schedule.Meeting.Request", "REPORT.IPM.Note.NDR", "IPM"] {
            let class = MessageClass::new(observed);
            assert_eq!(class, MessageClass::Other(observed.to_owned()));
            assert_eq!(class.as_str(), observed);
        }
    }

    /// Each of the four rules §2.2.1.3 states, refused where the server would refuse the save.
    #[test]
    fn a_class_the_property_cannot_hold_is_refused_before_it_is_sent() {
        for bad in ["", "IPM.Note.", "IPM.Caf\u{E9}", "IPM.\u{7}Bell"] {
            assert!(MessageClass::custom(bad).is_err(), "{bad:?}");
        }
        assert!(MessageClass::custom(&"A".repeat(MAX_LENGTH + 1)).is_err());
        assert_eq!(
            MessageClass::custom("IPM.Note").expect("a documented class"),
            MessageClass::Note
        );
        assert_eq!(
            MessageClass::custom(&"A".repeat(MAX_LENGTH)).expect("the longest allowed"),
            MessageClass::Other("A".repeat(MAX_LENGTH))
        );
    }
}
