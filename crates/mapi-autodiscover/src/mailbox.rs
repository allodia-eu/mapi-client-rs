//! The other mailboxes an account can open.
//!
//! MAPI/HTTP has no enumeration verb: nothing a client can send to a mailbox server asks "what else
//! may I open?". What Outlook shows in its folder pane below the user's own mailbox comes from
//! Autodiscover instead, as one `AlternativeMailbox` element per auto-mapped archive, shared or
//! delegate mailbox. Listing mailboxes is therefore a question for this crate rather than for
//! [`mapi-proto`](https://docs.rs/mapi-proto), and it is the only one of the requested operations
//! that is not a ROP at all.
//!
//! [MS-OXDSCLI] §2.2.4.1.1.2.5 — `AlternativeMailbox`

/// What kind of additional mailbox this is.
///
/// The three documented values plus whatever else a server names, because a deployment newer than
/// this crate answering with a fourth is a mailbox to list rather than an element to drop.
///
/// [MS-OXDSCLI] §2.2.4.1.1.2.5.5 — `Type`
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum MailboxKind {
    /// `Archive` — a second mailbox provisioned for the same user, holding historical mail.
    ///
    /// An archive belonging to *somebody else's* mailbox is also an `Archive`, and is told apart
    /// only by [`AlternativeMailbox::owner_smtp_address`] being present.
    Archive,
    /// `Delegate` — a mailbox owned by another user that this one has rights to. Shared mailboxes
    /// arrive under this value too.
    Delegate,
    /// `TeamMailbox` — a site mailbox.
    TeamMailbox,
    /// Anything else the server named.
    Other(String),
}

impl MailboxKind {
    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "Archive" => Self::Archive,
            "Delegate" => Self::Delegate,
            "TeamMailbox" => Self::TeamMailbox,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl core::fmt::Display for MailboxKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Archive => f.write_str("Archive"),
            Self::Delegate => f.write_str("Delegate"),
            Self::TeamMailbox => f.write_str("TeamMailbox"),
            Self::Other(name) => f.write_str(name),
        }
    }
}

/// How to reach an alternative mailbox — and there are two ways, which cost differently.
///
/// [MS-OXDSCLI] §2.2.4.1.1.2.5.2 and §2.2.4.1.1.2.5.4 make these **mutually exclusive**, in four
/// `MUST`s that between them say each form is present exactly when the other is not. That is why
/// this is an enum rather than a struct of options: a caller has to handle both, and cannot handle
/// a combination the document forbids.
///
/// [MS-OXDSCLI] §2.2.4.1.1.2.5.2 — `LegacyDN`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MailboxAddress<'a> {
    /// A distinguished name and the server holding it: everything a `Connect` needs, with no
    /// second Autodiscover round trip.
    Directory {
        /// The `legacyExchangeDN` to log on with, passed through verbatim.
        legacy_dn: &'a str,
        /// The fully qualified name of the server holding the mailbox.
        server: &'a str,
    },
    /// An SMTP address, which is an instruction to ask Autodiscover again.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.5.4 says so in as many words: the address "can be used in the
    /// `EMailAddress` element of an Autodiscover request to discover configuration settings for
    /// the alternative mailbox". It costs a round trip and answers with that mailbox's own
    /// endpoint, which the directory form does not.
    Smtp(&'a str),
}

/// One mailbox the authenticated account may open besides its own.
///
/// Opening one is an ordinary `Connect` carrying *this* mailbox's distinguished name while still
/// authenticating as the original user; the server does the access check. There is no ROP and no
/// second set of credentials involved.
///
/// [MS-OXDSCLI] §2.2.4.1.1.2.5 — `AlternativeMailbox`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlternativeMailbox {
    pub(crate) kind: MailboxKind,
    pub(crate) display_name: Option<String>,
    pub(crate) legacy_dn: Option<String>,
    pub(crate) server: Option<String>,
    pub(crate) smtp_address: Option<String>,
    pub(crate) owner_smtp_address: Option<String>,
}

impl AlternativeMailbox {
    /// Which kind of mailbox this is.
    ///
    /// The one child element [MS-OXDSCLI] §2.2.4.1.1.2.5.5 makes required.
    #[must_use]
    pub const fn kind(&self) -> &MailboxKind {
        &self.kind
    }

    /// What to call it, if the server said.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.5.1 — `DisplayName`
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// How to open it: a distinguished name to log on with, or an address to look up.
    ///
    /// `None` for an element carrying neither, which the specification's four `MUST`s do not
    /// allow — reported rather than guessed at, because either guess would name a mailbox nobody
    /// asked for.
    #[must_use]
    pub fn address(&self) -> Option<MailboxAddress<'_>> {
        match (
            self.legacy_dn.as_deref(),
            self.server.as_deref(),
            self.smtp_address.as_deref(),
        ) {
            // Checked before the directory form deliberately. A server sending both is deviating
            // whichever way this is read, and the SMTP form is the one that cannot be wrong: it
            // asks the deployment about the mailbox rather than assuming this endpoint serves it.
            (_, _, Some(address)) => Some(MailboxAddress::Smtp(address)),
            (Some(legacy_dn), Some(server), None) => {
                Some(MailboxAddress::Directory { legacy_dn, server })
            }
            _ => None,
        }
    }

    /// The `legacyExchangeDN`, for the form that carries one.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.5.2 — `LegacyDN`
    #[must_use]
    pub fn legacy_dn(&self) -> Option<&str> {
        self.legacy_dn.as_deref()
    }

    /// The fully qualified name of the server holding it.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.5.3 — `Server`
    #[must_use]
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// The SMTP address, for the form that carries one.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.5.4 — `SmtpAddress`
    #[must_use]
    pub fn smtp_address(&self) -> Option<&str> {
        self.smtp_address.as_deref()
    }

    /// Whose mailbox this is an archive of, when it is not the authenticated user's own.
    ///
    /// The only thing separating a user's own archive from a delegated mailbox's archive, both of
    /// which report [`MailboxKind::Archive`].
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.5.6 — `OwnerSmtpAddress`
    #[must_use]
    pub fn owner_smtp_address(&self) -> Option<&str> {
        self.owner_smtp_address.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox() -> AlternativeMailbox {
        AlternativeMailbox {
            kind: MailboxKind::Delegate,
            display_name: Some("Shared Mailbox".to_owned()),
            legacy_dn: None,
            server: None,
            smtp_address: None,
            owner_smtp_address: None,
        }
    }

    #[test]
    fn the_documented_kinds_round_trip_through_their_names() {
        for (name, expected) in [
            ("Archive", MailboxKind::Archive),
            ("Delegate", MailboxKind::Delegate),
            ("TeamMailbox", MailboxKind::TeamMailbox),
        ] {
            assert_eq!(MailboxKind::parse(name), expected);
            assert_eq!(expected.to_string(), name);
        }
    }

    /// A deployment newer than this crate is a mailbox to list, not an element to drop.
    #[test]
    fn a_kind_this_crate_has_never_heard_of_keeps_its_name() {
        let unknown = MailboxKind::parse("GroupMailbox");
        assert_eq!(unknown, MailboxKind::Other("GroupMailbox".to_owned()));
        assert_eq!(unknown.to_string(), "GroupMailbox");
    }

    /// The two forms, each on its own, which is how the specification says they arrive.
    #[test]
    fn each_form_reports_the_way_to_open_it() {
        let directory = AlternativeMailbox {
            legacy_dn: Some("/o=Dev/cn=shared".to_owned()),
            server: Some("mail.example.test".to_owned()),
            ..mailbox()
        };
        assert_eq!(
            directory.address(),
            Some(MailboxAddress::Directory {
                legacy_dn: "/o=Dev/cn=shared",
                server: "mail.example.test",
            })
        );

        let smtp = AlternativeMailbox {
            smtp_address: Some("shared@example.test".to_owned()),
            ..mailbox()
        };
        assert_eq!(
            smtp.address(),
            Some(MailboxAddress::Smtp("shared@example.test"))
        );
    }

    /// An element naming neither form names no mailbox, and saying so beats picking one: either
    /// guess would open something nobody asked for.
    #[test]
    fn an_element_that_names_no_way_in_is_reported_rather_than_guessed_at() {
        assert_eq!(mailbox().address(), None);

        // A distinguished name with no server is half of the directory form and not usable as it
        // stands, which §2.2.4.1.1.2.5.3's `MUST` says cannot happen.
        let half = AlternativeMailbox {
            legacy_dn: Some("/o=Dev/cn=shared".to_owned()),
            ..mailbox()
        };
        assert_eq!(half.address(), None);
        assert_eq!(half.legacy_dn(), Some("/o=Dev/cn=shared"));
    }

    /// The forms are exclusive by specification, so a server sending both is deviating. The SMTP
    /// form wins because it asks the deployment rather than assuming this endpoint serves it.
    #[test]
    fn a_server_sending_both_forms_is_taken_at_its_smtp_address() {
        let both = AlternativeMailbox {
            legacy_dn: Some("/o=Dev/cn=shared".to_owned()),
            server: Some("mail.example.test".to_owned()),
            smtp_address: Some("shared@example.test".to_owned()),
            ..mailbox()
        };
        assert_eq!(
            both.address(),
            Some(MailboxAddress::Smtp("shared@example.test"))
        );
    }

    #[test]
    fn every_child_element_is_handed_back() {
        let archive = AlternativeMailbox {
            kind: MailboxKind::Archive,
            owner_smtp_address: Some("someone@example.test".to_owned()),
            server: Some("mail.example.test".to_owned()),
            ..mailbox()
        };

        assert_eq!(*archive.kind(), MailboxKind::Archive);
        assert_eq!(archive.display_name(), Some("Shared Mailbox"));
        assert_eq!(archive.server(), Some("mail.example.test"));
        assert_eq!(archive.smtp_address(), None);
        assert_eq!(archive.owner_smtp_address(), Some("someone@example.test"));
    }
}
