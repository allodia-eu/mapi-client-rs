//! Mailboxes other than the account's own: shared, delegated and archive.
//!
//! **There is no ROP for this.** MAPI/HTTP has no verb that asks a mailbox server what else the
//! caller may open, so the list comes from Autodiscover's `AlternativeMailbox` elements and from
//! nowhere else. Opening one is then an ordinary `Connect` and `RopLogon` carrying *that* mailbox's
//! distinguished name while still authenticating as the original user; the server does the access
//! check.
//!
//! Two things measured against Exchange Server SE `15.02.2562.045` shape everything here, and both
//! cost a round trip to discover the hard way:
//!
//! 1. **Exchange names an alternative mailbox by SMTP address, never by distinguished name.**
//!    [MS-OXDSCLI] §2.2.4.1.1.2.5.2 offers a `LegacyDN` child, which would be everything a
//!    `Connect` needs; the lab sends [`MailboxAddress::Smtp`] instead. So listing *n* mailboxes
//!    costs *n + 1* Autodiscover round trips, and there is no way to make it cost fewer.
//! 2. **The endpoint URL and the distinguished name are a matched pair.** The `?MailboxId=` query
//!    parameter selects the mailbox just as the name does, and pairing one mailbox's URL with
//!    another's name is refused — but not where a reader would look for the refusal. `Connect`
//!    *succeeds*, and reports the right owner; the `RopLogon` in the next request answers
//!    [`ErrorCode::WRONG_SERVER`](mapi_proto::ErrorCode::WRONG_SERVER) with a redirect naming
//!    `cn=Configuration/cn=Servers/cn=<the other MailboxId>`. Reusing the first mailbox's endpoint
//!    is therefore not an optimisation that merely fails; it fails one request later, in an error
//!    about servers rather than about mailboxes.
//!
//! [MS-OXDSCLI] §2.2.4.1.1.2.5 — `AlternativeMailbox`

use std::collections::VecDeque;
use std::sync::Arc;

use mapi_autodiscover::{
    AlternativeMailbox, EmailAddress, MailboxAddress, MailboxKind, candidate_urls,
};
use mapi_proto::LegacyDn;

use crate::builder::{MapiClientBuilder, parse_endpoint};
use crate::client::MapiClient;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// One mailbox these credentials can open, resolved to the pair a session needs.
///
/// "Resolved" is the whole of it: an `AlternativeMailbox` names a mailbox, and this names a
/// mailbox *and the endpoint that serves it*, which on this deployment took a second Autodiscover
/// lookup to learn. [`MapiClientBuilder::mailboxes`] does that work; this is what it hands back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mailbox {
    pub(crate) kind: Option<MailboxKind>,
    pub(crate) display_name: Option<String>,
    pub(crate) smtp_address: Option<String>,
    pub(crate) endpoint: Option<String>,
    pub(crate) user_dn: Option<LegacyDn>,
}

impl Mailbox {
    /// Which kind of alternative mailbox this is, or `None` for the account's own.
    ///
    /// The account's own mailbox has no `AlternativeMailbox` element and therefore no `Type`;
    /// [`is_own`](Self::is_own) says the same thing in the direction most callers want it.
    #[must_use]
    pub const fn kind(&self) -> Option<&MailboxKind> {
        self.kind.as_ref()
    }

    /// Whether this is the mailbox the lookup was made for.
    #[must_use]
    pub const fn is_own(&self) -> bool {
        self.kind.is_none()
    }

    /// What to call it.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Its SMTP address, as the server gave it.
    #[must_use]
    pub fn smtp_address(&self) -> Option<&str> {
        self.smtp_address.as_deref()
    }

    /// The endpoint to POST to, `?MailboxId=` and all.
    ///
    /// `None` for a mailbox this client cannot reach — see [`is_openable`](Self::is_openable).
    #[must_use]
    pub fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    /// The distinguished name to log on with. Never the authenticating account's, unless this is
    /// that account's own mailbox.
    #[must_use]
    pub const fn user_dn(&self) -> Option<&LegacyDn> {
        self.user_dn.as_ref()
    }

    /// Whether a session can be opened on it.
    ///
    /// `false` for exactly one shape: an `AlternativeMailbox` given in the directory form of
    /// [MS-OXDSCLI] §2.2.4.1.1.2.5.2 — a `LegacyDN` and a `Server` — because a MAPI/HTTP endpoint
    /// needs a `?MailboxId=<guid>@<domain>` and a server's fully qualified name is not one. There
    /// is no arithmetic from the first to the second, and the primary mailbox's endpoint is not a
    /// substitute: it is refused at logon with
    /// [`ErrorCode::WRONG_SERVER`](mapi_proto::ErrorCode::WRONG_SERVER).
    ///
    /// The shape is documented rather than hypothetical, and also rather than observed: it is what
    /// [MS-OXDSCLI]'s notes 8 and 10 describe for Exchange 2007 and 2010, neither of which speaks
    /// MAPI/HTTP at all. Every mailbox the lab reported arrived openable.
    #[must_use]
    pub const fn is_openable(&self) -> bool {
        self.endpoint.is_some() && self.user_dn.is_some()
    }

    /// The mailbox the lookup was made for, which needs no second round trip.
    fn own(settings: &mapi_autodiscover::Settings) -> Option<Self> {
        let endpoint = settings.mapi_http()?;
        Some(Self {
            kind: None,
            display_name: settings.user().display_name().map(str::to_owned),
            smtp_address: settings.user().smtp_address().map(str::to_owned),
            endpoint: endpoint.mail_store_url().map(str::to_owned),
            user_dn: LegacyDn::new(endpoint.legacy_dn()).ok(),
        })
    }

    /// An alternative that named a distinguished name rather than an address: listed, and honest
    /// about not being openable.
    fn unopenable(alternative: &AlternativeMailbox) -> Self {
        Self {
            kind: Some(alternative.kind().clone()),
            display_name: alternative.display_name().map(str::to_owned),
            smtp_address: alternative.smtp_address().map(str::to_owned),
            endpoint: None,
            user_dn: None,
        }
    }
}

impl MapiClientBuilder {
    /// Every mailbox these credentials can open: the account's own, and each alternative
    /// Autodiscover named.
    ///
    /// The account's own mailbox is always first. What follows is one entry per
    /// `AlternativeMailbox`, in the order the server listed them, with the archives, shared
    /// mailboxes and delegated mailboxes told apart by [`Mailbox::kind`].
    ///
    /// **This costs one Autodiscover round trip plus one per alternative mailbox**, because
    /// Exchange names each alternative by SMTP address and an address is not an endpoint. A
    /// lookup that fails for one alternative does not fail the listing: that mailbox is reported
    /// unopenable and the rest are still returned, since a delegate whose mailbox has moved should
    /// not hide the four that have not.
    ///
    /// ```no_run
    /// use mapi_client::{Credentials, EmailAddress, MapiClient};
    ///
    /// # async fn example() -> Result<(), mapi_client::Error> {
    /// let builder = MapiClient::builder()
    ///     .credentials(Credentials::basic("alice@example.test", "hunter2"));
    /// let address = EmailAddress::new("alice@example.test")?;
    ///
    /// for mailbox in builder.mailboxes(&address).await? {
    ///     println!("{:?} {:?}", mailbox.kind(), mailbox.display_name());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`lookup`](MapiClientBuilder::lookup), for the first lookup only. A failure looking up an
    /// alternative is reported as that mailbox being unopenable rather than as an error.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.5 — `AlternativeMailbox`
    pub async fn mailboxes(&self, address: &EmailAddress) -> Result<Vec<Mailbox>> {
        self.list_mailboxes(address, None).await
    }

    /// The same, starting from an Autodiscover URL you already have.
    ///
    /// The counterpart of [`lookup_at`](MapiClientBuilder::lookup_at), and the URL is used for
    /// *every* lookup rather than only the first: an alternative mailbox is on the same deployment
    /// by definition — the account has rights to it — so the service that described the account
    /// is the one to ask about its mailboxes.
    ///
    /// # Errors
    ///
    /// As [`mailboxes`](MapiClientBuilder::mailboxes).
    pub async fn mailboxes_at(
        &self,
        url: impl Into<String>,
        address: &EmailAddress,
    ) -> Result<Vec<Mailbox>> {
        self.list_mailboxes(address, Some(url.into())).await
    }

    /// Both of the above: one lookup for the account, then one per alternative mailbox.
    async fn list_mailboxes(
        &self,
        address: &EmailAddress,
        url: Option<String>,
    ) -> Result<Vec<Mailbox>> {
        let settings = self
            .search(address, queue(address, url.clone()), true)
            .await?;
        let settings = settings.settings;
        let mut mailboxes: Vec<Mailbox> = Mailbox::own(&settings).into_iter().collect();

        for alternative in settings.alternative_mailboxes() {
            mailboxes.push(self.resolve(alternative, url.clone()).await);
        }
        Ok(mailboxes)
    }

    /// Turns one `AlternativeMailbox` into something openable, if it can be.
    async fn resolve(&self, alternative: &AlternativeMailbox, url: Option<String>) -> Mailbox {
        // The directory form carries no MailboxId, and there is no second question to ask: it
        // names a mailbox without naming an address to look it up by.
        let Some(MailboxAddress::Smtp(smtp)) = alternative.address() else {
            return Mailbox::unopenable(alternative);
        };
        let Ok(address) = EmailAddress::new(smtp) else {
            return Mailbox::unopenable(alternative);
        };

        let Ok(found) = self.search(&address, queue(&address, url), true).await else {
            return Mailbox::unopenable(alternative);
        };

        let endpoint = found.settings.mapi_http();
        Mailbox {
            kind: Some(alternative.kind().clone()),
            // The server describes the same mailbox twice, and the two need not agree: the
            // AlternativeMailbox element carries a DisplayName the deployment chose for how the
            // *delegate* should see it, and §2.2.4.1.1.2.5.1 says so in as many words — "used to
            // override how a client will display the user's name". So that one wins.
            display_name: alternative
                .display_name()
                .or_else(|| found.settings.user().display_name())
                .map(str::to_owned),
            smtp_address: Some(smtp.to_owned()),
            endpoint: endpoint
                .as_ref()
                .and_then(|endpoint| endpoint.mail_store_url())
                .map(str::to_owned),
            user_dn: endpoint.and_then(|endpoint| LegacyDn::new(endpoint.legacy_dn()).ok()),
        }
    }
}

impl MapiClient {
    /// The same client aimed at another mailbox on the same deployment.
    ///
    /// Cheaper than building a second client and not only in code: the HTTP connection pool and
    /// the TLS configuration are shared, and so is the client identity — which is what
    /// [MS-OXCMAPIHTTP] §2.2.3.3.4 actually asks for. `X-ClientInfo`'s GUID must be one per client
    /// *instance* with a counter that moves per Session Context, and two mailboxes opened by one
    /// program are one instance with two contexts. A second [`MapiClient::builder`] would mint a
    /// second GUID and claim to be a second Outlook.
    ///
    /// ```no_run
    /// # use mapi_client::{Error, Mailbox, MapiClient};
    /// # async fn example(client: &MapiClient, shared: &Mailbox) -> Result<(), Error> {
    /// let mut logon = client.for_mailbox(shared)?.connect().await?.logon().await?;
    /// # let _ = logon.mailbox();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingSetting`] if the mailbox is not openable — see
    /// [`Mailbox::is_openable`] — and [`Error::InvalidEndpoint`] or [`Error::PlaintextEndpoint`] if
    /// its URL is not one this crate will POST to.
    pub fn for_mailbox(&self, mailbox: &Mailbox) -> Result<Self> {
        let endpoint = mailbox.endpoint().ok_or(Error::MissingSetting {
            name: "endpoint",
            how: "an AlternativeMailbox that named a LegacyDN rather than an SmtpAddress, which \
                  carries no MailboxId and cannot be resolved to one",
        })?;
        let user_dn = mailbox.user_dn().ok_or(Error::MissingSetting {
            name: "user_dn",
            how: "the same",
        })?;

        self.at(endpoint, user_dn.clone())
    }

    /// The same, for a caller holding an endpoint and a distinguished name already.
    ///
    /// **Both, always.** Keeping this client's endpoint and changing only the name is the mistake
    /// this signature exists to prevent: it is accepted by `Connect`, which reports the new
    /// mailbox's owner as though it had worked, and refused by the `RopLogon` in the request after
    /// it with [`ErrorCode::WRONG_SERVER`](mapi_proto::ErrorCode::WRONG_SERVER).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEndpoint`] or [`Error::PlaintextEndpoint`] if the URL is not one this crate
    /// will POST to, and [`Error::Setup`] if the HTTP client cannot be rebuilt.
    pub fn at(&self, endpoint: &str, user_dn: LegacyDn) -> Result<Self> {
        let endpoint = parse_endpoint(endpoint, is_plaintext(&self.transport.endpoint))?;

        Ok(Self {
            transport: Transport {
                endpoint,
                ..self.transport.clone()
            },
            identity: Arc::clone(&self.identity),
            user_dn,
            locale: self.locale,
            client_application: self.client_application.clone(),
        })
    }
}

/// Where to look for one lookup: a URL that was given, or the documented candidate sequence.
fn queue(address: &EmailAddress, url: Option<String>) -> VecDeque<String> {
    url.map_or_else(
        || candidate_urls(address).collect(),
        |url| VecDeque::from([url]),
    )
}

/// Whether this client was built against a plaintext endpoint, and may therefore be pointed at
/// another one.
///
/// The permission travels with the client rather than being asked for again: a caller who accepted
/// `http://` for the mailbox it discovered is not made to accept it a second time for a mailbox on
/// the same deployment, and one who did not cannot be moved onto plaintext by a server's answer.
fn is_plaintext(endpoint: &reqwest::Url) -> bool {
    endpoint.scheme() == "http"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own() -> Mailbox {
        Mailbox {
            kind: None,
            display_name: Some("Alice Example".to_owned()),
            smtp_address: Some("alice@example.test".to_owned()),
            endpoint: Some(
                "https://mail.example.test/mapi/emsmdb/?MailboxId=a@example.test".to_owned(),
            ),
            user_dn: LegacyDn::new("/o=Example/cn=alice").ok(),
        }
    }

    fn directory_form() -> AlternativeMailbox {
        // Built by parsing, because the fields are the crate's own and this is what a server that
        // sends the older shape looks like.
        let xml = r"<Autodiscover><Response><Account>
             <Action>settings</Action>
             <AlternativeMailbox>
               <Type>Delegate</Type>
               <DisplayName>Old Shared</DisplayName>
               <LegacyDN>/o=Example/cn=shared</LegacyDN>
               <Server>mail.example.test</Server>
             </AlternativeMailbox>
           </Account></Response></Autodiscover>";
        match mapi_autodiscover::AutodiscoverResponse::parse(xml) {
            Ok(mapi_autodiscover::AutodiscoverResponse::Settings(settings)) => settings
                .alternative_mailboxes()
                .first()
                .cloned()
                .expect("one alternative mailbox"),
            other => panic!("expected settings, got {other:?}"),
        }
    }

    #[test]
    fn the_accounts_own_mailbox_is_not_an_alternative_one() {
        let own = own();
        assert!(own.is_own());
        assert_eq!(own.kind(), None);
        assert!(own.is_openable());
        assert_eq!(own.display_name(), Some("Alice Example"));
        assert_eq!(own.smtp_address(), Some("alice@example.test"));
    }

    /// The one shape that cannot be opened, and the reason: a server's fully qualified name is not
    /// a `?MailboxId=`, and nothing turns one into the other.
    #[test]
    fn a_mailbox_named_by_distinguished_name_is_listed_but_not_openable() {
        let mailbox = Mailbox::unopenable(&directory_form());

        assert!(!mailbox.is_own());
        assert_eq!(mailbox.kind(), Some(&MailboxKind::Delegate));
        assert_eq!(mailbox.display_name(), Some("Old Shared"));
        assert!(!mailbox.is_openable());
        assert_eq!(mailbox.endpoint(), None);
        assert_eq!(mailbox.user_dn(), None);
    }
}
