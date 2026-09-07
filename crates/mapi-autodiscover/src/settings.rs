//! What a server says about a mailbox.

use crate::mailbox::AlternativeMailbox;

/// The two URLs a protocol can be reachable at.
///
/// At least one is always present; which one to use depends on where the client is, which this
/// crate cannot know. [`Urls::preferred`] picks the internal one when there is a choice.
///
/// [MS-OXDSCLI] §2.2.4.1.1.2.6.29 — `MailStore`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Urls {
    pub(crate) internal: Option<String>,
    pub(crate) external: Option<String>,
}

impl Urls {
    /// The URL for a client inside the organisation's network.
    #[must_use]
    pub fn internal(&self) -> Option<&str> {
        self.internal.as_deref()
    }

    /// The URL for a client outside it.
    #[must_use]
    pub fn external(&self) -> Option<&str> {
        self.external.as_deref()
    }

    /// The internal URL if there is one, otherwise the external.
    ///
    /// A convenience, not a judgement: a client that knows it is outside the network should take
    /// [`Urls::external`] directly.
    #[must_use]
    pub fn preferred(&self) -> Option<&str> {
        self.internal().or_else(|| self.external())
    }

    /// Whether the server gave no URL at all for this protocol.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.internal.is_none() && self.external.is_none()
    }
}

/// Which protocol a `Protocol` element describes.
///
/// [MS-OXDSCLI] §2.2.4.1.1.2.6 — `Protocol`
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ProtocolType {
    /// `mapiHttp` — MAPI over HTTP, which is what this workspace speaks.
    MapiHttp,
    /// `EXCH` — the internal RPC endpoint.
    Exch,
    /// `EXPR` — RPC over HTTP ("Outlook Anywhere").
    Expr,
    /// `WEB` — the browser-facing URLs.
    Web,
    /// Anything else the server named.
    Other(String),
}

impl ProtocolType {
    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "mapiHttp" => Self::MapiHttp,
            "EXCH" => Self::Exch,
            "EXPR" => Self::Expr,
            "WEB" => Self::Web,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl core::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MapiHttp => f.write_str("mapiHttp"),
            Self::Exch => f.write_str("EXCH"),
            Self::Expr => f.write_str("EXPR"),
            Self::Web => f.write_str("WEB"),
            Self::Other(name) => f.write_str(name),
        }
    }
}

/// One way of reaching the mailbox.
///
/// [MS-OXDSCLI] §2.2.4.1.1.2.6 — `Protocol`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol {
    pub(crate) kind: ProtocolType,
    pub(crate) version: Option<u32>,
    pub(crate) server: Option<String>,
    pub(crate) auth_package: Option<String>,
    pub(crate) mail_store: Urls,
    pub(crate) address_book: Urls,
}

impl Protocol {
    /// Which protocol this is.
    #[must_use]
    pub const fn protocol_type(&self) -> &ProtocolType {
        &self.kind
    }

    /// The response-format version, which only `mapiHttp` carries.
    ///
    /// [MS-OXDSCLI] §3.2.5.1 — versions of the `Protocol` response format
    #[must_use]
    pub const fn version(&self) -> Option<u32> {
        self.version
    }

    /// The server name, for the protocols that give one.
    #[must_use]
    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    /// The authentication package the server asks for, such as `Ntlm`.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.6.4 — `AuthPackage`
    #[must_use]
    pub fn auth_package(&self) -> Option<&str> {
        self.auth_package.as_deref()
    }

    /// Where the mailbox itself is served from.
    #[must_use]
    pub const fn mail_store(&self) -> &Urls {
        &self.mail_store
    }

    /// Where the address book is served from.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.6.3 — `AddressBook`
    #[must_use]
    pub const fn address_book(&self) -> &Urls {
        &self.address_book
    }
}

/// Who the server thinks the mailbox belongs to.
///
/// [MS-OXDSCLI] §2.2.4.1.1.1 — `User`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct User {
    pub(crate) display_name: Option<String>,
    pub(crate) legacy_dn: Option<String>,
    pub(crate) smtp_address: Option<String>,
    pub(crate) deployment_id: Option<String>,
}

impl User {
    /// The mailbox owner's display name.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// The `legacyExchangeDN`, which is what a MAPI `Connect` needs.
    ///
    /// Pass it through verbatim: constructing one by hand is how a logon ends up refused with
    /// `UnknownUser`, which reads like an authentication failure and is not one.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.1.5 — `LegacyDN`
    #[must_use]
    pub fn legacy_dn(&self) -> Option<&str> {
        self.legacy_dn.as_deref()
    }

    /// The address the server considers canonical for this mailbox, which need not be the one that
    /// was asked about.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.1.1 — `AutoDiscoverSMTPAddress`
    #[must_use]
    pub fn smtp_address(&self) -> Option<&str> {
        self.smtp_address.as_deref()
    }

    /// The deployment this mailbox lives in.
    #[must_use]
    pub fn deployment_id(&self) -> Option<&str> {
        self.deployment_id.as_deref()
    }
}

/// Everything needed to open a MAPI/HTTP session, gathered in one place.
///
/// [MS-OXDSCLI] §3.2.5.1 — the `mapiHttp` response format
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapiHttpEndpoint {
    pub(crate) legacy_dn: String,
    pub(crate) version: u32,
    pub(crate) mail_store: Urls,
    pub(crate) address_book: Urls,
}

impl MapiHttpEndpoint {
    /// The URL to POST `Connect` and `Execute` to.
    ///
    /// Use it verbatim, including its `?MailboxId=` query parameter: without that parameter
    /// Exchange answers HTTP 400 with no `X-ResponseCode` header at all, which reads like "MAPI is
    /// not enabled" rather than "your URL is incomplete".
    #[must_use]
    pub fn mail_store_url(&self) -> Option<&str> {
        self.mail_store.preferred()
    }

    /// The address book endpoint, for the NSPI requests this workspace does not implement yet.
    #[must_use]
    pub fn address_book_url(&self) -> Option<&str> {
        self.address_book.preferred()
    }

    /// Both mail store URLs, internal and external.
    #[must_use]
    pub const fn mail_store(&self) -> &Urls {
        &self.mail_store
    }

    /// Both address book URLs.
    #[must_use]
    pub const fn address_book(&self) -> &Urls {
        &self.address_book
    }

    /// The `legacyExchangeDN` a MAPI `Connect` needs.
    #[must_use]
    pub fn legacy_dn(&self) -> &str {
        &self.legacy_dn
    }

    /// The response-format version the server answered with.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

/// A successful lookup: who the mailbox belongs to, and every way of reaching it.
///
/// [MS-OXDSCLI] §2.2.4.1.1 — `Response`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub(crate) user: User,
    pub(crate) protocols: Vec<Protocol>,
    pub(crate) alternative_mailboxes: Vec<AlternativeMailbox>,
}

impl Settings {
    /// Who the server says this mailbox belongs to.
    #[must_use]
    pub const fn user(&self) -> &User {
        &self.user
    }

    /// Every protocol the server offered, in the order it listed them.
    #[must_use]
    pub fn protocols(&self) -> &[Protocol] {
        &self.protocols
    }

    /// The other mailboxes this account may open: archives, shared mailboxes and delegated ones.
    ///
    /// **This is the whole of "list mailboxes".** MAPI/HTTP has no enumeration verb, so what
    /// Outlook shows below a user's own mailbox comes from here and nowhere else. An empty slice
    /// means the server named none, which [MS-OXDSCLI] §2.2.4.1.1.2.5 makes the ordinary case:
    /// the element is returned only when an alternative mailbox is associated with the user.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.2.5 — `AlternativeMailbox`
    #[must_use]
    pub fn alternative_mailboxes(&self) -> &[AlternativeMailbox] {
        &self.alternative_mailboxes
    }

    /// The `mapiHttp` protocol, paired with the distinguished name from the `User` element.
    ///
    /// `None` means the server did not offer MAPI/HTTP — which, if the request carried
    /// `X-MapiHttpCapability`, means the deployment really does not support it.
    ///
    /// [MS-OXDSCLI] §3.2.5.1 — what the capability header makes the server return
    #[must_use]
    pub fn mapi_http(&self) -> Option<MapiHttpEndpoint> {
        let protocol = self
            .protocols
            .iter()
            .find(|protocol| protocol.kind == ProtocolType::MapiHttp)?;

        Some(MapiHttpEndpoint {
            legacy_dn: self.user.legacy_dn.clone()?,
            version: protocol.version.unwrap_or(1),
            mail_store: protocol.mail_store.clone(),
            address_book: protocol.address_book.clone(),
        })
    }
}

/// The server understood the request and refused it.
///
/// [MS-OXDSCLI] §2.2.4.1.1.3 — `Error`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerError {
    pub(crate) code: Option<u32>,
    pub(crate) message: Option<String>,
    pub(crate) debug_data: Option<String>,
}

impl ServerError {
    /// The numeric code, such as `600` for a request the server could not act on.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1.3.2 — `ErrorCode`
    #[must_use]
    pub const fn code(&self) -> Option<u32> {
        self.code
    }

    /// The server's own description.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Whatever the server put in `DebugData`.
    #[must_use]
    pub fn debug_data(&self) -> Option<&str> {
        self.debug_data.as_deref()
    }
}

impl core::fmt::Display for ServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match (self.code, self.message()) {
            (Some(code), Some(message)) => write!(f, "Autodiscover error {code}: {message}"),
            (Some(code), None) => write!(f, "Autodiscover error {code}"),
            (None, Some(message)) => write!(f, "Autodiscover error: {message}"),
            (None, None) => f.write_str("Autodiscover error, with no code and no message"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_types_round_trip_through_their_names() {
        for (name, expected) in [
            ("mapiHttp", ProtocolType::MapiHttp),
            ("EXCH", ProtocolType::Exch),
            ("EXPR", ProtocolType::Expr),
            ("WEB", ProtocolType::Web),
        ] {
            assert_eq!(ProtocolType::parse(name), expected);
            assert_eq!(expected.to_string(), name);
        }
    }

    /// A protocol this crate has never heard of still has to survive being read and printed.
    #[test]
    fn an_unknown_protocol_keeps_its_name() {
        let unknown = ProtocolType::parse("EXHTTP");
        assert_eq!(unknown, ProtocolType::Other("EXHTTP".to_owned()));
        assert_eq!(unknown.to_string(), "EXHTTP");
    }

    #[test]
    fn urls_prefer_the_internal_one_but_report_both() {
        let both = Urls {
            internal: Some("https://inside.example/mapi".to_owned()),
            external: Some("https://outside.example/mapi".to_owned()),
        };
        assert_eq!(both.preferred(), both.internal());
        assert_eq!(both.external(), Some("https://outside.example/mapi"));
        assert!(!both.is_empty());

        assert_eq!(Urls::default().preferred(), None);
        assert!(Urls::default().is_empty());
    }

    #[test]
    fn an_endpoint_hands_out_both_url_pairs() {
        let endpoint = MapiHttpEndpoint {
            legacy_dn: "/o=X/cn=y".to_owned(),
            version: 1,
            mail_store: Urls {
                internal: Some("https://inside.example/mapi/emsmdb/".to_owned()),
                external: None,
            },
            address_book: Urls {
                internal: None,
                external: Some("https://outside.example/mapi/nspi/".to_owned()),
            },
        };

        assert_eq!(endpoint.mail_store().internal(), endpoint.mail_store_url());
        assert_eq!(
            endpoint.address_book().external(),
            endpoint.address_book_url()
        );
        assert_eq!(endpoint.legacy_dn(), "/o=X/cn=y");
        assert_eq!(endpoint.version(), 1);
    }

    #[test]
    fn a_server_error_keeps_its_debug_data() {
        let error = ServerError {
            code: Some(600),
            message: Some("Invalid Request".to_owned()),
            debug_data: Some("stack trace".to_owned()),
        };
        assert_eq!(error.debug_data(), Some("stack trace"));
    }
}
