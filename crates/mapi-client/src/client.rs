//! The client: what a caller holds, and what it can start.

use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use mapi_proto::{Lcid, LegacyDn, Outcome, Session};

use crate::builder::MapiClientBuilder;
use crate::connection::Connection;
use crate::describe;
use crate::error::{Error, Result};
use crate::transport::Transport;

/// The identity a *client instance* carries across every Session Context it opens.
///
/// Two headers want two different kinds of uniqueness, and reading them as the same thing is an
/// easy mistake to make:
///
/// * `X-ClientInfo`'s GUID must be unique across client *instances* and identical for every request
///   one instance makes — so it is generated here, once. Its counter must **differ for each new
///   Session Context**, which is what [`Identity::next_session`] is for.
/// * `X-RequestId`'s GUID must be unique across *Session Contexts* and must not change for the life
///   of one, so it is generated per connection rather than here.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.2 — `X-RequestId`
/// [MS-OXCMAPIHTTP] §2.2.3.3.4 — `X-ClientInfo`
#[derive(Debug)]
pub(crate) struct Identity {
    guid: String,
    sessions: AtomicU64,
}

impl Identity {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            guid: guid(),
            sessions: AtomicU64::new(0),
        })
    }

    /// The `X-ClientInfo` value for a new Session Context.
    fn next_session(&self) -> String {
        let counter = self.sessions.fetch_add(1, Ordering::Relaxed);
        format!("{}:{counter}", self.guid)
    }
}

/// A GUID in the brace-delimited form the header examples use.
fn guid() -> String {
    format!("{{{}}}", uuid::Uuid::new_v4())
}

/// A client for one mailbox's MAPI/HTTP endpoint.
///
/// Cheap to clone — clones share one HTTP connection pool and one client identity — and every
/// clone can open its own Session Context.
///
/// ```no_run
/// use mapi_client::{Credentials, LegacyDn, MapiClient, WellKnownFolder};
///
/// # async fn example() -> Result<(), mapi_client::Error> {
/// let endpoint = "https://mail.example.test/mapi/emsmdb/\
///                 ?MailboxId=00000000-0000-0000-0000-000000000000@example.test";
/// let user_dn = "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=alice";
///
/// let client = MapiClient::builder()
///     .endpoint(endpoint)
///     .user_dn(LegacyDn::new(user_dn)?)
///     .credentials(Credentials::basic("alice@example.test", "hunter2"))
///     .build()?;
///
/// let mut logon = client.connect().await?.logon().await?;
/// let mut rows = logon.well_known(WellKnownFolder::Inbox)?.contents().rows();
///
/// while let Some(row) = rows.try_next().await? {
///     println!("{:?}", row.string(mapi_client::PropertyTag::SUBJECT));
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct MapiClient {
    pub(crate) transport: Transport,
    pub(crate) identity: Arc<Identity>,
    pub(crate) user_dn: LegacyDn,
    pub(crate) locale: Lcid,
    pub(crate) client_application: String,
}

impl MapiClient {
    /// Starts configuring a client.
    #[must_use]
    pub fn builder() -> MapiClientBuilder {
        MapiClientBuilder::new()
    }

    /// The endpoint this client posts to.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        self.transport.endpoint.as_str()
    }

    /// The distinguished name this client logs on as.
    #[must_use]
    pub const fn user_dn(&self) -> &LegacyDn {
        &self.user_dn
    }

    /// Establishes a Session Context.
    ///
    /// One round trip. The [`Connection`] that comes back owns the session's cookies and its
    /// sequencing, and is the only thing that can run ROPs.
    ///
    /// # Errors
    ///
    /// [`Error::Unauthorized`] if the credentials were refused, [`Error::Connect`] or
    /// [`Error::Timeout`] if the endpoint could not be reached, and [`Error::Protocol`] carrying
    /// `ConnectFailed` if the server refused the distinguished name — which it also does when the
    /// authenticated account has no rights to that mailbox.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1 — `Connect`
    pub async fn connect(&self) -> Result<Connection> {
        let mut session = self.session();
        let request = session.begin_connect(&self.user_dn)?;
        let (headers, body) = self.transport.send(&request).await?;

        match session.on_response(&headers, &body)? {
            Outcome::Connected(connected) => Ok(Connection::new(
                self.transport.clone(),
                session,
                connected,
                self.user_dn.clone(),
            )),
            other => Err(Error::Unexpected {
                expected: "a Connect response",
                found: describe(&other),
            }),
        }
    }

    /// Asks the endpoint whether it is there, without establishing anything.
    ///
    /// The cheapest possible check that the URL is right, that the credentials work and that
    /// whatever answers speaks MAPI/HTTP.
    ///
    /// # Errors
    ///
    /// [`Error::Unauthorized`], [`Error::Connect`], [`Error::Timeout`] or [`Error::Http`] —
    /// whichever of them the endpoint's answer amounts to.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.6 — `PING`
    pub async fn ping(&self) -> Result<()> {
        let mut session = self.session();
        let request = session.begin_ping()?;
        let (headers, body) = self.transport.send(&request).await?;

        match session.on_response(&headers, &body)? {
            Outcome::Pong => Ok(()),
            other => Err(Error::Unexpected {
                expected: "a PING response",
                found: describe(&other),
            }),
        }
    }

    /// A session carrying this client's identity, ready for its first request.
    fn session(&self) -> Session {
        Session::builder()
            .locale(self.locale)
            .client_application(self.client_application.clone())
            .client_info(self.identity.next_session())
            .request_guid(guid())
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Arc<Identity> {
        Identity::new()
    }

    #[test]
    fn a_guid_has_the_shape_the_header_examples_show() {
        let value = guid();
        assert!(value.starts_with('{') && value.ends_with('}'), "{value}");
        assert_eq!(value.len(), 38);
        assert_ne!(guid(), guid(), "every GUID is its own");
    }

    /// The specification's rule, and the reason `X-ClientInfo` is not simply a constant: the GUID
    /// is the client instance's and never changes; the counter after it must differ for every new
    /// Session Context.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.4
    #[test]
    fn client_info_keeps_the_guid_and_moves_the_counter() {
        let identity = identity();
        let first = identity.next_session();
        let second = identity.next_session();

        let guid_of = |value: &str| value.rsplit_once(':').map(|(g, _)| g.to_owned()).unwrap();
        assert_eq!(guid_of(&first), guid_of(&second));
        assert_ne!(first, second);
        assert!(
            first.ends_with(":0") && second.ends_with(":1"),
            "{first} {second}"
        );
    }

    /// Clones share one identity, so two connections opened through two clones still count as one
    /// client instance with two sessions.
    #[test]
    fn clones_share_the_client_instance_identity() {
        let identity = identity();
        let clone = Arc::clone(&identity);
        assert!(identity.next_session().ends_with(":0"));
        assert!(clone.next_session().ends_with(":1"));
    }
}
