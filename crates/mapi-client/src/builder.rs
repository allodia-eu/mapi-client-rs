//! Everything decided before the first request.

use core::time::Duration;
use std::sync::Arc;

use mapi_proto::{Lcid, LegacyDn};
use reqwest::Url;

use crate::client::{Identity, MapiClient};
use crate::credentials::Credentials;
use crate::error::{Error, Result};
use crate::observer::Observer;
use crate::transport::Transport;

/// How long to wait for a whole request/response exchange.
///
/// A server working on a request holds the connection open and emits a `PENDING` keep-alive every
/// 30 seconds by default, so a timeout has to be a multiple of that to mean anything: this one
/// allows three. Anything shorter measures the keep-alive interval rather than the server.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.5 — `X-PendingPeriod`, default 30000 ms
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);

/// How long to wait for the TCP connection and TLS handshake alone.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// `X-ClientApplication`'s documented format is `Outlook/15.xx.xxxx.xxxx`, and servers parse it as
/// a version, so the default is a value in that shape rather than this crate's own name.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.6 — `X-ClientApplication`
const DEFAULT_CLIENT_APPLICATION: &str = "Outlook/15.00.0847.4040";

/// Builds a [`MapiClient`].
///
/// Two settings have no default and must be given, either directly or by
#[cfg_attr(
    feature = "autodiscover",
    doc = " [`discover`](MapiClientBuilder::discover):"
)]
#[cfg_attr(not(feature = "autodiscover"), doc = " Autodiscover:")]
/// the endpoint URL and the mailbox's `legacyExchangeDN`. They belong together — both name the
/// same mailbox, and Autodiscover hands them over as a pair.
///
/// ```
/// use core::time::Duration;
///
/// use mapi_client::{Credentials, LegacyDn, MapiClient};
///
/// // Autodiscover's MailStore URL and LegacyDN, used exactly as it gave them.
/// let endpoint = "https://mail.example.test/mapi/emsmdb/\
///                 ?MailboxId=00000000-0000-0000-0000-000000000000@example.test";
/// let user_dn = "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=alice";
///
/// let client = MapiClient::builder()
///     .endpoint(endpoint)
///     .user_dn(LegacyDn::new(user_dn)?)
///     .credentials(Credentials::basic("alice@example.test", "hunter2"))
///     .timeout(Duration::from_secs(30))
///     .build()?;
/// # let _ = client;
/// # Ok::<(), mapi_client::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct MapiClientBuilder {
    pub(crate) endpoint: Option<String>,
    pub(crate) user_dn: Option<LegacyDn>,
    pub(crate) credentials: Credentials,
    client_application: String,
    locale: Lcid,
    timeout: Duration,
    connect_timeout: Duration,
    root_certificates: Vec<Vec<u8>>,
    accept_invalid_certificates: bool,
    allow_plaintext_http: bool,
    observer: Option<Arc<dyn Observer>>,
}

impl Default for MapiClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MapiClientBuilder {
    /// A builder carrying the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            endpoint: None,
            user_dn: None,
            credentials: Credentials::None,
            client_application: DEFAULT_CLIENT_APPLICATION.to_owned(),
            locale: Lcid::EN_US,
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            root_certificates: Vec::new(),
            accept_invalid_certificates: false,
            allow_plaintext_http: false,
            observer: None,
        }
    }

    /// The mailbox server endpoint to POST to.
    ///
    /// Use what Autodiscover gave you **verbatim, including the `?MailboxId=` query parameter**.
    /// Exchange answers a URL without it with an empty HTTP 400 carrying no `X-ResponseCode` at
    /// all, which reads like "MAPI is switched off" rather than "your URL is incomplete".
    #[must_use]
    pub fn endpoint(mut self, url: impl Into<String>) -> Self {
        self.endpoint = Some(url.into());
        self
    }

    /// The mailbox's `legacyExchangeDN`.
    ///
    /// Autodiscover's `<User><LegacyDN>`, passed through unchanged. Building one by hand is how a
    /// logon ends up refused with `UnknownUser`, which reads like an authentication failure.
    #[must_use]
    pub fn user_dn(mut self, user_dn: LegacyDn) -> Self {
        self.user_dn = Some(user_dn);
        self
    }

    /// How to authenticate. Defaults to [`Credentials::None`].
    ///
    /// # A connection-oriented scheme changes the transport underneath
    ///
    /// [`Credentials::Ntlm`] and [`Credentials::Negotiate`] authenticate a TCP connection rather
    /// than a request, so choosing one reconfigures the HTTP client this builder produces:
    ///
    /// * **HTTP/1.1 only.** The lab's Exchange negotiates HTTP/2 by ALPN for an anonymous request,
    ///   and a multiplexed connection is not one a Windows-authentication handshake can be bound
    ///   to.
    /// * **One connection per host, and one request at a time.** A handshake whose three legs land
    ///   on different connections cannot complete, and nothing in `reqwest` pins a request to a
    ///   connection — so the pool is pinned and the requests are serialised instead. Cloning the
    ///   client does not get the concurrency back, and could not: two concurrent requests would
    ///   need two authenticated connections.
    /// * **The server certificate is retained**, because the channel binding that satisfies
    ///   Extended Protection is computed over it.
    ///
    /// None of that applies to [`Credentials::Basic`] or [`Credentials::Bearer`], which are a
    /// header and leave the transport alone.
    #[must_use]
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// The locale every Session Context this client opens runs under. Defaults to
    /// [`Lcid::EN_US`].
    ///
    /// This asks for the *session's* treatment of data — collation, above all. It is not the
    /// mailbox's own configured locale and does not become it; folder names come back in whatever
    /// language the mailbox already holds them.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.1 — `LcidSort`, `LcidString`
    #[must_use]
    pub const fn locale(mut self, locale: Lcid) -> Self {
        self.locale = locale;
        self
    }

    /// The `X-ClientApplication` header value, whose documented format is
    /// `Outlook/15.xx.xxxx.xxxx`.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.6
    #[must_use]
    pub fn client_application(mut self, value: impl Into<String>) -> Self {
        self.client_application = value.into();
        self
    }

    /// How long one request/response exchange may take. Defaults to 90 seconds.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How long the TCP connection and TLS handshake may take. Defaults to 15 seconds.
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Trusts one more certificate authority, as PEM or DER, on top of the operating system's own
    /// trust store.
    ///
    /// The usual reason: an on-premises Exchange fronted by a certificate from an internal CA that
    /// the machine running this code does not have installed. Adding the CA here is the safe fix;
    /// [`danger_accept_invalid_certificates`](Self::danger_accept_invalid_certificates) is not.
    ///
    /// # Errors
    ///
    /// Nothing here — the certificate is parsed by [`build`](Self::build), which reports
    /// [`Error::Setup`] if it will not.
    #[must_use]
    pub fn root_certificate(mut self, pem_or_der: impl Into<Vec<u8>>) -> Self {
        self.root_certificates.push(pem_or_der.into());
        self
    }

    /// Accepts any server certificate, valid or not.
    ///
    /// This turns off the check that makes TLS mean anything: with it on, anything that can answer
    /// on the endpoint's address can read the credentials in every request. It exists because a
    /// lab Exchange with a self-signed certificate is a real thing people develop against, and
    /// because the alternative is that they reach for a fork. Prefer
    /// [`root_certificate`](Self::root_certificate), which keeps verification on.
    #[must_use]
    pub const fn danger_accept_invalid_certificates(mut self, accept: bool) -> Self {
        self.accept_invalid_certificates = accept;
        self
    }

    /// Reports every request and the response it produced to an [`Observer`].
    ///
    /// Shared rather than given away, so the caller keeps its handle and can read whatever the
    /// observer collected once the client has finished with it. Clones of the built client share
    /// the same observer; a second call replaces the first, because one set of bytes reported twice
    /// is worse than a knob that does not compose.
    ///
    /// This is how `mapi-cli` captures the fixture corpus, which is the reason it is a supported
    /// part of the API rather than a debugging hook: the capture path and the diagnostic path are
    /// the same path.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use mapi_client::{Exchange, MapiClient, Observer};
    /// # #[derive(Debug)]
    /// # struct Log;
    /// # impl Observer for Log {
    /// #     fn observe(&self, _exchange: &Exchange<'_>) {}
    /// # }
    /// let watcher = Arc::new(Log);
    /// let builder = MapiClient::builder().observer(Arc::clone(&watcher));
    /// // `watcher` is still ours to read afterwards.
    /// # let _ = (builder, watcher);
    /// ```
    ///
    /// Takes the concrete `Arc<O>` rather than an `Arc<dyn Observer>` deliberately: the unsizing
    /// happens here, so a caller does not have to write the `as Arc<dyn Observer>` cast that
    /// `trivial_casts` — denied in this workspace, and in plenty of others — then rejects.
    #[must_use]
    pub fn observer<O: Observer + 'static>(mut self, observer: Arc<O>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Allows an `http://` endpoint.
    ///
    /// Without this, a plaintext endpoint is refused with [`Error::PlaintextEndpoint`] rather than
    /// sending credentials and mailbox contents in the clear. Tests pointing at a local fake
    /// server are the reason it exists.
    #[must_use]
    pub const fn danger_allow_plaintext_http(mut self) -> Self {
        self.allow_plaintext_http = true;
        self
    }

    /// The HTTP client these settings describe.
    ///
    /// Autodiscover runs before there is a [`MapiClient`] to borrow one from, and it has to run
    /// with the same TLS trust and the same timeouts as the session that follows it will.
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] if a certificate will not parse or the TLS backend will not start.
    #[cfg(feature = "autodiscover")]
    pub(crate) fn http(&self) -> Result<reqwest::Client> {
        http_client(
            self.timeout,
            self.connect_timeout,
            &self.root_certificates,
            self.accept_invalid_certificates,
            self.credentials.is_connection_oriented(),
        )
    }

    /// Whether a plaintext URL may be posted to. See
    /// [`danger_allow_plaintext_http`](Self::danger_allow_plaintext_http).
    #[cfg(feature = "autodiscover")]
    pub(crate) const fn allows_plaintext_http(&self) -> bool {
        self.allow_plaintext_http
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// [`Error::MissingSetting`] if the endpoint or the distinguished name was never set,
    /// [`Error::InvalidEndpoint`] or [`Error::PlaintextEndpoint`] if the URL is not one this crate
    /// will POST to, and [`Error::Setup`] if the HTTP client itself cannot be built — a
    /// certificate that will not parse, or a TLS backend that will not start.
    pub fn build(self) -> Result<MapiClient> {
        let endpoint = self.endpoint.ok_or(Error::MissingSetting {
            name: "endpoint",
            how: "MapiClientBuilder::endpoint",
        })?;
        let user_dn = self.user_dn.ok_or(Error::MissingSetting {
            name: "user_dn",
            how: "MapiClientBuilder::user_dn",
        })?;
        let endpoint = parse_endpoint(&endpoint, self.allow_plaintext_http)?;

        let http = http_client(
            self.timeout,
            self.connect_timeout,
            &self.root_certificates,
            self.accept_invalid_certificates,
            self.credentials.is_connection_oriented(),
        )?;

        Ok(MapiClient {
            transport: Transport {
                http,
                endpoint,
                credentials: self.credentials,
                timeout: self.timeout,
                observer: self.observer,
                #[cfg(feature = "ntlm")]
                connection: Arc::default(),
            },
            identity: Identity::new(),
            user_dn,
            locale: self.locale,
            client_application: self.client_application,
        })
    }
}

/// Builds the underlying HTTP client.
///
/// Redirects are **not** followed. A MAPI endpoint has no reason to redirect, and following one
/// would mean deciding whether to carry the `Authorization` header to wherever it points. A 3xx is
/// reported as [`Error::Http`] instead, which says where the server tried to send us.
///
/// `connection_oriented` says whether the credentials authenticate a connection rather than a
/// request, which changes three settings. See
/// [`MapiClientBuilder::credentials`](MapiClientBuilder::credentials) for what and why.
pub(crate) fn http_client(
    timeout: Duration,
    connect_timeout: Duration,
    root_certificates: &[Vec<u8>],
    accept_invalid_certificates: bool,
    connection_oriented: bool,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(connect_timeout)
        .danger_accept_invalid_certs(accept_invalid_certificates);

    if connection_oriented {
        builder = builder
            .http1_only()
            .pool_max_idle_per_host(1)
            .tls_info(true);
    }

    for certificate in root_certificates {
        let certificate = reqwest::Certificate::from_pem(certificate)
            .or_else(|_| reqwest::Certificate::from_der(certificate))
            .map_err(|error| Error::Setup {
                source: Box::new(error),
            })?;
        builder = builder.add_root_certificate(certificate);
    }

    builder.build().map_err(|error| Error::Setup {
        source: Box::new(error),
    })
}

/// Checks the endpoint URL before anything is sent to it.
///
/// There is deliberately no separate host check. `http` and `https` are what the URL standard
/// calls special schemes, and parsing rejects one of those with an empty host before this gets a
/// say — so a check here would be a branch that can never run.
pub(crate) fn parse_endpoint(url: &str, allow_plaintext_http: bool) -> Result<Url> {
    let parsed = Url::parse(url).map_err(|_| Error::InvalidEndpoint {
        url: url.to_owned(),
        reason: "not an absolute URL with a host",
    })?;

    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if allow_plaintext_http => Ok(parsed),
        "http" => Err(Error::PlaintextEndpoint {
            url: url.to_owned(),
        }),
        _ => Err(Error::InvalidEndpoint {
            url: url.to_owned(),
            reason: "the scheme must be https",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_endpoints_are_accepted_and_kept_verbatim() {
        let url = "https://mail.example.test/mapi/emsmdb/?MailboxId=abc@example.test";
        let parsed = parse_endpoint(url, false).unwrap();
        assert_eq!(parsed.as_str(), url);
        assert_eq!(parsed.query(), Some("MailboxId=abc@example.test"));
    }

    /// The rule that stops a password reaching the wire in the clear, and the one escape hatch.
    #[test]
    fn plaintext_is_refused_unless_it_was_asked_for() {
        let url = "http://localhost:8080/mapi/emsmdb/";
        assert!(matches!(
            parse_endpoint(url, false),
            Err(Error::PlaintextEndpoint { .. })
        ));
        assert!(parse_endpoint(url, true).is_ok());
    }

    /// Anything that is not an absolute `http`/`https` URL with a host, including the two shapes a
    /// caller is most likely to reach for by mistake: a bare path and a scheme-less host.
    ///
    /// Note what is *not* here: `https:///mapi/emsmdb/`. The URL standard collapses the extra
    /// slash and reads `mapi` as the host, which is a perfectly good single-label intranet name —
    /// so it is accepted, and a check for "no host" after a successful parse of a special scheme
    /// would be a branch that never runs.
    #[test]
    fn anything_that_is_not_an_http_url_is_refused() {
        for url in [
            "ftp://mail.example.test/mapi",
            "file:///etc/passwd",
            "/mapi/emsmdb/",
            "mail.example.test/mapi",
            "https://",
            "",
        ] {
            assert!(
                matches!(
                    parse_endpoint(url, true),
                    Err(Error::InvalidEndpoint { .. })
                ),
                "{url} was accepted"
            );
        }
    }

    #[test]
    fn the_two_settings_with_no_default_are_reported_by_name() {
        let missing_both = MapiClientBuilder::new().build();
        assert!(matches!(
            missing_both,
            Err(Error::MissingSetting {
                name: "endpoint",
                ..
            })
        ));

        let missing_dn = MapiClientBuilder::default()
            .endpoint("https://mail.example.test/mapi/emsmdb/")
            .build();
        assert!(matches!(
            missing_dn,
            Err(Error::MissingSetting {
                name: "user_dn",
                ..
            })
        ));
    }

    /// The reason this knob exists: an on-premises Exchange fronted by a certificate from an
    /// organisation's own CA, on a machine that does not have that CA installed.
    ///
    /// Both shapes a CA gets handed out in are accepted, and the same throwaway certificate is
    /// committed in each so that this is a statement about real certificate bytes.
    #[test]
    fn a_real_certificate_authority_is_accepted_as_pem_or_der() {
        for certificate in [
            include_bytes!("../tests/example-ca.pem").to_vec(),
            include_bytes!("../tests/example-ca.der").to_vec(),
        ] {
            let client = MapiClientBuilder::new()
                .endpoint("https://mail.example.test/mapi/emsmdb/")
                .user_dn(LegacyDn::new("/o=Example/cn=alice").unwrap())
                .root_certificate(certificate)
                .build();
            assert!(client.is_ok(), "{client:?}");
        }
    }

    /// Every knob at once, which is the only way to notice one that stopped being wired up.
    #[test]
    fn every_setting_reaches_the_client() {
        let client = MapiClientBuilder::new()
            .endpoint("https://mail.example.test/mapi/emsmdb/?MailboxId=x@example.test")
            .user_dn(LegacyDn::new("/o=Example/cn=alice").unwrap())
            .credentials(Credentials::bearer("a-token"))
            .locale(Lcid::new(0x0413))
            .client_application("Outlook/15.00.0000.0000")
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(1))
            .danger_accept_invalid_certificates(true)
            .build()
            .expect("a client");

        assert_eq!(
            client.endpoint(),
            "https://mail.example.test/mapi/emsmdb/?MailboxId=x@example.test"
        );
        assert_eq!(client.user_dn().as_str(), "/o=Example/cn=alice");
    }

    #[test]
    fn a_certificate_that_will_not_parse_is_reported_as_a_setup_failure() {
        let broken = MapiClientBuilder::new()
            .endpoint("https://mail.example.test/mapi/emsmdb/")
            .user_dn(LegacyDn::new("/o=Example/cn=alice").unwrap())
            .root_certificate(b"-----BEGIN CERTIFICATE-----\nnot a certificate\n".to_vec())
            .build();
        assert!(matches!(broken, Err(Error::Setup { .. })), "{broken:?}");
    }

    /// A builder is a value, and a client built from one carries no secret into its `Debug`.
    #[test]
    fn debug_output_carries_no_secret() {
        let builder = MapiClientBuilder::new()
            .endpoint("https://mail.example.test/mapi/emsmdb/")
            .user_dn(LegacyDn::new("/o=Example/cn=alice").unwrap())
            .credentials(Credentials::basic("alice", "hunter2"));
        assert!(!format!("{builder:?}").contains("hunter2"));
        assert!(!format!("{:?}", builder.build().unwrap()).contains("hunter2"));
    }
}
