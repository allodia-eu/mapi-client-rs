//! Where Autodiscover lets itself be sent, and how it says so.
//!
//! A redirect decides where the next request goes, and with it the credentials if that request is
//! challenged. So each kind is checked before it is followed, and each one followed is reported to
//! the observer. The plain-HTTP probe's redirect is not followed at all; that needs a resolver to
//! test and is tested beside the search itself, in `src/discovery/tests.rs`.
//!
//! [MS-OXDSCLI] §3.1.5.2 — HTTP 302 redirects
//! [MS-OXDSCLI] §3.1.5.3 — `redirectAddr` and `redirectUrl`

#![cfg(feature = "autodiscover")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a test asserting a known shape says something true about it"
)]

use core::time::Duration;
use std::sync::{Arc, Mutex};

use mapi_client::{
    Credentials, EmailAddress, Error, Exchange, MapiClient, MapiClientBuilder, Observer, Redirect,
    RedirectKind,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A settings response for a fictional deployment, in the shape Exchange sends one.
const SETTINGS: &str = include_str!("autodiscover-settings.xml");

const PATH: &str = "/Autodiscover/Autodiscover.xml";

fn address() -> EmailAddress {
    EmailAddress::new("alice@example.test").unwrap()
}

/// Every redirect reported, as (kind, from, to).
#[derive(Debug, Default)]
struct Hops(Mutex<Vec<(RedirectKind, String, String)>>);

impl Observer for Hops {
    fn observe(&self, _: &Exchange<'_>) {}

    fn redirected(&self, redirect: &Redirect<'_>) {
        self.0.lock().unwrap().push((
            redirect.kind(),
            redirect.from().to_owned(),
            redirect.to().to_owned(),
        ));
    }
}

fn builder(hops: &Arc<Hops>) -> MapiClientBuilder {
    MapiClient::builder()
        .credentials(Credentials::basic("alice@example.test", "hunter2"))
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_millis(500))
        .observer(Arc::clone(hops))
        .danger_allow_plaintext_http()
}

/// A service answering a POST to `at` with `response`.
async fn mount(server: &MockServer, at: &str, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path(at))
        .respond_with(response)
        .mount(server)
        .await;
}

fn body(xml: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_string(xml)
        .append_header("Content-Type", "text/xml; charset=utf-8")
}

/// [MS-OXDSCLI] §3.1.5.2: a 302 in answer to the POST means "repost the request to the
/// redirection URL contained in the Location header" — a relative one resolved against the URL it
/// answered — and the hop is reported.
#[tokio::test]
async fn a_302_to_the_post_is_followed_and_reported() {
    let server = MockServer::start().await;
    mount(
        &server,
        PATH,
        ResponseTemplate::new(302).append_header("Location", "/elsewhere/Autodiscover.xml"),
    )
    .await;
    mount(&server, "/elsewhere/Autodiscover.xml", body(SETTINGS)).await;

    let hops = Arc::new(Hops::default());
    let from = format!("{}{PATH}", server.uri());
    let endpoint = builder(&hops).lookup_at(&from, &address()).await.unwrap();

    assert!(endpoint.legacy_dn().ends_with("cn=alice"));
    let to = format!("{}/elsewhere/Autodiscover.xml", server.uri());
    assert_eq!(*hops.0.lock().unwrap(), [(RedirectKind::Http, from, to)]);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() == "POST")
    );
}

/// Only a 302 is the redirect §3.1.5.2 names. Anything else in the 3xx range is a candidate that
/// did not answer, like any other status that is not a success.
#[tokio::test]
async fn another_3xx_is_not_followed() {
    let server = MockServer::start().await;
    mount(
        &server,
        PATH,
        ResponseTemplate::new(307).append_header("Location", "/elsewhere/Autodiscover.xml"),
    )
    .await;

    let hops = Arc::new(Hops::default());
    let url = format!("{}{PATH}", server.uri());
    let error = builder(&hops)
        .lookup_at(&url, &address())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::NoEndpoint { .. }), "{error:?}");
    assert!(hops.0.lock().unwrap().is_empty());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// A 302 to a URL this crate would not ask is not followed either: here a scheme that is neither
/// `https` nor the plain HTTP the builder was told to allow.
#[tokio::test]
async fn a_302_to_a_url_that_is_not_asked_is_not_followed() {
    let server = MockServer::start().await;
    mount(
        &server,
        PATH,
        ResponseTemplate::new(302).append_header("Location", "ftp://example.test/Autodiscover.xml"),
    )
    .await;

    let hops = Arc::new(Hops::default());
    let url = format!("{}{PATH}", server.uri());
    let error = builder(&hops)
        .lookup_at(&url, &address())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::NoEndpoint { .. }), "{error:?}");
    assert!(hops.0.lock().unwrap().is_empty(), "nothing was followed");
}

/// `redirectUrl` and `redirectAddr` are each reported as the hop they are, in the order taken.
#[tokio::test]
async fn redirect_url_and_redirect_addr_are_reported() {
    let server = MockServer::start().await;
    let real = format!("{}/real{PATH}", server.uri());
    mount(
        &server,
        PATH,
        body(&format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <Action>redirectUrl</Action>
      <RedirectUrl>{real}</RedirectUrl>
    </Account>
  </Response>
</Autodiscover>"#
        )),
    )
    .await;
    mount(
        &server,
        &format!("/real{PATH}"),
        body(
            r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <Action>redirectAddr</Action>
      <RedirectAddr>alice@moved.invalid</RedirectAddr>
    </Account>
  </Response>
</Autodiscover>"#,
        ),
    )
    .await;

    let hops = Arc::new(Hops::default());
    let from = format!("{}{PATH}", server.uri());
    let _ = builder(&hops).lookup_at(&from, &address()).await;

    assert_eq!(
        *hops.0.lock().unwrap(),
        [
            (RedirectKind::Url, from, real.clone()),
            (
                RedirectKind::Address,
                real,
                "alice@moved.invalid".to_owned()
            ),
        ]
    );
}
