//! Driving Autodiscover against a fake service.
//!
//! The candidate-URL sequence itself is `mapi-autodiscover`'s and is tested there. What is tested
//! here is the part that needs a network: which answers end the search, which ones send it
//! somewhere else, and which ones mean "try the next candidate".

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a test asserting a known shape says something true about it"
)]

mod support;

use core::time::Duration;

use mapi_client::{Credentials, EmailAddress, Error, MapiClient};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A settings response for a fictional deployment, in the shape Exchange sends one.
const SETTINGS: &str = include_str!("autodiscover-settings.xml");

/// The `MailStore` URL that fixture carries.
const MAIL_STORE_URL: &str = "https://mail.example.test/mapi/emsmdb/\
                              ?MailboxId=00000000-0000-0000-0000-000000000000@example.test";

fn address() -> EmailAddress {
    EmailAddress::new("alice@example.test").unwrap()
}

/// A builder carrying credentials and a tolerance for the fake service's plaintext URL.
fn builder() -> mapi_client::MapiClientBuilder {
    MapiClient::builder()
        .credentials(Credentials::basic("alice@example.test", "hunter2"))
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(2))
        .danger_allow_plaintext_http()
}

/// An Autodiscover service that answers everything with one body.
async fn service(body: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(body)
                .append_header("Content-Type", "text/xml; charset=utf-8"),
        )
        .mount(&server)
        .await;
    server
}

/// A response asking for a redirect. [MS-OXDSCLI] §2.2.4.1.1.2.2 — `Action`
fn redirect_to_url(url: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <Action>redirectUrl</Action>
      <RedirectUrl>{url}</RedirectUrl>
    </Account>
  </Response>
</Autodiscover>"#
    )
}

/// The everything-works path, from an address to a URL and a distinguished name.
#[tokio::test]
async fn a_settings_response_ends_the_search() {
    let server = service(SETTINGS).await;
    let url = format!("{}/Autodiscover/Autodiscover.xml", server.uri());

    let endpoint = builder().lookup_at(&url, &address()).await.unwrap();

    assert_eq!(endpoint.mail_store_url(), Some(MAIL_STORE_URL));
    assert!(endpoint.legacy_dn().ends_with("cn=alice"));
    assert_eq!(endpoint.version(), 1);

    // The header without which the answer would not have carried a mapiHttp block at all.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers.get("X-MapiHttpCapability").unwrap(),
        &"1".to_owned()
    );
    assert!(requests[0].headers.get("Authorization").is_some());
}

/// `redirectUrl` means "ask over there instead", and the answer over there is the one that counts.
#[tokio::test]
async fn a_redirect_is_followed_to_the_url_it_names() {
    let real = service(SETTINGS).await;
    let real_url = format!("{}/Autodiscover/Autodiscover.xml", real.uri());
    let front = service(&redirect_to_url(&real_url)).await;

    let endpoint = builder()
        .lookup_at(
            format!("{}/Autodiscover/Autodiscover.xml", front.uri()),
            &address(),
        )
        .await
        .unwrap();

    assert!(endpoint.legacy_dn().ends_with("cn=alice"));
    assert_eq!(front.received_requests().await.unwrap().len(), 1);
    assert_eq!(real.received_requests().await.unwrap().len(), 1);
}

/// A deployment that redirects to itself describes a loop, and following it forever is not an
/// option worth having.
#[tokio::test]
async fn a_redirect_loop_is_refused_rather_than_followed() {
    let server = MockServer::start().await;
    let url = format!("{}/Autodiscover/Autodiscover.xml", server.uri());
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(redirect_to_url(&url)))
        .mount(&server)
        .await;

    let error = builder()
        .lookup_at(&url, &address())
        .await
        .expect_err("a loop is not an endpoint");

    assert!(
        matches!(error, Error::TooManyRedirects { limit: 10 }),
        "{error:?}"
    );
    // Ten hops followed, and the eleventh refused before it was sent.
    assert_eq!(server.received_requests().await.unwrap().len(), 11);
}

/// A server that answers with an `<Error>` element has understood the question and declined it,
/// and the documented reaction is to try the next candidate rather than to give up.
///
/// [MS-OXDSCLI] §3.1.5.5
#[tokio::test]
async fn a_server_error_is_not_the_end_of_the_search() {
    let refused = r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Error Time="12:00:00.000" Id="1234">
      <ErrorCode>600</ErrorCode>
      <Message>Invalid Request</Message>
      <DebugData />
    </Error>
  </Response>
</Autodiscover>"#;
    let server = service(refused).await;
    let url = format!("{}/Autodiscover/Autodiscover.xml", server.uri());

    let error = builder().lookup_at(&url, &address()).await.unwrap_err();
    let Error::NoEndpoint { address, tried } = &error else {
        panic!("expected NoEndpoint, got {error:?}");
    };
    assert_eq!(address, "alice@example.test");
    assert_eq!(tried, &[url]);
}

/// The first candidate URL is often just the organisation's website. Whatever it answers with is
/// one more candidate that did not answer, not a failure of the search.
#[tokio::test]
async fn a_url_that_is_not_autodiscover_at_all_is_skipped() {
    let server = service("<html><body>Welcome to Example</body></html>").await;
    let url = format!("{}/Autodiscover/Autodiscover.xml", server.uri());

    let error = builder().lookup_at(&url, &address()).await.unwrap_err();
    assert!(matches!(error, Error::NoEndpoint { .. }), "{error:?}");
}

/// A service that refuses the credentials has not been found wanting for candidates: it is there,
/// and it said no. Grinding on would replace a diagnosis with a shrug.
#[tokio::test]
async fn refused_credentials_stop_the_search_and_say_so() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(401).append_header("WWW-Authenticate", "Basic realm=\"x\""),
        )
        .mount(&server)
        .await;

    let error = builder()
        .lookup_at(
            format!("{}/Autodiscover/Autodiscover.xml", server.uri()),
            &address(),
        )
        .await
        .unwrap_err();

    let Error::Unauthorized { offered, sent, .. } = &error else {
        panic!("expected Unauthorized, got {error:?}");
    };
    assert_eq!(offered, &["Basic"]);
    assert_eq!(*sent, "Basic credentials");
}

/// The same rule the endpoint itself is held to: credentials do not go out in the clear unless
/// somebody said so. A candidate that would break it is skipped, not sent to.
#[tokio::test]
async fn a_plaintext_candidate_is_skipped_unless_plaintext_was_allowed() {
    let server = service(SETTINGS).await;
    let url = format!("{}/Autodiscover/Autodiscover.xml", server.uri());

    let error = MapiClient::builder()
        .credentials(Credentials::basic("alice@example.test", "hunter2"))
        .lookup_at(&url, &address())
        .await
        .unwrap_err();

    assert!(matches!(error, Error::NoEndpoint { .. }), "{error:?}");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "nothing should have been sent to a plaintext URL"
    );
}

/// The documented candidate sequence, and the plain-HTTP redirect probe that follows it: the
/// domain itself first, then its `autodiscover.` subdomain, and only then the probe.
///
/// A domain in the reserved `.invalid` top-level domain resolves nowhere, so every step fails —
/// which is the point. What is being asserted is the order and completeness of the search, and
/// that a search which finds nothing says what it looked at.
///
/// [MS-OXDISCO] §3.1.5.2 — locations found directly from the email domain
#[tokio::test]
async fn the_candidate_urls_are_tried_in_the_documented_order() {
    let address = EmailAddress::new("alice@nothing-here.invalid").unwrap();
    let error = builder()
        .connect_timeout(Duration::from_millis(500))
        .lookup(&address)
        .await
        .unwrap_err();

    let Error::NoEndpoint { tried, .. } = &error else {
        panic!("expected NoEndpoint, got {error:?}");
    };
    assert_eq!(
        tried,
        &[
            "https://nothing-here.invalid/Autodiscover/Autodiscover.xml".to_owned(),
            "https://autodiscover.nothing-here.invalid/Autodiscover/Autodiscover.xml".to_owned(),
        ]
    );

    // `discover` is `lookup` plus building a client, so it fails the same way.
    let error = builder()
        .connect_timeout(Duration::from_millis(500))
        .discover(&address)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NoEndpoint { .. }), "{error:?}");
}

/// Autodiscover authenticates separately from the MAPI endpoint, so it has to carry whatever the
/// client was given — including nothing at all.
#[tokio::test]
async fn the_lookup_carries_the_clients_own_credentials() {
    let server = service(SETTINGS).await;
    let url = format!("{}/Autodiscover/Autodiscover.xml", server.uri());

    MapiClient::builder()
        .credentials(Credentials::bearer("a-token"))
        .danger_allow_plaintext_http()
        .lookup_at(&url, &address())
        .await
        .unwrap();

    MapiClient::builder()
        .danger_allow_plaintext_http()
        .lookup_at(&url, &address())
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests[0].headers.get("Authorization").unwrap(),
        &"Bearer a-token".to_owned()
    );
    assert!(requests[1].headers.get("Authorization").is_none());
}

/// `redirectAddr` restarts the search for a different address, which means a different domain and
/// therefore a fresh candidate list.
///
/// [MS-OXDSCLI] §3.1.5.3
#[tokio::test]
async fn a_redirected_address_starts_the_candidate_list_again() {
    let redirect = r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <Action>redirectAddr</Action>
      <RedirectAddr>alice@moved.invalid</RedirectAddr>
    </Account>
  </Response>
</Autodiscover>"#;
    let server = service(redirect).await;
    let url = format!("{}/Autodiscover/Autodiscover.xml", server.uri());

    let error = builder()
        .connect_timeout(Duration::from_millis(500))
        .lookup_at(&url, &address())
        .await
        .unwrap_err();

    let Error::NoEndpoint { address, tried } = &error else {
        panic!("expected NoEndpoint, got {error:?}");
    };
    assert_eq!(address, "alice@moved.invalid", "the search moved address");
    assert_eq!(
        tried,
        &[
            url,
            "https://moved.invalid/Autodiscover/Autodiscover.xml".to_owned(),
            "https://autodiscover.moved.invalid/Autodiscover/Autodiscover.xml".to_owned(),
        ],
        "the new domain's candidates were tried, in the documented order"
    );
}
