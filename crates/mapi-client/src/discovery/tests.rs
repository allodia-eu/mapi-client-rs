//! The handover from a discovered endpoint to a client, and the redirect limit.

use mapi_autodiscover::{AutodiscoverResponse, Settings};

use super::*;

/// The `MailStore` URL the fixture carries, which is what a discovered client must post to.
const MAIL_STORE_URL: &str = "https://mail.example.test/mapi/emsmdb/\
                              ?MailboxId=00000000-0000-0000-0000-000000000000@example.test";

fn settings_from(xml: &str) -> Settings {
    match AutodiscoverResponse::parse(xml) {
        Ok(AutodiscoverResponse::Settings(settings)) => settings,
        other => panic!("the fixture is a settings response, not {other:?}"),
    }
}

fn settings() -> Settings {
    settings_from(include_str!("../../tests/autodiscover-settings.xml"))
}

fn address() -> EmailAddress {
    EmailAddress::new("alice@example.test").expect("a valid address")
}

/// The handover: what Autodiscover said becomes the endpoint and the distinguished name, which
/// are precisely the two settings a client cannot be built without.
#[test]
fn a_discovered_endpoint_fills_in_both_settings_that_have_no_default() {
    let endpoint = settings().mapi_http().expect("the fixture offers mapiHttp");
    let client = MapiClient::builder()
        .for_endpoint(&endpoint, &address())
        .expect("a client");

    assert_eq!(client.endpoint(), MAIL_STORE_URL);
    assert!(client.user_dn().as_str().ends_with("cn=alice"));
    assert!(
        endpoint
            .address_book_url()
            .is_some_and(|url| url.contains("/nspi/")),
        "the address book URL is carried through for whoever needs it"
    );
}

/// A `mapiHttp` block with no `MailStore` URL describes nothing this crate can connect to, and
/// saying so beats building a client that cannot work.
#[test]
fn an_endpoint_with_no_mail_store_url_is_refused() {
    let xml = include_str!("../../tests/autodiscover-settings.xml")
        .replace("<MailStore>", "<MailStore><!--")
        .replace("</MailStore>", "--></MailStore>");
    let endpoint = settings_from(&xml)
        .mapi_http()
        .expect("still offers mapiHttp");

    let error = MapiClient::builder()
        .for_endpoint(&endpoint, &address())
        .expect_err("no URL to connect to");
    assert!(matches!(error, Error::NoEndpoint { .. }), "{error:?}");
}

#[test]
fn a_redirect_chain_is_followed_up_to_the_limit_and_then_refused() {
    let mut count = 0;
    for _ in 0..MAX_REDIRECTS {
        count = bump(count).expect("within the limit");
    }
    assert_eq!(count, MAX_REDIRECTS);
    assert!(matches!(
        bump(count),
        Err(Error::TooManyRedirects {
            limit: MAX_REDIRECTS
        })
    ));
}

/// The plain-HTTP probe, over a network where every name below resolves to one fake service.
///
/// The probe's URL is fixed by the address — `http://autodiscover.<domain>/…` on port 80 — so
/// reaching a fake with it takes a resolver override, which only a test inside the crate can give
/// the search.
mod probe {
    use std::collections::VecDeque;

    use wiremock::matchers::{header_exists, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::credentials::Credentials;

    /// An HTTP client that sends every host the tests name to `server`.
    fn http(server: &MockServer) -> Client {
        let at = *server.address();
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(core::time::Duration::from_millis(500))
            .resolve("autodiscover.example.test", at)
            .resolve("example.test", at)
            .resolve("elsewhere.test", at)
            .build()
            .unwrap()
    }

    fn builder() -> MapiClientBuilder {
        MapiClient::builder()
            .credentials(Credentials::basic("alice@example.test", "hunter2"))
            .danger_allow_plaintext_http()
    }

    /// A probe answered with `status` and a `Location` on another host, and a service there that
    /// challenges for Basic and answers once it has it.
    async fn network(status: u16) -> (MockServer, String) {
        let server = MockServer::start().await;
        let location = format!(
            "http://elsewhere.test:{}/Autodiscover/Autodiscover.xml",
            server.address().port()
        );
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(status).append_header("Location", &location))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header_exists("Authorization"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(include_str!("../../tests/autodiscover-settings.xml")),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).append_header("WWW-Authenticate", "Basic"))
            .mount(&server)
            .await;
        (server, location)
    }

    /// [MS-OXDISCO] §3.1.5.4: "prompt the user to warn them of the redirection. If the user
    /// accepts, the new location is added". With nobody asked, nothing goes to the new location —
    /// no request at all, so no credentials — and the search ends saying where it would have gone.
    #[tokio::test]
    async fn a_probe_redirect_is_not_followed_without_the_callers_decision() {
        let (server, location) = network(302).await;
        let builder = builder();

        let error = builder
            .search_with(
                http(&server),
                &address(),
                candidate_urls(&address()).collect(),
                true,
            )
            .await
            .unwrap_err();

        let Error::RedirectNeedsConsent {
            address: asked,
            from,
            location: offered,
            tried,
        } = &error
        else {
            panic!("expected RedirectNeedsConsent, got {error:?}");
        };
        assert_eq!(asked, "alice@example.test");
        assert_eq!(
            from,
            "http://autodiscover.example.test/Autodiscover/Autodiscover.xml"
        );
        assert_eq!(offered, &location);
        assert_eq!(tried.len(), 2, "both candidates, then the probe");

        let requests = server.received_requests().await.unwrap();
        assert!(!requests.is_empty(), "the probe was asked");
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() == "GET")
        );
        assert!(
            requests
                .iter()
                .all(|request| !request.headers.contains_key("Authorization"))
        );
    }

    /// The caller's decision is a lookup at the location the error named, which then authenticates
    /// as any candidate does: asked first, sent credentials only once challenged.
    #[tokio::test]
    async fn a_probe_redirect_the_caller_accepts_is_asked_like_any_candidate() {
        let (server, location) = network(302).await;
        let builder = builder();

        let found = builder
            .search_with(http(&server), &address(), VecDeque::from([location]), false)
            .await
            .unwrap();
        assert!(found.settings.mapi_http().is_some());

        let posts: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method.as_str() == "POST")
            .collect();
        assert_eq!(posts.len(), 2);
        assert!(!posts[0].headers.contains_key("Authorization"));
        assert!(posts[1].headers.contains_key("Authorization"));
    }

    /// A candidate whose 401 asks only for a scheme these credentials are not cannot be used, and
    /// was sent nothing: [MS-OXDSCLI] §3.1.5.1's nonfunctional URI, so the next one is asked.
    #[tokio::test]
    async fn a_candidate_asking_for_another_scheme_is_passed_over() {
        use wiremock::matchers::path;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/sso/Autodiscover.xml"))
            .respond_with(ResponseTemplate::new(401).append_header("WWW-Authenticate", "Negotiate"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/mail/Autodiscover.xml"))
            .and(header_exists("Authorization"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(include_str!("../../tests/autodiscover-settings.xml")),
            )
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/mail/Autodiscover.xml"))
            .respond_with(ResponseTemplate::new(401).append_header("WWW-Authenticate", "Basic"))
            .mount(&server)
            .await;
        let queue = ["sso", "mail"]
            .map(|at| format!("{}/{at}/Autodiscover.xml", server.uri()))
            .into();

        let found = builder()
            .search_with(http(&server), &address(), queue, false)
            .await
            .unwrap();
        assert!(found.settings.mapi_http().is_some());
        assert_eq!(found.tried.len(), 2);
    }

    /// No credentials have no scheme, so every 401 they meet asked for something else and was sent
    /// nothing: the search goes on past it, and ends with that refusal only if nothing answered.
    #[tokio::test]
    async fn a_lookup_without_credentials_is_not_ended_by_a_challenge() {
        use wiremock::matchers::path;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/sso/Autodiscover.xml"))
            .respond_with(ResponseTemplate::new(401).append_header("WWW-Authenticate", "Negotiate"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/mail/Autodiscover.xml"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(include_str!("../../tests/autodiscover-settings.xml")),
            )
            .mount(&server)
            .await;
        let queue = |names: &[&str]| -> VecDeque<String> {
            names
                .iter()
                .map(|at| format!("{}/{at}/Autodiscover.xml", server.uri()))
                .collect()
        };
        let anonymous = || {
            MapiClient::builder()
                .credentials(Credentials::None)
                .danger_allow_plaintext_http()
        };

        let found = anonymous()
            .search_with(http(&server), &address(), queue(&["sso", "mail"]), false)
            .await
            .unwrap();
        assert_eq!(found.tried.len(), 2);

        let error = anonymous()
            .search_with(http(&server), &address(), queue(&["sso"]), false)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &error,
                Error::Unauthorized {
                    sent: "no credentials",
                    ..
                }
            ),
            "{error:?}"
        );
    }

    /// Only a 302 is the redirect §3.1.5.4 names, so a probe answered with any other status has
    /// nothing to offer, and the search ends as one that found nothing.
    #[tokio::test]
    async fn a_probe_answered_with_another_3xx_offers_nothing() {
        let (server, _) = network(301).await;

        let error = builder()
            .search_with(
                http(&server),
                &address(),
                candidate_urls(&address()).collect(),
                true,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, Error::NoEndpoint { .. }), "{error:?}");
    }

    /// A `Location` this crate would never ask — plain HTTP, here, with nobody having allowed it —
    /// is not offered to the caller either, since agreeing to it could not lead anywhere.
    #[tokio::test]
    async fn a_probe_redirect_to_a_url_that_would_not_be_asked_offers_nothing() {
        let (server, _) = network(302).await;

        let error = MapiClient::builder()
            .search_with(
                http(&server),
                &address(),
                candidate_urls(&address()).collect(),
                true,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, Error::NoEndpoint { .. }), "{error:?}");
    }
}
