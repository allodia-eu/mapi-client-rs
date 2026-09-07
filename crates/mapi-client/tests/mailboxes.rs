//! Listing and opening mailboxes other than the account's own, against a fake service.
//!
//! Its own file rather than part of `autodiscover.rs` because it is its own question. That one asks
//! which answers end the search; this one asks what happens *after* a search ends — how many more
//! searches it starts, and what a mailbox has to carry before a session can be opened on it.
//!
//! The shape being tested is the one measured against Exchange Server SE `15.02.2562.045`:
//! Exchange names an alternative mailbox by SMTP address, never by distinguished name, so listing
//! *n* mailboxes costs *n + 1* Autodiscover round trips and each alternative arrives with its own
//! endpoint.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a test asserting a known shape says something true about it"
)]

use core::time::Duration;

use mapi_client::{Credentials, EmailAddress, Error, MailboxKind, MapiClient};
use wiremock::matchers::{body_string_contains, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Alice's own settings, which name one alternative mailbox by address.
const SETTINGS: &str = include_str!("autodiscover-settings.xml");

/// What the second lookup answers about that mailbox: its own endpoint, and its own name.
const SHARED: &str = include_str!("autodiscover-shared.xml");

/// The `MailboxId` each fixture carries. They differ, which is the whole point — the endpoint and
/// the distinguished name are a matched pair.
const OWN_MAILBOX_ID: &str = "MailboxId=00000000-0000-0000-0000-000000000000@example.test";
const SHARED_MAILBOX_ID: &str = "MailboxId=11111111-1111-1111-1111-111111111111@example.test";

fn address() -> EmailAddress {
    EmailAddress::new("alice@example.test").unwrap()
}

fn builder() -> mapi_client::MapiClientBuilder {
    MapiClient::builder()
        .credentials(Credentials::basic("alice@example.test", "hunter2"))
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(2))
        .danger_allow_plaintext_http()
}

/// A service that answers about whichever address the request body asked about.
///
/// Matching on the body rather than serving one answer to everything is what makes this a test of
/// the *second* lookup: an implementation that reused the first answer would be handed alice's
/// endpoint for the shared mailbox and would pass a weaker mock.
async fn deployment() -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("shared@example.test"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SHARED))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(body_string_contains("alice@example.test"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SETTINGS))
        .mount(&server)
        .await;

    server
}

/// A service that answers about alice and refuses everything else, which is what a delegated
/// mailbox that has moved away looks like.
async fn deployment_without_the_shared_mailbox() -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(body_string_contains("alice@example.test"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SETTINGS))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    server
}

fn url(server: &MockServer) -> String {
    format!("{}/Autodiscover/Autodiscover.xml", server.uri())
}

/// A client aimed at one listed mailbox, the way `mapi-cli mailboxes` builds its first one.
fn client_for(mailbox: &mapi_client::Mailbox) -> MapiClient {
    builder()
        .endpoint(mailbox.endpoint().unwrap())
        .user_dn(mailbox.user_dn().unwrap().clone())
        .build()
        .unwrap()
}

/// The whole of "list mailboxes": the account's own first, then one per `AlternativeMailbox`.
#[tokio::test]
async fn every_mailbox_the_account_can_open_is_listed_own_first() {
    let server = deployment().await;
    let mailboxes = builder()
        .mailboxes_at(url(&server), &address())
        .await
        .unwrap();

    assert_eq!(mailboxes.len(), 2);

    let own = &mailboxes[0];
    assert!(own.is_own());
    assert_eq!(own.kind(), None);
    assert_eq!(own.display_name(), Some("Alice Example"));
    assert_eq!(own.smtp_address(), Some("alice@example.test"));

    let shared = &mailboxes[1];
    assert!(!shared.is_own());
    assert_eq!(shared.kind(), Some(&MailboxKind::Delegate));
    assert_eq!(shared.smtp_address(), Some("shared@example.test"));
}

/// **The measurement this whole module exists for.** Exchange names an alternative mailbox by
/// address, and an address is not an endpoint — so each one costs a lookup of its own, and what
/// comes back is a *different* `?MailboxId=`. Reusing the first would be refused at logon.
#[tokio::test]
async fn an_alternative_mailbox_is_resolved_to_its_own_endpoint() {
    let server = deployment().await;
    let mailboxes = builder()
        .mailboxes_at(url(&server), &address())
        .await
        .unwrap();

    assert!(mailboxes[0].endpoint().unwrap().contains(OWN_MAILBOX_ID));
    assert!(mailboxes[1].endpoint().unwrap().contains(SHARED_MAILBOX_ID));
    assert!(
        mailboxes[1]
            .user_dn()
            .unwrap()
            .as_str()
            .ends_with("cn=shared"),
        "the distinguished name is the shared mailbox's, not alice's"
    );

    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "one lookup for the account and one for the alternative"
    );
}

/// The `AlternativeMailbox`'s own `DisplayName` wins over the one the second lookup reports.
/// [MS-OXDSCLI] §2.2.4.1.1.2.5.1 says it is there to "override how a client will display the
/// user's name", so the two fixtures deliberately disagree.
#[tokio::test]
async fn the_delegates_own_label_for_a_mailbox_wins() {
    let server = deployment().await;
    let mailboxes = builder()
        .mailboxes_at(url(&server), &address())
        .await
        .unwrap();

    assert_eq!(mailboxes[1].display_name(), Some("Shared Mailbox"));
}

/// A mailbox whose lookup fails is reported unopenable rather than failing the whole listing: a
/// delegate whose mailbox has moved should not hide the ones that have not.
#[tokio::test]
async fn a_lookup_that_fails_costs_one_mailbox_not_the_listing() {
    let server = deployment_without_the_shared_mailbox().await;
    let mailboxes = builder()
        .mailboxes_at(url(&server), &address())
        .await
        .unwrap();

    assert_eq!(mailboxes.len(), 2);
    assert!(
        mailboxes[0].is_openable(),
        "the account's own is unaffected"
    );

    let shared = &mailboxes[1];
    assert!(!shared.is_openable());
    assert_eq!(shared.endpoint(), None);
    assert_eq!(shared.user_dn(), None);
    // Still listed, and still named: a caller can say *which* mailbox could not be reached.
    assert_eq!(shared.kind(), Some(&MailboxKind::Delegate));
    assert_eq!(shared.display_name(), Some("Shared Mailbox"));
}

/// Re-aiming a client is what opening a second mailbox costs, and it must move *both* halves of
/// the pair. Keeping the endpoint would be accepted by `Connect` and refused by the `RopLogon`
/// after it.
#[tokio::test]
async fn a_client_re_aimed_at_another_mailbox_moves_endpoint_and_name_together() {
    let server = deployment().await;
    let mailboxes = builder()
        .mailboxes_at(url(&server), &address())
        .await
        .unwrap();

    let client = client_for(&mailboxes[0]);
    assert!(client.endpoint().contains(OWN_MAILBOX_ID));

    let shared = client.for_mailbox(&mailboxes[1]).unwrap();
    assert!(shared.endpoint().contains(SHARED_MAILBOX_ID));
    assert!(shared.user_dn().as_str().ends_with("cn=shared"));

    // And the client it came from is untouched, so a caller can hold both at once.
    assert!(client.endpoint().contains(OWN_MAILBOX_ID));
    assert!(client.user_dn().as_str().ends_with("cn=alice"));
}

/// A mailbox that named no endpoint cannot be opened, and says so by name rather than by producing
/// a client that fails a round trip later.
#[tokio::test]
async fn an_unopenable_mailbox_is_refused_before_anything_is_sent() {
    let server = deployment_without_the_shared_mailbox().await;
    let mailboxes = builder()
        .mailboxes_at(url(&server), &address())
        .await
        .unwrap();
    let client = client_for(&mailboxes[0]);

    let error = client
        .for_mailbox(&mailboxes[1])
        .expect_err("no endpoint to aim at");
    assert!(
        matches!(
            error,
            Error::MissingSetting {
                name: "endpoint",
                ..
            }
        ),
        "{error:?}"
    );
}

/// An account with nothing shared with it lists exactly one mailbox and makes exactly one request,
/// which is the ordinary case and must not cost a round trip to discover.
#[tokio::test]
async fn an_account_with_no_alternatives_costs_one_lookup() {
    let server = MockServer::start().await;
    let without = SETTINGS
        .replace("<AlternativeMailbox>", "<!--")
        .replace("</AlternativeMailbox>", "-->");
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(without))
        .mount(&server)
        .await;

    let mailboxes = builder()
        .mailboxes_at(url(&server), &address())
        .await
        .unwrap();

    assert_eq!(mailboxes.len(), 1);
    assert!(mailboxes[0].is_own());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
