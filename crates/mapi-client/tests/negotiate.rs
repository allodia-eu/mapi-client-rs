//! `Negotiate` with Kerberos, end to end, with nothing real in it: a KDC listening on a loopback
//! socket and a service behind a fake HTTP server, both `negotiate-auth`'s test KDC.
//!
//! What this checks is the client's side of the arrangement, in CI where no domain controller is:
//! that it finds the KDC, carries the messages, keeps the tickets, presents one, checks the AP-REP,
//! falls back to NTLM when it should and reports a refusal when it should — and says which
//! mechanism authenticated. The messages are `negotiate-auth`'s and are tested there; a real KDC's
//! and a real Exchange's agreement with all of it is `tests/live.rs`.

#![cfg(feature = "kerberos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a test asserting a known shape says something true about it"
)]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use mapi_client::{Credentials, Error, KdcLocator, SrvLookup, SrvRecord, SrvResolver};
use negotiate_auth::Mechanism;
use negotiate_auth::testing::TestKdc;
use support::{MapiServer, connect_ok};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The service the fake server is: `HTTP/` and the loopback host its URL names.
const SERVICE: &str = "HTTP/127.0.0.1";

fn test_kdc(password: &str) -> Arc<TestKdc> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    Arc::new(TestKdc::new("EXAMPLE.TEST", "alice@example.test", password, SERVICE, now).unwrap())
}

/// The KDC on a loopback socket, speaking [RFC 4120] §7.2.2's framing, counting what it answers.
async fn kdc_on_a_socket(kdc: Arc<TestKdc>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let answered = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&answered);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let kdc = Arc::clone(&kdc);
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                let mut prefix = [0u8; 4];
                stream.read_exact(&mut prefix).await.unwrap();
                let mut request = vec![0u8; usize::try_from(u32::from_be_bytes(prefix)).unwrap()];
                stream.read_exact(&mut request).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let reply = kdc.answer(&request);
                let mut framed = u32::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
                framed.extend_from_slice(&reply);
                stream.write_all(&framed).await.unwrap();
            });
        }
    });
    (address, answered)
}

/// The MAPI endpoint as a Kerberos service: a 401 offering `Negotiate` to anything it cannot
/// accept, and `body` with the AP-REP to an AP-REQ for a ticket the test KDC issued.
struct Service {
    kdc: Arc<TestKdc>,
    body: fn() -> ResponseTemplate,
}

impl Respond for Service {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let accepted = request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| self.kdc.accept(value));
        match accepted {
            Some(success) => (self.body)().append_header("WWW-Authenticate", success.as_str()),
            None => ResponseTemplate::new(401)
                .append_header("WWW-Authenticate", "Negotiate")
                .append_header("WWW-Authenticate", "NTLM"),
        }
    }
}

async fn service(kdc: Arc<TestKdc>, body: fn() -> ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Service { kdc, body })
        .mount(&server)
        .await;
    server
}

fn endpoint(server: &MockServer) -> String {
    format!(
        "{}/mapi/emsmdb/?MailboxId=00000000-0000-0000-0000-000000000000@example.test",
        server.uri()
    )
}

fn connected() -> ResponseTemplate {
    connect_ok("Alice Example")
}

/// The whole of it: the KDC found, three messages to it, the ticket presented, the AP-REP checked
/// — and on a second connection, the ticket reused rather than asked for again.
#[tokio::test]
async fn negotiate_authenticates_with_a_ticket_and_reuses_it() {
    let kdc = test_kdc("hunter2");
    let (address, answered) = kdc_on_a_socket(Arc::clone(&kdc)).await;
    let server = service(kdc, connected).await;

    let client = MapiServer::builder_for(endpoint(&server))
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .kdc_locator(KdcLocator::new().kdc("EXAMPLE.TEST", address))
        .build()
        .unwrap();
    client.connect().await.expect("Connect, over Kerberos");

    let authentication = client.authentication().unwrap();
    assert_eq!(authentication.mechanism, Mechanism::Kerberos);
    assert_eq!(authentication.kerberos_unavailable, None);
    assert_eq!(answered.load(Ordering::SeqCst), 3, "AS twice, then TGS");

    // The first request fetches the certificate the AP-REQ would bind to; the second carries it.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].headers.get("authorization").is_none());
    assert!(
        requests[1].headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("Negotiate ")
    );

    // The fake server forgets every connection, so the next request authenticates again — from
    // the cache: the KDC hears nothing more.
    client.connect().await.expect("Connect again");
    assert_eq!(answered.load(Ordering::SeqCst), 3, "the ticket was reused");
    assert_eq!(
        client.authentication().unwrap().mechanism,
        Mechanism::Kerberos
    );
}

/// A resolver is the usual way to the KDC: the SRV record it returns names the socket.
#[tokio::test]
async fn the_kdc_is_found_through_the_hosts_resolver() {
    #[derive(Debug)]
    struct Fixed(u16);
    impl SrvResolver for Fixed {
        fn resolve<'a>(&'a self, name: &'a str) -> SrvLookup<'a> {
            assert_eq!(name, "_kerberos._tcp.EXAMPLE.TEST");
            let record = SrvRecord::new(0, 100, self.0, "127.0.0.1.");
            Box::pin(async move { Ok(vec![record]) })
        }
    }

    let kdc = test_kdc("hunter2");
    let (address, _) = kdc_on_a_socket(Arc::clone(&kdc)).await;
    let port = address.rsplit_once(':').unwrap().1.parse().unwrap();
    let server = service(kdc, connected).await;

    let client = MapiServer::builder_for(endpoint(&server))
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .kdc_locator(KdcLocator::new().resolver(Arc::new(Fixed(port))))
        .build()
        .unwrap();
    client.connect().await.unwrap();
    assert_eq!(
        client.authentication().unwrap().mechanism,
        Mechanism::Kerberos
    );
}

/// A KDC that refuses the password is the answer: NTLM is not tried, because it would fail too
/// and say less, and the server is asked nothing after the 401 that sent the client to the KDC.
#[tokio::test]
async fn a_kdc_that_refuses_the_password_is_reported() {
    let kdc = test_kdc("the real password");
    let (address, _) = kdc_on_a_socket(Arc::clone(&kdc)).await;
    let server = service(kdc, connected).await;

    let client = MapiServer::builder_for(endpoint(&server))
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .kdc_locator(KdcLocator::new().kdc("EXAMPLE.TEST", address))
        .build()
        .unwrap();
    let error = client.connect().await.unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized { offered, .. }
            if offered.iter().any(|reason| reason.contains("PREAUTH_FAILED"))),
        "{error}"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].headers.get("authorization").is_none());
    assert_eq!(client.authentication(), None);
}

/// A server that offers something other than `Negotiate` is refused before any KDC is asked: the
/// ticket is not worth its round trips until a server has said it wants one.
#[tokio::test]
async fn no_kdc_is_asked_until_the_server_asks_for_negotiate() {
    let kdc = test_kdc("hunter2");
    let (address, answered) = kdc_on_a_socket(kdc).await;
    let server = MapiServer::start().await;
    server.reply(ResponseTemplate::new(401).append_header("WWW-Authenticate", "Basic"));

    let client = MapiServer::builder_for(server.endpoint())
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .kdc_locator(KdcLocator::new().kdc("EXAMPLE.TEST", address))
        .build()
        .unwrap();
    let error = client.connect().await.unwrap_err();
    assert!(
        matches!(&error, Error::Unauthorized { offered, .. } if offered == &["Basic"]),
        "{error}"
    );
    assert_eq!(answered.load(Ordering::SeqCst), 0);
}

/// With no KDC answering, `Negotiate` is NTLM on a leg of its own after the 401 — and the next
/// connection knows, so it opens with NTLM and does not wait for the KDCs again.
#[tokio::test]
async fn a_kdc_that_does_not_answer_is_not_waited_for_twice() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let dialled = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&dialled);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let negotiate = ResponseTemplate::new(401).append_header("WWW-Authenticate", "Negotiate");
    let challenge = ResponseTemplate::new(401)
        .append_header("WWW-Authenticate", format!("Negotiate {SPNEGO_CHALLENGE}"));
    let server = MapiServer::start().await;
    for _ in 0..2 {
        server.reply(negotiate.clone());
        server.reply(challenge.clone());
        server.reply(connected());
    }

    let client = MapiServer::builder_for(server.endpoint())
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .kdc_locator(KdcLocator::new().kdc("EXAMPLE.TEST", address))
        .build()
        .unwrap();
    for _ in 0..2 {
        client.connect().await.expect("NTLM inside SPNEGO");
        let authentication = client.authentication().unwrap();
        assert_eq!(authentication.mechanism, Mechanism::Ntlm);
        let reason = authentication.kerberos_unavailable.unwrap();
        assert!(
            reason.contains("no KDC for EXAMPLE.TEST answered"),
            "{reason}"
        );
    }
    assert_eq!(dialled.load(Ordering::SeqCst), 1, "the KDC was tried once");

    let requests = server.requests().await;
    assert_eq!(requests.len(), 6);
    // First: nothing, then NTLM's opening, then its answer. Second: the request on a connection
    // believed authenticated, then NTLM's opening at once.
    let authorization = |at: usize| requests[at].headers.get("authorization").is_some();
    assert_eq!(
        (0..6).map(authorization).collect::<Vec<_>>(),
        [false, true, true, false, true, true]
    );
}

/// [MS-NLMP] §4.2.4.3's challenge inside a `NegTokenResp`, as `tests/auth.rs` carries it.
const SPNEGO_CHALLENGE: &str = concat!(
    "oYGBMH+gAwoBAaEMBgorBgEEAYI3AgIKomoEaE5UTE1TU1AAAgAAAAwADAA4AAAA",
    "M4KK4gEjRWeJq83vAAAAAAAAAAAkACQARAAAAAYAcBcAAAAPUwBlAHIAdgBlAHIA",
    "AgAMAEQAbwBtAGEAaQBuAAEADABTAGUAcgB2AGUAcgAAAAAA",
);

/// [RFC 4178] §3.2: a server that picks NTLM over the optimistic Kerberos token gets NTLM inside
/// SPNEGO — and the client reports that Kerberos was offered and not chosen.
#[tokio::test]
async fn a_server_that_picks_ntlm_over_the_ticket_gets_ntlm_and_it_is_reported() {
    /// `NegTokenResp`: accept-incomplete, `supportedMech` NTLM, and no token yet.
    const NTLM_CHOSEN: &str = "oRUwE6ADCgEBoQwGCisGAQQBgjcCAgo=";
    let negotiate = |token: &str| {
        ResponseTemplate::new(401).append_header("WWW-Authenticate", format!("Negotiate {token}"))
    };

    let kdc = test_kdc("hunter2");
    let (address, _) = kdc_on_a_socket(kdc).await;
    let server = MapiServer::start().await;
    server.reply(ResponseTemplate::new(401).append_header("WWW-Authenticate", "Negotiate"));
    server.reply(negotiate(NTLM_CHOSEN));
    server.reply(negotiate(SPNEGO_CHALLENGE));
    server.reply(connected());

    let client = MapiServer::builder_for(server.endpoint().replace("localhost", "127.0.0.1"))
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .kdc_locator(KdcLocator::new().kdc("EXAMPLE.TEST", address))
        .build()
        .unwrap();
    client
        .connect()
        .await
        .expect("NTLM inside SPNEGO, after Kerberos was declined");

    let authentication = client.authentication().unwrap();
    assert_eq!(authentication.mechanism, Mechanism::Ntlm);
    assert_eq!(
        authentication.kerberos_unavailable.as_deref(),
        Some("the server chose NTLM over the Kerberos ticket")
    );
    assert_eq!(server.requests().await.len(), 4);
}

/// A server that wants no authentication answers the request that would have fetched its
/// certificate, and the real request then goes out with nothing in front of it.
#[tokio::test]
async fn a_server_that_does_not_challenge_is_simply_answered() {
    let kdc = test_kdc("hunter2");
    let (address, answered) = kdc_on_a_socket(kdc).await;
    let server = MapiServer::start().await;
    server.reply(ResponseTemplate::new(200));
    server.reply(connected());

    let client = MapiServer::builder_for(server.endpoint())
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .kdc_locator(KdcLocator::new().kdc("EXAMPLE.TEST", address))
        .build()
        .unwrap();
    client.connect().await.unwrap();
    let requests = server.requests().await;
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("authorization").is_none())
    );
    assert_eq!(client.authentication(), None, "no handshake ran");
    assert_eq!(answered.load(Ordering::SeqCst), 0, "and no KDC was asked");
}

/// Autodiscover runs the same handshake, with the same ticket cache.
#[cfg(feature = "autodiscover")]
#[tokio::test]
async fn autodiscover_authenticates_with_kerberos_too() {
    use core::time::Duration;

    use mapi_client::{EmailAddress, MapiClient};

    fn settings() -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_string(include_str!("autodiscover-settings.xml"))
            .append_header("Content-Type", "text/xml; charset=utf-8")
    }

    let kdc = test_kdc("hunter2");
    let (address, answered) = kdc_on_a_socket(Arc::clone(&kdc)).await;
    let server = service(kdc, settings).await;

    let found = MapiClient::builder()
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .kdc_locator(KdcLocator::new().kdc("EXAMPLE.TEST", address))
        .timeout(Duration::from_secs(5))
        .danger_allow_plaintext_http()
        .lookup_at(
            format!("{}/Autodiscover/Autodiscover.xml", server.uri()),
            &EmailAddress::new("alice@example.test").unwrap(),
        )
        .await
        .expect("the settings, over Kerberos");
    assert!(found.mail_store_url().is_some());
    assert_eq!(answered.load(Ordering::SeqCst), 3);
}

/// Answers each request with the next of a fixed list.
#[cfg(feature = "autodiscover")]
struct Turns(std::sync::Mutex<std::collections::VecDeque<ResponseTemplate>>);

#[cfg(feature = "autodiscover")]
impl Respond for Turns {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        self.0.lock().unwrap().pop_front().unwrap()
    }
}

/// Autodiscover with no KDC answering: NTLM's opening on a leg of its own after the 401, as for
/// the MAPI transport, carrying the request as every Autodiscover leg does.
#[cfg(feature = "autodiscover")]
#[tokio::test]
async fn autodiscover_falls_back_to_ntlm_when_no_kdc_answers() {
    use core::time::Duration;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use mapi_client::{EmailAddress, MapiClient};

    let turns = VecDeque::from([
        ResponseTemplate::new(401).append_header("WWW-Authenticate", "Negotiate"),
        ResponseTemplate::new(401)
            .append_header("WWW-Authenticate", format!("Negotiate {SPNEGO_CHALLENGE}")),
        ResponseTemplate::new(200)
            .set_body_string(include_str!("autodiscover-settings.xml"))
            .append_header("Content-Type", "text/xml; charset=utf-8"),
    ]);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Turns(Mutex::new(turns)))
        .mount(&server)
        .await;

    let found = MapiClient::builder()
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .kdc_locator(KdcLocator::new().kdc("EXAMPLE.TEST", "127.0.0.1:1"))
        .timeout(Duration::from_secs(5))
        .danger_allow_plaintext_http()
        .lookup_at(
            format!("{}/Autodiscover/Autodiscover.xml", server.uri()),
            &EmailAddress::new("alice@example.test").unwrap(),
        )
        .await
        .expect("the settings, over NTLM inside SPNEGO");
    assert!(found.mail_store_url().is_some());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].headers.get("authorization").is_none());
    assert!(requests.iter().all(|request| !request.body.is_empty()));
}

/// Autodiscover's own legs after the first: a server that picks NTLM over the ticket, mid-lookup.
#[cfg(feature = "autodiscover")]
#[tokio::test]
async fn autodiscover_follows_a_server_that_picks_ntlm() {
    use core::time::Duration;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use mapi_client::{EmailAddress, MapiClient};

    let negotiate = |token: &str| {
        ResponseTemplate::new(401).append_header("WWW-Authenticate", format!("Negotiate {token}"))
    };
    let turns = VecDeque::from([
        ResponseTemplate::new(401).append_header("WWW-Authenticate", "Negotiate"),
        negotiate("oRUwE6ADCgEBoQwGCisGAQQBgjcCAgo="),
        negotiate(concat!(
            "oYGBMH+gAwoBAaEMBgorBgEEAYI3AgIKomoEaE5UTE1TU1AAAgAAAAwADAA4AAAA",
            "M4KK4gEjRWeJq83vAAAAAAAAAAAkACQARAAAAAYAcBcAAAAPUwBlAHIAdgBlAHIA",
            "AgAMAEQAbwBtAGEAaQBuAAEADABTAGUAcgB2AGUAcgAAAAAA",
        )),
        ResponseTemplate::new(200)
            .set_body_string(include_str!("autodiscover-settings.xml"))
            .append_header("Content-Type", "text/xml; charset=utf-8"),
    ]);
    let kdc = test_kdc("hunter2");
    let (address, _) = kdc_on_a_socket(kdc).await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Turns(Mutex::new(turns)))
        .mount(&server)
        .await;

    let found = MapiClient::builder()
        .credentials(Credentials::negotiate("alice@example.test", "hunter2"))
        .kdc_locator(KdcLocator::new().kdc("EXAMPLE.TEST", address))
        .timeout(Duration::from_secs(5))
        .danger_allow_plaintext_http()
        .lookup_at(
            format!("{}/Autodiscover/Autodiscover.xml", server.uri()),
            &EmailAddress::new("alice@example.test").unwrap(),
        )
        .await
        .expect("the settings, over NTLM inside SPNEGO");
    assert!(found.mail_store_url().is_some());
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}
