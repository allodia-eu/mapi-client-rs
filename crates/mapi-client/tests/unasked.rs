//! Autodiscover sends credentials only where they are asked for.
//!
//! A candidate URL is a guess built from the address's domain, and the first is usually the
//! organisation's website, run by whoever runs it. So every candidate is asked without credentials
//! first, and is sent them only in answer to a 401 that offers their scheme: Basic and Bearer as a
//! header, NTLM and `Negotiate` as the opening of their handshake. A candidate that never asks
//! is never sent a credential. The one `Authorization` header it may see is a bare `Bearer`, which
//! names the scheme and carries no token: Exchange offers `Bearer` only to a request that names it.

#![cfg(feature = "autodiscover")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test asserting a known shape says something true about it"
)]

use core::time::Duration;

use mapi_client::{Credentials, EmailAddress, Error, MapiClient, MapiClientBuilder};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// A settings response for a fictional deployment, in the shape Exchange sends one.
const SETTINGS: &str = include_str!("autodiscover-settings.xml");

fn address() -> EmailAddress {
    EmailAddress::new("alice@example.test").unwrap()
}

fn builder(credentials: Credentials) -> MapiClientBuilder {
    MapiClient::builder()
        .credentials(credentials)
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(2))
        .danger_allow_plaintext_http()
}

/// Every kind of credential this build can hold that would put something in `Authorization`.
fn every_credential() -> Vec<Credentials> {
    vec![
        Credentials::basic("alice@example.test", "hunter2"),
        Credentials::bearer("a-token"),
        #[cfg(feature = "ntlm")]
        Credentials::ntlm("DEV\\alice", "hunter2"),
        #[cfg(feature = "ntlm")]
        Credentials::negotiate("alice@EXAMPLE.TEST", "hunter2"),
    ]
}

fn url(server: &MockServer) -> String {
    format!("{}/Autodiscover/Autodiscover.xml", server.uri())
}

/// A service that answers every request with `status`, `body` and these `WWW-Authenticate` values.
async fn answering(status: u16, body: &str, challenges: &[&str]) -> MockServer {
    let server = MockServer::start().await;
    let mut response = ResponseTemplate::new(status)
        .set_body_string(body)
        .append_header("Content-Type", "text/xml; charset=utf-8");
    for challenge in challenges {
        response = response.append_header("WWW-Authenticate", *challenge);
    }
    Mock::given(method("POST"))
        .respond_with(response)
        .mount(&server)
        .await;
    server
}

/// A service that challenges with `scheme` and answers a request that carries `credential`.
async fn challenging(scheme: &str, credential: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("Authorization", credential))
        .respond_with(ResponseTemplate::new(200).set_body_string(SETTINGS))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).append_header("WWW-Authenticate", scheme))
        .mount(&server)
        .await;
    server
}

fn authorization(request: &Request) -> Option<&str> {
    request
        .headers
        .get("Authorization")
        .map(|value| value.to_str().unwrap())
}

/// The credential a request carried, if any: its `Authorization`, unless that only named
/// `Bearer`, which proves nothing.
fn credential(request: &Request) -> Option<&str> {
    authorization(request).filter(|value| *value != "Bearer")
}

/// The rule itself: whatever the credentials, a candidate that does not challenge is sent none —
/// whether it answers with settings or, like most websites, with a page that is not Autodiscover.
#[tokio::test]
async fn a_candidate_that_never_challenges_never_sees_an_authorization_header() {
    for body in [SETTINGS, "<html><body>Welcome to Example</body></html>"] {
        let server = answering(200, body, &[]).await;
        for credentials in every_credential() {
            let _ = builder(credentials)
                .lookup_at(url(&server), &address())
                .await;
        }

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), every_credential().len(), "one request each");
        for request in &requests {
            assert_eq!(credential(request), None, "{}", request.url);
            assert!(!request.body.is_empty(), "the request itself still went");
        }
        // Only the Bearer lookup named its scheme, and with nothing after the name.
        let named: Vec<_> = requests.iter().filter_map(authorization).collect();
        assert_eq!(named, ["Bearer"]);
    }
}

/// A 401 that asks for another scheme is sent nothing, and the error says so rather than claiming
/// the credentials were refused.
#[tokio::test]
async fn a_challenge_for_another_scheme_is_sent_nothing() {
    let windows = answering(401, "", &["Negotiate", "NTLM"]).await;
    for (credentials, scheme) in [
        (Credentials::basic("alice", "hunter2"), "Basic"),
        (Credentials::bearer("a-token"), "Bearer"),
    ] {
        let error = builder(credentials)
            .lookup_at(url(&windows), &address())
            .await
            .unwrap_err();
        let Error::Unauthorized { offered, sent, .. } = &error else {
            panic!("expected Unauthorized, got {error:?}");
        };
        assert_eq!(offered, &["Negotiate", "NTLM"]);
        assert_eq!(*sent, format!("nothing, since it does not offer {scheme}"));
    }

    let requests = windows.received_requests().await.unwrap();
    assert!(requests.iter().all(|request| credential(request).is_none()));
}

/// Exchange offers `Bearer` only to a request that names it, so a Bearer lookup opens with the bare
/// scheme name — measured against Exchange Server SE `15.02.2562.056` — and its token goes only to
/// the `Bearer` challenge that comes back.
#[tokio::test]
async fn a_bearer_lookup_names_its_scheme_before_it_sends_a_token() {
    let server = challenging(
        "Bearer client_id=\"00000002-0000-0ff1-ce00-000000000000\"",
        "Bearer a-token",
    )
    .await;
    builder(Credentials::bearer("a-token"))
        .lookup_at(url(&server), &address())
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    let sent: Vec<_> = requests.iter().map(authorization).collect();
    assert_eq!(sent, [Some("Bearer"), Some("Bearer a-token")]);
}

/// A challenge for the credentials' own scheme is answered, on a second request — the one round
/// trip the rule costs.
#[tokio::test]
async fn a_challenge_for_the_credentials_scheme_is_answered() {
    for (credentials, scheme, expected) in [
        (
            Credentials::basic("alice@example.test", "hunter2"),
            "Basic realm=\"x\"",
            "Basic YWxpY2VAZXhhbXBsZS50ZXN0Omh1bnRlcjI=",
        ),
        (Credentials::bearer("a-token"), "Bearer", "Bearer a-token"),
    ] {
        let server = challenging(scheme, expected).await;
        let endpoint = builder(credentials)
            .lookup_at(url(&server), &address())
            .await
            .unwrap();
        assert!(endpoint.legacy_dn().ends_with("cn=alice"));

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(credential(&requests[0]), None);
        assert_eq!(authorization(&requests[1]), Some(expected));
    }
}

/// A service that refuses the credentials it asked for has said no, and that ends the search.
#[tokio::test]
async fn credentials_refused_after_being_asked_for_say_they_were_sent() {
    let server = answering(401, "", &["Basic realm=\"x\""]).await;
    let error = builder(Credentials::basic("alice", "hunter2"))
        .lookup_at(url(&server), &address())
        .await
        .unwrap_err();
    let Error::Unauthorized { offered, sent, .. } = &error else {
        panic!("expected Unauthorized, got {error:?}");
    };
    assert_eq!(offered, &["Basic"]);
    assert_eq!(*sent, "Basic credentials");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[cfg(feature = "ntlm")]
mod handshake {
    //! The connection-oriented schemes, which answer the 401 with an opening instead of a header.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use wiremock::{Request, Respond};

    use super::*;

    /// [MS-NLMP] §4.2.4.3's own `CHALLENGE_MESSAGE`, which is the only one that can be written
    /// down here without a server to get it from.
    const CHALLENGE: &str = concat!(
        "TlRMTVNTUAACAAAADAAMADgAAAAzgoriASNFZ4mrze8AAAAAAAAAACQAJABE",
        "AAAABgBwFwAAAA9TAGUAcgB2AGUAcgACAAwARABvAG0AYQBpAG4AAQAMAFMAZQBy",
        "AHYAZQByAAAAAAA="
    );

    /// Answers each leg in turn with the next of `legs`, and the last of them for ever after.
    struct Scripted(Arc<AtomicUsize>, Vec<ResponseTemplate>);
    impl Respond for Scripted {
        fn respond(&self, _: &Request) -> ResponseTemplate {
            let leg = self.0.fetch_add(1, Ordering::SeqCst);
            self.1.get(leg).or(self.1.last()).unwrap().clone()
        }
    }

    async fn scripted(legs: Vec<ResponseTemplate>) -> (MockServer, Arc<AtomicUsize>) {
        let seen = Arc::new(AtomicUsize::new(0));
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(Scripted(Arc::clone(&seen), legs))
            .mount(&server)
            .await;
        (server, seen)
    }

    fn settings() -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_string(SETTINGS)
            .append_header("Content-Type", "text/xml; charset=utf-8")
    }

    /// The handshake schemes keep the same rule: a 401 that does not offer theirs is sent no
    /// opening, and no KDC is asked for a ticket to a server that wants none.
    #[tokio::test]
    async fn a_challenge_for_another_scheme_is_sent_no_opening() {
        let basic_only = answering(401, "", &["Basic realm=\"x\""]).await;
        for (credentials, scheme) in [
            (Credentials::ntlm("DEV\\alice", "hunter2"), "NTLM"),
            (
                Credentials::negotiate("alice@EXAMPLE.TEST", "hunter2"),
                "Negotiate",
            ),
        ] {
            let error = builder(credentials)
                .lookup_at(url(&basic_only), &address())
                .await
                .unwrap_err();
            let Error::Unauthorized { sent, .. } = &error else {
                panic!("expected Unauthorized, got {error:?}");
            };
            assert_eq!(*sent, format!("nothing, since it does not offer {scheme}"));
        }

        let requests = basic_only.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2, "one each");
        assert!(
            requests
                .iter()
                .all(|request| authorization(request).is_none())
        );
    }

    /// Autodiscover has to answer a handshake too, and it is the *first* thing a caller does.
    ///
    /// The opening goes only after the first 401 asks for it, as IIS does ask: unauthenticated,
    /// challenged, opened, answered. Every leg carries the request body, which is what makes the
    /// last leg a request rather than one round trip more.
    #[tokio::test]
    async fn a_connection_oriented_scheme_completes_its_handshake_during_discovery() {
        let (server, seen) = scripted(vec![
            ResponseTemplate::new(401)
                .append_header("WWW-Authenticate", "NTLM")
                .append_header("WWW-Authenticate", "Basic realm=\"x\""),
            ResponseTemplate::new(401)
                .append_header("WWW-Authenticate", format!("NTLM {CHALLENGE}")),
            settings(),
        ])
        .await;

        let endpoint = builder(Credentials::ntlm("DEV\\alice", "hunter2"))
            .lookup_at(url(&server), &address())
            .await
            .expect("the handshake completes and the settings arrive");

        assert!(endpoint.legacy_dn().ends_with("cn=alice"));
        assert_eq!(seen.load(Ordering::SeqCst), 3, "three legs, one candidate");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(authorization(&requests[0]), None, "nothing before the 401");
        for request in &requests[1..] {
            let scheme = authorization(request).unwrap();
            assert!(scheme.starts_with("NTLM "), "{scheme}");
        }
        assert!(requests.iter().all(|request| !request.body.is_empty()));
    }

    /// The unauthenticated leg is not part of the handshake, so a server that closes its connection
    /// after the first 401 costs nothing: the opening starts the handshake on a new one, and it
    /// completes there without being started again.
    ///
    /// A socket of its own rather than wiremock, which keeps a connection open whatever the
    /// response says.
    #[tokio::test]
    async fn a_first_401_on_a_connection_that_closes_does_not_restart_the_handshake() {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::sync::Mutex;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // The connection each request arrived on, in order.
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&arrivals);
        std::thread::spawn(move || {
            for (connection, stream) in listener.incoming().enumerate() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut length = 0;
                    // Which NTLM message the leg carried, by its type byte: none, 1 or 3.
                    let mut message = None;
                    let mut line = String::new();
                    loop {
                        line.clear();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            break;
                        }
                        let lower = line.to_ascii_lowercase();
                        if let Some(value) = lower.strip_prefix("content-length:") {
                            length = value.trim().parse().unwrap();
                        }
                        if lower.starts_with("authorization: ntlm ") {
                            message = line.chars().nth("authorization: ntlm ".len() + 11);
                        }
                        if line == "\r\n" {
                            break;
                        }
                    }
                    if line != "\r\n" {
                        break;
                    }
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    let first = {
                        let mut arrivals = seen.lock().unwrap();
                        arrivals.push(connection);
                        arrivals.len() == 1
                    };
                    // `TlRMTVNTUAAB` opens a NEGOTIATE_MESSAGE, `TlRMTVNTUAAD` an AUTHENTICATE.
                    let response = match message {
                        None => format!(
                            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n{}\
                             Content-Length: 0\r\n\r\n",
                            if first { "Connection: close\r\n" } else { "" }
                        ),
                        Some('B') => format!(
                            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {CHALLENGE}\r\n\
                             Content-Length: 0\r\n\r\n"
                        ),
                        _ => format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\
                             \r\n{SETTINGS}",
                            SETTINGS.len()
                        ),
                    };
                    stream.write_all(response.as_bytes()).unwrap();
                    if first {
                        break;
                    }
                }
            }
        });

        builder(Credentials::ntlm("DEV\\alice", "hunter2"))
            .lookup_at(
                format!("http://127.0.0.1:{port}/Autodiscover/Autodiscover.xml"),
                &address(),
            )
            .await
            .expect("the handshake completes on the second connection");
        assert_eq!(
            *arrivals.lock().unwrap(),
            [0, 1, 1],
            "the first leg on one connection, the handshake whole on the next"
        );
    }

    /// Discovery checks a `Negotiate` server's last token as the transport does: a `mechListMIC`
    /// on the final `200` that is not the session's signature ends the lookup instead of being
    /// trusted.
    #[tokio::test]
    async fn a_forged_mech_list_mic_on_the_last_discovery_leg_is_refused() {
        // §4.2.4.3's `CHALLENGE_MESSAGE` in an accept-incomplete `NegTokenResp`, then a completing
        // one whose `mechListMIC` has a byte flipped.
        let (server, _) = scripted(vec![
            ResponseTemplate::new(401).append_header("WWW-Authenticate", "Negotiate"),
            ResponseTemplate::new(401).append_header(
                "WWW-Authenticate",
                concat!(
                    "Negotiate oYGBMH+gAwoBAaEMBgorBgEEAYI3AgIKomoEaE5UTE1TU1AAAgAAAAwADAA4",
                    "AAAAM4KK4gEjRWeJq83vAAAAAAAAAAAkACQARAAAAAYAcBcAAAAPUwBlAHIAdgBlAHIA",
                    "AgAMAEQAbwBtAGEAaQBuAAEADABTAGUAcgB2AGUAcgAAAAAA",
                ),
            ),
            settings().append_header(
                "WWW-Authenticate",
                "Negotiate oRswGaADCgEAoxIEEAEAAAD/AAAAAAAAAAAAAAA=",
            ),
        ])
        .await;

        let error = builder(Credentials::negotiate("DEV\\alice", "hunter2"))
            .lookup_at(url(&server), &address())
            .await
            .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("mechListMIC"), "{rendered}");
    }
}
