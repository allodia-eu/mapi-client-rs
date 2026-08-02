//! Reading the committed corpus, and answering with it.
//!
//! Split out of `replay.rs` so that the file which makes the *claims* stays readable on its own.
//! Nothing here asserts anything about the protocol: it loads captures off disk and stands up a
//! fake endpoint that replays them in order, which is the machinery every replay test needs and
//! none of them is about.

#![allow(
    dead_code,
    reason = "this module is compiled into each test target that declares it, and no single one \
              uses all of it"
)]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use mapi_client::LegacyDn;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// One captured exchange.
#[derive(Clone, Debug)]
pub(crate) struct Exchange {
    pub(crate) stem: String,
    pub(crate) status: u16,
    pub(crate) response_headers: Vec<(String, String)>,
    pub(crate) request_body: Vec<u8>,
    pub(crate) response_body: Vec<u8>,
}

/// The workspace's `fixtures/` directory.
pub(crate) fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

/// Reads one scenario, in exchange order.
pub(crate) fn scenario(name: &str) -> Vec<Exchange> {
    let directory = fixtures().join("exchange-se").join(name);
    assert!(
        directory.is_dir(),
        "no fixtures at {}. Capture them with scripts\\Capture-Fixtures.ps1.",
        directory.display()
    );

    let mut stems: Vec<String> = std::fs::read_dir(&directory)
        .expect("a readable scenario directory")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()?
                .strip_suffix(".meta.txt")
                .map(str::to_owned)
        })
        .collect();
    stems.sort();
    assert!(
        !stems.is_empty(),
        "{} holds no exchanges",
        directory.display()
    );

    stems
        .into_iter()
        .map(|stem| {
            let meta = std::fs::read_to_string(directory.join(format!("{stem}.meta.txt")))
                .expect("a meta file");
            Exchange {
                status: value(&meta, "status").parse().expect("an HTTP status"),
                response_headers: headers(&meta, "[response-headers]"),
                request_body: std::fs::read(directory.join(format!("{stem}.request.bin")))
                    .expect("a request body"),
                response_body: std::fs::read(directory.join(format!("{stem}.response.bin")))
                    .expect("a response body"),
                stem,
            }
        })
        .collect()
}

/// A `key = value` from the `[exchange]` section.
fn value(meta: &str, key: &str) -> String {
    meta.lines()
        .find_map(|line| line.strip_prefix(&format!("{key} = ")))
        .unwrap_or_else(|| panic!("no `{key}` in the meta file"))
        .trim()
        .to_owned()
}

/// The `Name: value` lines of one section.
fn headers(meta: &str, section: &str) -> Vec<(String, String)> {
    meta.lines()
        .skip_while(|line| line.trim() != section)
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.trim().to_owned(), value.to_owned()))
        .collect()
}

/// Answers each request with the next recorded response, and keeps what it was sent.
struct Recording {
    queued: Mutex<VecDeque<ResponseTemplate>>,
}

impl Respond for Recording {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.queued.lock().unwrap().pop_front().unwrap_or_else(|| {
            ResponseTemplate::new(500).set_body_string("the corpus has no further response")
        })
    }
}

/// A fake endpoint that answers exactly what Exchange answered, in order.
pub(crate) async fn server(exchanges: &[Exchange]) -> MockServer {
    let mut queued = VecDeque::new();
    for exchange in exchanges {
        let mut template = ResponseTemplate::new(exchange.status);
        for (name, value) in &exchange.response_headers {
            // `Set-Cookie` appears more than once and every one of them matters: a Session Context
            // that has silently lost a cookie is reported several requests later as
            // `X-ResponseCode` 13, pointing nowhere near the cause.
            template = template.append_header(name.as_str(), value.as_str());
        }
        queued.push_back(template.set_body_bytes(exchange.response_body.clone()));
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Recording {
            queued: Mutex::new(queued),
        })
        .mount(&server)
        .await;
    server
}

/// The distinguished name the capture used, read back out of its `Connect` request body.
///
/// Taken from the corpus rather than written here, because the committed name is the redacted one
/// and the request bodies only match byte for byte if the replay logs on as exactly that.
///
/// [MS-OXCMAPIHTTP] §2.2.4.1.1 — `UserDn`, 8-bit and null-terminated
pub(crate) fn user_dn(exchanges: &[Exchange]) -> LegacyDn {
    // `-connect`, not `connect`: the latter also matches `14-disconnect`, whose body is four bytes
    // with no name in it, and which would be picked the moment a scenario stopped starting with a
    // `Connect`.
    let connect = exchanges
        .iter()
        .find(|exchange| exchange.stem.ends_with("-connect"))
        .expect("every scenario starts by connecting");
    let end = connect
        .request_body
        .iter()
        .position(|&byte| byte == 0)
        .expect("a null-terminated name");
    LegacyDn::new(String::from_utf8_lossy(&connect.request_body[..end]).into_owned())
        .expect("a usable name")
}

/// Compares what the client sent against what was captured, one exchange at a time.
pub(crate) async fn assert_requests_match(server: &MockServer, exchanges: &[Exchange]) {
    let sent = server.received_requests().await.unwrap_or_default();

    assert_eq!(
        sent.len(),
        exchanges.len(),
        "the replay made {} request(s), the corpus holds {}",
        sent.len(),
        exchanges.len()
    );

    for (request, exchange) in sent.iter().zip(exchanges) {
        assert_eq!(
            request.body, exchange.request_body,
            "{} differs from what a real server was sent",
            exchange.stem
        );
    }
}
