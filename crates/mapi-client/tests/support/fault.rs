//! A fake endpoint that fails the way networks do, which `wiremock` cannot: it goes away and comes
//! back on the same port, and it hangs up on a request it has read.
//!
//! [MS-OXCMAPIHTTP] §3.1.7 tells a failure while the request is being sent from one after the
//! whole of it was, and only a server that can do both shows the client telling them apart. HTTP
//! is spoken by hand, and only as much of it as `reqwest` sends: one request per read, with a
//! `Content-Length`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// What the server does with the next request it reads.
#[derive(Clone, Debug)]
pub(crate) enum Act {
    /// Answer it: a whole HTTP response, written as given.
    Reply(Vec<u8>),
    /// Read all of it, then close the connection without a word — §3.1.7.2's failure.
    HangUp,
    /// Read all of it, write these bytes, then close: an answer cut off part way.
    Partial(Vec<u8>),
}

/// One request as the server read it.
#[derive(Clone, Debug)]
pub(crate) struct Received {
    pub(crate) head: String,
    pub(crate) body: Vec<u8>,
}

impl Received {
    /// A header's value, by case-insensitive name.
    pub(crate) fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    }
}

#[derive(Default)]
struct Shared {
    script: Mutex<VecDeque<Act>>,
    received: Mutex<Vec<Received>>,
    connections: Mutex<Vec<JoinHandle<()>>>,
}

/// The server, and the port it keeps while it is down.
pub(crate) struct FaultServer {
    port: u16,
    shared: Arc<Shared>,
    accepting: Option<JoinHandle<()>>,
}

impl FaultServer {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = Arc::new(Shared::default());
        let accepting = Some(tokio::spawn(accept(listener, Arc::clone(&shared))));
        Self {
            port,
            shared,
            accepting,
        }
    }

    pub(crate) fn endpoint(&self) -> String {
        format!(
            "http://127.0.0.1:{}/mapi/emsmdb/?MailboxId={}@example.test",
            self.port, "00000000-0000-0000-0000-000000000000"
        )
    }

    pub(crate) fn then(&self, act: Act) -> &Self {
        self.shared.script.lock().unwrap().push_back(act);
        self
    }

    pub(crate) fn received(&self) -> Vec<Received> {
        self.shared.received.lock().unwrap().clone()
    }

    /// Goes away: the port refuses connections, and every open one is closed.
    pub(crate) async fn stop(&mut self) {
        if let Some(accepting) = self.accepting.take() {
            accepting.abort();
            let _ = accepting.await;
        }
        let connections: Vec<_> = self.shared.connections.lock().unwrap().drain(..).collect();
        for connection in connections {
            connection.abort();
            let _ = connection.await;
        }
    }

    /// Comes back, on the same port.
    pub(crate) async fn restart(&mut self) {
        let listener = TcpListener::bind(("127.0.0.1", self.port)).await.unwrap();
        self.accepting = Some(tokio::spawn(accept(listener, Arc::clone(&self.shared))));
    }
}

async fn accept(listener: TcpListener, shared: Arc<Shared>) {
    while let Ok((stream, _)) = listener.accept().await {
        let connection = tokio::spawn(serve(stream, Arc::clone(&shared)));
        shared.connections.lock().unwrap().push(connection);
    }
}

/// Reads requests off one connection and does whatever the script says with each.
async fn serve(mut stream: TcpStream, shared: Arc<Shared>) {
    let mut buffer = Vec::new();
    loop {
        let Some(request) = read_request(&mut stream, &mut buffer).await else {
            return;
        };
        shared.received.lock().unwrap().push(request);
        let act = shared.script.lock().unwrap().pop_front();
        match act {
            Some(Act::Reply(response)) => {
                if stream.write_all(&response).await.is_err() {
                    return;
                }
            }
            Some(Act::Partial(bytes)) => {
                let _ = stream.write_all(&bytes).await;
                let _ = stream.flush().await;
                return;
            }
            Some(Act::HangUp) | None => return,
        }
    }
}

/// One request: the head up to the blank line, then `Content-Length` bytes of body.
async fn read_request(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Received> {
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break at;
        }
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    let body_start = head_end + 4;
    while buffer.len() < body_start + length {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = buffer[body_start..body_start + length].to_vec();
    buffer.drain(..body_start + length);
    Some(Received { head, body })
}

/// A successful MAPI response, whole: status line, headers, the meta-tag preamble and `body`.
pub(crate) fn mapi_reply(body: &[u8], extra_headers: &[&str]) -> Vec<u8> {
    let mut payload = b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 1\r\n\r\n".to_vec();
    payload.extend_from_slice(body);
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/mapi-http\r\nX-ResponseCode: 0\r\n\
         Content-Length: {}\r\n",
        payload.len()
    );
    for header in extra_headers {
        response.push_str(header);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(&payload);
    bytes
}
