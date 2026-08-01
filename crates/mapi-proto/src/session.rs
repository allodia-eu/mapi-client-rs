//! The state machine: what is legal when, and what a response means.
//!
//! [`Session`] owns every byte and every piece of protocol state; the caller owns the I/O. Each
//! `begin_*` method hands back a [`Request`] to send, and [`Session::on_response`] takes the
//! headers and payload back. Nothing here opens a socket, spawns a task or reads a clock.
//!
//! Sequencing is enforced rather than documented: MAPI/HTTP allows exactly one request in flight
//! per Session Context, and violating that is reported by the server as `X-ResponseCode` 15
//! (Invalid Sequence) — a diagnostic that points nowhere near the cause.
//!
//! [MS-OXCMAPIHTTP] §3.1.4 — client higher-layer triggered events
//! [MS-OXCMAPIHTTP] §2.2.3.3.3 — `X-ResponseCode` 15, one request at a time

use crate::error::{Error, Result};
use crate::http::{
    ConnectResponse, CookieJar, ExecuteResponse, Headers, Payload, Request, RequestType,
    ResponseCode, connect_body, disconnect_body, execute_body,
};
use crate::oxcdata::{LegacyDn, PropertyTag};
use crate::rop::{ObjectHandle, RopBatch, RopBuffer, decode_all};

mod outcome;

pub use outcome::{Connected, Execution, Outcome};

/// `Content-Type` for every request. [MS-OXCMAPIHTTP] §2.2.3.2.2
const CONTENT_TYPE: &str = "application/mapi-http";

/// Default `X-ClientApplication`.
///
/// The header's documented format is `Outlook/15.xx.xxxx.xxxx` and servers read it as a version,
/// so the default is a value in that shape rather than this crate's own name. Override it with
/// [`SessionBuilder::client_application`] if you would rather be identifiable.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.6 — `X-ClientApplication`
const DEFAULT_CLIENT_APPLICATION: &str = "Outlook/15.00.0847.4040";

/// Default GUID for `X-RequestId` and `X-ClientInfo`.
///
/// The specification requires this GUID to be unique per client instance, and a crate that
/// performs no I/O cannot obtain randomness to make one. A transport that can — such as
/// `mapi-client` — sets its own through [`SessionBuilder`].
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.2 — `X-RequestId`
/// [MS-OXCMAPIHTTP] §2.2.3.3.4 — `X-ClientInfo`
const DEFAULT_GUID: &str = "{2EF33C39-49C8-421C-B876-CDF7F2AC3AA0}";

/// What the session is waiting for, and what it needs to interpret the answer.
#[derive(Clone, Debug)]
enum Pending {
    /// Carries the distinguished name, so a refusal can name what failed to map.
    Connect(LegacyDn),
    /// Carries each handle slot's column set, for decoding `RopQueryRows` responses.
    Execute(Vec<Option<Vec<PropertyTag>>>),
    Disconnect,
    Ping,
}

/// One MAPI/HTTP Session Context, driven entirely by the caller.
///
/// ```
/// use mapi_proto::{LegacyDn, Session};
///
/// let mut session = Session::new();
/// let user_dn = LegacyDn::new("/o=First/ou=Exchange Administrative Group/cn=alice")?;
///
/// let request = session.begin_connect(&user_dn)?;
/// assert_eq!(request.request_type().as_str(), "Connect");
/// assert_eq!(request.headers().get("Content-Type"), Some("application/mapi-http"));
///
/// // POST request.body() to the endpoint with request.headers(), then hand the response back:
/// //     let outcome = session.on_response(&response_headers, &response_payload)?;
/// # Ok::<(), mapi_proto::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Session {
    client_application: String,
    client_info: String,
    request_guid: String,
    counter: u64,
    cookies: CookieJar,
    pending: Option<Pending>,
    connected: bool,
    table_columns: Vec<(ObjectHandle, Vec<PropertyTag>)>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    /// A session with the default client identity.
    #[must_use]
    pub fn new() -> Self {
        Self::builder().build()
    }

    /// Configures the client identity headers before building a session.
    #[must_use]
    pub fn builder() -> SessionBuilder {
        SessionBuilder::new()
    }

    /// Whether a Session Context has been established.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    /// Whether a request is in flight, which is the state in which no new one may be sent.
    #[must_use]
    pub const fn is_awaiting_response(&self) -> bool {
        self.pending.is_some()
    }

    /// The session cookies, which identify the Session Context to the server.
    #[must_use]
    pub const fn cookies(&self) -> &CookieJar {
        &self.cookies
    }

    /// Builds the `Connect` request that establishes a Session Context.
    ///
    /// `user_dn` is Autodiscover's `<User><LegacyDN>`, passed through verbatim.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidState`] if a request is already in flight or the session is already
    /// connected.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1 — `Connect`
    pub fn begin_connect(&mut self, user_dn: &LegacyDn) -> Result<Request> {
        self.check_idle("send Connect")?;
        if self.connected {
            return Err(Error::InvalidState {
                attempted: "send Connect",
                reason: "this session already has a Session Context",
            });
        }

        let request = self.request(RequestType::Connect, connect_body(user_dn));
        self.pending = Some(Pending::Connect(user_dn.clone()));
        Ok(request)
    }

    /// Builds the `Execute` request that runs a batch of ROPs in one round trip.
    ///
    /// The batch's column sets are remembered here, so the rows that come back decode without the
    /// caller passing columns to anything.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidState`] if a request is in flight or no Session Context exists, plus
    /// whatever the batch itself recorded while it was being built — an unknown handle slot, or a
    /// buffer past what its length fields can describe.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.2 — `Execute`
    pub fn execute(&mut self, batch: RopBatch) -> Result<Request> {
        self.check_idle("send Execute")?;
        if !self.connected {
            return Err(Error::InvalidState {
                attempted: "send Execute",
                reason: "no Session Context yet; send Connect first",
            });
        }

        let mut built = batch.build()?;
        self.recall_columns(&mut built.columns, &built.initial_handles);

        let request = self.request(RequestType::Execute, execute_body(&built.bytes));
        self.pending = Some(Pending::Execute(built.columns));
        Ok(request)
    }

    /// Builds the `Disconnect` request that tears the Session Context down.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidState`] if a request is in flight or there is no Session Context.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.3 — `Disconnect`
    pub fn begin_disconnect(&mut self) -> Result<Request> {
        self.check_idle("send Disconnect")?;
        if !self.connected {
            return Err(Error::InvalidState {
                attempted: "send Disconnect",
                reason: "there is no Session Context to disconnect",
            });
        }

        let request = self.request(RequestType::Disconnect, disconnect_body());
        self.pending = Some(Pending::Disconnect);
        Ok(request)
    }

    /// Builds a `PING` request.
    ///
    /// `PING` validates an *existing* Session Context, so on a fresh session the honest answer is
    /// a non-zero `X-ResponseCode` rather than success. That still proves the endpoint exists,
    /// that authentication works and that the server speaks MAPI/HTTP.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidState`] if a request is already in flight.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.6 — `PING`
    pub fn begin_ping(&mut self) -> Result<Request> {
        self.check_idle("send PING")?;
        let request = self.request(RequestType::Ping, Vec::new());
        self.pending = Some(Pending::Ping);
        Ok(request)
    }

    /// Interprets the response to the request in flight.
    ///
    /// `payload` is the HTTP response body after chunked transfer decoding and before anything
    /// else: the meta-tag preamble is part of it and is parsed here.
    ///
    /// # Errors
    ///
    /// [`Error::MissingResponseCode`] when the `X-ResponseCode` header is absent — which is what
    /// an endpoint URL missing its `MailboxId` parameter looks like. [`Error::Transport`] when
    /// that code is non-zero. [`Error::ConnectFailed`] or [`Error::ExecuteFailed`] when the server
    /// refused the request itself, and a decoding error if the body does not match its documented
    /// layout.
    pub fn on_response(&mut self, headers: &Headers, payload: &[u8]) -> Result<Outcome> {
        // A response ends the in-flight request whatever it says, so take it before any `?`.
        let pending = self.pending.take().ok_or(Error::NoRequestInFlight)?;

        for value in headers.get_all("Set-Cookie") {
            self.cookies.absorb(value);
        }

        let code = headers
            .get("X-ResponseCode")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .map(ResponseCode::new)
            .ok_or(Error::MissingResponseCode)?;

        let payload = Payload::parse(payload);
        if !code.is_success() {
            return Err(Error::Transport {
                code,
                diagnostic: diagnostic(payload.body()),
            });
        }

        match pending {
            Pending::Connect(user_dn) => self.on_connect(payload.body(), user_dn),
            Pending::Execute(columns) => self.on_execute(payload.body(), &columns),
            Pending::Disconnect => {
                self.connected = false;
                self.cookies.clear();
                self.table_columns.clear();
                Ok(Outcome::Disconnected)
            }
            Pending::Ping => Ok(Outcome::Pong),
        }
    }

    fn on_connect(&mut self, body: &[u8], user_dn: LegacyDn) -> Result<Outcome> {
        let response = ConnectResponse::parse(body)?;
        if !response.is_success() {
            return Err(Error::ConnectFailed {
                code: response.error_code,
                user_dn,
            });
        }

        self.connected = true;
        Ok(Outcome::Connected(Connected {
            display_name: response.display_name,
            dn_prefix: response.dn_prefix,
            polls_max: response.polls_max,
            retry_count: response.retry_count,
            retry_delay: response.retry_delay,
        }))
    }

    fn on_execute(&mut self, body: &[u8], columns: &[Option<Vec<PropertyTag>>]) -> Result<Outcome> {
        let response = ExecuteResponse::parse(body)?;
        if !response.is_success() {
            return Err(Error::ExecuteFailed {
                status: response.status_code,
                code: response.error_code,
            });
        }

        let buffer = RopBuffer::parse(&response.rop_buffer)?;
        let responses = decode_all(&buffer.rops, columns)?;
        self.remember_columns(columns, &buffer.handles);

        Ok(Outcome::Executed(Execution {
            responses,
            handles: buffer.handles,
        }))
    }

    /// Fills in the column set for slots bound to a table this session has already configured, so
    /// paging through a table does not mean re-sending `RopSetColumns`.
    fn recall_columns(
        &self,
        columns: &mut [Option<Vec<PropertyTag>>],
        initial_handles: &[ObjectHandle],
    ) {
        for (slot, entry) in columns.iter_mut().enumerate() {
            if entry.is_some() {
                continue;
            }
            let Some(handle) = initial_handles.get(slot) else {
                continue;
            };
            if let Some((_, known)) = self.table_columns.iter().find(|(h, _)| h == handle) {
                *entry = Some(known.clone());
            }
        }
    }

    /// Records which column set now belongs to which server handle.
    fn remember_columns(&mut self, columns: &[Option<Vec<PropertyTag>>], handles: &[ObjectHandle]) {
        for (slot, entry) in columns.iter().enumerate() {
            let (Some(tags), Some(&handle)) = (entry.as_ref(), handles.get(slot)) else {
                continue;
            };
            if handle.is_none() {
                continue;
            }
            match self.table_columns.iter_mut().find(|(h, _)| *h == handle) {
                Some(known) => known.1.clone_from(tags),
                None => self.table_columns.push((handle, tags.clone())),
            }
        }
    }

    fn check_idle(&self, attempted: &'static str) -> Result<()> {
        if self.pending.is_some() {
            return Err(Error::InvalidState {
                attempted,
                reason: "a request is already in flight, and a Session Context allows only one",
            });
        }
        Ok(())
    }

    /// Builds the headers every request carries, then the request itself.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.2.1 — common request format
    fn request(&mut self, request_type: RequestType, body: Vec<u8>) -> Request {
        self.counter = self.counter.saturating_add(1);

        let mut headers = Headers::new();
        headers
            .append("Content-Type", CONTENT_TYPE)
            .append("X-RequestType", request_type.as_str())
            .append(
                "X-RequestId",
                format!("{}:{}", self.request_guid, self.counter),
            )
            .append("X-ClientApplication", self.client_application.clone())
            .append("X-ClientInfo", self.client_info.clone());

        if let Some(cookie) = self.cookies.header_value() {
            headers.append("Cookie", cookie);
        }

        Request::new(request_type, headers, body)
    }
}

/// Extracts whatever diagnostic text a server put in a failure body.
///
/// Servers answer a rejected request with an HTML error page rather than a protocol body, and the
/// one sentence in it is often the only statement of what was actually wrong.
fn diagnostic(body: &[u8]) -> Option<String> {
    // A binary body is a protocol response that arrived under a failing code, not a message; only
    // something that is legible as text can be quoted back to a human.
    let text = core::str::from_utf8(body).ok()?;
    let paragraph = text
        .split_once("<p>")
        .and_then(|(_, tail)| tail.split_once("</p>"))
        .map(|(inner, _)| inner);

    let text = paragraph.unwrap_or(text).trim();
    let legible = !text.is_empty()
        && !text.contains('<')
        && !text.chars().any(|c| c.is_control() && !c.is_whitespace());

    legible.then(|| text.chars().take(200).collect())
}

/// Builds a [`Session`] with a client identity of your own.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3 — X-header fields
#[derive(Clone, Debug)]
pub struct SessionBuilder {
    client_application: String,
    client_info: String,
    request_guid: String,
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionBuilder {
    /// A builder carrying the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client_application: DEFAULT_CLIENT_APPLICATION.to_owned(),
            client_info: format!("{DEFAULT_GUID}:1"),
            request_guid: DEFAULT_GUID.to_owned(),
        }
    }

    /// Sets `X-ClientApplication`, whose documented format is `Outlook/15.xx.xxxx.xxxx`.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.6
    #[must_use]
    pub fn client_application(mut self, value: impl Into<String>) -> Self {
        self.client_application = value.into();
        self
    }

    /// Sets `X-ClientInfo`, a GUID and a decimal counter such as `{GUID}:123`.
    ///
    /// The GUID must be unique per client instance and stable for its lifetime.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.4
    #[must_use]
    pub fn client_info(mut self, value: impl Into<String>) -> Self {
        self.client_info = value.into();
        self
    }

    /// Sets the GUID used in `X-RequestId`, which must not change for the life of the Session
    /// Context. The counter after it is maintained by the session.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.2
    #[must_use]
    pub fn request_guid(mut self, value: impl Into<String>) -> Self {
        self.request_guid = value.into();
        self
    }

    /// Builds the session.
    #[must_use]
    pub fn build(self) -> Session {
        Session {
            client_application: self.client_application,
            client_info: self.client_info,
            request_guid: self.request_guid,
            counter: 0,
            cookies: CookieJar::new(),
            pending: None,
            connected: false,
            table_columns: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests;
