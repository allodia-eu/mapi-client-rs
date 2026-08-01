//! The MAPI/HTTP envelope: request types, headers, cookies and the response stream.
//!
//! Two things here were learned from live servers rather than read out of the documents, and both
//! are recorded where they bite:
//!
//! * **`X-ClientInfo` is required by at least one implementation** and ignored by another. The
//!   specification says the client MUST send it, so this crate always does — but a client must not
//!   read its absence from a *server* as fatal.
//! * **The mailbox endpoint URL needs its `?MailboxId=` query parameter.** Without it Exchange
//!   answers HTTP 400 with no `X-ResponseCode` header at all, which reads like "MAPI is not
//!   enabled" rather than "your URL is incomplete". Autodiscover returns the full URL; use it
//!   verbatim.
//!
//! [MS-OXCMAPIHTTP] §2.2.2 — POST method
//! [MS-OXCMAPIHTTP] §2.2.3 — header fields

mod body;
mod cookie;
mod headers;
mod request;
mod response;

pub(crate) use body::{ConnectResponse, ExecuteResponse};
pub use cookie::{CookieJar, SessionCookie};
pub use headers::{GetAll, Headers, Iter};
pub use request::{Request, RequestType};
pub(crate) use request::{connect_body, disconnect_body, execute_body};
pub use response::{MetaTag, Payload, ResponseCode};
