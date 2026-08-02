//! The HTTP boundary: the only module in this crate that knows which HTTP client is underneath.
//!
//! Everything above this file works in terms of [`mapi_proto::Request`] and
//! [`mapi_proto::Headers`], which is what keeps the choice of HTTP client an implementation detail
//! rather than part of the public API.
//!
//! [MS-OXCMAPIHTTP] §2.2.2.1 — common request format

use core::time::Duration;

use mapi_proto::{Headers, Request};
use reqwest::{Client, Response, StatusCode, Url};

use crate::credentials::Credentials;
use crate::error::{Error, Result};

/// Longest a diagnostic taken from an error body is worth quoting back.
const MAX_DIAGNOSTIC: usize = 200;

/// Everything the transport needs that does not change between requests.
#[derive(Clone, Debug)]
pub(crate) struct Transport {
    pub(crate) http: Client,
    pub(crate) endpoint: Url,
    pub(crate) credentials: Credentials,
    pub(crate) timeout: Duration,
}

impl Transport {
    /// POSTs one request and returns the response headers and payload.
    ///
    /// The payload is handed back whole rather than streamed. A MAPI response is bounded by the
    /// 64 KiB `MaxRopOut` this crate asks for plus the meta-tag preamble, so there is nothing to
    /// gain by streaming it — and the preamble is only parseable once `DONE` has arrived anyway.
    pub(crate) async fn send(&self, request: &Request) -> Result<(Headers, Vec<u8>)> {
        let mut builder = self.http.post(self.endpoint.clone());
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        builder = match &self.credentials {
            Credentials::None => builder,
            Credentials::Basic { username, password } => {
                builder.basic_auth(username, Some(password))
            }
            Credentials::Bearer { token } => builder.bearer_auth(token),
        };

        let response = builder
            .body(request.body().to_vec())
            .send()
            .await
            .map_err(|error| self.classify(error))?;

        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(self.unauthorized(&response));
        }

        let headers = read_headers(&response);
        let body = response
            .bytes()
            .await
            .map_err(|error| self.classify(error))?
            .to_vec();

        // A MAPI endpoint reports protocol-level refusals as HTTP 200 with a non-zero
        // `X-ResponseCode`, so any other status means the request never reached the protocol and
        // the body is not a MAPI response. Measured against Exchange Server SE `15.02.2562.045`:
        // an unknown `X-RequestType` and a missing required header both come back 200, while an
        // endpoint URL without its `MailboxId` parameter comes back 400 with an empty body.
        if !status.is_success() {
            return Err(Error::Http {
                status: status.as_u16(),
                url: self.endpoint.to_string(),
                detail: diagnostic(&body),
            });
        }

        Ok((headers, body))
    }

    /// Turns the HTTP client's own error into one of ours, keeping the original as the source.
    ///
    /// The connect check comes first deliberately. A connection that times out reports *both* as
    /// true, and calling that a request timeout would attach the wrong duration to it — the whole
    /// 90-second request budget rather than the connect timeout that actually elapsed — and send
    /// the reader looking at a slow server rather than at an unreachable one.
    fn classify(&self, error: reqwest::Error) -> Error {
        let url = self.endpoint.to_string();
        if error.is_connect() {
            return Error::Connect {
                url,
                source: Box::new(error),
            };
        }
        if error.is_timeout() {
            return Error::Timeout {
                url,
                after: self.timeout,
            };
        }
        Error::Request {
            url,
            source: Box::new(error),
        }
    }

    /// Reports a 401 with the schemes the server offered, which is what distinguishes "wrong
    /// password" from "this client cannot speak any scheme this server accepts".
    fn unauthorized(&self, response: &Response) -> Error {
        let offered = response
            .headers()
            .get_all("WWW-Authenticate")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split_whitespace().next())
            .map(str::to_owned)
            .collect();

        Error::Unauthorized {
            url: self.endpoint.to_string(),
            offered,
            sent: self.credentials.describe(),
        }
    }
}

/// Copies the response headers into the codec's neutral header type.
///
/// Values are converted lossily rather than skipped when they are not valid UTF-8. Dropping one
/// would mean dropping a `Set-Cookie`, and a Session Context that has silently lost a cookie comes
/// back as `X-ResponseCode` 13 several requests later, pointing nowhere near the cause.
fn read_headers(response: &Response) -> Headers {
    let mut headers = Headers::new();
    for (name, value) in response.headers() {
        headers.append(name.as_str(), String::from_utf8_lossy(value.as_bytes()));
    }
    headers
}

/// Extracts whatever legible text an error body holds.
///
/// The rule mirrors [`mapi_proto`]'s for a failing `X-ResponseCode` body, so a diagnostic reads the
/// same whichever layer produced it: a server's HTML error page usually has exactly one sentence
/// worth quoting, and a body that is not legible text is a response, not a message.
fn diagnostic(body: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(body).ok()?;
    let paragraph = text
        .split_once("<p>")
        .and_then(|(_, tail)| tail.split_once("</p>"))
        .map(|(inner, _)| inner);

    let text = paragraph.unwrap_or(text).trim();
    let legible = !text.is_empty()
        && !text.contains('<')
        && !text.chars().any(|c| c.is_control() && !c.is_whitespace());

    legible.then(|| text.chars().take(MAX_DIAGNOSTIC).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binary_body_is_never_quoted_as_a_message() {
        assert_eq!(diagnostic(&[0x00, 0xFF, 0xFE]), None);
        assert_eq!(diagnostic(b""), None);
        assert_eq!(diagnostic(b"   \r\n  "), None);
    }

    #[test]
    fn one_sentence_is_lifted_out_of_an_error_page() {
        let page = b"<html><body><h2>Error</h2><p>MAPI over HTTP is disabled</p></body></html>";
        assert_eq!(
            diagnostic(page).as_deref(),
            Some("MAPI over HTTP is disabled")
        );
        // No paragraph and no markup: the whole body is the message.
        assert_eq!(
            diagnostic(b"Service Unavailable").as_deref(),
            Some("Service Unavailable")
        );
        // Markup with no paragraph to lift is not worth quoting.
        assert_eq!(diagnostic(b"<html><h2>Nope</h2></html>"), None);
    }

    #[test]
    fn a_long_diagnostic_is_truncated_rather_than_dumped() {
        let long = "x".repeat(500);
        let quoted = diagnostic(long.as_bytes()).unwrap();
        assert_eq!(quoted.chars().count(), MAX_DIAGNOSTIC);
    }
}
