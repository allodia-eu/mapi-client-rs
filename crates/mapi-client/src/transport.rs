//! The HTTP boundary: the only module in this crate that knows which HTTP client is underneath.
//!
//! Everything above this file works in terms of [`mapi_proto::Request`] and
//! [`mapi_proto::Headers`], which is what keeps the choice of HTTP client an implementation detail
//! rather than part of the public API.
//!
//! [MS-OXCMAPIHTTP] §2.2.2.1 — common request format

#[cfg(feature = "ntlm")]
mod negotiated;

use core::time::Duration;
use std::sync::Arc;

use mapi_proto::{Headers, Request};
use reqwest::{Client, Response, StatusCode, Url};

use crate::credentials::Credentials;
use crate::error::{Error, Result};
use crate::observer::{Exchange, Observer};

/// Longest a diagnostic taken from an error body is worth quoting back.
const MAX_DIAGNOSTIC: usize = 200;

/// Everything the transport needs that does not change between requests.
#[derive(Clone, Debug)]
pub(crate) struct Transport {
    pub(crate) http: Client,
    pub(crate) endpoint: Url,
    pub(crate) credentials: Credentials,
    pub(crate) timeout: Duration,
    pub(crate) observer: Option<Arc<dyn Observer>>,
    /// Whether this transport's connection has already been authenticated, and the lock that keeps
    /// only one request at a time near it.
    ///
    /// Shared across clones, because clones share the connection pool that the state is about.
    #[cfg(feature = "ntlm")]
    pub(crate) connection: Arc<tokio::sync::Mutex<negotiated::ConnectionAuth>>,
}

/// One HTTP exchange, before anything has decided whether it was a success.
struct Reply {
    status: StatusCode,
    headers: Headers,
    body: Vec<u8>,
    /// The `WWW-Authenticate` values, whole. Read only on a 401, where they are what distinguishes
    /// "wrong password" from "this client speaks no scheme this server accepts" — and, for a
    /// connection-oriented scheme, where the next message of the handshake comes from.
    challenges: Vec<String>,
    /// The server's certificate, in DER, for computing a channel binding.
    #[cfg(feature = "ntlm")]
    certificate: Option<Vec<u8>>,
}

impl Transport {
    /// POSTs one request and returns the response headers and payload.
    ///
    /// The payload is handed back whole rather than streamed. A MAPI response is bounded by the
    /// 64 KiB `MaxRopOut` this crate asks for plus the meta-tag preamble, so there is nothing to
    /// gain by streaming it — and the preamble is only parseable once `DONE` has arrived anyway.
    pub(crate) async fn send(&self, request: &Request) -> Result<(Headers, Vec<u8>)> {
        #[cfg(feature = "ntlm")]
        if self.credentials.handshake().is_some() {
            return self.send_negotiated(request).await;
        }

        let reply = self.post(Some(request), None).await?;
        self.finish(request, reply)
    }

    /// POSTs once, with an optional MAPI request and an optional `Authorization` value.
    ///
    /// Both are optional because a handshake leg is neither: it carries no MAPI request — the
    /// server will answer 401 before anything reaches the protocol — and it carries an
    /// `Authorization` header this crate computed rather than one derived from the credentials.
    async fn post(&self, request: Option<&Request>, authorization: Option<&str>) -> Result<Reply> {
        let mut builder = self.http.post(self.endpoint.clone());
        if let Some(request) = request {
            for (name, value) in request.headers() {
                builder = builder.header(name, value);
            }
        }

        builder = if let Some(value) = authorization {
            builder.header(reqwest::header::AUTHORIZATION, value)
        } else {
            match &self.credentials {
                Credentials::Basic { username, password } => {
                    builder.basic_auth(username, Some(password))
                }
                Credentials::Bearer { token } => builder.bearer_auth(token),
                // `None`, and the handshake schemes, which supply their own header above.
                _ => builder,
            }
        };

        let body = request
            .map(|request| request.body().to_vec())
            .unwrap_or_default();
        if body.is_empty() {
            // `reqwest` sends no `Content-Length` at all for an empty body, and `http.sys` answers
            // a POST without one with 411 — *before* authentication, so the handshake leg that
            // carries no MAPI request never reaches the challenge it was sent for. Measured
            // against Exchange Server SE `15.02.2562.045`: the same request with this header is a
            // 401 carrying `WWW-Authenticate`, and without it a 411 carrying none.
            builder = builder.header(reqwest::header::CONTENT_LENGTH, "0");
        }

        let response = builder
            .body(body)
            .send()
            .await
            .map_err(|error| self.classify(error))?;

        let status = response.status();
        let challenges = if status == StatusCode::UNAUTHORIZED {
            challenges(&response)
        } else {
            Vec::new()
        };
        #[cfg(feature = "ntlm")]
        let certificate = peer_certificate(&response);
        let headers = read_headers(&response);

        // Read whatever the status, so that an observer sees the refusals too — a 401 body and a
        // 400 body are exactly what somebody debugging a deployment needs, and downloading a few
        // hundred bytes of error page costs nothing. It is also what returns the connection to the
        // pool, which a handshake depends on: an unread body means the next leg opens a second
        // connection and the server has no challenge outstanding on it.
        let body = response
            .bytes()
            .await
            .map_err(|error| self.classify(error))?
            .to_vec();

        Ok(Reply {
            status,
            headers,
            body,
            challenges,
            #[cfg(feature = "ntlm")]
            certificate,
        })
    }

    /// Reports the exchange to the observer and turns a refusal into an error.
    ///
    /// Only the exchange that carried the real request reaches an observer. A handshake leg is not
    /// a MAPI exchange — it has no `X-RequestType` and an empty body — and feeding one to the
    /// fixture recorder would write a file that is not a request/response pair.
    fn finish(&self, request: &Request, reply: Reply) -> Result<(Headers, Vec<u8>)> {
        let Reply {
            status,
            headers,
            body,
            challenges,
            ..
        } = reply;

        if let Some(observer) = &self.observer {
            observer.observe(&Exchange::new(request, status.as_u16(), &headers, &body));
        }

        if status == StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized {
                url: self.endpoint.to_string(),
                offered: scheme_names(&challenges),
                sent: self.credentials.describe(),
            });
        }

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
}

/// The `WWW-Authenticate` values, whole.
fn challenges(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all("WWW-Authenticate")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect()
}

/// The scheme each challenge names, which is what an error message quotes.
fn scheme_names(challenges: &[String]) -> Vec<String> {
    challenges
        .iter()
        .filter_map(|value| value.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// The end-entity certificate the TLS handshake presented, in DER.
///
/// Present only when the client was built with `tls_info(true)`, and absent for a plaintext
/// endpoint, which is why a missing one is a `None` rather than an error: it means "there is no
/// channel to bind to", and that is a legitimate state.
#[cfg(feature = "ntlm")]
fn peer_certificate(response: &Response) -> Option<Vec<u8>> {
    response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate().map(<[u8]>::to_vec))
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

    /// A 401 from Exchange carries one header per scheme, and the token is on the same line as the
    /// name. An error message wants the names; a handshake wants the whole value.
    #[test]
    fn a_challenge_keeps_its_token_and_reports_only_its_name() {
        let offered = [
            "Negotiate TlRMTVNTUAACAAAA".to_owned(),
            "NTLM".to_owned(),
            "Basic realm=\"exchange-lab-01\"".to_owned(),
        ];
        assert_eq!(scheme_names(&offered), ["Negotiate", "NTLM", "Basic"]);
        assert_eq!(scheme_names(&[]), Vec::<String>::new());
        assert_eq!(scheme_names(&["   ".to_owned()]), Vec::<String>::new());
    }
}
