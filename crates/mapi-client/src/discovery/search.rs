//! The HTTP side of one lookup: asking a candidate, answering its challenge, and the probe.

use mapi_autodiscover::{AutodiscoverRequest, AutodiscoverResponse, EmailAddress};
use reqwest::{Client, Response, StatusCode, Url};

use crate::builder::{MapiClientBuilder, parse_endpoint};
use crate::credentials::Credentials;
use crate::error::{Error, Result};
use crate::observer::{Observer, Redirect};
use crate::transport::{challenges, scheme_names};

/// What one candidate came to.
#[derive(Debug)]
pub(super) enum Answer {
    /// Nothing useful: refused, timed out, not Autodiscover, or not a URL to ask.
    Nothing,
    /// An HTTP 302 to a URL this crate would ask, absolute.
    Moved(String),
    /// An Autodiscover response.
    Response(AutodiscoverResponse),
    /// A 401 asking for a scheme these credentials are not, which was sent nothing: a candidate
    /// this client cannot use, and the refusal to report if no other candidate answers.
    Unasked(Error),
}

/// What asking one candidate, and answering its challenge, came to.
#[derive(Debug)]
pub(super) enum Reply {
    /// It did not answer at all.
    Silent,
    /// Its last response, whatever the status.
    Answered(Response),
    /// It answered 401, offering these challenges and none in the credentials' scheme.
    Unasked(Vec<String>),
}

/// What goes in a request's `Authorization` header.
#[derive(Debug)]
pub(super) enum Authorization {
    /// Nothing: the candidate has not asked.
    Withheld,
    /// `Bearer` and no token, which asks for a `Bearer` challenge and proves nothing. Measured
    /// against Exchange Server SE `15.02.2562.056`: an Autodiscover or MAPI POST with no
    /// `Authorization` is answered 401 offering `Negotiate`, `NTLM` and Basic, and the same POST
    /// carrying a bare `Authorization: Bearer` is answered 401 offering `Bearer` first. So a token
    /// can only be asked for by announcing one.
    Announced,
    /// The Basic or Bearer header the credentials make, in answer to a 401 that asked for it.
    Credentials,
    /// A handshake leg this crate computed.
    #[cfg(feature = "ntlm")]
    Value(String),
}

/// The HTTP side of one lookup.
#[derive(Debug)]
pub(super) struct Search<'a> {
    http: Client,
    pub(super) credentials: &'a Credentials,
    allow_plaintext_http: bool,
    observer: Option<&'a dyn Observer>,
    /// The builder's KDCs and tickets, for `Negotiate`.
    #[cfg(feature = "ntlm")]
    pub(super) kerberos: Option<&'a crate::handshake::Kdcs>,
    /// How long to wait for each KDC: the connect timeout. See
    /// [`Context::kdc_timeout`](crate::handshake::Context::kdc_timeout).
    #[cfg(feature = "ntlm")]
    pub(super) kdc_timeout: core::time::Duration,
}

impl<'a> Search<'a> {
    /// The HTTP side of a lookup `builder` describes, over `http`.
    pub(super) fn new(builder: &'a MapiClientBuilder, http: Client) -> Self {
        Self {
            http,
            credentials: &builder.credentials,
            allow_plaintext_http: builder.allows_plaintext_http(),
            observer: builder.observer.as_deref(),
            #[cfg(feature = "kerberos")]
            kerberos: Some(&builder.kerberos),
            #[cfg(all(feature = "ntlm", not(feature = "kerberos")))]
            kerberos: None,
            #[cfg(feature = "ntlm")]
            kdc_timeout: builder.connect_timeout,
        }
    }

    /// Tells the observer, if there is one, that the search is being sent elsewhere.
    pub(super) fn report(&self, redirect: Redirect<'_>) {
        if let Some(observer) = self.observer {
            observer.redirected(&redirect);
        }
    }

    /// Asks one candidate URL.
    ///
    /// [`Answer::Nothing`] and [`Answer::Unasked`] mean the next candidate, not the end of the
    /// search. A 401 after the credentials were sent is the end: they were refused.
    pub(super) async fn ask(&self, url: &str, address: &EmailAddress) -> Result<Answer> {
        let Ok(url) = parse_endpoint(url, self.allow_plaintext_http) else {
            return Ok(Answer::Nothing);
        };

        // A connection-oriented scheme has to run its handshake here too. Autodiscover is the
        // *first* thing a caller does, so NTLM that worked only on the MAPI endpoint would fail at
        // the step before it.
        #[cfg(feature = "ntlm")]
        let reply = self.authenticate(&url, address).await?;
        #[cfg(not(feature = "ntlm"))]
        let reply = self.challenged(&url, address).await;
        let response = match reply {
            Reply::Silent => return Ok(Answer::Nothing),
            Reply::Answered(response) => response,
            Reply::Unasked(offered) => {
                let error = refused(&url, &offered, self.credentials.withheld());
                return Ok(Answer::Unasked(error));
            }
        };

        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(refused(
                &url,
                &challenges(&response),
                self.credentials.describe(),
            ));
        }

        // [MS-OXDSCLI] §3.1.5.2: "the client SHOULD repost the request to the redirection URL
        // contained in the Location header". Only to one this crate would ask in the first place,
        // which is an `https` one: this answer came over TLS, and the next request may carry
        // credentials if it is challenged.
        if status == StatusCode::FOUND {
            let target = location(&response, &url)
                .filter(|target| parse_endpoint(target, self.allow_plaintext_http).is_ok());
            let _ = response.bytes().await;
            return Ok(target.map_or(Answer::Nothing, Answer::Moved));
        }

        if !status.is_success() {
            return Ok(Answer::Nothing);
        }

        let Ok(body) = response.text().await else {
            return Ok(Answer::Nothing);
        };

        // Not every 200 on this path is an Autodiscover response — the first candidate URL is
        // often just the organisation's website — so a body that will not parse is one more
        // candidate that did not answer.
        Ok(AutodiscoverResponse::parse(&body).map_or(Answer::Nothing, Answer::Response))
    }

    /// Asks with no credentials, and again with a Basic or Bearer header if the 401 that came back
    /// offered its scheme. The whole of authentication for those two, and for no credentials —
    /// which have no scheme to offer, so every 401 they meet asked for something they are not and
    /// was sent nothing: a candidate this client cannot use, like any other.
    pub(super) async fn challenged(&self, url: &Url, address: &EmailAddress) -> Reply {
        let opening = match self.credentials {
            Credentials::Bearer { .. } => Authorization::Announced,
            _ => Authorization::Withheld,
        };
        let Some(first) = self.post(url, address, opening).await else {
            return Reply::Silent;
        };
        if first.status() != StatusCode::UNAUTHORIZED {
            return Reply::Answered(first);
        }

        let offered = challenges(&first);
        let _ = first.bytes().await;
        let Some(scheme) = self.credentials.header_scheme() else {
            return Reply::Unasked(offered);
        };
        if !offered.iter().any(|value| names(value, scheme)) {
            return Reply::Unasked(offered);
        }
        self.post(url, address, Authorization::Credentials)
            .await
            .map_or(Reply::Silent, Reply::Answered)
    }

    /// POSTs one Autodiscover request, with whatever `authorization` says to send.
    ///
    /// `None` means the candidate did not answer at all, which is a reason to try the next one
    /// rather than to stop.
    pub(super) async fn post(
        &self,
        url: &Url,
        address: &EmailAddress,
        authorization: Authorization,
    ) -> Option<Response> {
        let request = AutodiscoverRequest::new(address);
        let mut builder = self.http.post(url.clone());
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        builder = match (authorization, self.credentials) {
            #[cfg(feature = "ntlm")]
            (Authorization::Value(value), _) => {
                builder.header(reqwest::header::AUTHORIZATION, value)
            }
            (Authorization::Credentials, Credentials::Basic { username, password }) => {
                builder.basic_auth(username, Some(password))
            }
            (Authorization::Credentials, Credentials::Bearer { token }) => {
                builder.bearer_auth(token)
            }
            (Authorization::Announced, _) => {
                builder.header(reqwest::header::AUTHORIZATION, "Bearer")
            }
            // Withheld, and credentials that make no header of their own.
            _ => builder,
        };

        builder.body(request.into_body()).send().await.ok()
    }

    /// The plain-HTTP redirect probe: a `GET` of `url` whose 302 names the real service.
    ///
    /// The `Location`, absolute, when it is one this crate would ask — which the caller then puts
    /// to the user rather than following. Only a 302 counts: it is the one status §3.1.5.4 names,
    /// and "if the response is not a 302 redirection, then the expected response is an
    /// Autodiscover server URI", which a `GET` cannot return. Redirects are not followed
    /// automatically anywhere in this crate, which is what makes this readable at all: the 302
    /// arrives as a 302.
    ///
    /// [MS-OXDISCO] §3.1.5.4 — locations found by an HTTP redirect
    pub(super) async fn probe(&self, url: &str) -> Option<String> {
        let probe = Url::parse(url).ok()?;
        let response = self.http.get(probe.clone()).send().await.ok()?;
        if response.status() != StatusCode::FOUND {
            return None;
        }
        location(&response, &probe)
            .filter(|target| parse_endpoint(target, self.allow_plaintext_http).is_ok())
    }
}

/// The refusal for a 401 from `url` that offered `challenges`, having sent what `sent` says.
pub(super) fn refused(url: &Url, challenges: &[String], sent: &'static str) -> Error {
    Error::Unauthorized {
        url: url.to_string(),
        offered: scheme_names(challenges),
        sent,
    }
}

/// A response's `Location`, resolved against the URL it answered.
fn location(response: &Response, base: &Url) -> Option<String> {
    let value = response.headers().get(reqwest::header::LOCATION)?;
    let target = base.join(value.to_str().ok()?).ok()?;
    Some(target.to_string())
}

/// Whether a `WWW-Authenticate` value names `scheme`, which is case-insensitive.
///
/// [RFC 9110] §11.1 — "It uses a case-insensitive token to identify the authentication scheme"
fn names(challenge: &str, scheme: &str) -> bool {
    challenge
        .split_whitespace()
        .next()
        .is_some_and(|token| token.eq_ignore_ascii_case(scheme))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_challenge_names_its_scheme_whatever_the_case() {
        assert!(names("Basic realm=\"x\"", "Basic"));
        assert!(names("basic", "Basic"));
        assert!(names("Bearer client_id=\"0\"", "Bearer"));
        assert!(!names("Negotiate", "Basic"));
        assert!(!names("BasicAuth", "Basic"), "a token is the whole word");
        assert!(!names("", "Basic"));
    }
}
