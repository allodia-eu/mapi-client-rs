//! Driving Autodiscover: turning an email address into an endpoint URL and a distinguished name.
//!
//! [`mapi-autodiscover`](mapi_autodiscover) says where to look, what to send and what came back.
//! This module does the looking. The sequence is [MS-OXDISCO] §3.1.5's: try each candidate URL in
//! turn, follow whatever redirects the answers ask for, and only then fall back to the plain-HTTP
//! redirect probe.
//!
//! **A candidate that does not answer is not a failure** — a refused connection, a timeout, a page
//! that is not Autodiscover at all, or a server that answers with an `<Error>` element all mean
//! "try the next one", which is why an unreachable first candidate does not stop the search. A
//! **401 does** stop it: the service is there and has refused these credentials, and grinding
//! through the remaining candidates would replace that diagnosis with "nothing was found".
//!
//! DNS `SRV` lookup is not performed here — it needs a resolver, and this crate has no opinion
//! about which one. [`mapi_autodiscover::srv_query`] gives the query to make and
//! [`mapi_autodiscover::url_for_host`] turns each answer into a URL for
//! [`MapiClientBuilder::lookup_at`].
//!
//! [MS-OXDISCO] §3.1.5 — how a client builds its list of candidate URIs
//! [MS-OXDSCLI] §3.1.5.3 — acting on `redirectAddr` and `redirectUrl`

use std::collections::VecDeque;

use mapi_autodiscover::{
    AutodiscoverRequest, AutodiscoverResponse, EmailAddress, MapiHttpEndpoint, candidate_urls,
    redirect_probe_url,
};
use mapi_proto::LegacyDn;
use reqwest::{Client, StatusCode};

use crate::builder::{MapiClientBuilder, parse_endpoint};
use crate::client::MapiClient;
use crate::credentials::Credentials;
use crate::error::{Error, Result};

/// How many redirects to follow before calling it a loop.
///
/// A redirect chain is a deployment describing itself, and no real one is deep. Ten is generous
/// and still terminates.
const MAX_REDIRECTS: usize = 10;

impl MapiClientBuilder {
    /// Locates the mailbox with Autodiscover and builds a client for it.
    ///
    /// The terminal call for the common path, in place of [`build`](MapiClientBuilder::build):
    /// it fills in the endpoint URL and the distinguished name, which is exactly the pair that
    /// has no default.
    ///
    /// ```no_run
    /// use mapi_client::{Credentials, EmailAddress, MapiClient};
    ///
    /// # async fn example() -> Result<(), mapi_client::Error> {
    /// let client = MapiClient::builder()
    ///     .credentials(Credentials::basic("alice@example.test", "hunter2"))
    ///     .discover(&EmailAddress::new("alice@example.test")?)
    ///     .await?;
    /// # let _ = client;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::NoEndpoint`] if no candidate produced a MAPI/HTTP endpoint,
    /// [`Error::Unauthorized`] if one refused the credentials, [`Error::TooManyRedirects`] if the
    /// deployment describes a loop, and whatever [`build`](MapiClientBuilder::build) reports once
    /// the answer is in hand.
    pub async fn discover(self, address: &EmailAddress) -> Result<MapiClient> {
        let endpoint = self.lookup(address).await?;
        self.for_endpoint(&endpoint, address)
    }

    /// Builds a client for an endpoint Autodiscover has already described.
    ///
    /// The two settings that have no default are exactly the two a `mapiHttp` block carries, which
    /// is why discovery is a terminal call rather than a separate step the caller has to wire up.
    fn for_endpoint(
        mut self,
        endpoint: &MapiHttpEndpoint,
        address: &EmailAddress,
    ) -> Result<MapiClient> {
        let url = endpoint.mail_store_url().ok_or_else(|| Error::NoEndpoint {
            address: address.to_string(),
            tried: vec!["a mapiHttp block that named no MailStore URL".to_owned()],
        })?;

        self.endpoint = Some(url.to_owned());
        self.user_dn = Some(LegacyDn::new(endpoint.legacy_dn())?);
        self.build()
    }

    /// Locates the mailbox without building anything.
    ///
    /// For a caller that wants what Autodiscover said — the address book URL, both the internal
    /// and external mail store URLs — rather than just a working client.
    ///
    /// # Errors
    ///
    /// As [`discover`](MapiClientBuilder::discover), minus the ones that come from building.
    pub async fn lookup(&self, address: &EmailAddress) -> Result<MapiHttpEndpoint> {
        let queue = candidate_urls(address).collect();
        self.search(address, queue, true).await
    }

    /// Locates the mailbox starting from an Autodiscover URL you already have.
    ///
    /// Two reasons to reach for this: a deployment whose Autodiscover service is somewhere the
    /// candidate sequence would never look, and the `SRV` step this crate leaves to the caller —
    /// resolve [`mapi_autodiscover::srv_query`] yourself and pass each host through
    /// [`mapi_autodiscover::url_for_host`].
    ///
    /// Redirects are still followed from here.
    ///
    /// # Errors
    ///
    /// As [`lookup`](MapiClientBuilder::lookup).
    pub async fn lookup_at(
        &self,
        url: impl Into<String>,
        address: &EmailAddress,
    ) -> Result<MapiHttpEndpoint> {
        let queue = VecDeque::from([url.into()]);
        self.search(address, queue, false).await
    }

    /// Works through the queue, following redirects, until something answers with settings.
    async fn search(
        &self,
        address: &EmailAddress,
        mut queue: VecDeque<String>,
        probe: bool,
    ) -> Result<MapiHttpEndpoint> {
        let search = Search {
            http: self.http()?,
            credentials: &self.credentials,
            allow_plaintext_http: self.allows_plaintext_http(),
        };

        let mut address = address.clone();
        let mut tried: Vec<String> = Vec::new();
        let mut redirects = 0_usize;
        let mut probed = !probe;

        loop {
            let Some(url) = queue.pop_front() else {
                if probed {
                    break;
                }
                probed = true;
                // Last resort: a GET over plain HTTP whose `Location` names the real service.
                // It carries no body and no credentials, which is why plain HTTP is tolerable
                // here and nowhere else. [MS-OXDISCO] §3.1.5.4
                if let Some(target) = search.probe(&address).await {
                    queue.push_back(target);
                }
                continue;
            };

            tried.push(url.clone());
            let Some(response) = search.ask(&url, &address).await? else {
                continue;
            };

            match response {
                AutodiscoverResponse::Settings(settings) => {
                    // A settings response ends the search whether or not it is the answer we
                    // wanted: the server has described the mailbox, and asking a different URL
                    // about the same mailbox will not change what it supports.
                    // [MS-OXDSCLI] §3.1.5.4
                    return settings.mapi_http().ok_or(Error::NoEndpoint {
                        address: address.to_string(),
                        tried,
                    });
                }
                AutodiscoverResponse::RedirectUrl(target) => {
                    redirects = bump(redirects)?;
                    queue.push_front(target);
                }
                AutodiscoverResponse::RedirectAddress(next) => {
                    redirects = bump(redirects)?;
                    // A new address means a new domain, so the candidate list starts over.
                    queue = candidate_urls(&next).collect();
                    probed = !probe;
                    address = next;
                }
                // The server understood and refused. Documented reaction: try the next candidate.
                // The same goes for a response kind added to that enum after this was written:
                // "move on" is the only safe reading of one this crate does not know.
                AutodiscoverResponse::Failed(_) | _ => {}
            }
        }

        Err(Error::NoEndpoint {
            address: address.to_string(),
            tried,
        })
    }
}

/// Counts a redirect, refusing to follow a chain that is really a loop.
fn bump(redirects: usize) -> Result<usize> {
    let next = redirects.saturating_add(1);
    if next > MAX_REDIRECTS {
        return Err(Error::TooManyRedirects {
            limit: MAX_REDIRECTS,
        });
    }
    Ok(next)
}

/// The HTTP side of one lookup.
#[derive(Debug)]
struct Search<'a> {
    http: Client,
    credentials: &'a Credentials,
    allow_plaintext_http: bool,
}

impl Search<'_> {
    /// Asks one candidate URL.
    ///
    /// `Ok(None)` means "this URL had nothing useful to say" — refused, timed out, answered with
    /// something that is not an Autodiscover response, or is not a URL this crate will POST
    /// credentials to. Every one of those means the next candidate, not the end of the search.
    async fn ask(&self, url: &str, address: &EmailAddress) -> Result<Option<AutodiscoverResponse>> {
        let Ok(url) = parse_endpoint(url, self.allow_plaintext_http) else {
            return Ok(None);
        };

        let request = AutodiscoverRequest::new(address);
        let mut builder = self.http.post(url.clone());
        for (name, value) in request.headers() {
            builder = builder.header(name, value);
        }
        builder = match self.credentials {
            Credentials::None => builder,
            Credentials::Basic { username, password } => {
                builder.basic_auth(username, Some(password))
            }
            Credentials::Bearer { token } => builder.bearer_auth(token),
        };

        let Ok(response) = builder.body(request.into_body()).send().await else {
            return Ok(None);
        };

        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized {
                url: url.to_string(),
                offered: response
                    .headers()
                    .get_all("WWW-Authenticate")
                    .iter()
                    .filter_map(|value| value.to_str().ok())
                    .filter_map(|value| value.split_whitespace().next())
                    .map(str::to_owned)
                    .collect(),
                sent: self.credentials.describe(),
            });
        }

        if !response.status().is_success() {
            return Ok(None);
        }

        let Ok(body) = response.text().await else {
            return Ok(None);
        };

        // Not every 200 on this path is an Autodiscover response — the first candidate URL is
        // often just the organisation's website — so a body that will not parse is one more
        // candidate that did not answer.
        Ok(AutodiscoverResponse::parse(&body).ok())
    }

    /// The plain-HTTP redirect probe: a `GET` whose `Location` header names the real service.
    ///
    /// Redirects are not followed automatically anywhere in this crate, which is what makes this
    /// readable at all: the 302 arrives as a 302.
    ///
    /// [MS-OXDISCO] §3.1.5.4 — locations found by an HTTP redirect
    async fn probe(&self, address: &EmailAddress) -> Option<String> {
        let response = self
            .http
            .get(redirect_probe_url(address))
            .send()
            .await
            .ok()?;

        if !response.status().is_redirection() {
            return None;
        }
        response
            .headers()
            .get("Location")?
            .to_str()
            .ok()
            .map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use mapi_autodiscover::{AutodiscoverResponse, Settings};

    use super::*;

    /// The `MailStore` URL the fixture carries, which is what a discovered client must post to.
    const MAIL_STORE_URL: &str = "https://mail.example.test/mapi/emsmdb/\
                                  ?MailboxId=00000000-0000-0000-0000-000000000000@example.test";

    fn settings_from(xml: &str) -> Settings {
        match AutodiscoverResponse::parse(xml) {
            Ok(AutodiscoverResponse::Settings(settings)) => settings,
            other => panic!("the fixture is a settings response, not {other:?}"),
        }
    }

    fn settings() -> Settings {
        settings_from(include_str!("../tests/autodiscover-settings.xml"))
    }

    fn address() -> EmailAddress {
        EmailAddress::new("alice@example.test").expect("a valid address")
    }

    /// The handover: what Autodiscover said becomes the endpoint and the distinguished name, which
    /// are precisely the two settings a client cannot be built without.
    #[test]
    fn a_discovered_endpoint_fills_in_both_settings_that_have_no_default() {
        let endpoint = settings().mapi_http().expect("the fixture offers mapiHttp");
        let client = MapiClient::builder()
            .for_endpoint(&endpoint, &address())
            .expect("a client");

        assert_eq!(client.endpoint(), MAIL_STORE_URL);
        assert!(client.user_dn().as_str().ends_with("cn=alice"));
        assert!(
            endpoint
                .address_book_url()
                .is_some_and(|url| url.contains("/nspi/")),
            "the address book URL is carried through for whoever needs it"
        );
    }

    /// A `mapiHttp` block with no `MailStore` URL describes nothing this crate can connect to, and
    /// saying so beats building a client that cannot work.
    #[test]
    fn an_endpoint_with_no_mail_store_url_is_refused() {
        let xml = include_str!("../tests/autodiscover-settings.xml")
            .replace("<MailStore>", "<MailStore><!--")
            .replace("</MailStore>", "--></MailStore>");
        let endpoint = settings_from(&xml)
            .mapi_http()
            .expect("still offers mapiHttp");

        let error = MapiClient::builder()
            .for_endpoint(&endpoint, &address())
            .expect_err("no URL to connect to");
        assert!(matches!(error, Error::NoEndpoint { .. }), "{error:?}");
    }

    #[test]
    fn a_redirect_chain_is_followed_up_to_the_limit_and_then_refused() {
        let mut count = 0;
        for _ in 0..MAX_REDIRECTS {
            count = bump(count).expect("within the limit");
        }
        assert_eq!(count, MAX_REDIRECTS);
        assert!(matches!(
            bump(count),
            Err(Error::TooManyRedirects {
                limit: MAX_REDIRECTS
            })
        ));
    }
}
