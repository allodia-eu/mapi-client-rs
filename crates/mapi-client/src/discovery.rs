//! Driving Autodiscover: turning an email address into an endpoint URL and a distinguished name.
//!
//! [`mapi-autodiscover`](mapi_autodiscover) says where to look, what to send and what came back.
//! This module does the looking. The sequence is [MS-OXDISCO] §3.1.5's: try each candidate URL in
//! turn, follow whatever redirects the answers ask for, and only then fall back to the plain-HTTP
//! redirect probe.
//!
//! # Where credentials go
//!
//! **Only where they are asked for.** Every candidate is first asked without them, and is sent
//! them only in answer to a 401 offering their scheme — Basic and Bearer as a header, NTLM and
//! `Negotiate` as the handshake's opening. A candidate is a guess built from the address's domain,
//! and the first is usually the organisation's website, run by whoever runs it; a credential sent
//! to it unasked is sent to them. Exchange asks: [MS-OXDSCLI] §5.1 recommends "that a server not
//! answer Autodiscover queries unless the Autodiscover client has been authenticated", and
//! measured against Exchange Server SE `15.02.2562.056`, an unauthenticated POST is answered 401
//! with `Negotiate`, `NTLM` and Basic on offer. The cost is that round trip, once per candidate.
//!
//! Bearer is the exception that proves the rule: the same server offers `Bearer` only to a request
//! that names it, so a Bearer lookup's first request carries `Authorization: Bearer` with no token
//! — a question, not a credential — and the token goes only to a 401 that answers with a `Bearer`
//! challenge.
//!
//! What this does not stop is a candidate that answers instead of challenging. Its settings name
//! the MAPI endpoint, and the client built from them sends Basic or Bearer there unasked. That
//! gives whoever runs the candidate nothing a 401 offering Basic would not have got them: what is
//! withheld here is credentials sent to a server that never wanted them, not credentials a server
//! sets out to collect.
//!
//! Redirects decide where the next request goes, so each is checked before it is followed:
//!
//! - **An HTTP 302** in answer to a POST, and a `redirectUrl`, are followed to an `https` URL only
//!   ([MS-OXDSCLI] §3.1.5.2, §3.1.5.3). They come from a candidate that answered over TLS.
//! - **A `redirectAddr`** starts the search again for the new address, under the same rules.
//! - **The plain-HTTP probe's 302 is never followed on its own.** [MS-OXDISCO] §3.1.5.4 says to
//!   "prompt the user to warn them of the redirection", and anyone on the path of a cleartext
//!   request can write its `Location`. The search ends with [`Error::RedirectNeedsConsent`]
//!   instead, and the caller follows it — or not — with [`MapiClientBuilder::discover_at`].
//!
//! Each redirect followed is reported to the [`Observer`](crate::Observer), if there is one.
//!
//! # What ends a search
//!
//! **A candidate that does not answer is not a failure** — a refused connection, a timeout, a page
//! that is not Autodiscover at all, or a server that answers with an `<Error>` element all mean
//! "try the next one", which is why an unreachable first candidate does not stop the search. So
//! does a 401 offering only schemes these credentials are not, which was sent nothing: it cannot
//! be used, which is [MS-OXDSCLI] §3.1.5.1's nonfunctional URI. If nothing else answers, that
//! refusal is what the search ends with, rather than "nothing was found", since it says why.
//!
//! **A 401 to the credentials does** stop it: the service is there and has refused them, and
//! grinding through the remaining candidates would replace that diagnosis with "nothing was
//! found".
//!
//! DNS `SRV` lookup is not performed here — it needs a resolver, and this crate has no opinion
//! about which one. [`mapi_autodiscover::srv_query`] gives the query to make and
//! [`mapi_autodiscover::url_for_host`] turns each answer into a URL for
//! [`MapiClientBuilder::lookup_at`].
//!
//! [MS-OXDISCO] §3.1.5 — how a client builds its list of candidate URIs
//! [MS-OXDSCLI] §3.1.5.2 — following an HTTP 302
//! [MS-OXDSCLI] §3.1.5.3 — acting on `redirectAddr` and `redirectUrl`

use std::collections::VecDeque;

use mapi_autodiscover::{
    AutodiscoverResponse, EmailAddress, MapiHttpEndpoint, Settings, candidate_urls,
    redirect_probe_url,
};
use mapi_proto::LegacyDn;
use reqwest::Client;
use search::{Answer, Search};

use crate::builder::MapiClientBuilder;
use crate::client::MapiClient;
use crate::error::{Error, Result};
use crate::observer::{Redirect, RedirectKind};

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
    /// [`Error::RedirectNeedsConsent`] if none did and the plain-HTTP probe redirects somewhere
    /// only the user can agree to, [`Error::Unauthorized`] if one refused the credentials,
    /// [`Error::TooManyRedirects`] if the deployment describes a loop, and whatever
    /// [`build`](MapiClientBuilder::build) reports once the answer is in hand.
    pub async fn discover(self, address: &EmailAddress) -> Result<MapiClient> {
        let endpoint = self.lookup(address).await?;
        self.for_endpoint(&endpoint, address)
    }

    /// Locates the mailbox starting from an Autodiscover URL, and builds a client for it.
    ///
    /// [`discover`](MapiClientBuilder::discover) for a service the caller has named, which is how
    /// a redirect the user agreed to is followed: the `location` an
    /// [`Error::RedirectNeedsConsent`] carries goes here.
    ///
    /// ```no_run
    /// use mapi_client::{Credentials, EmailAddress, Error, MapiClient};
    ///
    /// # fn the_user_agrees(_: &str) -> bool { true }
    /// # async fn example() -> Result<(), Error> {
    /// let builder =
    ///     MapiClient::builder().credentials(Credentials::basic("alice", "hunter2"));
    /// let address = EmailAddress::new("alice@example.test")?;
    /// let client = match builder.clone().discover(&address).await {
    ///     Err(Error::RedirectNeedsConsent { location, .. })
    ///         if the_user_agrees(&location) =>
    ///     {
    ///         builder.discover_at(location, &address).await?
    ///     }
    ///     other => other?,
    /// };
    /// # let _ = client;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As [`lookup_at`](MapiClientBuilder::lookup_at), and whatever
    /// [`build`](MapiClientBuilder::build) reports once the answer is in hand.
    pub async fn discover_at(
        self,
        url: impl Into<String>,
        address: &EmailAddress,
    ) -> Result<MapiClient> {
        let endpoint = self.lookup_at(url, address).await?;
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
        self.search(address, queue, true).await?.endpoint(address)
    }

    /// Everything the server said about the mailbox, rather than only the endpoint.
    ///
    /// [`lookup`](MapiClientBuilder::lookup) narrows the answer to the `mapiHttp` block, which
    /// throws away the one thing that names *other* mailboxes: MAPI/HTTP has no enumeration verb,
    /// so the `AlternativeMailbox` elements are the only description of a shared, delegated or
    /// archive mailbox anywhere in the protocol family.
    ///
    /// [`mailboxes`](MapiClientBuilder::mailboxes) is the answer for most callers; this is for one
    /// that wants the response itself.
    ///
    /// # Errors
    ///
    /// As [`lookup`](MapiClientBuilder::lookup), minus [`Error::NoEndpoint`] for a deployment that
    /// answered without a `mapiHttp` block — which is a settings response like any other and is
    /// handed back rather than refused.
    ///
    /// [MS-OXDSCLI] §2.2.4.1.1 — `Response`
    pub async fn lookup_settings(&self, address: &EmailAddress) -> Result<Settings> {
        let queue = candidate_urls(address).collect();
        Ok(self.search(address, queue, true).await?.settings)
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
        self.search(address, queue, false).await?.endpoint(address)
    }

    /// Works through the queue, following redirects, until something answers with settings.
    async fn search(
        &self,
        address: &EmailAddress,
        queue: VecDeque<String>,
        probe: bool,
    ) -> Result<Found> {
        self.search_with(self.http()?, address, queue, probe).await
    }

    /// The same, over an HTTP client the caller already has.
    ///
    /// For a caller making several lookups in a row, which then shares one client — and with it
    /// the TLS configuration and the pooled connections — rather than building one per lookup.
    pub(crate) async fn search_with(
        &self,
        http: Client,
        address: &EmailAddress,
        mut queue: VecDeque<String>,
        probe: bool,
    ) -> Result<Found> {
        let search = Search::new(self, http);

        let mut address = address.clone();
        let mut tried: Vec<String> = Vec::new();
        let mut redirects = 0_usize;
        let mut probed = !probe;
        // The first candidate that asked for credentials in another scheme, for an error that says
        // more than "nothing was found" if nothing else answers.
        let mut unasked = None;

        loop {
            let Some(url) = queue.pop_front() else {
                if probed {
                    break;
                }
                probed = true;
                // Last resort: a GET over plain HTTP whose `Location` names the real service.
                // It carries no body and no credentials, which is why plain HTTP is tolerable
                // here and nowhere else — and why what it says is the user's to accept, not
                // this crate's. [MS-OXDISCO] §3.1.5.4
                let from = redirect_probe_url(&address);
                if let Some(location) = search.probe(&from).await {
                    return Err(Error::RedirectNeedsConsent {
                        address: address.to_string(),
                        from,
                        location,
                        tried,
                    });
                }
                continue;
            };

            tried.push(url.clone());
            let response = match search.ask(&url, &address).await? {
                Answer::Nothing => continue,
                Answer::Unasked(error) => {
                    unasked.get_or_insert(error);
                    continue;
                }
                Answer::Moved(target) => {
                    redirects = bump(redirects)?;
                    search.report(Redirect::new(RedirectKind::Http, &url, &target));
                    queue.push_front(target);
                    continue;
                }
                Answer::Response(response) => response,
            };

            match response {
                AutodiscoverResponse::Settings(settings) => {
                    // A settings response ends the search whether or not it is the answer we
                    // wanted: the server has described the mailbox, and asking a different URL
                    // about the same mailbox will not change what it supports.
                    // [MS-OXDSCLI] §3.1.5.4
                    return Ok(Found { settings, tried });
                }
                AutodiscoverResponse::RedirectUrl(target) => {
                    redirects = bump(redirects)?;
                    search.report(Redirect::new(RedirectKind::Url, &url, &target));
                    queue.push_front(target);
                }
                AutodiscoverResponse::RedirectAddress(next) => {
                    redirects = bump(redirects)?;
                    search.report(Redirect::new(RedirectKind::Address, &url, next.as_str()));
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

        Err(unasked.unwrap_or_else(|| Error::NoEndpoint {
            address: address.to_string(),
            tried,
        }))
    }
}

/// What a completed search found, and the URLs it asked on the way.
///
/// The two travel together because [`Error::NoEndpoint`] reports the list of candidates tried, and
/// that list only exists inside the search — so narrowing the settings to an endpoint has to happen
/// where the trail is still in hand.
#[derive(Debug)]
pub(crate) struct Found {
    /// What the server said about the mailbox.
    pub(crate) settings: Settings,
    /// Every URL asked, in order, for a diagnostic that has to say where it looked.
    tried: Vec<String>,
}

impl Found {
    /// The `mapiHttp` block, or a refusal naming everywhere that was asked.
    fn endpoint(self, address: &EmailAddress) -> Result<MapiHttpEndpoint> {
        self.with_endpoint(address).map(|(_, endpoint)| endpoint)
    }

    /// The settings and their `mapiHttp` block together, or the same refusal.
    pub(crate) fn with_endpoint(
        self,
        address: &EmailAddress,
    ) -> Result<(Settings, MapiHttpEndpoint)> {
        match self.settings.mapi_http() {
            Some(endpoint) => Ok((self.settings, endpoint)),
            None => Err(Error::NoEndpoint {
                address: address.to_string(),
                tried: self.tried,
            }),
        }
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

mod search;

#[cfg(feature = "ntlm")]
mod negotiated;

#[cfg(test)]
mod tests;
