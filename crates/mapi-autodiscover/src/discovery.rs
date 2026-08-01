//! Where to look for the Autodiscover service.
//!
//! [MS-OXDISCO] §3.1.5 — how a client builds its list of candidate URIs

use crate::EmailAddress;

/// The path every Autodiscover URL ends with.
const PATH: &str = "/Autodiscover/Autodiscover.xml";

/// The candidate URLs to POST an Autodiscover request to, in the order to try them.
///
/// A candidate that does not answer is not a failure: [MS-OXDISCO] §3.1.5.1 says to move to the
/// next one, and only to give up once the list is exhausted.
///
/// **One deliberate deviation, recorded rather than hidden.** [MS-OXDISCO] §3.1.5.2 lists
/// `http://<domain>/Autodiscover/Autodiscover.xml` — plain HTTP — as the first URI. This crate
/// emits `https://` for it. An Autodiscover POST body carries the user's own address, and a
/// cleartext POST of it to a host chosen from that same address is not a trade this crate is
/// willing to make on a caller's behalf. Exchange publishes the service over HTTPS; the plain-HTTP
/// step survives as [`redirect_probe_url`], which is a `GET` that only ever reads a `Location`
/// header.
///
/// [MS-OXDISCO] §3.1.5.2 — locations found directly from the email domain
#[derive(Clone, Debug)]
pub struct CandidateUrls {
    domain: String,
    step: usize,
}

impl CandidateUrls {
    pub(crate) fn new(address: &EmailAddress) -> Self {
        Self {
            domain: address.domain().to_owned(),
            step: 0,
        }
    }
}

impl Iterator for CandidateUrls {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        let url = match self.step {
            0 => format!("https://{}{PATH}", self.domain),
            1 => format!("https://autodiscover.{}{PATH}", self.domain),
            _ => return None,
        };
        self.step = self.step.saturating_add(1);
        Some(url)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = 2_usize.saturating_sub(self.step);
        (left, Some(left))
    }
}

impl ExactSizeIterator for CandidateUrls {}

/// The candidate URLs for an address, in the order to try them.
///
/// [MS-OXDISCO] §3.1.5.2 — locations found directly from the email domain
#[must_use]
pub fn candidate_urls(address: &EmailAddress) -> CandidateUrls {
    CandidateUrls::new(address)
}

/// The URL to `GET` when the candidates have not answered.
///
/// A `302` response's `Location` header is itself a candidate — that is how a domain that hosts no
/// Autodiscover service points at the one that does. This is a `GET` and carries no body, which is
/// why plain HTTP is the specification's choice here and is kept.
///
/// [MS-OXDISCO] §3.1.5.4 — locations found by an HTTP redirect
#[must_use]
pub fn redirect_probe_url(address: &EmailAddress) -> String {
    format!("http://autodiscover.{}{PATH}", address.domain())
}

/// The DNS SRV query whose hosts are further candidates.
///
/// Resolving it is I/O, so it is the caller's to make; each returned host becomes
/// `https://<host>/Autodiscover/Autodiscover.xml`.
///
/// [MS-OXDISCO] §3.1.5.3 — locations found from SRV DNS records
#[must_use]
pub fn srv_query(address: &EmailAddress) -> String {
    format!("_autodiscover._tcp.{}", address.domain())
}

/// The candidate URL for a host found by SRV lookup or by a redirect.
///
/// [MS-OXDISCO] §3.1.5.3 — locations found from SRV DNS records
#[must_use]
pub fn url_for_host(host: &str) -> String {
    format!("https://{host}{PATH}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> EmailAddress {
        EmailAddress::new("developer@dev.local").unwrap()
    }

    #[test]
    fn the_domain_is_tried_before_the_autodiscover_subdomain() {
        let urls: Vec<_> = candidate_urls(&address()).collect();
        assert_eq!(
            urls,
            vec![
                "https://dev.local/Autodiscover/Autodiscover.xml",
                "https://autodiscover.dev.local/Autodiscover/Autodiscover.xml",
            ]
        );
    }

    #[test]
    fn the_iterator_reports_how_much_is_left() {
        let mut urls = candidate_urls(&address());
        assert_eq!(urls.len(), 2);
        urls.next();
        assert_eq!(urls.len(), 1);
        urls.next();
        assert_eq!(urls.len(), 0);
        assert_eq!(urls.next(), None);
        assert_eq!(urls.next(), None, "exhausted stays exhausted");
    }

    /// Every candidate is HTTPS. The one plain-HTTP step the specification describes is a `GET`
    /// that reads a redirect, and it is kept separate for exactly that reason.
    #[test]
    fn no_candidate_posts_over_plain_http() {
        for url in candidate_urls(&address()) {
            assert!(url.starts_with("https://"), "{url} is not HTTPS");
        }
        assert!(redirect_probe_url(&address()).starts_with("http://"));
    }

    #[test]
    fn the_srv_query_and_host_form_follow_the_specification() {
        assert_eq!(srv_query(&address()), "_autodiscover._tcp.dev.local");
        assert_eq!(
            url_for_host("mail.dev.local"),
            "https://mail.dev.local/Autodiscover/Autodiscover.xml"
        );
        assert_eq!(
            redirect_probe_url(&address()),
            "http://autodiscover.dev.local/Autodiscover/Autodiscover.xml"
        );
    }
}
