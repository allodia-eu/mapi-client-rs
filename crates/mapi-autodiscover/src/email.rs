//! The address an Autodiscover lookup starts from.

use crate::error::{Error, Result};

/// An SMTP address, validated well enough to go into a URL and an XML document.
///
/// Deliberately not a full RFC 5322 parser: this crate needs the domain to build candidate URLs
/// and the address to put in the request body, so what it checks is that both of those are safe
/// and non-empty. Anything the local mail system considers deliverable but this rejects would have
/// broken the request anyway.
///
/// [MS-OXDSCLI] §2.2.3.1.1.2 — `EMailAddress`
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Validates and wraps an address.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEmailAddress`] if the address has no domain, has more than one `@`, or
    /// holds a character that would have to be escaped to appear in XML or in a URL — which in an
    /// address is a sign of injection rather than of an unusual mailbox.
    pub fn new(address: impl Into<String>) -> Result<Self> {
        let address = address.into();

        let unsafe_char =
            |c: char| c.is_whitespace() || c.is_control() || "<>&\"'/\\?#%".contains(c);

        let reason = if address.is_empty() {
            Some("an address cannot be empty")
        } else if address.chars().any(unsafe_char) {
            Some("an address cannot hold whitespace, a control character, or any of <>&\"'/\\?#%")
        } else {
            match address.split_once('@') {
                None => Some("an address needs a domain, after an '@'"),
                Some(("", _)) => Some("the part before '@' is empty"),
                Some((_, "")) => Some("the part after '@' is empty"),
                Some((_, domain)) if domain.contains('@') => {
                    Some("an address has one '@', not two")
                }
                Some((_, domain)) if domain.starts_with('.') || domain.ends_with('.') => {
                    Some("the domain cannot start or end with a dot")
                }
                Some(_) => None,
            }
        };

        match reason {
            Some(reason) => Err(Error::InvalidEmailAddress { reason }),
            None => Ok(Self(address)),
        }
    }

    /// The address as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Everything before the `@`.
    #[must_use]
    pub fn local_part(&self) -> &str {
        self.0.split_once('@').map_or("", |(local, _)| local)
    }

    /// Everything after the `@` — what the candidate URLs are built from.
    #[must_use]
    pub fn domain(&self) -> &str {
        self.0.split_once('@').map_or("", |(_, domain)| domain)
    }
}

impl core::str::FromStr for EmailAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl core::fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_address_splits_into_its_two_halves() {
        let address = EmailAddress::new("developer@dev.local").unwrap();
        assert_eq!(address.local_part(), "developer");
        assert_eq!(address.domain(), "dev.local");
        assert_eq!(address.as_str(), "developer@dev.local");
        assert_eq!(address.to_string(), "developer@dev.local");
    }

    #[test]
    fn addresses_parse_from_strings() {
        let address: EmailAddress = "user@contoso.com".parse().unwrap();
        assert_eq!(address.domain(), "contoso.com");
        assert!("not-an-address".parse::<EmailAddress>().is_err());
    }

    /// Every one of these would either break the request body or change which host is contacted.
    #[test]
    fn addresses_that_would_corrupt_a_request_are_refused() {
        for bad in [
            "",
            "no-at-sign",
            "@dev.local",
            "developer@",
            "two@at@signs",
            "developer@.dev.local",
            "developer@dev.local.",
            "dev eloper@dev.local",
            "developer@dev.local/../evil",
            "developer@dev.local?x=1",
            "developer@dev.local#frag",
            "<script>@dev.local",
            "developer@dev.local\u{7}",
        ] {
            assert!(
                EmailAddress::new(bad).is_err(),
                "{bad:?} should have been refused"
            );
        }
    }

    #[test]
    fn the_reason_says_which_rule_was_broken() {
        assert!(matches!(
            EmailAddress::new("no-at-sign"),
            Err(Error::InvalidEmailAddress { reason }) if reason.contains("domain")
        ));
        assert!(
            EmailAddress::new("a@b").is_ok(),
            "a domain without a dot is still a domain"
        );
    }
}
