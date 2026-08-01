//! The session cookies that make a Session Context findable.
//!
//! The server identifies a Session Context by the cookies it set on the `Connect` response, and
//! every later request has to echo them back. Losing them is reported as `X-ResponseCode` 10
//! (Context Not Found) or 13 (Missing Cookie), neither of which mentions cookies in a way that
//! points at the client.
//!
//! [MS-OXCMAPIHTTP] §2.2.3.2.3 — `Set-Cookie`
//! [MS-OXCMAPIHTTP] §2.2.3.2.4 — `Cookie`

/// One session cookie: a name and the opaque value the server chose.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionCookie {
    name: String,
    value: String,
}

impl SessionCookie {
    /// The cookie's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The cookie's value, exactly as the server sent it.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl core::fmt::Display for SessionCookie {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

/// The cookies belonging to one Session Context.
///
/// Deliberately minimal: MAPI/HTTP needs "echo back whatever the server set", so attributes such
/// as `Path`, `Expires` and `HttpOnly` are parsed off and discarded rather than honoured.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CookieJar {
    cookies: Vec<SessionCookie>,
}

impl CookieJar {
    /// An empty jar.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cookies: Vec::new(),
        }
    }

    /// Takes in one `Set-Cookie` value, replacing any cookie of the same name.
    ///
    /// A value with no `=` is ignored: it cannot be echoed back as a name/value pair.
    pub fn absorb(&mut self, set_cookie: &str) {
        let pair = set_cookie.split(';').next().unwrap_or_default().trim();
        let Some((name, value)) = pair.split_once('=') else {
            return;
        };

        let (name, value) = (name.trim(), value.trim());
        if let Some(existing) = self.cookies.iter_mut().find(|c| c.name == name) {
            value.clone_into(&mut existing.value);
        } else {
            self.cookies.push(SessionCookie {
                name: name.to_owned(),
                value: value.to_owned(),
            });
        }
    }

    /// The value for the `Cookie` request header, or `None` while the jar is empty.
    #[must_use]
    pub fn header_value(&self) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        Some(
            self.cookies
                .iter()
                .map(SessionCookie::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Every cookie held.
    #[must_use]
    pub fn cookies(&self) -> &[SessionCookie] {
        &self.cookies
    }

    /// Whether a Session Context has been established.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Forgets every cookie, ending the Session Context locally.
    pub fn clear(&mut self) {
        self.cookies.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cookie_replaces_rather_than_duplicates() {
        let mut jar = CookieJar::new();
        jar.absorb("MapiContext=abc; Path=/; HttpOnly");
        assert_eq!(jar.header_value().as_deref(), Some("MapiContext=abc"));

        jar.absorb("MapiContext=def; Path=/");
        assert_eq!(jar.header_value().as_deref(), Some("MapiContext=def"));

        jar.absorb("MapiSequence=1");
        assert_eq!(
            jar.header_value().as_deref(),
            Some("MapiContext=def; MapiSequence=1")
        );
        assert_eq!(jar.cookies().len(), 2);
    }

    #[test]
    fn an_empty_jar_sends_no_cookie_header() {
        let mut jar = CookieJar::new();
        assert!(jar.is_empty());
        assert_eq!(jar.header_value(), None);

        jar.absorb("MapiContext=abc");
        assert!(!jar.is_empty());
        jar.clear();
        assert!(jar.is_empty());
    }

    #[test]
    fn a_malformed_set_cookie_is_ignored() {
        let mut jar = CookieJar::new();
        jar.absorb("no-equals-sign");
        jar.absorb("");
        jar.absorb(";;;");
        assert!(jar.is_empty());
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        let mut jar = CookieJar::new();
        jar.absorb("  MapiContext = abc  ; Path=/");
        let cookie = jar.cookies().first().unwrap();
        assert_eq!(cookie.name(), "MapiContext");
        assert_eq!(cookie.value(), "abc");
        assert_eq!(cookie.to_string(), "MapiContext=abc");
    }
}
