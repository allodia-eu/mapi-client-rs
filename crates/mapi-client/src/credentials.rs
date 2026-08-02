//! How a request proves who is asking.
//!
//! # What is here, and what is not
//!
//! Two schemes are implemented, and both are the same shape: a header computed once and attached
//! to every request. **`Negotiate` (Kerberos/SPNEGO) and `NTLM` are not**, and that omission is
//! worth stating plainly rather than leaving to be discovered by a 401, because a
//! default-configured Exchange offers exactly those two.
//!
//! They are absent because they are not the same shape. Both are multi-leg challenge/response
//! handshakes carried over several HTTP round trips, bound to the connection rather than to the
//! request, and on Windows the credential is normally held by the operating system rather than by
//! the program. A `Credentials` variant that adds one header cannot express any of that, so adding
//! one would be a promise this crate could not keep. Making it work means either a platform SSPI
//! binding or a full NTLM/SPNEGO implementation, and both are their own piece of work.
//!
//! Until then: enable Basic on the MAPI virtual directory (over TLS), put a reverse proxy in front
//! that terminates Negotiate, or use [`mapi-proto`](mapi_proto) directly with an HTTP client of
//! your own that speaks the scheme you need. The sans-io core exists precisely so that last option
//! costs nothing.
//!
//! [MS-OXCMAPIHTTP] §3.1.5.1 — the client authenticates before the first request

/// How to authenticate to the endpoint.
///
/// # Secrets
///
/// [`Debug`] is implemented by hand and prints no secret: a password or token would otherwise
/// reach a log the moment anyone derived `Debug` on a struct that holds a client.
///
/// [`PartialEq`] is deliberately **not** implemented. Comparing credentials is a comparison of
/// secrets, and the obvious implementation compares them in non-constant time.
#[derive(Clone)]
#[non_exhaustive]
pub enum Credentials {
    /// Send no `Authorization` header.
    ///
    /// For an endpoint fronted by something that has already authenticated the caller — a
    /// reverse proxy, a service mesh — and for finding out what a server offers.
    None,

    /// HTTP Basic, sent preemptively rather than after a 401.
    ///
    /// The username may be `user`, `user@domain` or `DOMAIN\user`; Exchange accepts all three,
    /// measured against Exchange Server SE `15.02.2562.045`.
    ///
    /// Basic puts a reusable password in every request, so the endpoint must be HTTPS. This crate
    /// enforces that: see [`Error::PlaintextEndpoint`](crate::Error::PlaintextEndpoint).
    Basic {
        /// The account name.
        username: String,
        /// Its password.
        password: String,
    },

    /// An OAuth 2.0 bearer token, as `Authorization: Bearer <token>`.
    ///
    /// Obtaining and refreshing the token is the caller's: this crate attaches what it is given
    /// and never talks to an authorisation server. A token that expires mid-session surfaces as
    /// [`Error::Unauthorized`](crate::Error::Unauthorized) on the next request.
    ///
    /// Unlike [`Credentials::Basic`], this path has not been exercised against a live Exchange by
    /// this crate's authors — only that the header goes out in the documented form.
    Bearer {
        /// The token, without the `Bearer ` prefix.
        token: String,
    },
}

impl Credentials {
    /// HTTP Basic credentials.
    #[must_use]
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Basic {
            username: username.into(),
            password: password.into(),
        }
    }

    /// An OAuth 2.0 bearer token.
    #[must_use]
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer {
            token: token.into(),
        }
    }

    /// How to describe what was sent, for a message a human reads after a 401.
    #[must_use]
    pub const fn describe(&self) -> &'static str {
        match self {
            Self::None => "no credentials",
            Self::Basic { .. } => "Basic credentials",
            Self::Bearer { .. } => "a bearer token",
        }
    }
}

impl Default for Credentials {
    /// [`Credentials::None`].
    fn default() -> Self {
        Self::None
    }
}

/// Prints which scheme is in use and nothing else. See the type's documentation for why.
impl core::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => f.write_str("Credentials::None"),
            Self::Basic { username, .. } => f
                .debug_struct("Credentials::Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::Bearer { .. } => f
                .debug_struct("Credentials::Bearer")
                .field("token", &"<redacted>")
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the hand-written `Debug`: a password must not reach a log because
    /// somebody derived `Debug` three types further out.
    #[test]
    fn debug_never_prints_a_secret() {
        /// Nested inside another type, which is how a secret actually reaches a log.
        #[derive(Debug)]
        struct Holder {
            #[allow(dead_code, reason = "read only by the derived Debug this test checks")]
            credentials: Credentials,
        }

        let basic = Credentials::basic("alice@example.test", "hunter2");
        let rendered = format!("{basic:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("alice@example.test"));
        assert!(rendered.contains("<redacted>"));

        let bearer = Credentials::bearer("eyJhbGciOiJIUzI1NiJ9.secret");
        let rendered = format!("{bearer:?}");
        assert!(!rendered.contains("secret"), "{rendered}");
        assert!(rendered.contains("<redacted>"));

        let holder = Holder {
            credentials: Credentials::basic("u", "p4ssw0rd"),
        };
        assert!(!format!("{holder:?}").contains("p4ssw0rd"));
    }

    #[test]
    fn each_scheme_describes_itself_for_a_401_message() {
        assert_eq!(Credentials::None.describe(), "no credentials");
        assert_eq!(Credentials::default().describe(), "no credentials");
        assert_eq!(Credentials::basic("u", "p").describe(), "Basic credentials");
        assert_eq!(Credentials::bearer("t").describe(), "a bearer token");
        assert_eq!(format!("{:?}", Credentials::None), "Credentials::None");
    }
}
