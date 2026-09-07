//! The account a handshake authenticates as.

/// A Windows account name and its password.
///
/// # Which of the three name forms to use
///
/// NTLM carries the domain and the user as two separate fields, so the split matters and is not
/// cosmetic: it is an input to the response key.
///
/// [MS-NLMP] §3.3.2 defines `NTOWFv2(Passwd, User, UserDom)` as
/// `HMAC_MD5(MD4(UNICODE(Passwd)), UNICODE(Uppercase(User) + UserDom))` — the user name is folded
/// to upper case and the domain is not, and both go into the key. Splitting `DOMAIN\user` wrongly
/// therefore produces a valid message carrying a response derived from the wrong key, which the
/// server reports as a refused credential rather than as a malformed name.
///
/// [`Identity::new`] accepts all three forms a person writes and splits each the way Windows does:
///
/// | Written            | `domain`     | `username`         |
/// |--------------------|--------------|--------------------|
/// | `DEV\developer`    | `DEV`        | `developer`        |
/// | `developer@dev.local` | *(empty)* | `developer@dev.local` |
/// | `developer`        | *(empty)*    | `developer`        |
///
/// The user-principal form is deliberately **not** split at the `@`. A UPN is a single name that
/// the domain controller resolves, and halving it yields a domain that is not the account's NetBIOS
/// domain — which is a wrong key again. Use [`Identity::with_domain`] when the NetBIOS domain is
/// known and matters.
///
/// # Secrets
///
/// [`Debug`] is written by hand and prints no password, and [`PartialEq`] is deliberately absent:
/// comparing identities is comparing secrets, and the obvious implementation does it in
/// non-constant time. This mirrors `mapi_client::Credentials`, for the same reasons.
#[derive(Clone)]
pub struct Identity {
    domain: String,
    username: String,
    password: String,
    workstation: String,
}

impl Identity {
    /// An identity from a name in any of the three forms above.
    #[must_use]
    pub fn new(username: &str, password: impl Into<String>) -> Self {
        let (domain, username) = split_name(username);
        Self {
            domain,
            username,
            password: password.into(),
            workstation: String::new(),
        }
    }

    /// An identity whose domain is given separately, with the name left exactly as written.
    ///
    /// Use this when the name itself contains a backslash that is part of it, or when a
    /// user-principal name has to be paired with an explicit NetBIOS domain.
    #[must_use]
    pub fn with_domain(
        domain: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            username: username.into(),
            password: password.into(),
            workstation: String::new(),
        }
    }

    /// Names the machine this client runs on, which is otherwise sent empty.
    ///
    /// The server does not authenticate this field — it reaches the security log and nothing else
    /// — so the default is to send nothing rather than to put the local host name on the wire for
    /// a value no decision depends on.
    ///
    /// [MS-NLMP] §2.2.1.3 — `Workstation` in the `AUTHENTICATE_MESSAGE`
    #[must_use]
    pub fn workstation(mut self, name: impl Into<String>) -> Self {
        self.workstation = name.into();
        self
    }

    /// The NetBIOS or DNS domain, which may be empty.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The account name, without a domain prefix.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The password.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// The workstation name, which may be empty.
    #[must_use]
    pub fn workstation_name(&self) -> &str {
        &self.workstation
    }
}

/// Splits `DOMAIN\user` and leaves every other form alone.
///
/// A forward slash is accepted alongside the backslash because `DOMAIN/user` is what a name
/// survives as once it has been through a shell that rewrites paths — the same class of mistake
/// as `mapi-client`'s `legacyExchangeDN` trap.
fn split_name(name: &str) -> (String, String) {
    match name.split_once(['\\', '/']) {
        Some((domain, user)) => (domain.to_owned(), user.to_owned()),
        None => (String::new(), name.to_owned()),
    }
}

/// Prints the account and never the password. See the type's documentation for why.
impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field("domain", &self.domain)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("workstation", &self.workstation)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_name_form_splits_the_way_windows_splits_it() {
        let down_level = Identity::new("DEV\\developer", "Login123");
        assert_eq!(down_level.domain(), "DEV");
        assert_eq!(down_level.username(), "developer");

        // A user-principal name stays whole: halving it yields a domain that is not the
        // account's NetBIOS domain, and the domain is an input to the response key.
        let upn = Identity::new("developer@dev.local", "Login123");
        assert_eq!(upn.domain(), "");
        assert_eq!(upn.username(), "developer@dev.local");

        let bare = Identity::new("developer", "Login123");
        assert_eq!(bare.domain(), "");
        assert_eq!(bare.username(), "developer");

        // What a down-level name survives as once a shell has rewritten the separator.
        let slashed = Identity::new("DEV/developer", "Login123");
        assert_eq!(slashed.domain(), "DEV");
        assert_eq!(slashed.username(), "developer");
    }

    #[test]
    fn an_explicit_domain_leaves_the_name_untouched() {
        let identity = Identity::with_domain("DEV", "developer@dev.local", "Login123");
        assert_eq!(identity.domain(), "DEV");
        assert_eq!(identity.username(), "developer@dev.local");
        assert_eq!(identity.password(), "Login123");
        assert_eq!(identity.workstation_name(), "");
    }

    #[test]
    fn the_workstation_is_empty_until_it_is_asked_for() {
        let named = Identity::new("developer", "Login123").workstation("BUILD-01");
        assert_eq!(named.workstation_name(), "BUILD-01");
    }

    /// The whole point of the hand-written `Debug`.
    #[test]
    fn debug_never_prints_the_password() {
        /// Nested, which is how a secret actually reaches a log.
        #[derive(Debug)]
        struct Holder {
            #[allow(dead_code, reason = "read only by the derived Debug this test checks")]
            identity: Identity,
        }

        let holder = Holder {
            identity: Identity::new("DEV\\developer", "Login123"),
        };
        let rendered = format!("{holder:?}");
        assert!(!rendered.contains("Login123"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("developer"));
    }
}
