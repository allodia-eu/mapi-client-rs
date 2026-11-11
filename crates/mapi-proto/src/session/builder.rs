//! Everything about a [`Session`] that is decided before it starts and never changes afterwards.
//!
//! Client identity and locale are both of that kind: the headers must stay stable for the life of
//! the Session Context, and the locale is sent once, at `Connect`, with no way to revise it. A
//! builder is the shape that says so — a setting that cannot be changed mid-session should not be
//! reachable as a method on a running one.
//!
//! [MS-OXCMAPIHTTP] §2.2.3.3 — X-header fields
//! [MS-OXCMAPIHTTP] §2.2.4.1.1 — `LcidSort`, `LcidString`

use super::{DEFAULT_CLIENT_APPLICATION, DEFAULT_GUID, Session};
use crate::http::{CookieJar, Lcid};
use crate::oxcdata::CodePage;

/// Builds a [`Session`] with a client identity and locale of your own.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3 — X-header fields
#[derive(Clone, Debug)]
pub struct SessionBuilder {
    client_application: String,
    client_info: String,
    request_guid: String,
    code_page: CodePage,
    lcid_sort: Lcid,
    lcid_string: Lcid,
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionBuilder {
    /// A builder carrying the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client_application: DEFAULT_CLIENT_APPLICATION.to_owned(),
            client_info: format!("{DEFAULT_GUID}:1"),
            request_guid: DEFAULT_GUID.to_owned(),
            code_page: CodePage::WINDOWS_1252,
            lcid_sort: Lcid::EN_US,
            lcid_string: Lcid::EN_US,
        }
    }

    /// Sets the locale the Session Context runs under: both `LcidSort` and `LcidString`.
    ///
    /// Defaults to [`Lcid::EN_US`]. The value is sent once, at `Connect`, and neither the response
    /// nor any later ROP offers a way to revise it — which is why it lives here rather than as an
    /// argument to [`Session::begin_connect`].
    ///
    /// What is set here is a request about *this session*, not a description of the mailbox. The
    /// mailbox's own configured locale is a property of the Logon object — `PidTagLocaleId`,
    /// `PidTagSortLocaleId` — read after logon and unaffected by this.
    ///
    /// ```
    /// use mapi_proto::{Lcid, Session};
    ///
    /// // 0x0413 is nl-NL.
    /// let session = Session::builder().locale(Lcid::new(0x0413)).build();
    /// # let _ = session;
    /// ```
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.1 — `LcidSort`, `LcidString`
    /// [MS-OXCSTOR] §2.2.2.1.1.12, §2.2.2.1.1.14 — the mailbox's own locales
    #[must_use]
    pub const fn locale(mut self, lcid: Lcid) -> Self {
        self.lcid_sort = lcid;
        self.lcid_string = lcid;
        self
    }

    /// Sets `LcidSort` alone: the locale whose collation orders table rows.
    ///
    /// Worth reaching for only when it has to differ from [`SessionBuilder::string_locale`] —
    /// sorting a Dutch address book for someone reading in English, say. Call it *after*
    /// [`SessionBuilder::locale`], which sets both.
    #[must_use]
    pub const fn sort_locale(mut self, lcid: Lcid) -> Self {
        self.lcid_sort = lcid;
        self
    }

    /// Sets `LcidString` alone: the locale for everything that is not sorting.
    ///
    /// See [`SessionBuilder::sort_locale`] for when splitting the two earns its keep.
    #[must_use]
    pub const fn string_locale(mut self, lcid: Lcid) -> Self {
        self.lcid_string = lcid;
        self
    }

    /// Sets the code page the Session Context runs under: `Connect`'s `DefaultCodePage`.
    ///
    /// Defaults to [`CodePage::WINDOWS_1252`]. It decides one thing: what the bytes of an 8-bit
    /// string mean, in a request and in a response — a `PtypString8` value, a table column asked
    /// for as one, an 8-bit `TypedString` ([MS-OXCDATA] §2.11.1.2). Every such value this session
    /// reads is decoded in it. A recipient row without its Unicode flag is in it too (§2.8.3.1),
    /// but [`OpenRecipient`](crate::OpenRecipient) hands rows back undecoded, naming their code
    /// page. A `PtypString` is UTF-16 whatever this says, which is why this crate asks for that
    /// wherever a request lets it.
    ///
    /// Exchange converts each string from the Unicode it stores into this code page, and a
    /// character the code page cannot hold arrives as `?` or as the nearest letter it has. Measured
    /// on Exchange Server SE `15.02.2562.056`: a subject `Café € ž При` read as `PtypString8`
    /// arrived as `Café € ž ???` under 1252 and as `Cafe € z При` under 1251.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.1 — `DefaultCodePage`
    #[must_use]
    pub const fn code_page(mut self, code_page: CodePage) -> Self {
        self.code_page = code_page;
        self
    }

    /// Sets `X-ClientApplication`, whose documented format is `Outlook/15.xx.xxxx.xxxx`.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.6
    #[must_use]
    pub fn client_application(mut self, value: impl Into<String>) -> Self {
        self.client_application = value.into();
        self
    }

    /// Sets `X-ClientInfo`, a GUID and a decimal counter such as `{GUID}:123`.
    ///
    /// The GUID must be unique per client instance and stable for its lifetime.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.4
    #[must_use]
    pub fn client_info(mut self, value: impl Into<String>) -> Self {
        self.client_info = value.into();
        self
    }

    /// Sets the GUID used in `X-RequestId`, which must not change for the life of the Session
    /// Context. The counter after it is maintained by the session.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.2
    #[must_use]
    pub fn request_guid(mut self, value: impl Into<String>) -> Self {
        self.request_guid = value.into();
        self
    }

    /// Builds the session.
    #[must_use]
    pub fn build(self) -> Session {
        Session {
            client_application: self.client_application,
            client_info: self.client_info,
            request_guid: self.request_guid,
            counter: 0,
            code_page: self.code_page,
            lcid_sort: self.lcid_sort,
            lcid_string: self.lcid_string,
            cookies: CookieJar::new(),
            pending: None,
            abandoned: false,
            connected: false,
            table_columns: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oxcdata::LegacyDn;

    /// The locale defaults to en-US, an override reaches both fields, and the two can be split —
    /// which is the only reason the structure declares them separately.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.1
    #[test]
    fn the_builders_locale_is_what_connect_carries() {
        let dn = LegacyDn::new("/o=X").unwrap();
        // UserDn is null-terminated, then Flags and DefaultCodePage precede the pair.
        let at = dn.as_str().len() + 1 + 8;
        let locales = |mut session: Session| {
            session.begin_connect(&dn).unwrap().into_body()[at..at + 8].to_vec()
        };
        let dutch = Lcid::new(0x0413);

        assert_eq!(
            locales(Session::new()),
            [0x09, 0x04, 0, 0, 0x09, 0x04, 0, 0]
        );
        assert_eq!(
            locales(SessionBuilder::new().locale(dutch).build()),
            [0x13, 0x04, 0, 0, 0x13, 0x04, 0, 0]
        );
        assert_eq!(
            locales(
                SessionBuilder::new()
                    .locale(dutch)
                    .string_locale(Lcid::EN_US)
                    .build()
            ),
            [0x13, 0x04, 0, 0, 0x09, 0x04, 0, 0]
        );
    }

    /// The code page defaults to 1252 and an override is what `Connect` carries and what the
    /// session then reads 8-bit strings in.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.1 — `DefaultCodePage`
    #[test]
    fn the_builders_code_page_is_what_connect_carries() {
        let dn = LegacyDn::new("/o=X").unwrap();
        // UserDn is null-terminated, then Flags precede DefaultCodePage.
        let at = dn.as_str().len() + 1 + 4;
        let code_page = |mut session: Session| {
            session.begin_connect(&dn).unwrap().into_body()[at..at + 4].to_vec()
        };
        assert_eq!(code_page(Session::new()), [0xE4, 0x04, 0, 0]);
        assert_eq!(Session::new().code_page(), CodePage::WINDOWS_1252);

        let cyrillic = CodePage::new(1251).unwrap();
        let session = SessionBuilder::new().code_page(cyrillic).build();
        assert_eq!(session.code_page(), cyrillic);
        assert_eq!(code_page(session), [0xE3, 0x04, 0, 0]);
    }
}
