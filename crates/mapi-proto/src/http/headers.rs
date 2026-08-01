//! A small case-insensitive header list.
//!
//! Deliberately not a dependency on an HTTP crate: this crate performs no I/O, and the caller's
//! HTTP client already has its own header type. This is the neutral shape in between — build one
//! from whatever the transport produced, and read the ones the protocol defines back out.
//!
//! [MS-OXCMAPIHTTP] §2.2.3 — header fields

/// Request or response headers, in the order they were added.
///
/// Names compare case-insensitively, as HTTP requires. A name may appear more than once — which
/// `Set-Cookie` does — so [`Headers::get`] returns the first and [`Headers::get_all`] returns
/// every one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    /// An empty list.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a header, keeping any header of the same name that is already present.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.entries.push((name.into(), value.into()));
        self
    }

    /// The first value for `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| &**value)
    }

    /// Every value for `name`, in order.
    #[must_use]
    pub fn get_all<'a>(&'a self, name: &'a str) -> GetAll<'a> {
        GetAll {
            entries: self.entries.iter(),
            name,
        }
    }

    /// Every header, in order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.entries.iter())
    }

    /// How many headers are present.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<'a> IntoIterator for &'a Headers {
    type IntoIter = Iter<'a>;
    type Item = (&'a str, &'a str);

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for Headers {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut headers = Self::new();
        for (name, value) in iter {
            headers.append(name, value);
        }
        headers
    }
}

/// Every header in a [`Headers`], in order. Created by [`Headers::iter`].
#[derive(Clone, Debug)]
pub struct Iter<'a>(core::slice::Iter<'a, (String, String)>);

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(name, value)| (&**name, &**value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for Iter<'_> {}

/// Every value for one header name. Created by [`Headers::get_all`].
#[derive(Clone, Debug)]
pub struct GetAll<'a> {
    entries: core::slice::Iter<'a, (String, String)>,
    name: &'a str,
}

impl<'a> Iterator for GetAll<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries
            .find(|(name, _)| name.eq_ignore_ascii_case(self.name))
            .map(|(_, value)| &**value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Headers {
        let mut headers = Headers::new();
        headers
            .append("X-ResponseCode", "0")
            .append("Set-Cookie", "MapiContext=abc; Path=/")
            .append("set-cookie", "MapiSequence=1; Path=/");
        headers
    }

    #[test]
    fn names_compare_case_insensitively() {
        let headers = sample();
        assert_eq!(headers.get("x-responsecode"), Some("0"));
        assert_eq!(headers.get("X-RESPONSECODE"), Some("0"));
        assert_eq!(headers.get("X-ServerApplication"), None);
    }

    /// `Set-Cookie` arrives more than once, and dropping all but one loses the session.
    #[test]
    fn repeated_headers_are_all_kept() {
        let headers = sample();
        let cookies: Vec<_> = headers.get_all("Set-Cookie").collect();
        assert_eq!(cookies.len(), 2);
        assert_eq!(headers.get("Set-Cookie"), Some("MapiContext=abc; Path=/"));
    }

    #[test]
    fn iteration_yields_every_header_in_order() {
        let headers = sample();
        assert_eq!(headers.len(), 3);
        assert!(!headers.is_empty());
        assert_eq!(headers.iter().count(), 3);
        assert_eq!(headers.iter().size_hint(), (3, Some(3)));
        assert_eq!((&headers).into_iter().next(), Some(("X-ResponseCode", "0")));
    }

    #[test]
    fn headers_can_be_collected_from_pairs() {
        let headers: Headers = [("X-RequestType", "Connect"), ("X-RequestId", "abc:1")]
            .into_iter()
            .collect();
        assert_eq!(headers.get("x-requesttype"), Some("Connect"));
        assert!(Headers::new().is_empty());
    }
}
