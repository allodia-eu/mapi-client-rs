//! The `.meta.txt` that travels with every capture, and the header normalisation behind it.
//!
//! A `.bin` on its own is unreadable and unverifiable: it says nothing about which request it
//! answered, what the server called itself, or what was changed on the way to disk. The meta file
//! is where all of that lives, in a shape both a person and a script can read — sections in
//! brackets, `key = value` in the summary, `Name: value` in the header blocks.
//!
//! It is also where the *honesty* of a fixture lives. Two sections at the end itemise every
//! departure from what the wire carried: `[normalised]` for the fields zeroed because they differ
//! on every capture, `[redacted]` for the identities replaced. Nothing about a committed capture
//! has to be taken on trust.

use crate::capture::Recorded;
use crate::scrub::Rules;

/// Header values that are a fresh random number or a clock reading on every run.
///
/// Left alone, each of these would make two captures of the same exchange differ, which would turn
/// `Verify-Fixtures.ps1` into a script that always reports a change and therefore never reports
/// one that matters.
const VOLATILE_HEADERS: [&str; 7] = [
    // The client's own per-instance and per-session GUIDs.
    // [MS-OXCMAPIHTTP] §2.2.3.3.2, §2.2.3.3.4
    "X-RequestId",
    "X-ClientInfo",
    // The Session Context's cookies, which the server mints per session.
    // [MS-OXCMAPIHTTP] §2.2.3.2.3
    "Cookie",
    "Set-Cookie",
    // Clocks.
    "Date",
    "X-ElapsedTime",
    "request-id",
];

/// What replaces a volatile header value that carries no structure worth keeping.
const NORMALISED: &str = "<normalised by capture>";

/// The GUID that replaces a client-generated one, keeping the counter that follows it.
const ZERO_GUID: &str = "{00000000-0000-0000-0000-000000000000}";

/// Applies the scrub rules to a string, which is what the URL and the header values need.
pub(crate) fn scrub_text(text: &str, rules: &Rules, into: &mut Vec<(String, usize)>) -> String {
    let mut bytes = text.as_bytes().to_vec();
    merge(into, rules.apply(&mut bytes));
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Scrubs every header value and normalises the volatile ones, noting each change.
pub(crate) fn normalise_headers(
    headers: &[(String, String)],
    rules: &Rules,
    changes: &mut Vec<String>,
    redactions: &mut Vec<(String, usize)>,
) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = scrub_text(value, rules, redactions);
            if !VOLATILE_HEADERS
                .iter()
                .any(|volatile| volatile.eq_ignore_ascii_case(name))
            {
                return (name.clone(), value);
            }

            let (replacement, what) = match name.to_ascii_lowercase().as_str() {
                // `{GUID}:counter` — the GUID is this client instance's and means nothing to a
                // reader, but the counter is the protocol's own sequencing and is worth keeping.
                "x-requestid" | "x-clientinfo" => (keep_counter(&value), "GUID replaced"),
                "cookie" | "set-cookie" => (redact_cookie(&value), "value replaced"),
                _ => (NORMALISED.to_owned(), "value replaced"),
            };
            changes.push(format!("header `{name}`: {what}"));
            (name.clone(), replacement)
        })
        .collect()
}

/// Replaces the GUID in `{GUID}:counter`, keeping the counter.
fn keep_counter(value: &str) -> String {
    match value.rsplit_once(':') {
        Some((_, counter)) => format!("{ZERO_GUID}:{counter}"),
        None => ZERO_GUID.to_owned(),
    }
}

/// Replaces each cookie's value, keeping the names and the attributes that mean something.
///
/// A `Set-Cookie` is `name=value` followed by attributes; a `Cookie` is `name=value` pairs. The
/// structure survives, because which cookies a Session Context uses and which paths they are
/// scoped to is exactly what a reader of the fixture came for. Two things do not survive: the
/// cookie values, which the server mints per session, and `expires`, which Exchange sets to a
/// month from now and which would therefore make every re-capture differ.
fn redact_cookie(value: &str) -> String {
    value
        .split(';')
        .map(|part| match part.split_once('=') {
            Some((name, _)) if is_volatile_pair(name.trim()) => {
                format!("{}=<normalised>", name.trim())
            }
            _ => part.trim().to_owned(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Whether this `name=value` pair carries something that differs between captures.
///
/// True for a cookie — the value is the session's — and for the two attributes that are a clock.
/// False for `path`, `domain` and `samesite`, whose values are fixed by the deployment and are
/// worth keeping.
fn is_volatile_pair(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "path" | "domain" | "samesite" | "version" | "secure" | "httponly"
    )
}

/// Merges one rule-hit report into another.
pub(crate) fn merge(into: &mut Vec<(String, usize)>, more: Vec<(String, usize)>) {
    for (label, count) in more {
        match into.iter_mut().find(|(existing, _)| *existing == label) {
            Some(entry) => entry.1 = entry.1.saturating_add(count),
            None => into.push((label, count)),
        }
    }
}

/// Renders the `.meta.txt` that accompanies one exchange.
#[expect(
    clippy::too_many_arguments,
    reason = "a record of one exchange has this many parts; bundling them would only move the \
              list somewhere less readable"
)]
pub(crate) fn render(
    stem: &str,
    exchange: &Recorded,
    endpoint: &str,
    request_headers: &[(String, String)],
    response_headers: &[(String, String)],
    request_bytes: usize,
    response_bytes: usize,
    changes: &[String],
    redactions: &[(String, usize)],
) -> String {
    let mut lines: Vec<String> = vec![
        "# Captured from a real Exchange Server by `mapi-cli capture`.".to_owned(),
        "# Byte-exact apart from the two sections at the end of this file, which itemise every"
            .to_owned(),
        "# change: identities redacted length-preservingly, and the few fields that differ on"
            .to_owned(),
        "# every capture zeroed. See fixtures/MANIFEST.toml for the server version and the hash"
            .to_owned(),
        "# of each file.".to_owned(),
        String::new(),
        "[exchange]".to_owned(),
        format!("name = {stem}"),
        format!("request-type = {}", exchange.request_type.as_str()),
        format!("url = {endpoint}"),
        format!("status = {}", exchange.status),
        format!("request-bytes = {request_bytes}"),
        format!("response-bytes = {response_bytes}"),
    ];

    for (section, headers) in [
        ("request-headers", request_headers),
        ("response-headers", response_headers),
    ] {
        lines.push(String::new());
        lines.push(format!("[{section}]"));
        lines.extend(
            headers
                .iter()
                .map(|(name, value)| format!("{name}: {value}")),
        );
    }

    lines.push(String::new());
    lines.push("[normalised]".to_owned());
    if changes.is_empty() {
        lines.push("# nothing in this exchange varies between captures".to_owned());
    }
    lines.extend(changes.iter().map(|change| format!("- {change}")));

    lines.push(String::new());
    lines.push("[redacted]".to_owned());
    if redactions.is_empty() {
        lines.push("# no scrub rule matched anything in this exchange".to_owned());
    }
    lines.extend(
        redactions
            .iter()
            .map(|(placeholder, count)| format!("- {placeholder} x{count}")),
    );

    // A trailing newline, because a text file without one is a text file every tool complains
    // about — and these are read by `git diff` as often as by a person.
    lines.push(String::new());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use mapi_client::RequestType;

    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// The GUIDs, cookies and clocks that would otherwise make two captures of one exchange differ
    /// — and, just as importantly, the headers that must survive untouched because they are what a
    /// reader came for.
    #[test]
    fn volatile_header_values_are_replaced_and_stable_ones_are_not() {
        let rules = Rules::default();
        let mut changes = Vec::new();
        let mut redactions = Vec::new();

        let normalised = normalise_headers(
            &headers(&[
                ("X-RequestId", "{7C9E6679-7425-40DE-944B-E07FC1F90AE7}:3"),
                ("X-ClientInfo", "{7C9E6679-7425-40DE-944B-E07FC1F90AE7}:0"),
                ("Cookie", "MapiContext=abc-123; MapiSequence=def-456"),
                (
                    "Set-Cookie",
                    "MapiContext=abc-123; path=/mapi; secure; HttpOnly",
                ),
                ("Date", "Sun, 02 Aug 2026 09:12:44 GMT"),
                ("X-ResponseCode", "0"),
                ("X-ServerApplication", "Exchange/15.02.2562.045"),
            ]),
            &rules,
            &mut changes,
            &mut redactions,
        );

        let rendered: Vec<String> = normalised
            .iter()
            .map(|(name, value)| format!("{name}: {value}"))
            .collect();

        assert!(
            rendered.contains(&format!("X-RequestId: {ZERO_GUID}:3")),
            "{rendered:?}"
        );
        assert!(
            rendered.contains(&format!("X-ClientInfo: {ZERO_GUID}:0")),
            "{rendered:?}"
        );
        assert!(
            rendered.contains(
                &"Cookie: MapiContext=<normalised>; MapiSequence=<normalised>".to_owned()
            ),
            "{rendered:?}"
        );
        assert!(
            rendered.contains(&format!("Date: {NORMALISED}")),
            "{rendered:?}"
        );

        // What a reader of the fixture actually came for, untouched.
        assert!(
            rendered.contains(&"X-ResponseCode: 0".to_owned()),
            "{rendered:?}"
        );
        assert!(
            rendered.contains(&"X-ServerApplication: Exchange/15.02.2562.045".to_owned()),
            "{rendered:?}"
        );
        assert_eq!(changes.len(), 5, "one note per header changed: {changes:?}");
    }

    /// A cookie keeps its name and its attributes, because which cookies a Session Context uses is
    /// exactly what somebody reads a captured `Set-Cookie` to find out.
    #[test]
    fn cookie_attributes_are_kept_and_only_values_are_replaced() {
        assert_eq!(
            redact_cookie("MapiContext=abc; path=/mapi; secure; HttpOnly"),
            "MapiContext=<normalised>; path=/mapi; secure; HttpOnly"
        );
        assert_eq!(redact_cookie("secure"), "secure");

        // `expires` is a clock — Exchange sets it a month out — so it goes the way of the value,
        // while `path` stays because it says where the cookie applies.
        assert_eq!(
            redact_cookie(
                "X-BackEndCookie=abc; expires=Tue, 01-Sep-2026 14:15:40 GMT; path=/mapi; secure"
            ),
            "X-BackEndCookie=<normalised>; expires=<normalised>; path=/mapi; secure"
        );
        assert_eq!(keep_counter("{ABC}:12"), format!("{ZERO_GUID}:12"));
        assert_eq!(keep_counter("no-counter"), ZERO_GUID);
    }

    /// The two sections that make a fixture auditable say so explicitly when there is nothing to
    /// report, rather than being absent — an empty section and a missing one read very differently
    /// to somebody checking whether the scrub ran at all.
    #[test]
    fn nothing_to_report_is_stated_rather_than_left_out() {
        let exchange = Recorded::for_test(RequestType::Ping, 200);
        let rendered = render(
            "01-ping",
            &exchange,
            "https://exchange-lab-01/mapi/emsmdb/",
            &headers(&[("X-RequestType", "PING")]),
            &headers(&[("X-ResponseCode", "0")]),
            0,
            38,
            &[],
            &[],
        );

        assert!(
            rendered.contains(
                "[normalised]
# nothing in this exchange varies"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "[redacted]
# no scrub rule matched anything"
            ),
            "{rendered}"
        );
        assert!(rendered.contains("name = 01-ping"), "{rendered}");
        assert!(rendered.contains("request-type = PING"), "{rendered}");
        assert!(rendered.contains("status = 200"), "{rendered}");
        assert!(rendered.contains("request-bytes = 0"), "{rendered}");
        assert!(rendered.ends_with('\n'), "a text file ends with a newline");
    }

    /// Every section a reader — or `Verify-Fixtures.ps1` — expects to find, in order.
    #[test]
    fn the_sections_are_the_ones_the_format_promises() {
        let exchange = Recorded::for_test(RequestType::Connect, 200);
        let rendered = render(
            "02-connect",
            &exchange,
            "https://exchange-lab-01/mapi/emsmdb/",
            &headers(&[("X-RequestType", "Connect")]),
            &headers(&[("X-ResponseCode", "0")]),
            42,
            96,
            &["response body: `RetryDelay` zeroed".to_owned()],
            &[("text:exchange-lab-01".to_owned(), 3)],
        );

        let sections: Vec<&str> = rendered
            .lines()
            .filter(|line| line.starts_with('[') && line.ends_with(']'))
            .collect();
        assert_eq!(
            sections,
            [
                "[exchange]",
                "[request-headers]",
                "[response-headers]",
                "[normalised]",
                "[redacted]"
            ]
        );
        assert!(
            rendered.contains("- response body: `RetryDelay` zeroed"),
            "{rendered}"
        );
        assert!(rendered.contains("- text:exchange-lab-01 x3"), "{rendered}");
    }
}
