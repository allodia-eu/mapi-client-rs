//! Taking a deployment's identity out of a capture, without moving a single byte.
//!
//! Three rules, each of which has already cost real debugging time in this project:
//!
//! 1. **Replacements are length-preserving.** Fixtures are read by byte offset, and a shifted
//!    offset is worse than an unscrubbed name because it fails somewhere unrelated to the change
//!    that caused it. A rule whose two sides differ in length is refused rather than applied.
//! 2. **Both encodings are scrubbed.** MAPI carries 8-bit strings and UTF-16LE in the same body — a
//!    distinguished name in ASCII, a display name in UTF-16 — so every text rule is applied in
//!    both.
//! 3. **Matching is case-sensitive.** Exchange echoes a host name uppercase while the URL carries
//!    it lowercase, and a single lowercase rule silently left the real name in a capture. Here
//!    every text rule automatically expands to the as-written, lowercased and uppercased forms,
//!    with the replacement cased to match, so the rule that catches one case catches all three.
//!
//! And because a rule that matched nothing looks exactly like a rule that worked, [`Rules::find`]
//! re-scans the output for every needle afterwards. That is the check `Assert-NoSecrets.ps1` then
//! performs again, independently, over what is about to be committed.

use core::fmt;
use core::fmt::Write as _;
use std::collections::BTreeSet;

/// A rules file that could not be read.
#[derive(Debug)]
pub(crate) enum RuleError {
    /// A line that is neither blank, a comment, nor three tab-separated fields.
    Malformed { line: usize },
    /// A rule kind that is not `text` or `bytes`.
    UnknownKind { line: usize, kind: String },
    /// The two sides of a rule are different lengths, which no scrub may be.
    LengthMismatch {
        line: usize,
        needle: usize,
        replacement: usize,
    },
    /// A `text` rule whose sides are not both ASCII, so their UTF-16LE forms could differ in
    /// length even when their ASCII forms do not.
    NotAscii { line: usize },
    /// A `bytes` rule that is not an even number of hexadecimal digits.
    NotHex { line: usize },
    /// A rule with an empty needle, which would match everywhere and nowhere.
    Empty { line: usize },
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { line } => write!(
                f,
                "line {line}: expected three tab-separated fields, \
                 `kind<TAB>needle<TAB>replacement`"
            ),
            Self::UnknownKind { line, kind } => {
                write!(
                    f,
                    "line {line}: unknown rule kind `{kind}`, expected `text` or `bytes`"
                )
            }
            Self::LengthMismatch {
                line,
                needle,
                replacement,
            } => write!(
                f,
                "line {line}: a scrub must be length-preserving, but the needle is {needle} bytes \
                 and the replacement is {replacement}. Pad or trim the replacement."
            ),
            Self::NotAscii { line } => write!(
                f,
                "line {line}: a `text` rule must be ASCII on both sides, so that its UTF-16LE form \
                 stays the same length. Use a `bytes` rule for anything else."
            ),
            Self::NotHex { line } => {
                write!(
                    f,
                    "line {line}: a `bytes` rule takes an even number of hexadecimal digits"
                )
            }
            Self::Empty { line } => write!(f, "line {line}: the needle is empty"),
        }
    }
}

impl core::error::Error for RuleError {}

/// One byte sequence to replace with another of the same length.
///
/// Two labels, and the distinction is load-bearing. `found` names what is being removed and is
/// only ever printed to whoever is running the capture — they already know their own host name.
/// `placed` names the placeholder that replaced it and is the only one that may be written into a
/// committed file: a fixture that helpfully recorded "3 occurrences of win-m382a5je4u9 removed"
/// would have leaked exactly what the scrub existed to remove.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Rule {
    placed: String,
    found: String,
    needle: Vec<u8>,
    replacement: Vec<u8>,
}

/// Every replacement to apply to a capture.
#[derive(Clone, Debug, Default)]
pub(crate) struct Rules {
    rules: Vec<Rule>,
}

impl Rules {
    /// Reads a rules file.
    ///
    /// ```text
    /// # everything after a hash is a comment
    /// text    win-m382a5je4u9                         exchange-lab-01
    /// bytes   59496a17d3ac6742913a19997ffd7e93        00000000000000000000000000000001
    /// ```
    ///
    /// Fields are separated by tabs, because a needle routinely contains spaces — an Exchange
    /// distinguished name has `ou=Exchange Administrative Group (FYDIBOHF23SPDLT)` in the middle
    /// of it.
    pub(crate) fn parse(text: &str) -> Result<Self, RuleError> {
        let mut rules: BTreeSet<Rule> = BTreeSet::new();

        for (index, raw) in text.lines().enumerate() {
            let line = index.saturating_add(1);
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let mut fields = raw.split('\t').map(str::trim);
            let (Some(kind), Some(needle), Some(replacement), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(RuleError::Malformed { line });
            };

            if needle.is_empty() {
                return Err(RuleError::Empty { line });
            }

            match kind {
                "text" => expand_text(line, needle, replacement, &mut rules)?,
                "bytes" => {
                    let needle = from_hex(needle).ok_or(RuleError::NotHex { line })?;
                    let replacement = from_hex(replacement).ok_or(RuleError::NotHex { line })?;
                    if needle.len() != replacement.len() {
                        return Err(RuleError::LengthMismatch {
                            line,
                            needle: needle.len(),
                            replacement: replacement.len(),
                        });
                    }
                    rules.insert(Rule {
                        placed: format!("bytes:{}", to_hex(&replacement)),
                        found: format!("bytes:{}", to_hex(&needle)),
                        needle,
                        replacement,
                    });
                }
                other => {
                    return Err(RuleError::UnknownKind {
                        line,
                        kind: other.to_owned(),
                    });
                }
            }
        }

        Ok(Self {
            rules: rules.into_iter().collect(),
        })
    }

    /// How many byte-level replacements these rules amount to.
    pub(crate) fn len(&self) -> usize {
        self.rules.len()
    }

    /// Applies every rule in place, reporting each placeholder it wrote and how often.
    ///
    /// In place is possible only because every replacement is the same length as its needle, which
    /// is checked when the rules are parsed and is the whole reason for that restriction. The
    /// report names placeholders rather than needles because it ends up in a committed file.
    pub(crate) fn apply(&self, bytes: &mut [u8]) -> Vec<(String, usize)> {
        let mut hits = Vec::new();
        for rule in &self.rules {
            let count = replace_all(bytes, &rule.needle, &rule.replacement);
            if count > 0 {
                hits.push((rule.placed.clone(), count));
            }
        }
        hits
    }

    /// Every needle still present, which after [`Rules::apply`] must be none.
    ///
    /// This is the check that matters: a rule that matched nothing is indistinguishable from a
    /// rule that worked, so the only way to know a capture is clean is to look for what should not
    /// be in it. Names needles, so it is for the terminal and never for a file.
    pub(crate) fn find(&self, bytes: &[u8]) -> Vec<String> {
        self.rules
            .iter()
            .filter(|rule| find_from(bytes, &rule.needle, 0).is_some())
            .map(|rule| rule.found.clone())
            .collect()
    }
}

/// Expands one text rule into the six byte rules it stands for: three casings, two encodings.
fn expand_text(
    line: usize,
    needle: &str,
    replacement: &str,
    into: &mut BTreeSet<Rule>,
) -> Result<(), RuleError> {
    if !needle.is_ascii() || !replacement.is_ascii() {
        return Err(RuleError::NotAscii { line });
    }
    if needle.len() != replacement.len() {
        return Err(RuleError::LengthMismatch {
            line,
            needle: needle.len(),
            replacement: replacement.len(),
        });
    }

    for (needle, replacement) in [
        (needle.to_owned(), replacement.to_owned()),
        (
            needle.to_ascii_lowercase(),
            replacement.to_ascii_lowercase(),
        ),
        (
            needle.to_ascii_uppercase(),
            replacement.to_ascii_uppercase(),
        ),
    ] {
        into.insert(Rule {
            placed: format!("text:{replacement}"),
            found: format!("text:{needle}"),
            needle: needle.as_bytes().to_vec(),
            replacement: replacement.as_bytes().to_vec(),
        });
        into.insert(Rule {
            placed: format!("utf16:{replacement}"),
            found: format!("utf16:{needle}"),
            needle: utf16le(&needle),
            replacement: utf16le(&replacement),
        });
    }

    Ok(())
}

/// The UTF-16LE encoding of an ASCII string, which is what `PtypString` carries.
///
/// [MS-OXCDATA] §2.11.1
fn utf16le(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(2));
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Overwrites every occurrence of `needle`, which must be the same length as `replacement`.
fn replace_all(haystack: &mut [u8], needle: &[u8], replacement: &[u8]) -> usize {
    if needle.is_empty() || needle.len() != replacement.len() {
        return 0;
    }

    let mut count = 0_usize;
    let mut at = 0_usize;
    while let Some(found) = find_from(haystack, needle, at) {
        let end = found.saturating_add(needle.len());
        if let Some(slot) = haystack.get_mut(found..end) {
            slot.copy_from_slice(replacement);
        }
        count = count.saturating_add(1);
        at = end;
    }
    count
}

/// The first occurrence of `needle` at or after `from`.
fn find_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let tail = haystack.get(from..)?;
    tail.windows(needle.len())
        .position(|window| window == needle)
        .map(|at| from.saturating_add(at))
}

/// Parses an even-length run of hexadecimal digits.
fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let digits: Vec<char> = text.chars().collect();
    digits
        .chunks(2)
        .map(|pair| {
            let high = pair.first()?.to_digit(16)?;
            let low = pair.get(1)?.to_digit(16)?;
            u8::try_from(high.checked_mul(16)?.checked_add(low)?).ok()
        })
        .collect()
}

/// Renders bytes as lower-case hexadecimal.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        // Writing into a `String` cannot fail, and unwrapping is denied outside tests, so the
        // result is discarded deliberately rather than by oversight.
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> Rules {
        Rules::parse(text).expect("valid rules")
    }

    /// The rule that costs the most when it is wrong, stated as a test: a replacement of a
    /// different length is refused, not padded, not truncated, not applied.
    #[test]
    fn a_replacement_of_a_different_length_is_refused() {
        let error = Rules::parse("text\twin-m382a5je4u9\tlab").expect_err("lengths differ");
        assert!(
            matches!(error, RuleError::LengthMismatch { .. }),
            "{error:?}"
        );
        assert!(error.to_string().contains("length-preserving"));

        let error = Rules::parse("bytes\tAABB\tCC").expect_err("lengths differ");
        assert!(
            matches!(error, RuleError::LengthMismatch { .. }),
            "{error:?}"
        );
    }

    /// The trap the project already fell into once: Exchange echoes the host name uppercase while
    /// the URL carries it lowercase. One rule, every casing.
    #[test]
    fn one_text_rule_catches_every_casing_in_both_encodings() {
        let rules = rules("text\twin-m382a5je4u9\texchange-lab-01");

        // The two forms one Exchange sends: lowercase in the URL it was given, uppercase in the
        // `X-FEServer` header it echoes back — plus the UTF-16 a display name would carry.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"https://win-m382a5je4u9/mapi ");
        bytes.extend_from_slice(b"WIN-M382A5JE4U9 ");
        bytes.extend_from_slice(&utf16le("win-m382a5je4u9"));

        let before = bytes.len();
        let hits = rules.apply(&mut bytes);

        assert_eq!(bytes.len(), before, "the length never moves");
        assert_eq!(
            hits.len(),
            3,
            "lowercase ASCII, uppercase ASCII, lowercase UTF-16: {hits:?}"
        );
        assert!(rules.find(&bytes).is_empty(), "nothing is left behind");

        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("https://exchange-lab-01/mapi"));
        assert!(text.contains("EXCHANGE-LAB-01"));
        assert!(bytes.ends_with(&utf16le("exchange-lab-01")));
    }

    /// The limit of automatic casing, stated rather than discovered: three casings are covered,
    /// and a casing that is none of them needs its own rule. `Assert-NoSecrets.ps1` greps
    /// case-insensitively for exactly this reason — it is the backstop, not a duplicate.
    #[test]
    fn a_casing_that_is_none_of_the_three_needs_its_own_rule() {
        let automatic = rules("text	win-m382a5je4u9	exchange-lab-01");
        let mut mixed = b"Win-M382a5je4u9".to_vec();
        assert!(automatic.apply(&mut mixed).is_empty());
        assert_eq!(mixed, b"Win-M382a5je4u9");

        let explicit = rules(
            "text	win-m382a5je4u9	exchange-lab-01
             text	Win-M382a5je4u9	Exchange-Lab-01",
        );
        assert_eq!(explicit.apply(&mut mixed).len(), 1);
        assert_eq!(mixed, b"Exchange-Lab-01");
    }

    /// A capture carries both encodings in one body, and a rule that only knew about one of them
    /// would leave the other in place while reporting a hit.
    #[test]
    fn both_encodings_are_scrubbed_from_the_same_body() {
        let rules = rules("text\tDeveloper User\tExample Person");
        let mut body = b"/cn=Developer User\0".to_vec();
        body.extend_from_slice(&utf16le("Developer User"));

        assert_eq!(rules.apply(&mut body).len(), 2);
        assert!(rules.find(&body).is_empty());
        assert!(body.starts_with(b"/cn=Example Person\0"));
        assert!(body.ends_with(&utf16le("Example Person")));
    }

    /// A GUID in a logon response is sixteen raw bytes, not text, so it needs a `bytes` rule.
    ///
    /// [MS-OXCSTOR] §2.2.1.1.3 — `MailboxGuid`
    #[test]
    fn a_binary_guid_is_scrubbed_by_a_bytes_rule() {
        let rules =
            rules("bytes\t59496a17d3ac6742913a19997ffd7e93\t00000000000000000000000000000001");
        let mut body = vec![0xAA, 0xBB];
        body.extend_from_slice(&[
            0x59, 0x49, 0x6A, 0x17, 0xD3, 0xAC, 0x67, 0x42, 0x91, 0x3A, 0x19, 0x99, 0x7F, 0xFD,
            0x7E, 0x93,
        ]);
        body.push(0xCC);

        assert_eq!(rules.apply(&mut body).len(), 1);
        assert!(rules.find(&body).is_empty());
        assert_eq!(body.first(), Some(&0xAA));
        assert_eq!(body.last(), Some(&0xCC));
        assert_eq!(body.get(2..6), Some(&[0x00, 0x00, 0x00, 0x00][..]));
        assert_eq!(body.get(17), Some(&0x01));
    }

    /// Every occurrence, not just the first: a distinguished name appears in the `Connect` body
    /// and again in the `RopLogon` that follows it.
    #[test]
    fn every_occurrence_is_replaced() {
        let rules = rules("text\tsecret\tredact");
        let mut body = b"secret secret secret".to_vec();
        assert_eq!(rules.apply(&mut body), vec![("text:redact".to_owned(), 3)]);
        assert_eq!(body, b"redact redact redact");
    }

    /// Overlapping occurrences advance past the match rather than rescanning inside it, so a
    /// needle that is a prefix of itself terminates.
    #[test]
    fn overlapping_needles_terminate() {
        let rules = rules("text\taaa\tbbb");
        let mut body = b"aaaaa".to_vec();
        assert_eq!(rules.apply(&mut body), vec![("text:bbb".to_owned(), 1)]);
        assert_eq!(body, b"bbbaa");
    }

    /// The distinction that keeps a scrub from undoing itself: what goes in a committed file names
    /// the placeholder, never the thing being hidden.
    #[test]
    fn a_report_that_reaches_a_file_names_placeholders_only() {
        let rules = rules("text\twin-m382a5je4u9\texchange-lab-01");
        let mut body = b"https://win-m382a5je4u9/mapi".to_vec();

        let placed = rules.apply(&mut body);
        let rendered = format!("{placed:?}");
        assert!(rendered.contains("exchange-lab-01"), "{rendered}");
        assert!(!rendered.contains("win-m382a5je4u9"), "{rendered}");

        // `find` is the operator's diagnostic, so it may — and must — name what survived.
        let survived = format!("{:?}", rules.find(b"WIN-M382A5JE4U9"));
        assert!(survived.contains("WIN-M382A5JE4U9"), "{survived}");
    }

    #[test]
    fn a_rule_that_matches_nothing_is_reported_as_no_hit() {
        let rules = rules("text\tabsent\tredact");
        let mut body = b"nothing to see".to_vec();
        assert!(rules.apply(&mut body).is_empty());
        assert!(rules.find(&body).is_empty());
    }

    /// `find` is the self-check, so it has to actually notice.
    #[test]
    fn find_reports_what_a_scrub_would_have_left_behind() {
        let rules = rules("text\twin-m382a5je4u9\texchange-lab-01");
        let left = rules.find(b"X-FEServer: WIN-M382A5JE4U9");
        assert_eq!(left, vec!["text:WIN-M382A5JE4U9".to_owned()]);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored_and_duplicates_collapse() {
        let rules = rules(
            "# a comment\n\
             \n\
             text\tabc\txyz\n\
             text\tabc\txyz\n",
        );
        // Three casings times two encodings, but `abc`/`ABC`/`abc` collapse to two distinct
        // casings, so four rules rather than six — and the duplicate line adds nothing.
        assert_eq!(rules.len(), 4);
    }

    #[test]
    fn a_malformed_rules_file_says_which_line_and_why() {
        for (text, expected) in [
            ("text abc xyz", "three tab-separated fields"),
            ("shout\tabc\txyz", "unknown rule kind"),
            ("text\tnaïve\tnaive", "must be ASCII"),
            ("bytes\tAAB\tCCD", "hexadecimal"),
            ("text\t\tabc", "needle is empty"),
        ] {
            let error = Rules::parse(text).expect_err(text);
            assert!(
                error.to_string().contains(expected),
                "{text:?} reported {error}"
            );
            assert!(error.to_string().starts_with("line 1:"), "{error}");
        }
    }

    #[test]
    fn hexadecimal_round_trips() {
        assert_eq!(from_hex("00ff10"), Some(vec![0x00, 0xFF, 0x10]));
        assert_eq!(to_hex(&[0x00, 0xFF, 0x10]), "00ff10");
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex(""), None);
        assert_eq!(from_hex("abc"), None);
    }

    #[test]
    fn an_empty_rules_file_is_valid_and_changes_nothing() {
        let rules = Rules::parse("").expect("an empty file is a file");
        let mut body = b"unchanged".to_vec();
        assert_eq!(rules.len(), 0);
        assert!(rules.apply(&mut body).is_empty());
        assert_eq!(body, b"unchanged");
    }
}
