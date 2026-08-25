//! Recording exchanges, and writing them out as fixtures.
//!
//! CI never sees an Exchange server, so the committed captures are the only thing standing between
//! CI and a false green. What makes them worth trusting is that they are produced by the ordinary
//! client, through the ordinary [`Observer`] hook — no special code path that only runs at capture
//! time and could therefore be wrong in a way nobody notices.
//!
//! Each exchange becomes three files:
//!
//! | File | What it is |
//! |---|---|
//! | `NN-<type>-<label>.request.bin` | the POST body, byte for byte |
//! | `NN-<type>-<label>.response.bin` | the response payload, preamble included, byte for byte |
//! | `NN-<type>-<label>.meta.txt` | headers, sizes, and every change made to the two above |
//!
//! Everything in all three has been through [`Rules`] — the deployment's identity replaced,
//! length preservingly — and through [`crate::normalise`], which removes the few fields that
//! differ on every capture. Both are itemised in the `.meta.txt`, so nothing about a fixture is a
//! change somebody has to take on trust.
//!
//! # What a write scenario adds
//!
//! A read scenario's requests are the same bytes every run. A write scenario's are not: the server
//! mints an identifier for the item it created, and that identifier then travels in the *request*
//! bodies of everything the scenario does with it afterwards. There is no anchor for it in the ROP
//! buffer — a message id is eight bytes in the middle of a variable-length list — so
//! [`crate::normalise`]'s offset-and-anchor approach cannot reach it.
//!
//! Instead the scenario says what the server gave it, through [`Recorder::server_assigned`], and
//! every occurrence of those exact bytes is replaced with zeros of the same length. That is
//! narrower than it sounds: nothing is guessed, only values the run itself watched a server mint
//! are touched, and the replacement is length-preserving like every other one here. On replay the
//! client reads the zero out of the fake server's answer and sends the same zero back, so the
//! request bodies match byte for byte — which is the property the replay tests exist to check.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use mapi_client::{Exchange, Observer, RequestType};

use crate::meta::{merge, normalise_headers, scrub_text};
use crate::scrub::Rules;
use crate::{Failure, meta, normalise};

/// One exchange, owned.
#[derive(Clone, Debug)]
pub(crate) struct Recorded {
    label: String,
    pub(crate) request_type: RequestType,
    request_headers: Vec<(String, String)>,
    request_body: Vec<u8>,
    pub(crate) status: u16,
    response_headers: Vec<(String, String)>,
    response_body: Vec<u8>,
}

impl Recorded {
    /// An exchange with nothing in it but a request type and a status, for the tests that render
    /// a meta file without needing a server to have said anything.
    #[cfg(test)]
    pub(crate) fn for_test(request_type: RequestType, status: u16) -> Self {
        Self {
            label: String::new(),
            request_type,
            request_headers: Vec::new(),
            request_body: Vec::new(),
            status,
            response_headers: Vec::new(),
            response_body: Vec::new(),
        }
    }
}

/// A value the server minted during a capture, which will differ on the next one.
#[derive(Clone, Debug)]
pub(crate) struct ServerAssigned {
    /// What it is, for the `.meta.txt`. Never the value itself.
    what: String,
    /// The bytes as they appear on the wire.
    bytes: Vec<u8>,
}

/// Keeps every exchange a client makes, in order.
///
/// The label is set by whoever is driving the client, immediately before the call that will
/// produce the next exchange, so a file name says what the request was *for* — `hierarchy`,
/// `contents` — rather than only which request type it used.
#[derive(Debug, Default)]
pub(crate) struct Recorder {
    label: Mutex<String>,
    exchanges: Mutex<Vec<Recorded>>,
    assigned: Mutex<Vec<ServerAssigned>>,
}

impl Recorder {
    /// Names whatever happens next.
    pub(crate) fn label(&self, label: &str) {
        if let Ok(mut current) = self.label.lock() {
            label.clone_into(&mut current);
        }
    }

    /// Records a value the server minted, so the capture can zero it wherever it appears.
    ///
    /// Called by a scenario that has just been handed an identifier — a message id from a save —
    /// and knows that the next run will be handed a different one. The name is for the `.meta.txt`;
    /// the bytes never appear in it.
    ///
    /// **Declaring one is the scenario's job and nothing checks that it did.** If it forgets, the
    /// capture still succeeds and `Verify-Fixtures.ps1` reports a difference on the very next run —
    /// which is a loud failure at the right moment rather than a quiet one later.
    ///
    /// What *is* checked is the width: the replacement matches a byte sequence across the whole
    /// capture, so anything under [`NARROWEST_ASSIGNED`] is refused before a file is written rather
    /// than allowed to zero bytes nobody meant.
    pub(crate) fn server_assigned(&self, what: &str, bytes: &[u8]) {
        if let Ok(mut assigned) = self.assigned.lock() {
            assigned.push(ServerAssigned {
                what: what.to_owned(),
                bytes: bytes.to_vec(),
            });
        }
    }

    /// Everything recorded so far, in order.
    pub(crate) fn exchanges(&self) -> Vec<Recorded> {
        self.exchanges
            .lock()
            .map(|exchanges| exchanges.clone())
            .unwrap_or_default()
    }

    /// Every value a scenario said the server minted.
    pub(crate) fn assigned(&self) -> Vec<ServerAssigned> {
        self.assigned
            .lock()
            .map(|assigned| assigned.clone())
            .unwrap_or_default()
    }
}

/// The narrowest value a scenario may declare.
///
/// The replacement is a byte-sequence match across the whole capture, so a value narrow enough to
/// occur by coincidence would zero something nobody meant. Eight bytes is what the two real cases
/// are — a message id and a mailbox size — and is wide enough that an accidental match is not a
/// thing to plan around. Four would not be: `PidTagContentCount` of 280 is `18 01 00 00`, which is
/// exactly the sort of small integer a ROP buffer is full of.
const NARROWEST_ASSIGNED: usize = 8;

/// Refuses a declaration too narrow to match only what was meant.
///
/// A hard failure before anything is written, for the same reason a scrub rule that leaves a needle
/// behind is one: a fixture that has had unrelated bytes zeroed is worse than no fixture, and it
/// would be invisible.
fn check_assigned(assigned: &[ServerAssigned]) -> Result<(), Failure> {
    for value in assigned {
        if value.bytes.len() < NARROWEST_ASSIGNED {
            return Err(Failure::from(format!(
                "the scenario declared {} as server-assigned, and it is {} byte(s). Anything under \
                 {NARROWEST_ASSIGNED} is matched across the whole capture often enough to zero \
                 bytes nobody meant, which is invisible once written. Declare a wider value, or \
                 normalise this one against an anchor instead.",
                value.what,
                value.bytes.len()
            )));
        }
    }
    Ok(())
}

/// Replaces every occurrence of each minted value with zeros of the same length.
///
/// Length-preserving, like every replacement in this pipeline: a fixture is read by byte offset,
/// and a shifted offset fails somewhere unrelated to the change that caused it.
fn zero_assigned(payload: &mut [u8], assigned: &[ServerAssigned], changes: &mut Vec<String>) {
    for value in assigned {
        let width = value.bytes.len();
        if width == 0 {
            continue;
        }

        let mut replaced = 0_usize;
        let mut at = 0_usize;
        while let Some(found) = payload
            .get(at..)
            .and_then(|rest| rest.windows(width).position(|window| window == value.bytes))
        {
            let start = at.saturating_add(found);
            if let Some(field) = payload.get_mut(start..start.saturating_add(width)) {
                field.fill(0);
            }
            replaced = replaced.saturating_add(1);
            at = start.saturating_add(width);
        }

        if replaced > 0 {
            changes.push(format!(
                "{replaced} occurrence(s) of {} zeroed: {width} bytes minted by this capture",
                value.what
            ));
        }
    }
}

impl Observer for Recorder {
    fn observe(&self, exchange: &Exchange<'_>) {
        let label = self
            .label
            .lock()
            .map(|label| label.clone())
            .unwrap_or_default();

        let recorded = Recorded {
            label,
            request_type: exchange.request_type(),
            request_headers: own(exchange.request_headers()),
            request_body: exchange.request_body().to_vec(),
            status: exchange.status(),
            response_headers: own(exchange.response_headers()),
            response_body: exchange.response_body().to_vec(),
        };

        if let Ok(mut exchanges) = self.exchanges.lock() {
            exchanges.push(recorded);
        }
    }
}

fn own(headers: &mapi_client::Headers) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

/// A fixture that has been written.
#[derive(Clone, Debug)]
pub(crate) struct Written {
    /// The file stem, which is what `MANIFEST.toml` and the replay tests refer to.
    pub(crate) stem: String,
    pub(crate) request_bytes: usize,
    pub(crate) response_bytes: usize,
    /// Placeholders written by the scrub, and how often. Never names what was replaced.
    pub(crate) redactions: Vec<(String, usize)>,
}

/// Writes a whole scenario into `directory`, replacing whatever was there.
///
/// The directory is emptied first. A scenario that used to have six exchanges and now has five
/// would otherwise keep the sixth, and a fixture nothing produces any more is a fixture nobody can
/// re-verify.
pub(crate) fn write_scenario(
    directory: &Path,
    endpoint: &str,
    exchanges: &[Recorded],
    assigned: &[ServerAssigned],
    rules: &Rules,
    keep_raw: bool,
) -> Result<Vec<Written>, Failure> {
    check_assigned(assigned)?;

    if directory.exists() {
        fs::remove_dir_all(directory)?;
    }
    fs::create_dir_all(directory)?;

    let raw_directory = directory.join("raw");
    if keep_raw {
        fs::create_dir_all(&raw_directory)?;
    }

    let mut written = Vec::with_capacity(exchanges.len());

    for (index, exchange) in exchanges.iter().enumerate() {
        let stem = stem_for(index, exchange);

        if keep_raw {
            fs::write(
                raw_directory.join(format!("{stem}.request.bin")),
                &exchange.request_body,
            )?;
            fs::write(
                raw_directory.join(format!("{stem}.response.bin")),
                &exchange.response_body,
            )?;
        }

        let mut request_body = exchange.request_body.clone();
        let mut response_body = exchange.response_body.clone();

        // Normalising comes first, and the order is load-bearing. It deletes the response's
        // auxiliary buffer outright, so scrubbing before it would count redactions inside bytes
        // that never reach the file — a `[redacted]` tally describing content the reader cannot
        // see. Worse, that buffer's contents differ on every connection, so the count would differ
        // between two captures of an unchanged server, and Verify-Fixtures.ps1 would report a
        // difference that says nothing about the protocol.
        let mut changes = normalise::response(exchange.request_type, &mut response_body);
        // After the structural normalisation and before the scrub, for the same reason the scrub
        // comes second: the auxiliary buffer is already gone, so nothing is counted inside bytes
        // that never reach the file.
        zero_assigned(&mut request_body, assigned, &mut changes);
        zero_assigned(&mut response_body, assigned, &mut changes);

        let mut redactions = rules.apply(&mut request_body);
        merge(&mut redactions, rules.apply(&mut response_body));
        // Headers and the URL carry the deployment's identity as surely as the bodies do — the
        // host name is echoed in `X-FEServer` and the mailbox GUID is in the endpoint's query
        // string — so their redactions are counted here too, not silently dropped.
        let endpoint = scrub_text(endpoint, rules, &mut redactions);
        let request_headers = normalise_headers(
            &exchange.request_headers,
            rules,
            &mut changes,
            &mut redactions,
        );
        let response_headers = normalise_headers(
            &exchange.response_headers,
            rules,
            &mut changes,
            &mut redactions,
        );

        let meta = meta::render(
            &stem,
            exchange,
            &endpoint,
            &request_headers,
            &response_headers,
            request_body.len(),
            response_body.len(),
            &changes,
            &redactions,
        );

        // Checked before anything is written, not after: a file that leaks is one somebody can
        // commit, and "I meant to delete it" is not a control. A rule that matched nothing looks
        // exactly like a rule that worked, so the only honest check is to go looking for what
        // should not be there.
        for (what, bytes) in [
            ("request body", &request_body[..]),
            ("response body", &response_body[..]),
            ("meta file", meta.as_bytes()),
        ] {
            let survived = rules.find(bytes);
            if !survived.is_empty() {
                return Err(Failure::from(format!(
                    "the {what} of {stem} still carries {} after scrubbing. Nothing was written. \
                     This is a bug in the scrub rules, not in the capture.",
                    survived.join(", ")
                )));
            }
        }

        fs::write(directory.join(format!("{stem}.request.bin")), &request_body)?;
        fs::write(
            directory.join(format!("{stem}.response.bin")),
            &response_body,
        )?;
        fs::write(directory.join(format!("{stem}.meta.txt")), meta)?;

        written.push(Written {
            stem,
            request_bytes: request_body.len(),
            response_bytes: response_body.len(),
            redactions,
        });
    }

    Ok(written)
}

/// `NN-<request type>-<label>`, or `NN-<request type>` when the label adds nothing.
fn stem_for(index: usize, exchange: &Recorded) -> String {
    let sequence = index.saturating_add(1);
    let kind = exchange.request_type.as_str().to_ascii_lowercase();
    if exchange.label.is_empty() || exchange.label == kind {
        format!("{sequence:02}-{kind}")
    } else {
        format!("{sequence:02}-{kind}-{}", exchange.label)
    }
}

/// The directory a scenario is written to, under a fixture set.
pub(crate) fn scenario_directory(root: &Path, set: &str, scenario: &str) -> PathBuf {
    root.join(set).join(scenario)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recorded(label: &str, request_type: RequestType) -> Recorded {
        Recorded {
            label: label.to_owned(),
            request_type,
            request_headers: vec![
                ("X-RequestType".to_owned(), request_type.as_str().to_owned()),
                (
                    "X-RequestId".to_owned(),
                    "{7C9E6679-7425-40DE-944B-E07FC1F90AE7}:3".to_owned(),
                ),
                (
                    "Cookie".to_owned(),
                    "MapiContext=abc-123; MapiSequence=def-456".to_owned(),
                ),
            ],
            request_body: b"/o=Dev/cn=win-m382a5je4u9".to_vec(),
            status: 200,
            response_headers: vec![
                ("X-ResponseCode".to_owned(), "0".to_owned()),
                (
                    "Set-Cookie".to_owned(),
                    "MapiContext=abc-123; path=/mapi; secure; HttpOnly".to_owned(),
                ),
                (
                    "Date".to_owned(),
                    "Sun, 02 Aug 2026 09:12:44 GMT".to_owned(),
                ),
                ("X-FEServer".to_owned(), "WIN-M382A5JE4U9".to_owned()),
            ],
            response_body: b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 5\r\n\r\n".to_vec(),
        }
    }

    fn rules() -> Rules {
        Rules::parse("text\twin-m382a5je4u9\texchange-lab-01").expect("valid rules")
    }

    fn temporary() -> PathBuf {
        let mut directory = std::env::temp_dir();
        directory.push(format!("mapi-cli-capture-{}", std::process::id()));
        directory
    }

    #[test]
    fn a_scenario_becomes_three_files_per_exchange() {
        let directory = temporary().join("scenario");
        let exchanges = vec![
            recorded("", RequestType::Ping),
            recorded("logon", RequestType::Execute),
        ];

        let written = write_scenario(
            &directory,
            "https://win-m382a5je4u9/mapi/emsmdb/",
            &exchanges,
            &[],
            &rules(),
            false,
        )
        .expect("written");

        assert_eq!(written.len(), 2);
        assert_eq!(written[0].stem, "01-ping");
        assert_eq!(written[1].stem, "02-execute-logon");

        for entry in &written {
            for suffix in ["request.bin", "response.bin", "meta.txt"] {
                let path = directory.join(format!("{}.{suffix}", entry.stem));
                assert!(path.is_file(), "{}", path.display());
            }
        }
        assert!(!directory.join("raw").exists(), "raw is opt-in");

        fs::remove_dir_all(&directory).ok();
    }

    /// Everything that identifies the lab is gone from every file, including the URL and the
    /// headers — a scrub that only covered the bodies would leave the host name in `X-FEServer`.
    #[test]
    fn nothing_identifying_survives_in_any_file() {
        let directory = temporary().join("scrubbed");
        let rules = rules();
        let exchanges = vec![recorded("connect", RequestType::Connect)];

        let written = write_scenario(
            &directory,
            "https://win-m382a5je4u9/mapi/emsmdb/?MailboxId=x@dev.local",
            &exchanges,
            &[],
            &rules,
            true,
        )
        .expect("written");

        for entry in fs::read_dir(&directory).expect("readable") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                continue; // raw/ is deliberately unscrubbed, and gitignored
            }
            let bytes = fs::read(&path).expect("readable");
            assert!(
                rules.find(&bytes).is_empty(),
                "{} still carries something",
                path.display()
            );
        }

        let meta = fs::read_to_string(directory.join("01-connect.meta.txt")).expect("a meta file");
        assert!(meta.contains("url = https://exchange-lab-01/mapi/emsmdb/"));
        assert!(meta.contains("X-FEServer: EXCHANGE-LAB-01"));
        // The report says what was written, never what was removed.
        assert!(meta.contains("text:exchange-lab-01"), "{meta}");
        assert!(!meta.contains("win-m382a5je4u9"), "{meta}");
        // The lowercase form in the request body and the URL, and the uppercase form Exchange
        // echoed in `X-FEServer` — one rule, two casings, both counted.
        assert_eq!(
            written[0].redactions.len(),
            2,
            "{:?}",
            written[0].redactions
        );

        // The raw copy is the unscrubbed original, which is why it is gitignored.
        let raw =
            fs::read(directory.join("raw").join("01-connect.request.bin")).expect("a raw copy");
        assert_eq!(raw, b"/o=Dev/cn=win-m382a5je4u9");

        fs::remove_dir_all(&directory).ok();
    }

    /// A scenario that shrinks must not leave the files it no longer produces behind.
    #[test]
    fn rewriting_a_scenario_removes_what_it_no_longer_produces() {
        let directory = temporary().join("shrinking");
        write_scenario(
            &directory,
            "https://exchange-lab-01/",
            &[
                recorded("", RequestType::Ping),
                recorded("", RequestType::Connect),
            ],
            &[],
            &rules(),
            false,
        )
        .expect("written");
        assert!(directory.join("02-connect.meta.txt").is_file());

        write_scenario(
            &directory,
            "https://exchange-lab-01/",
            &[recorded("", RequestType::Ping)],
            &[],
            &rules(),
            false,
        )
        .expect("written");
        assert!(!directory.join("02-connect.meta.txt").exists());

        fs::remove_dir_all(&directory).ok();
    }
}
