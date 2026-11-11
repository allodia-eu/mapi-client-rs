//! Writing a scenario out: the files, the scrub, and what a re-capture removes.

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
        request_body: b"/o=Lab/cn=mail-host-0815a".to_vec(),
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
            ("X-FEServer".to_owned(), "MAIL-HOST-0815A".to_owned()),
        ],
        response_body: b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 5\r\n\r\n".to_vec(),
    }
}

fn rules() -> Rules {
    Rules::parse("text\tmail-host-0815a\texchange-lab-01").expect("valid rules")
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
        "https://mail-host-0815a/mapi/emsmdb/",
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
        "https://mail-host-0815a/mapi/emsmdb/?MailboxId=x@lab.local",
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
    assert!(!meta.contains("mail-host-0815a"), "{meta}");
    // The lowercase form in the request body and the URL, and the uppercase form Exchange
    // echoed in `X-FEServer` — one rule, two casings, both counted.
    assert_eq!(
        written[0].redactions.len(),
        2,
        "{:?}",
        written[0].redactions
    );

    // The raw copy is the unscrubbed original, which is why it is gitignored.
    let raw = fs::read(directory.join("raw").join("01-connect.request.bin")).expect("a raw copy");
    assert_eq!(raw, b"/o=Lab/cn=mail-host-0815a");

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
