//! The whole sequence against a real Exchange Server.
//!
//! **Ignored by default, and CI never runs it.** A green CI badge on this repository means "the
//! fake server and the committed fixtures still decode"; it does not and cannot mean "verified
//! against Exchange". This file is the other half, run deliberately by whoever has a lab:
//!
//! ```powershell
//! powershell.exe -File scripts\Test-Live.ps1
//! ```
//!
//! Everything that identifies a deployment — the host, the mailbox, the credentials — arrives in
//! environment variables, so nothing about anybody's lab is committed here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "a live diagnostic is meant to be read by the person running it"
)]

use core::time::Duration;

use mapi_client::{Credentials, LegacyDn, MapiClient, PropertyTag, TableString, WellKnownFolder};

/// Reads one of the variables that describe the lab, failing with the name of the missing one.
///
/// Deliberately a hard failure rather than a skip: this test only runs when somebody asked for it
/// by name, and silently passing without contacting a server would be the worst of both worlds.
fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set. Run scripts\\Test-Live.ps1, which explains what each one is.")
    })
}

fn client() -> MapiClient {
    MapiClient::builder()
        .endpoint(required("MAPI_LIVE_ENDPOINT"))
        .user_dn(LegacyDn::new(required("MAPI_LIVE_USER_DN")).expect("a usable legacyExchangeDN"))
        .credentials(Credentials::basic(
            required("MAPI_LIVE_USERNAME"),
            required("MAPI_LIVE_PASSWORD"),
        ))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("a client")
}

/// `Connect`, `RopLogon`, both kinds of table, paging, and `Disconnect` — the whole path this
/// crate claims to implement, against a server that has never heard of it.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn the_whole_sequence_works_against_a_real_server() {
    let client = client();

    client.ping().await.expect("PING");
    println!("PING answered");

    let connection = client.connect().await.expect("Connect");
    println!(
        "connected as {:?} (polls_max {} ms, retry {}x after {} ms)",
        connection.server().display_name(),
        connection.server().polls_max(),
        connection.server().retry_count(),
        connection.server().retry_delay()
    );

    let mut logon = connection.logon().await.expect("RopLogon");
    let subtree = logon
        .folder_id(WellKnownFolder::IpmSubtree)
        .expect("the IPM subtree");
    let inbox = logon.folder_id(WellKnownFolder::Inbox).expect("an Inbox");
    println!(
        "logon returned {} folder ids",
        logon.mailbox().folder_ids().len()
    );

    // A page size of two forces the paging path: a real mailbox has more folders than that, so
    // this proves that a bound table handle keeps its column set across round trips.
    let mut rows = logon.folder(subtree).subfolders().page_size(2).rows();
    let mut folders = Vec::new();
    while let Some(row) = rows.try_next().await.expect("a page of folders") {
        let name = row
            .string(PropertyTag::DISPLAY_NAME)
            .map(TableString::as_str)
            .unwrap_or_default()
            .to_owned();
        folders.push((row.folder_id(), name));
    }
    let total = rows.row_count();
    rows.close().await.expect("releasing the table");

    let names: Vec<&str> = folders.iter().map(|(_, name)| &**name).collect();
    println!(
        "{} subfolders (server reported {total:?}): {names:?}",
        folders.len()
    );

    // By id, not by name. A mailbox's folder names are localised to the language it was
    // provisioned with — a Dutch mailbox calls its Inbox `Postvak IN` — so a test that looked for
    // "Inbox" would pass against an English mailbox and fail against every other one, which is the
    // most misleading way for a test to be wrong. The id a logon reported is the same in every
    // language, and finding it here is what proves the two agree.
    //
    // [MS-OXCSTOR] §2.2.1.1.3 — `FolderIds`
    let Some((_, inbox_name)) = folders.iter().find(|(id, _)| *id == Some(inbox)) else {
        panic!("the Inbox the logon named is not in the hierarchy: {names:?}")
    };
    println!("the Inbox in this mailbox's language is {inbox_name:?}");

    assert_eq!(total, Some(u32::try_from(folders.len()).unwrap()));

    // The contents table, read with the columns this crate defaults to.
    let messages = logon
        .well_known(WellKnownFolder::Inbox)
        .expect("the Inbox")
        .contents()
        .collect()
        .await
        .expect("the Inbox contents");

    println!("{} messages in the Inbox", messages.len());
    for row in messages.iter().take(5) {
        let subject = row.string(PropertyTag::SUBJECT);
        println!(
            "  {:?} {:?}{}",
            row.message_id(),
            subject.map(TableString::as_str),
            // The trap this crate refuses to hide: a table truncates a string at 255 characters
            // and says so nowhere except in the value's own length.
            if subject.is_some_and(TableString::is_truncated) {
                "  <- truncated by the table"
            } else {
                ""
            }
        );
    }

    logon.disconnect().await.expect("Disconnect");
    println!("disconnected");
}

/// Credentials the server will not accept must be reported as a refusal naming the schemes it
/// does accept — the diagnosis that distinguishes a wrong password from an unsupported scheme.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_wrong_password_is_reported_as_a_refusal_not_a_mystery() {
    let client = MapiClient::builder()
        .endpoint(required("MAPI_LIVE_ENDPOINT"))
        .user_dn(LegacyDn::new(required("MAPI_LIVE_USER_DN")).expect("a usable legacyExchangeDN"))
        .credentials(Credentials::basic(
            required("MAPI_LIVE_USERNAME"),
            "definitely-not-the-password",
        ))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("a client");

    let error = client
        .ping()
        .await
        .expect_err("a wrong password is refused");
    println!("{error}");
    assert!(
        matches!(error, mapi_client::Error::Unauthorized { .. }),
        "{error:?}"
    );
}
