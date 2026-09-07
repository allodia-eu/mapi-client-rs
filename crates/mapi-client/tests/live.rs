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

use mapi_client::{
    Credentials, LegacyDn, MAILBOX_PROPERTIES, MapiClient, MapiClientBuilder, PropertyTag,
    PropertyValue, TableString, TaggedValue, WellKnownFolder,
};

// Each suite below is its own file for two reasons that apply to all of them: each asks its own
// question, and this file is at the workspace's 500-line limit.

/// The entry-id chain, the `Depth` flag and the identifier conversions — the folders `RopLogon`
/// never names.
mod folders;

/// Calendar events, contacts, a body larger than a response buffer, and both kinds of attachment.
/// The only suite that needs a mailbox seeded by `scripts\Add-LabItems.ps1`.
mod items;

/// The ids a store allocates for named properties, and what carrying one across mailboxes costs.
mod named;

/// Items this crate creates itself: a draft with an attachment, a contact, an appointment, and the
/// delete that takes each of them out again. Every test in it is self-cleaning, because the counts
/// the `items` suite asserts are exact.
mod writes;

/// Acting on an item once it exists: sending mail to the other lab mailbox, archiving a message,
/// and marking one read. Self-cleaning like `writes`, and the only suite needing two mailboxes.
mod acts;

/// A mailbox the authenticated account does not own: listing it, opening it, and the pairing
/// mistake that opening one invites. The only suite whose subject is not a ROP.
mod shared;

/// Reads one of the variables that describe the lab, failing with the name of the missing one.
///
/// Deliberately a hard failure rather than a skip: this test only runs when somebody asked for it
/// by name, and silently passing without contacting a server would be the worst of both worlds.
fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set. Run scripts\\Test-Live.ps1, which explains what each one is.")
    })
}

/// The lab client, stopping one step short of `build` so a test can add its own.
///
/// Split out because an [`Observer`](mapi_client::Observer) is a builder step and not something
/// that can be attached afterwards: a test that counts round trips has to reach the builder, and
/// the only other way to do that is to name every lab variable a second time — which is how the
/// two copies drift apart, and the copy that is wrong is the one nobody runs.
fn builder() -> MapiClientBuilder {
    MapiClient::builder()
        .endpoint(required("MAPI_LIVE_ENDPOINT"))
        .user_dn(LegacyDn::new(required("MAPI_LIVE_USER_DN")).expect("a usable legacyExchangeDN"))
        .credentials(Credentials::basic(
            required("MAPI_LIVE_USERNAME"),
            required("MAPI_LIVE_PASSWORD"),
        ))
        .timeout(LIVE_TIMEOUT)
}

fn client() -> MapiClient {
    builder().build().expect("a client")
}

/// How long a live request is given before it is called a failure.
const LIVE_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Both property-reading ROPs against a real Store object.
///
/// The two answer in different wire forms — one a row decoded against the tags of the request, the
/// other tag/value pairs read off the wire — so running both is the point rather than a
/// convenience.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn reading_store_properties_works_against_a_real_server() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");

    // Everything the store holds. This is the ROP that needs no tag list, so it is also the only
    // way to see what a deployment actually carries.
    let everything = logon
        .store()
        .read_all()
        .await
        .expect("RopGetPropertiesAll on the Logon object");
    println!(
        "RopGetPropertiesAll returned {} properties",
        everything.len()
    );

    let types: Vec<&str> = {
        let mut names: Vec<&str> = everything
            .iter()
            .filter_map(|cell| cell.tag().property_type().name())
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    };
    println!("  types present: {types:?}");

    // The named set, which is the other ROP and the other wire form.
    let named = logon
        .store()
        .read(MAILBOX_PROPERTIES)
        .await
        .expect("RopGetPropertiesSpecific on the Logon object");
    assert_eq!(
        named.len(),
        MAILBOX_PROPERTIES.len(),
        "a property fetch answers for every tag it was given, present or not"
    );

    for cell in &named {
        println!("  {} = {}", cell.tag(), cell.value());
    }
    assert!(
        named.string(PropertyTag::DISPLAY_NAME).is_some(),
        "a private mailbox logon has a display name"
    );

    // **"All" does not mean every readable property.** Measured on Exchange Server SE
    // `15.02.2562.045`: `PidTagMailboxOwnerEntryId` is absent from `RopGetPropertiesAll` and 151
    // bytes long when asked for by name. [MS-OXCPRPT] §3.2.5.2 says the server returns the values
    // for all properties *on the object*, and §3.2.5.1 says an explicit fetch returns computed
    // properties too — so a computed property is not "on the object" and only the second ROP finds
    // it. A client that dumped everything and concluded the property was unset would be wrong.
    assert!(
        everything
            .get(PropertyTag::MAILBOX_OWNER_ENTRY_ID)
            .is_none(),
        "the measurement this assertion records has changed; re-measure it rather than deleting it"
    );
    assert!(
        named
            .get(PropertyTag::MAILBOX_OWNER_ENTRY_ID)
            .and_then(PropertyValue::as_binary)
            .is_some_and(|entry_id| !entry_id.is_empty()),
        "the same property, asked for by name, is there"
    );

    logon.disconnect().await.expect("Disconnect");
}

/// Writing to a real Store object, and the report that says what did not take.
///
/// **Nothing here changes the mailbox.** [MS-OXCSTOR] §2.2.2.1.2 lists five read/write properties
/// of a private mailbox logon, and its own product-behaviour notes then say that Exchange 2013 SP1
/// and later refuse three of them — `PidTagComment` (note 14), `PidTagDeleteAfterSubmit` (15) and
/// `PidTagDisplayName` (16) — with `ecAccessDenied`. Of the remaining two, `PidTagSentMailSvrEID`
/// is a `PtypServerId`, which this crate does not model.
///
/// So the write path is exercised two ways, neither of which mutates anything: the documented
/// refusal, which is the more valuable of the two because it is the case where the ROP succeeds
/// and the property does not; and an idempotent write of `PidTagOutOfOfficeState` back to the
/// value it already holds.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn writing_a_store_property_reports_what_the_server_refused() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");

    let before = logon
        .store()
        .read([PropertyTag::COMMENT])
        .await
        .expect("reading the comment first");

    // The write the specification's own note 14 says will be refused. The ROP succeeds and the
    // property is not written, which is the failure shape a caller that only checked the ROP's
    // return value would report as a completed write.
    let refused = logon
        .store()
        .write(&[TaggedValue::new(
            PropertyTag::COMMENT,
            PropertyValue::String("mapi-client-rs live test".into()),
        )
        .expect("a string tag carrying a string")])
        .await
        .expect("RopSetProperties itself succeeds; the property inside it is what fails");

    println!(
        "setting PidTagComment reported {} problem(s)",
        refused.len()
    );
    for problem in &refused {
        println!("  {problem}");
    }
    assert_eq!(
        refused
            .iter()
            .map(|problem| problem.tag())
            .collect::<Vec<_>>(),
        vec![PropertyTag::COMMENT],
        "[MS-OXCSTOR] note 14: Exchange 2013 SP1 and later refuse this write"
    );
    assert_eq!(
        refused.first().map(|problem| problem.code()),
        Some(mapi_client::ErrorCode::ACCESS_DENIED)
    );

    let unchanged = logon
        .store()
        .read([PropertyTag::COMMENT])
        .await
        .expect("reading the comment back");
    assert_eq!(
        unchanged
            .string(PropertyTag::COMMENT)
            .map(TableString::as_str),
        before.string(PropertyTag::COMMENT).map(TableString::as_str),
        "a refused property is not written"
    );

    // `RopDeleteProperties` is decoded rather than asserted: nothing on a Logon object is both
    // deletable and of a type this crate models, so what a refusal looks like here is a
    // measurement. What is asserted is that the session survives it, which is what would break if
    // the response were read wrongly.
    let deleted = logon
        .store()
        .delete([PropertyTag::COMMENT])
        .await
        .expect("RopDeleteProperties on the Logon object");
    println!(
        "deleting PidTagComment reported {} problem(s)",
        deleted.len()
    );
    for problem in &deleted {
        println!("  {problem}");
    }

    let still_readable = logon
        .store()
        .read([PropertyTag::COMMENT])
        .await
        .expect("the session still decodes after a delete");
    assert_eq!(still_readable.len(), 1);

    logon.disconnect().await.expect("Disconnect");
}

/// A write the server does accept, made idempotent by setting the value the Store object already
/// holds — so the encoder, the ROP and the empty-problems path are all exercised and the mailbox
/// does not move.
///
/// `PidTagOutOfOfficeState` is the one read/write Store property of a type this crate models that
/// [MS-OXCSTOR] does not footnote as refused.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn an_accepted_store_write_persists_without_a_save_rop() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");

    let out_of_office = logon
        .store()
        .read([PropertyTag::OUT_OF_OFFICE_STATE])
        .await
        .expect("reading the OOF state")
        .get(PropertyTag::OUT_OF_OFFICE_STATE)
        .and_then(PropertyValue::as_bool)
        .expect("a private mailbox logon reports its OOF state");

    let problems = logon
        .store()
        .write(&[TaggedValue::new(
            PropertyTag::OUT_OF_OFFICE_STATE,
            PropertyValue::Boolean(out_of_office),
        )
        .expect("a boolean tag carrying a boolean")])
        .await
        .expect("RopSetProperties on the Logon object");
    assert!(problems.is_empty(), "{problems:?}");

    let after = logon
        .store()
        .read([PropertyTag::OUT_OF_OFFICE_STATE])
        .await
        .expect("reading the OOF state back");
    assert_eq!(
        after
            .get(PropertyTag::OUT_OF_OFFICE_STATE)
            .and_then(PropertyValue::as_bool),
        Some(out_of_office),
        "a Logon object persists a property write immediately, with no save ROP"
    );
    println!("RopSetProperties applied cleanly, OOF state still {out_of_office}");

    logon.disconnect().await.expect("Disconnect");
}

/// **The COUNT-width measurement.**
///
/// [MS-OXCDATA] contradicts itself about how wide the count in front of a `PtypMultiple` value is
/// inside a ROP buffer: §2.11.1.1 says 32 bits, §2.11.2.1 says 16. Reading the wrong one does not
/// fail — it consumes the wrong number of bytes and every column after it decodes against the
/// wrong offset — so this is settled by putting a multivalued column **before** two columns whose
/// correct values are already known, and checking that those still arrive.
///
/// `PidTagAdditionalRenEntryIds` (`PtypMultipleBinary`) is set on the Inbox of an ordinary mailbox
/// and is therefore reachable with nothing but a hierarchy table, which is why it is the one used
/// here rather than something a test would have to create.
///
/// [MS-OXCDATA] §2.11.1.1 — COUNT data type values
/// [MS-OXOSFLD] §2.2.4 — `PidTagAdditionalRenEntryIds` on the Inbox
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_multivalued_column_decodes_at_the_documented_count_width() {
    let client = client();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let subtree = logon
        .folder_id(WellKnownFolder::IpmSubtree)
        .expect("the IPM subtree");

    // The control: the same table, read without the multivalued column.
    let control: Vec<_> = logon
        .folder(subtree)
        .subfolders()
        .columns([PropertyTag::FOLDER_ID, PropertyTag::DISPLAY_NAME])
        .collect()
        .await
        .expect("a hierarchy table")
        .iter()
        .map(|row| {
            (
                row.folder_id(),
                row.string(PropertyTag::DISPLAY_NAME)
                    .map(|name| name.as_str().to_owned()),
            )
        })
        .collect();

    // The same again, with the variable-length multivalued column in front. If its COUNT were
    // read at the wrong width, the two columns after it would start at the wrong offset and the
    // ids and names below would not match the control.
    let multivalued = PropertyTag::ADDITIONAL_REN_ENTRY_IDS;
    let rows = logon
        .folder(subtree)
        .subfolders()
        .columns([
            multivalued,
            PropertyTag::FOLDER_ID,
            PropertyTag::DISPLAY_NAME,
        ])
        .collect()
        .await
        .expect("a hierarchy table with a multivalued column");

    let observed: Vec<_> = rows
        .iter()
        .map(|row| {
            (
                row.folder_id(),
                row.string(PropertyTag::DISPLAY_NAME)
                    .map(|name| name.as_str().to_owned()),
            )
        })
        .collect();
    assert_eq!(
        observed, control,
        "a column after the multivalued one moved, so its COUNT was read at the wrong width"
    );

    let values: Vec<(&str, usize, usize)> = rows
        .iter()
        .filter_map(|row| {
            let name = row.string(PropertyTag::DISPLAY_NAME)?.as_str();
            match row.get(multivalued)? {
                PropertyValue::MultipleBinary(values) => {
                    Some((name, values.len(), values.iter().map(Vec::len).sum()))
                }
                _ => None,
            }
        })
        .collect();

    println!("PidTagAdditionalRenEntryIds, by folder: {values:?}");
    assert!(
        !values.is_empty(),
        "no folder in this mailbox carries the property this test measures"
    );
    assert!(
        values.iter().any(|(_, count, _)| *count > 1),
        "a single-element list would not tell a 16-bit count from a 32-bit one"
    );

    logon.disconnect().await.expect("Disconnect");
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
        .timeout(LIVE_TIMEOUT)
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
