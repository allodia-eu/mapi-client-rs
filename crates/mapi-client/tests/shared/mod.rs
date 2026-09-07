//! Opening a mailbox the authenticated account does not own.
//!
//! Its own file because it is its own question, and because it is the only suite here whose subject
//! is not a ROP: `Connect` and `RopLogon` are unchanged, and all of the new work happens in
//! Autodiscover and in which endpoint the pair is aimed at.
//!
//! What it needs from the lab is a **shared mailbox** with `FullAccess` granted to the mailbox
//! being run as, with automapping on — which is what makes Exchange name it in an
//! `AlternativeMailbox` element. `scripts\Initialize-ExchangeLab.ps1 -SharedMailbox shared` sets
//! that up and `scripts\Test-Live.ps1` passes the variables.

use mapi_client::{
    Credentials, EmailAddress, Error, LegacyDn, MailboxKind, MapiClient, WellKnownFolder,
};

use super::{LIVE_TIMEOUT, builder, client, required};

/// The lab's Autodiscover service, taken from the host already in `MAPI_LIVE_ENDPOINT`.
///
/// **Why `mailboxes_at` rather than `mailboxes` here**, which is a fact about lab certificates and
/// not about this client: [MS-OXDISCO] §3.1.5.2's candidate sequence asks `dev.local` and
/// `autodiscover.dev.local`, and a lab certificate issued for the machine name alone matches
/// neither — so every candidate fails its TLS handshake, is skipped as "did not answer", and the
/// documented sequence finds nothing on a deployment that works perfectly well. Naming the service
/// directly is exactly what that method is for. A deployment with a certificate covering its own
/// mail domain needs none of this.
fn autodiscover_url() -> String {
    let endpoint = required("MAPI_LIVE_ENDPOINT");
    let host = endpoint
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .expect("MAPI_LIVE_ENDPOINT is an absolute URL");
    format!("https://{host}/Autodiscover/Autodiscover.xml")
}

/// The shared mailbox's address, or `None` if this lab has none.
///
/// Optional rather than required, unlike everything else here: a lab can be perfectly good and
/// have no shared mailbox, and failing the whole suite over one would make the rest harder to run
/// rather than easier. The tests that need it say so by name.
fn shared_address() -> Option<String> {
    std::env::var("MAPI_LIVE_SHARED_ADDRESS").ok()
}

/// The address the run is authenticating as, which is also the one to list mailboxes for.
fn own_address() -> EmailAddress {
    EmailAddress::new(required("MAPI_LIVE_USERNAME")).expect("a usable email address")
}

/// The whole of "list mailboxes", against a deployment that has one to list.
///
/// **Two things are asserted here that no offline fixture can assert**, because both are facts
/// about a live deployment rather than about bytes: that Exchange names an alternative mailbox at
/// all once one is shared, and that the endpoint it resolves to is a *different* one from the
/// account's own.
#[tokio::test]
#[ignore = "needs a live Exchange Server and a shared mailbox; run scripts\\Test-Live.ps1"]
async fn a_shared_mailbox_is_listed_alongside_the_accounts_own() {
    let Some(shared) = shared_address() else {
        panic!(
            "MAPI_LIVE_SHARED_ADDRESS is not set. This test needs a shared mailbox with \
             FullAccess granted to this one and automapping on, because that is what makes \
             Exchange name it. scripts\\Initialize-ExchangeLab.ps1 -SharedMailbox creates one."
        );
    };

    let mailboxes = builder()
        .mailboxes_at(autodiscover_url(), &own_address())
        .await
        .expect("Autodiscover described the account");

    println!("  {} mailbox(es) listed", mailboxes.len());
    for mailbox in &mailboxes {
        println!(
            "    {:<20} {:?}  {}",
            mailbox.display_name().unwrap_or("(no name)"),
            mailbox.kind(),
            mailbox.smtp_address().unwrap_or("(no address)")
        );
    }

    let own = mailboxes.first().expect("the account's own mailbox");
    assert!(own.is_own(), "the account's own mailbox is listed first");
    assert!(own.is_openable());

    let listed = mailboxes
        .iter()
        .find(|mailbox| mailbox.smtp_address() == Some(shared.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "the shared mailbox {shared} was not named. Is FullAccess granted with \
                 -AutoMapping $true? Without automapping Exchange grants the access and does not \
                 advertise it, which is a permission this client can use and cannot discover."
            )
        });

    // A shared mailbox arrives as a Delegate: [MS-OXDSCLI] §2.2.4.1.1.2.5.5 has no separate value
    // for one, and "owned by another user" is what a shared mailbox is.
    assert_eq!(listed.kind(), Some(&MailboxKind::Delegate));
    assert!(
        listed.is_openable(),
        "Exchange named it by address, so a second lookup resolved it"
    );

    // The measurement the whole design rests on: a different mailbox is a different endpoint.
    assert_ne!(
        listed.endpoint(),
        own.endpoint(),
        "the ?MailboxId= selects the mailbox, so the two cannot share an endpoint"
    );
    assert_ne!(listed.user_dn(), own.user_dn());
}

/// Opening it, which is the only thing that proves the access rather than the advertisement.
///
/// The `Connect` authenticates as the original account throughout — there is no second credential
/// anywhere in this test — and the server does the access check.
#[tokio::test]
#[ignore = "needs a live Exchange Server and a shared mailbox; run scripts\\Test-Live.ps1"]
async fn a_shared_mailbox_can_be_read_on_the_accounts_own_credentials() {
    let Some(shared) = shared_address() else {
        panic!("MAPI_LIVE_SHARED_ADDRESS is not set; see the test above");
    };

    let mailboxes = builder()
        .mailboxes_at(autodiscover_url(), &own_address())
        .await
        .expect("Autodiscover described the account");
    let listed = mailboxes
        .iter()
        .find(|mailbox| mailbox.smtp_address() == Some(shared.as_str()))
        .expect("the shared mailbox is listed");

    // Re-aimed rather than rebuilt, which is what a caller holding both mailboxes open would do.
    let session = client()
        .for_mailbox(listed)
        .expect("the shared mailbox resolved to an endpoint and a name")
        .connect()
        .await
        .expect("Connect, authenticating as the original account");

    println!(
        "  Connect reports the owner as {}",
        session.server().display_name()
    );

    let mut logon = session
        .logon()
        .await
        .expect("RopLogon on the shared mailbox");
    let inbox = logon
        .folder_id(WellKnownFolder::Inbox)
        .expect("a private-mailbox logon names the Inbox");

    // A folder read is what makes this a session rather than a handshake: a logon that answered
    // and a table that will not is the shape a permissions problem takes.
    let rows = logon
        .folder(inbox)
        .contents()
        .collect()
        .await
        .expect("the shared mailbox's Inbox is readable");
    println!("  its Inbox holds {} message(s)", rows.len());

    logon.disconnect().await.expect("Disconnect");
}

/// **The trap this phase exists to remove.** One mailbox's endpoint with another's distinguished
/// name is not refused where a reader would look for the refusal.
///
/// `Connect` succeeds and reports the *other* mailbox's owner, so a client that stopped there would
/// report having opened a mailbox it has not. The `RopLogon` in the next request is what refuses,
/// with `ecWrongServer` and a redirect naming a server rather than a mailbox.
///
/// [MS-OXCSTOR] §2.2.1.1.2 — `RopLogon` redirect response buffer
#[tokio::test]
#[ignore = "needs a live Exchange Server and a shared mailbox; run scripts\\Test-Live.ps1"]
async fn the_accounts_own_endpoint_will_not_serve_another_mailboxs_name() {
    let Some(shared) = shared_address() else {
        panic!("MAPI_LIVE_SHARED_ADDRESS is not set; see the test above");
    };

    let mailboxes = builder()
        .mailboxes_at(autodiscover_url(), &own_address())
        .await
        .expect("Autodiscover described the account");
    let listed = mailboxes
        .iter()
        .find(|mailbox| mailbox.smtp_address() == Some(shared.as_str()))
        .expect("the shared mailbox is listed");
    let user_dn = listed.user_dn().expect("it resolved to a name").clone();

    // Deliberately the wrong pairing: this account's endpoint, the shared mailbox's name.
    let wrong = MapiClient::builder()
        .endpoint(required("MAPI_LIVE_ENDPOINT"))
        .user_dn(LegacyDn::new(user_dn.as_str()).expect("a usable legacyExchangeDN"))
        .credentials(Credentials::basic(
            required("MAPI_LIVE_USERNAME"),
            required("MAPI_LIVE_PASSWORD"),
        ))
        .timeout(LIVE_TIMEOUT)
        .build()
        .expect("a client");

    let session = wrong
        .connect()
        .await
        .expect("Connect accepts a name this endpoint does not serve");
    println!(
        "  Connect succeeded and reported the owner as {}",
        session.server().display_name()
    );

    let error = session
        .logon()
        .await
        .expect_err("the logon is where the mismatch is caught");
    println!("  and the logon refused it: {error}");

    match error {
        Error::WrongServer { server_name } => assert!(
            server_name.contains("cn=Servers/"),
            "the redirect names a server DN: {server_name}"
        ),
        other => panic!("expected a logon redirect, got {other:?}"),
    }
}
