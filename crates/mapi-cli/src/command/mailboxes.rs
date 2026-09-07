//! Listing the mailboxes an account can open, and opening them.
//!
//! The one requested operation with no ROP behind it. Everything else this tool does is a verb the
//! mailbox server understands; this is a question only Autodiscover can answer, which is why it
//! needs no `--endpoint` and no `--user-dn`.
//!
//! [MS-OXDSCLI] §2.2.4.1.1.2.5 — `AlternativeMailbox`

use mapi_client::{EmailAddress, Mailbox, MapiClient, WellKnownFolder};

use crate::Failure;
use crate::settings::Connection;

/// List every mailbox these credentials can open, and optionally log on to each.
pub(crate) async fn mailboxes(
    connection: &Connection,
    address: &str,
    open: bool,
) -> Result<(), Failure> {
    let address = EmailAddress::new(address)?;
    let found = connection.base()?.mailboxes(&address).await?;

    let alternatives = found.iter().filter(|mailbox| !mailbox.is_own()).count();
    println!("Autodiscover named {alternatives} alternative mailbox(es) for {address}");
    if alternatives > 0 {
        // Worth printing rather than assuming: [MS-OXDSCLI] §2.2.4.1.1.2.5.2 offers a LegacyDN
        // that would make this one lookup, and Exchange sends an address instead.
        println!(
            "  {} lookups: one for the account and one per alternative, because Exchange names \
             each alternative by address rather than by distinguished name",
            alternatives.saturating_add(1)
        );
    }
    println!();

    // One client for the deployment, re-aimed per mailbox. Sharing it is the point rather than an
    // economy: `X-ClientInfo` is a GUID per client instance with a counter per Session Context,
    // and two mailboxes opened by one program are one instance with two contexts.
    // [MS-OXCMAPIHTTP] §2.2.3.3.4
    let root = found
        .iter()
        .find(|mailbox| mailbox.is_own() && mailbox.is_openable())
        .map(|mailbox| client_for(connection, mailbox))
        .transpose()?;

    for mailbox in &found {
        describe(mailbox);
        if open {
            match root.as_ref() {
                Some(root) => report_logon(root, mailbox).await,
                None => println!("  not opened: the account's own mailbox offered no endpoint"),
            }
        }
        println!();
    }

    if !open && alternatives > 0 {
        println!(
            "Pass --open to log on to each. A listing proves the deployment names them; only a \
             logon proves this account may open one, because the access check is the server's and \
             happens at Connect."
        );
    }
    Ok(())
}

/// What Autodiscover said about one mailbox.
fn describe(mailbox: &Mailbox) {
    let kind = mailbox
        .kind()
        .map_or_else(|| "own mailbox".to_owned(), ToString::to_string);

    println!(
        "{} [{kind}]",
        mailbox.display_name().unwrap_or("(no display name)")
    );
    println!(
        "  address    {}",
        mailbox.smtp_address().unwrap_or("(none given)")
    );

    match (mailbox.endpoint(), mailbox.user_dn()) {
        (Some(endpoint), Some(user_dn)) => {
            println!("  endpoint   {endpoint}");
            println!("  LegacyDN   {}", user_dn.as_str());
        }
        // The directory form of [MS-OXDSCLI] §2.2.4.1.1.2.5.2. A server's name is not a
        // ?MailboxId=, and the account's own endpoint is not a substitute for one: that pairing is
        // refused at logon rather than at Connect.
        _ => println!(
            "  cannot be opened: the server named a LegacyDN and a Server rather than an \
             SmtpAddress, and a MAPI/HTTP endpoint needs the ?MailboxId= only a lookup by address \
             produces"
        ),
    }
}

/// Log on to one mailbox and report what came back, which is the only proof of access there is.
async fn report_logon(root: &MapiClient, mailbox: &Mailbox) {
    if !mailbox.is_openable() {
        return;
    }

    match open_and_read(root, mailbox).await {
        Ok(report) => println!("  opened     {report}"),
        // A refusal here is a measurement rather than a crash: a mailbox the deployment auto-maps
        // and this account may not open is what a revoked permission looks like from outside, and
        // it must not stop the mailboxes after it being listed.
        Err(failure) => println!("  refused    {failure}"),
    }
}

/// One `Connect`, one `RopLogon`, one contents-table read, and a `Disconnect`.
async fn open_and_read(root: &MapiClient, mailbox: &Mailbox) -> Result<String, Failure> {
    let session = root.for_mailbox(mailbox)?.connect().await?;
    let owner = session.server().display_name().to_owned();
    let mut logon = session.logon().await?;

    let inbox = logon.folder_id(WellKnownFolder::Inbox)?;
    let count = logon.folder(inbox).contents().collect().await?.len();

    logon.disconnect().await?;
    Ok(format!("as {owner}, whose Inbox holds {count} message(s)"))
}

/// A client aimed at one mailbox, carrying everything the command line asked for.
fn client_for(connection: &Connection, mailbox: &Mailbox) -> Result<MapiClient, Failure> {
    let endpoint = mailbox
        .endpoint()
        .ok_or_else(|| Failure::from("the mailbox named no endpoint".to_owned()))?;
    let user_dn = mailbox
        .user_dn()
        .ok_or_else(|| Failure::from("the mailbox named no distinguished name".to_owned()))?;

    Ok(connection
        .base()?
        .endpoint(endpoint)
        .user_dn(user_dn.clone())
        .build()?)
}
