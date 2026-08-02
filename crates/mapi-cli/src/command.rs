//! What each subcommand does.
//!
//! Every one of these is an ordinary use of `mapi-client` with nothing stubbed, which is the
//! property that makes this binary worth having: what it prints is what the library saw.

use mapi_client::{EmailAddress, FolderId, Logon, PropertyTag, WellKnownFolder};

use crate::settings::Connection;
use crate::{Failure, report};

/// Is the endpoint there, and do the credentials work?
pub(crate) async fn ping(connection: &Connection) -> Result<(), Failure> {
    let client = connection.client()?;
    client.ping().await?;
    println!("PING answered by {}", client.endpoint());
    Ok(())
}

/// Establish a Session Context and report what the server said.
pub(crate) async fn connect(connection: &Connection) -> Result<(), Failure> {
    let client = connection.client()?;
    let session = client.connect().await?;
    let server = session.server();

    println!("connected to {}", client.endpoint());
    println!("  mailbox owner  {}", server.display_name());
    println!("  DN prefix      {}", server.dn_prefix());
    println!("  polls max      {} ms", server.polls_max());
    println!(
        "  retry advice   {} attempts, {} ms apart",
        server.retry_count(),
        server.retry_delay()
    );

    let logon = session.logon().await?;
    let mailbox = logon.mailbox();
    println!("  mailbox GUID   {}", mailbox.mailbox_guid());
    println!("  replica id     {}", mailbox.replica_id().as_u16());
    println!("  special folders");
    for folder in WellKnownFolder::ALL {
        match mailbox.folder(folder) {
            Some(id) => println!("    {:<16} {:#018x}", folder.name(), id.as_u64()),
            None => println!("    {:<16} (absent)", folder.name()),
        }
    }

    logon.disconnect().await?;
    Ok(())
}

/// Walk a folder's hierarchy table.
pub(crate) async fn folders(
    connection: &Connection,
    folder: &str,
    page_size: u16,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let id = resolve(&logon, folder)?;

    println!("subfolders of {folder} ({:#018x})", id.as_u64());
    let mut rows = logon.folder(id).subfolders().page_size(page_size).rows();
    let mut seen = 0_usize;
    while let Some(row) = rows.try_next().await? {
        println!("{}", report::folder_line(&row));
        seen = seen.saturating_add(1);
    }
    let reported = rows.row_count();
    rows.close().await?;

    summarise(seen, reported);
    logon.disconnect().await?;
    Ok(())
}

/// Read a folder's contents table.
pub(crate) async fn messages(
    connection: &Connection,
    folder: &str,
    page_size: u16,
    limit: usize,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let id = resolve(&logon, folder)?;

    println!("contents of {folder} ({:#018x})", id.as_u64());
    let mut rows = logon.folder(id).contents().page_size(page_size).rows();
    let mut seen = 0_usize;
    let mut truncated = 0_usize;
    while let Some(row) = rows.try_next().await? {
        if seen < limit {
            println!("{}", report::message_line(&row));
        }
        if row
            .string(PropertyTag::SUBJECT)
            .is_some_and(mapi_client::TableString::is_truncated)
        {
            truncated = truncated.saturating_add(1);
        }
        seen = seen.saturating_add(1);
    }
    let reported = rows.row_count();
    rows.close().await?;

    if seen > limit {
        println!(
            "  ... {} more row(s) read but not shown",
            seen.saturating_sub(limit)
        );
    }
    summarise(seen, reported);
    if truncated > 0 {
        println!(
            "  {truncated} subject(s) were truncated by the table at 255 characters — the full \
             value is only available by opening the message"
        );
    }

    logon.disconnect().await?;
    Ok(())
}

/// Ask Autodiscover where a mailbox lives.
pub(crate) async fn discover(connection: &Connection, address: &str) -> Result<(), Failure> {
    let address = EmailAddress::new(address)?;
    let endpoint = connection.base()?.lookup(&address).await?;

    println!("Autodiscover found {address}");
    println!(
        "  MailStore URL   {}",
        endpoint.mail_store_url().unwrap_or("(none offered)")
    );
    println!(
        "  AddressBook URL {}",
        endpoint.address_book_url().unwrap_or("(none offered)")
    );
    println!("  LegacyDN        {}", endpoint.legacy_dn());
    println!();
    println!("Use both of the first and third verbatim:");
    println!(
        "  --endpoint '{}'",
        endpoint.mail_store_url().unwrap_or_default()
    );
    println!("  --user-dn  '{}'", endpoint.legacy_dn());

    Ok(())
}

/// Turns a folder argument into an id: a well-known name, or a raw id in hexadecimal.
fn resolve(logon: &Logon, folder: &str) -> Result<FolderId, Failure> {
    if let Some(hexadecimal) = folder
        .strip_prefix("0x")
        .or_else(|| folder.strip_prefix("0X"))
    {
        let raw = u64::from_str_radix(hexadecimal, 16)
            .map_err(|_| Failure::from(format!("`{folder}` is not a folder id")))?;
        return Ok(FolderId::new(raw));
    }

    let wanted = folder.trim().to_ascii_lowercase();
    for candidate in WellKnownFolder::ALL {
        if slug(candidate.name()) == wanted {
            return Ok(logon.folder_id(candidate)?);
        }
    }

    Err(Failure::from(format!(
        "`{folder}` is not a folder. Give a folder id as `0x...`, or one of: {}",
        WellKnownFolder::ALL
            .map(|folder| slug(folder.name()))
            .join(", ")
    )))
}

/// `IPM subtree` becomes `ipm-subtree`, so a folder can be named on a command line.
fn slug(name: &str) -> String {
    name.to_ascii_lowercase().replace(' ', "-")
}

/// Reports how many rows arrived against how many the server said there were.
///
/// A table is a live view of a folder, so the two disagreeing is a measurement rather than a bug —
/// but it is worth seeing rather than hiding.
fn summarise(seen: usize, reported: Option<u32>) {
    match reported {
        Some(count) if usize::try_from(count).is_ok_and(|count| count == seen) => {
            println!("  {seen} row(s)");
        }
        Some(count) => {
            println!("  {seen} row(s) read, server reported {count} when the table opened");
        }
        None => println!("  {seen} row(s), server reported no count"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_folders_have_command_line_names() {
        assert_eq!(slug("IPM subtree"), "ipm-subtree");
        assert_eq!(slug("Inbox"), "inbox");
        assert_eq!(slug("Deleted Items"), "deleted-items");

        // Every one of the thirteen is reachable by name, and no two share one.
        let names: Vec<String> = WellKnownFolder::ALL.map(|f| slug(f.name())).to_vec();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "{names:?}");
    }
}
