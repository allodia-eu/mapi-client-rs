//! What each subcommand does.
//!
//! Every one of these is an ordinary use of `mapi-client` with nothing stubbed, which is the
//! property that makes this binary worth having: what it prints is what the library saw.

mod acts;
mod items;
mod writes;

use std::collections::HashMap;

pub(crate) use acts::{flag, mark, move_messages, send, state};
pub(crate) use items::{contacts, events, message, messages};
use mapi_client::{
    ContainerClass, EmailAddress, FOLDER_PROPERTIES, FolderId, Logon, NamedProperty,
    NamedPropertyEntry, NamedPropertyId, PropertyName, PropertyRow, PropertyTag, PropertyValue,
    SpecialFolder, SpecialFolderState, TableString, WellKnownFolder,
};
pub(crate) use writes::{contact, delete, draft, event};

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
    recursive: bool,
    class: Option<&str>,
) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let id = resolve(&mut logon, folder).await?;
    let wanted = class.map(ContainerClass::new);

    println!(
        "{} {folder} ({:#018x})",
        if recursive {
            "every folder below"
        } else {
            "subfolders of"
        },
        id.as_u64()
    );

    let read = logon.folder(id);
    let table = if recursive {
        read.descendants()
    } else {
        read.subfolders()
    };
    let mut rows = table.page_size(page_size).rows();

    let mut all = Vec::new();
    while let Some(row) = rows.try_next().await? {
        all.push(row);
    }
    let reported = rows.row_count();
    rows.close().await?;

    // With `Depth` set the rows arrive flat, so the depth of each is worked out here from the
    // parent ids the same read carried. Without that a recursive listing is a bag of names.
    let depths = depths(&all, id);
    let mut shown = 0_usize;
    for row in &all {
        let class_of = row
            .string(PropertyTag::CONTAINER_CLASS)
            .map(TableString::as_str)
            .map(ContainerClass::new);
        if let Some(wanted) = &wanted
            && !class_of.is_some_and(|found| found.is_a(wanted))
        {
            continue;
        }
        let depth = row.folder_id().and_then(|id| depths.get(&id)).copied();
        println!("{}", report::folder_line(row, depth.unwrap_or(0)));
        shown = shown.saturating_add(1);
    }

    if wanted.is_some() {
        println!(
            "  {shown} of {} folder(s) match; a class matches its own refinements, so IPF.Contact \
             finds IPF.Contact.MOC.QuickContacts too",
            all.len()
        );
    }
    summarise(all.len(), reported);
    logon.disconnect().await?;
    Ok(())
}

/// How far below `root` each folder sits, from the parent ids in the same read.
///
/// A folder whose parent is not in the table — which is every row of a non-recursive read — sits at
/// depth zero, so the same routine serves both kinds of listing.
fn depths(rows: &[PropertyRow], root: FolderId) -> HashMap<FolderId, usize> {
    let parents: HashMap<FolderId, FolderId> = rows
        .iter()
        .filter_map(|row| {
            let id = row.folder_id()?;
            let parent = row
                .get(PropertyTag::PARENT_FOLDER_ID)
                .and_then(PropertyValue::as_u64)
                .map(FolderId::new)?;
            Some((id, parent))
        })
        .collect();

    parents
        .keys()
        .map(|id| {
            let mut depth = 0_usize;
            let mut walk = *id;
            // Bounded by the number of folders, so a parent cycle costs one pass and not a hang.
            while let Some(parent) = parents.get(&walk).filter(|parent| **parent != root) {
                depth = depth.saturating_add(1);
                walk = *parent;
                if depth >= parents.len() {
                    break;
                }
            }
            (*id, depth)
        })
        .collect()
}

/// Find the folders the logon does not name, and say what each one is.
pub(crate) async fn special(connection: &Connection, details: bool) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let mailbox_guid = logon.mailbox().mailbox_guid();

    let special = logon.special_folders().await?;
    println!("special folders, from the entry ids on the Inbox");
    println!("  mailbox {mailbox_guid}");
    for entry in &special {
        println!("  {:<10} {}", entry.folder(), entry.state());
        if let SpecialFolderState::Found { entry_id, .. } = entry.state() {
            println!("             long-term {}", entry_id.long_term_id());
            if !entry_id.belongs_to(mailbox_guid) {
                println!(
                    "             ^ issued by {}, not this mailbox — converting it would open a \
                     folder in another store",
                    entry_id.provider_uid()
                );
            }
        }
    }
    println!(
        "  {} of {} present",
        special.found(),
        SpecialFolder::ALL.len()
    );

    if details {
        for entry in &special {
            let Some(id) = entry.id() else { continue };
            println!();
            println!("{} ({:#018x})", entry.folder(), id.as_u64());
            let properties = logon
                .folder(id)
                .properties()
                .read(FOLDER_PROPERTIES)
                .await?;
            println!("{}", report::folder_summary(&properties));
        }
    }

    logon.disconnect().await?;
    Ok(())
}

/// Ask what this store calls each named property, then ask it back the other way.
///
/// The round trip *back* is the point. A `RopGetPropertyIdsFromNames` response is a bare array of
/// numbers whose only claim to meaning is the order the server put them in; feeding each one to
/// `RopGetNamesFromPropertyIds` and checking that the name that comes back is the name that went in
/// is the only independent evidence that the pairing is right.
pub(crate) async fn named(
    connection: &Connection,
    verify: bool,
    ids: &[String],
) -> Result<(), Failure> {
    let foreign = ids
        .iter()
        .map(|id| parse_property_id(id))
        .collect::<Result<Vec<_>, Failure>>()?;
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let mailbox_guid = logon.mailbox().mailbox_guid();

    let resolved = logon.resolve_names(NamedProperty::ALL).await?;
    let entries: Vec<NamedPropertyEntry> = resolved.iter().cloned().collect();
    let mapped = resolved.mapped();

    println!("named properties, as this store numbers them");
    println!("  mailbox {mailbox_guid}");
    for (property, entry) in NamedProperty::ALL.into_iter().zip(&entries) {
        println!(
            "  {:<28} {:<22} {}",
            property,
            entry
                .id()
                .map_or_else(|| "not mapped".to_owned(), |id| id.to_string()),
            property.property_type()
        );
    }
    println!(
        "  {mapped} of {} mapped. These ids are this mailbox's own: the same number means a \
         different property in another store.",
        entries.len()
    );

    if verify {
        verify_ids(&mut logon, &entries).await?;
    }

    if !foreign.is_empty() {
        println!();
        println!("what this store calls the ids you named");
        for (id, name) in foreign.iter().zip(logon.names_of(&foreign).await?) {
            println!(
                "  0x{id:04X} -> {}",
                name.map_or_else(
                    || "no name in this store".to_owned(),
                    |name| name.to_string()
                )
            );
        }
        println!(
            "  An id resolved against another mailbox is a number, not a property. Whatever came \
             back above is what reading with it would actually have read."
        );
    }

    logon.disconnect().await?;
    Ok(())
}

/// Turns a `0x8186` argument into a property id.
fn parse_property_id(id: &str) -> Result<u16, Failure> {
    let hexadecimal = id
        .strip_prefix("0x")
        .or_else(|| id.strip_prefix("0X"))
        .ok_or_else(|| Failure::from(format!("`{id}` is not a property id; write it as 0x...")))?;

    u16::from_str_radix(hexadecimal, 16)
        .map_err(|_| Failure::from(format!("`{id}` is not a property id; write it as 0x...")))
}

/// Asks the store what each resolved id is called, and reports any that answered something else.
async fn verify_ids(logon: &mut Logon, entries: &[NamedPropertyEntry]) -> Result<(), Failure> {
    let asked: Vec<(&PropertyName, NamedPropertyId)> = entries
        .iter()
        .filter_map(|entry| Some((entry.name(), entry.id()?)))
        .collect();
    let ids: Vec<u16> = asked.iter().map(|(_, id)| id.as_u16()).collect();
    let answered = logon.names_of(&ids).await?;

    println!();
    println!("what the store says those ids are");
    let mut disagreed = 0_usize;
    for (index, (wanted, id)) in asked.iter().enumerate() {
        let back = answered.get(index).and_then(Option::as_ref);
        let agrees = back == Some(*wanted);
        if !agrees {
            disagreed = disagreed.saturating_add(1);
        }
        println!(
            "  {id} {} {}",
            if agrees { "->" } else { "!!" },
            back.map_or_else(|| "no name in this store".to_owned(), ToString::to_string)
        );
    }

    if disagreed > 0 {
        return Err(Failure::from(format!(
            "{disagreed} id(s) came back as a different property than the one they were resolved \
             for. Either the response ordering is not what [MS-OXCPRPT] §2.2.12.2 requires, or \
             this client paired them wrongly."
        )));
    }
    println!("  every id round-trips to the name it was resolved for");
    Ok(())
}

/// Dump the Store object's properties — what the mailbox knows about itself.
///
/// With no tags this is `RopGetPropertiesAll`, which names nothing and gets everything. That is
/// also the useful diagnostic: it is the only way to see what a deployment actually holds, as
/// against what [MS-OXCSTOR] §2.2.2.1 says it should.
pub(crate) async fn properties(connection: &Connection, tags: &[String]) -> Result<(), Failure> {
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;

    let properties = if tags.is_empty() {
        logon.store().read_all().await?
    } else {
        let wanted = tags
            .iter()
            .map(|tag| parse_tag(tag))
            .collect::<Result<Vec<_>, Failure>>()?;
        logon.store().read(wanted).await?
    };

    println!("mailbox");
    println!("{}", report::mailbox_summary(&properties));

    println!();
    println!("{} properties on the Store object", properties.len());
    for cell in &properties {
        println!("{}", report::property_line(cell));
    }

    let refused = properties
        .iter()
        .filter(|cell| cell.value().as_error().is_some())
        .count();
    let named = properties
        .iter()
        .filter(|cell| cell.tag().is_named())
        .count();
    if refused > 0 {
        println!("  {refused} of them came back as an error rather than a value");
    }
    if named > 0 {
        println!(
            "  {named} named-property id(s), which are allocated per store and mean nothing in \
             another mailbox"
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

/// Turns a `0x...` argument into the number it names.
fn parse_hexadecimal(value: &str, what: &str) -> Result<u64, Failure> {
    let hexadecimal = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| Failure::from(format!("`{value}` is not {what}; write it as 0x...")))?;

    u64::from_str_radix(hexadecimal, 16)
        .map_err(|_| Failure::from(format!("`{value}` is not {what}; write it as 0x...")))
}

/// A folder id given directly, for the commands that do not take a well-known name.
fn parse_folder_id(folder: &str) -> Result<FolderId, Failure> {
    parse_hexadecimal(folder, "a folder id").map(FolderId::new)
}

/// Turns a folder argument into an id: a well-known name, a special-folder name, or a raw id.
///
/// The three are not equivalent, and what each costs is the reason to say so here. A well-known
/// name is free — the logon reported its id. A special-folder name costs two round trips, because
/// Calendar, Contacts and Drafts live behind entry-id properties on the Inbox and an entry id has
/// to be converted before `RopOpenFolder` will take it. A raw id costs nothing and is meaningful
/// only in the mailbox it came from.
///
/// [MS-OXOSFLD] §2.2.3 — where the special folders' entry ids live
async fn resolve(logon: &mut Logon, folder: &str) -> Result<FolderId, Failure> {
    if folder.starts_with("0x") || folder.starts_with("0X") {
        return parse_folder_id(folder);
    }

    let wanted = folder.trim().to_ascii_lowercase();
    for candidate in WellKnownFolder::ALL {
        if slug(candidate.name()) == wanted {
            return Ok(logon.folder_id(candidate)?);
        }
    }
    for candidate in SpecialFolder::ALL {
        if slug(candidate.name()) == wanted {
            return Ok(logon.special_folder(candidate).await?);
        }
    }

    Err(Failure::from(format!(
        "`{folder}` is not a folder. Give a folder id as `0x...`, or one of: {}, {}",
        WellKnownFolder::ALL
            .map(|folder| slug(folder.name()))
            .join(", "),
        SpecialFolder::ALL
            .map(|folder| slug(folder.name()))
            .join(", ")
    )))
}

/// Turns a `0x3001001F` argument into a tag.
///
/// Written the way the documents write it — id first, type second — because that is the form every
/// specification, every property list and every other tool uses, and reversing it here would be a
/// trap laid for whoever copies a constant out of [MS-OXPROPS].
fn parse_tag(tag: &str) -> Result<PropertyTag, Failure> {
    let hexadecimal = tag
        .strip_prefix("0x")
        .or_else(|| tag.strip_prefix("0X"))
        .ok_or_else(|| {
            Failure::from(format!("`{tag}` is not a property tag; write it as 0x..."))
        })?;

    u32::from_str_radix(hexadecimal, 16)
        .map(PropertyTag::new)
        .map_err(|_| Failure::from(format!("`{tag}` is not a property tag; write it as 0x...")))
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

    /// Tags are written id-first, as every specification writes them. The little-endian encoding
    /// of that `u32` is the wire form, which is the opposite order — and getting the two confused
    /// asks the server for a property nobody meant.
    #[test]
    fn a_property_tag_is_parsed_the_way_the_documents_write_it() {
        let tag = parse_tag("0x3001001F").expect("a display-name tag");
        assert_eq!(tag, PropertyTag::DISPLAY_NAME);
        assert_eq!(tag.id(), 0x3001);
        assert_eq!(parse_tag("0X3001001f").unwrap(), PropertyTag::DISPLAY_NAME);

        for bad in ["3001001F", "0xZZ", "0x1_2", ""] {
            assert!(parse_tag(bad).is_err(), "{bad} was accepted");
        }
    }

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
