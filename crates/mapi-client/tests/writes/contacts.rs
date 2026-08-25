//! Contacts this crate wrote, and the identifier that makes one usable.
//!
//! Split from the draft tests because a contact's difficulty is entirely in its properties: half of
//! them are named, and one of those is a `PidLidEmail1OriginalEntryId` that has to be a well-formed
//! one-off entry id or the address is something a client can display and not send to.

use mapi_client::{
    MessageClass, NEW_CONTACT_PROPERTIES, NamedProperty, OneOffEntryId, PropertyTag, PropertyValue,
    SpecialFolder, TableString, TaggedValue,
};

use crate::client;
use crate::writes::{MARKER, string};

/// A contact, with the one-off entry id that makes its address usable rather than merely visible.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_contact_written_here_carries_a_usable_address() {
    let mut logon = client()
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let contacts = logon
        .special_folder(SpecialFolder::Contacts)
        .await
        .expect("a Contacts folder");

    let address = "probe@example.test";
    let one_off = OneOffEntryId::smtp(address, address).expect("an address with no NUL in it");
    let named = logon
        .resolve_names(NEW_CONTACT_PROPERTIES)
        .await
        .expect("the contact properties")
        .clone();
    let tag = |property: NamedProperty| {
        named
            .tag_of(property)
            .unwrap_or_else(|| panic!("this store maps {property}"))
    };

    let saved = logon
        .folder(contacts)
        .create_message(MessageClass::Contact)
        .set([
            TaggedValue::new(PropertyTag::DISPLAY_NAME, string(MARKER)).expect("a string tag"),
            TaggedValue::new(PropertyTag::GIVEN_NAME, string("Probe")).expect("a string tag"),
            TaggedValue::new(PropertyTag::SURNAME, string("Contact")).expect("a string tag"),
            TaggedValue::new(tag(NamedProperty::Email1EmailAddress), string(address))
                .expect("a string tag"),
            TaggedValue::new(tag(NamedProperty::Email1AddressType), string("SMTP"))
                .expect("a string tag"),
            TaggedValue::new(tag(NamedProperty::Email1DisplayName), string(MARKER))
                .expect("a string tag"),
            TaggedValue::new(
                tag(NamedProperty::Email1OriginalDisplayName),
                string(address),
            )
            .expect("a string tag"),
            TaggedValue::new(
                tag(NamedProperty::Email1OriginalEntryId),
                PropertyValue::Binary(one_off.to_bytes()),
            )
            .expect("a binary tag"),
            TaggedValue::new(tag(NamedProperty::FileUnder), string("Contact, Probe"))
                .expect("a string tag"),
        ])
        .save()
        .await
        .expect("the contact saves");

    let read_back = logon
        .message(contacts, saved.id())
        .properties()
        .read([
            PropertyTag::MESSAGE_CLASS,
            PropertyTag::DISPLAY_NAME,
            tag(NamedProperty::Email1EmailAddress),
            tag(NamedProperty::Email1OriginalEntryId),
        ])
        .await;

    let deleted = logon
        .folder(contacts)
        .delete_messages(&[saved.id()])
        .await
        .expect("the contact deletes");
    assert!(deleted, "the contact this test created is still there");

    let properties = read_back.expect("the contact reads back");
    logon.disconnect().await.expect("Disconnect");

    let class = properties
        .string(PropertyTag::MESSAGE_CLASS)
        .map(TableString::as_str)
        .map(MessageClass::new);
    assert_eq!(class, Some(MessageClass::Contact));
    assert_eq!(
        properties
            .string(tag(NamedProperty::Email1EmailAddress))
            .map(TableString::as_str),
        Some(address)
    );

    // The identifier is the point. It came back as bytes, and those bytes have to parse as the
    // one-off that was written — which is what proves the flag word's byte order, on a value the
    // server stored and handed back rather than one this crate built for itself.
    let stored = properties
        .get(tag(NamedProperty::Email1OriginalEntryId))
        .and_then(PropertyValue::as_binary)
        .expect("PidLidEmail1OriginalEntryId came back");
    assert_eq!(stored, one_off.to_bytes());
    assert_eq!(
        OneOffEntryId::parse(stored).expect("the server's own bytes"),
        one_off
    );
    println!("the contact's address survived as {one_off}");
}

/// The one-off entry id this crate writes is the one Exchange writes.
///
/// The evidence for [MS-OXCDATA] §2.2.5.1's flag word being big-endian, taken from a contact
/// `scripts\Add-LabItems.ps1` seeded **through EWS** — so the bytes are the server's own and not
/// something this crate produced and then agreed with.
#[tokio::test]
#[ignore = "needs a live Exchange Server seeded by scripts\\Add-LabItems.ps1"]
async fn the_server_writes_the_one_off_identifier_this_crate_writes() {
    let mut logon = client()
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let contacts = logon
        .special_folder(SpecialFolder::Contacts)
        .await
        .expect("a Contacts folder");

    let named = logon
        .resolve_names(NEW_CONTACT_PROPERTIES)
        .await
        .expect("the contact properties")
        .clone();
    let address_tag = named
        .tag_of(NamedProperty::Email1EmailAddress)
        .expect("this store maps PidLidEmail1EmailAddress");
    let entry_id_tag = named
        .tag_of(NamedProperty::Email1OriginalEntryId)
        .expect("this store maps PidLidEmail1OriginalEntryId");

    let rows = logon
        .folder(contacts)
        .contents()
        .columns([PropertyTag::MID, address_tag])
        .collect()
        .await
        .expect("a contacts table");

    let mut compared = 0_usize;
    for row in &rows {
        let (Some(id), Some(address)) = (
            mapi_client::PropertyRow::message_id(row),
            row.string(address_tag).map(TableString::as_str),
        ) else {
            continue;
        };
        if address.is_empty() {
            continue;
        }

        let properties = logon
            .message(contacts, id)
            .properties()
            .read([entry_id_tag])
            .await
            .expect("the contact's original entry id");
        let Some(stored) = properties
            .get(entry_id_tag)
            .and_then(PropertyValue::as_binary)
        else {
            continue;
        };

        // EWS names the address entry after the address itself, which is what the display name in
        // the identifier then is. Both halves are compared, so a server that chose otherwise fails
        // here rather than being papered over.
        let expected = OneOffEntryId::smtp(address, address).expect("an address with no NUL in it");
        assert_eq!(
            stored,
            expected.to_bytes(),
            "the server's identifier for {address} is not the one this crate writes"
        );
        compared = compared.saturating_add(1);
    }

    logon.disconnect().await.expect("Disconnect");
    assert!(
        compared > 0,
        "no contact in this mailbox has an address to compare. Run scripts\\Add-LabItems.ps1."
    );
    println!("{compared} seeded contact(s) carry the identifier this crate writes");
}
