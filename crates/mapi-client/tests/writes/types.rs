//! Properties asked for without a type, and under the placeholder type: what Exchange answers each
//! with, read back from a draft this test writes and deletes.
//!
//! Measured on Exchange Server SE `15.02.2562.056`, which answers the first read in a standard row
//! and the last in a flagged one, so both of the shapes a typed value can take are read here.
//!
//! [MS-OXCDATA] §2.8.1 — `PropertyRow` structures
//! [MS-OXCDATA] §2.11.1 — `PtypUnspecified`, `PtypNull`

use mapi_client::{
    ErrorCode, MessageClass, PropertyTag, PropertyType, PropertyValue, SpecialFolder, TableString,
    TaggedValue,
};

use super::{MARKER, string};
use crate::client;

const UNSPECIFIED_SUBJECT: PropertyTag = PropertyTag::new(0x0037_0000);
const UNSPECIFIED_FLAGS: PropertyTag = PropertyTag::new(0x0E07_0000);
const NULL_SUBJECT: PropertyTag = PropertyTag::new(0x0037_0001);
/// A property no draft has, asked for without a type.
const UNSPECIFIED_ABSENT: PropertyTag = PropertyTag::new(0x6FFE_0000);

#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_property_asked_for_without_a_type_arrives_in_its_own() {
    let mut logon = client()
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let drafts = logon
        .special_folder(SpecialFolder::Drafts)
        .await
        .expect("a Drafts folder");
    let subject = format!("{MARKER}: untyped");
    let id = logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([TaggedValue::new(PropertyTag::SUBJECT, string(&subject)).expect("a string tag")])
        .save()
        .await
        .expect("the draft saves")
        .id();

    // Each read on its own: a flagged row and a standard one are the server's choice per row, and
    // which one each request earns is part of what is measured.
    let mut read = Vec::new();
    for tags in [
        &[UNSPECIFIED_SUBJECT, UNSPECIFIED_FLAGS][..],
        &[NULL_SUBJECT],
        &[UNSPECIFIED_SUBJECT, UNSPECIFIED_ABSENT],
    ] {
        read.push(
            logon
                .message(drafts, id)
                .properties()
                .read(tags.iter().copied())
                .await,
        );
    }
    let deleted = logon.folder(drafts).delete_messages(&[id]).await;
    logon.disconnect().await.expect("Disconnect");
    assert!(
        deleted.expect("the draft deletes"),
        "the draft is still in Drafts"
    );

    let read: Vec<_> = read
        .into_iter()
        .map(|set| set.expect("the properties read"))
        .collect();
    for set in &read {
        for cell in set.cells() {
            println!("  {cell}");
        }
    }

    // Reported under the type each arrived in, so the usual tags find them.
    let typed = &read[0];
    assert_eq!(
        typed.string(PropertyTag::SUBJECT),
        Some(&TableString::from(subject.as_str()))
    );
    assert!(matches!(
        typed.get(PropertyTag::MESSAGE_FLAGS),
        Some(PropertyValue::Integer32(_))
    ));

    // PtypNull is a type like any other to the server, and a subject is not one.
    assert_eq!(
        read[1].get(NULL_SUBJECT).and_then(PropertyValue::as_error),
        Some(ErrorCode::NOT_FOUND)
    );

    // A property that is not there still arrives with a type, which is PtypErrorCode.
    let absent = &read[2];
    let cell = absent
        .cells()
        .iter()
        .find(|cell| cell.tag().id() == UNSPECIFIED_ABSENT.id())
        .expect("a cell for the absent property");
    assert_eq!(cell.tag().property_type(), PropertyType::ErrorCode);
    assert_eq!(cell.value().as_error(), Some(ErrorCode::NOT_FOUND));
}
