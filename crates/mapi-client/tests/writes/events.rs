//! An appointment this crate wrote, and the update that changed it.
//!
//! Split from the draft tests for the same reason the contacts are: what makes an appointment an
//! appointment is a list of properties out of [MS-OXOCAL], and the list is longer than the code
//! around it.

use mapi_client::{
    MessageClass, NamedProperty, PropertyTag, PropertyValue, SpecialFolder, TableString,
    TaggedValue,
};

use crate::client;
use crate::writes::{MARKER, string};

/// The properties a single-instance appointment carries, against ids this store has resolved.
///
/// Hoisted out of the test because it is a transcription of [MS-OXOCAL] §2.2.1 and §2.2.2 and the
/// assertions around it are not — and because the list is what a caller would copy.
fn appointment_properties(
    named: &mapi_client::NamedProperties,
    start: mapi_client::FileTime,
    end: mapi_client::FileTime,
) -> Vec<TaggedValue> {
    let tag = |property: NamedProperty| {
        named
            .tag_of(property)
            .unwrap_or_else(|| panic!("this store maps {property}"))
    };
    let value = |property, value| TaggedValue::new(tag(property), value).expect("the right type");

    vec![
        TaggedValue::new(PropertyTag::SUBJECT, string(MARKER)).expect("a string tag"),
        TaggedValue::new(PropertyTag::START_DATE, PropertyValue::Time(start)).expect("a time tag"),
        TaggedValue::new(PropertyTag::END_DATE, PropertyValue::Time(end)).expect("a time tag"),
        value(
            NamedProperty::AppointmentStartWhole,
            PropertyValue::Time(start),
        ),
        value(NamedProperty::AppointmentEndWhole, PropertyValue::Time(end)),
        value(NamedProperty::Location, string("Lab")),
        value(NamedProperty::BusyStatus, PropertyValue::Integer32(2)),
        value(
            NamedProperty::AppointmentSubType,
            PropertyValue::Boolean(false),
        ),
        value(NamedProperty::Recurring, PropertyValue::Boolean(false)),
        value(NamedProperty::ResponseStatus, PropertyValue::Integer32(0)),
        value(
            NamedProperty::AppointmentStateFlags,
            PropertyValue::Integer32(0),
        ),
        // The five flags [MS-OXOCAL] §2.2.2.2 has every Calendar object set — `seOpenToDelete`,
        // `seOpenToCopy`, `seOpenToMove`, `seCoerceToInbox` and `seOpenForCtxMenu`. Here because
        // `mapi-cli event` sends it: a live test that wrote a shorter list than the tool does
        // would be proving the server accepts something nobody sends.
        value(NamedProperty::SideEffects, PropertyValue::Integer32(0x0561)),
    ]
}

/// A single-instance appointment, and the update that changes one.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn an_appointment_written_here_reads_back_as_one() {
    use mapi_client::{FileTime, NEW_APPOINTMENT_PROPERTIES};

    let mut logon = client()
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let calendar = logon
        .special_folder(SpecialFolder::Calendar)
        .await
        .expect("a Calendar folder");

    // Fixed instants, never "now": a test whose assertions move with the clock is a test whose
    // failures cannot be reproduced. 2026-09-10T09:00:00Z and an hour later.
    let start = FileTime::from_unix_seconds(1_789_030_800).expect("after 1601");
    let end = FileTime::from_unix_seconds(1_789_034_400).expect("after 1601");

    let named = logon
        .resolve_names(NEW_APPOINTMENT_PROPERTIES)
        .await
        .expect("the appointment properties")
        .clone();
    let tag = |property: NamedProperty| {
        named
            .tag_of(property)
            .unwrap_or_else(|| panic!("this store maps {property}"))
    };

    let saved = logon
        .folder(calendar)
        .create_message(MessageClass::Appointment)
        .set(appointment_properties(&named, start, end))
        .save()
        .await
        .expect("the appointment saves");
    assert!(
        saved.is_clean(),
        "the server refused {:?}, so this property list is not one it accepts",
        saved.problems()
    );

    // Changing an item in place is the other half of the phase, and the check that a read/write
    // open followed by a save is not a second item.
    let refused = logon
        .message(calendar, saved.id())
        .update()
        .set([
            TaggedValue::new(tag(NamedProperty::Location), string("Lab, second floor"))
                .expect("a string tag"),
        ])
        .save()
        .await
        .expect("the appointment updates");
    assert!(refused.is_empty(), "{refused:?}");

    let read_back = logon
        .message(calendar, saved.id())
        .properties()
        .read([
            PropertyTag::MESSAGE_CLASS,
            PropertyTag::SUBJECT,
            tag(NamedProperty::AppointmentStartWhole),
            tag(NamedProperty::Location),
        ])
        .await;

    let deleted = logon
        .folder(calendar)
        .delete_messages(&[saved.id()])
        .await
        .expect("the appointment deletes");
    assert!(deleted, "the appointment this test created is still there");

    let properties = read_back.expect("the appointment reads back");
    logon.disconnect().await.expect("Disconnect");

    assert_eq!(
        properties
            .string(PropertyTag::MESSAGE_CLASS)
            .map(TableString::as_str)
            .map(MessageClass::new),
        Some(MessageClass::Appointment)
    );
    assert_eq!(
        properties.get(tag(NamedProperty::AppointmentStartWhole)),
        Some(&PropertyValue::Time(start)),
        "the start time came back as it was written"
    );
    assert_eq!(
        properties
            .string(tag(NamedProperty::Location))
            .map(TableString::as_str),
        Some("Lab, second floor"),
        "the update replaced the location rather than creating a second item"
    );
    println!("the appointment round-tripped, updated location included");
}
