//! The follow-up flag: setting one, marking it complete, and taking it off.
//!
//! Its own file because it is a property list rather than an operation, and the list is the whole
//! of the work. [MS-OXOFLAG] §3.1.4.1.1 names seven properties for a colour flag and §3.1.4.1.4
//! names thirteen for a complete one; a message carrying some of them is a message whose flag
//! renders differently in every client that reads it, and a message whose `PidTagFlagStatus` says
//! `followupComplete` while `PidLidTaskComplete` is still false reads as done in one pane of a
//! client and as outstanding in another.
//!
//! So the lists are here, in full, with the section that justifies each entry — rather than inside
//! a crate, which would be taking positions the document leaves to the client.
//!
//! [MS-OXOFLAG] §3.1.4.1 — flagging a Message object
//! [MS-OXOFLAG] §3.1.4.2 — clearing a flag

use mapi_client::{
    COMPLETE_FLAG_PROPERTIES, FOLLOW_UP_PROPERTIES, FileTime, FlagStatus, Floating64, FollowupIcon,
    MessageId, NamedProperty, PropertyTag, PropertyValue, TaggedValue,
};

use super::now_unix;
use crate::Failure;
use crate::command::writes::{string, tag_of};
use crate::command::{parse_hexadecimal, resolve};
use crate::settings::Connection;

/// `PidLidToDoItemFlags`: `todoTimeFlagged`, which is the bit a time or complete flag sets.
///
/// [MS-OXOFLAG] §2.2.1.6
const TODO_TIME_FLAGGED: u32 = 0x0000_0001;

/// `PidLidTaskStatus`: `tsComplete`. [MS-OXOTASK] §2.2.2.2.3
const TASK_COMPLETE: u32 = 0x0000_0002;

/// `PidLidTaskStatus`: `tsNotStarted`, which is what clearing a flag puts back.
const TASK_NOT_STARTED: u32 = 0x0000_0000;

/// `PidLidToDoSubOrdinal`, which breaks a tie between two items flagged in the same instant.
///
/// Empty rather than computed: [MS-OXOFLAG] §2.2.1.14 leaves the algorithm to the client, and a
/// tool that flags one message at a time has no ties to break.
const NO_SUB_ORDINAL: &str = "";

/// Set or clear a follow-up flag.
pub(crate) async fn flag(
    connection: &Connection,
    folder: &str,
    id: &str,
    text: &str,
    colour: Option<&str>,
    complete: bool,
    clear: bool,
) -> Result<(), Failure> {
    let colour = colour.map(parse_colour).transpose()?;
    let client = connection.client()?;
    let mut logon = client.connect().await?.logon().await?;
    let folder_id = resolve(&mut logon, folder).await?;
    let message = MessageId::new(parse_hexadecimal(id, "a message id")?);

    // Clearing needs the same list completing does, and for a reason worth stating: [MS-OXOFLAG]
    // §3.1.4.2.3's table sets the four task properties back rather than deleting them, so a clear
    // has to be able to name them even on a message that was only ever flagged, not completed.
    let wanted = if complete || clear {
        &COMPLETE_FLAG_PROPERTIES[..]
    } else {
        &FOLLOW_UP_PROPERTIES[..]
    };
    let named = logon.register_names(wanted.iter().copied()).await?.clone();
    let tag = |property| tag_of(&named, property);

    // The moment the flag was set, which every client uses to order a consolidated to-do list —
    // and, for a completed one, the moment it was finished. There is no clock in `mapi-proto`, so
    // it comes from here.
    let now = FileTime::from_unix_seconds(now_unix()?)
        .ok_or_else(|| Failure::from("the system clock is before 1601".to_owned()))?;

    let (values, removed) = if clear {
        (clearing(&tag)?, cleared_away(&tag)?)
    } else if complete {
        (completing(&tag, text, now)?, Vec::new())
    } else {
        (flagging(&tag, text, colour)?, Vec::new())
    };

    let problems = logon
        .folder(folder_id)
        .message(message)
        .update()
        .set(values)
        .delete(removed)
        .save()
        .await?;

    let what = if clear {
        "cleared the flag on"
    } else if complete {
        "marked the flag complete on"
    } else {
        "flagged"
    };
    println!("{what} {:#018x} in {folder}", message.as_u64());
    if let Some(colour) = colour {
        println!("  colour {colour} (PidTagFollowupIcon {})", colour.as_u32());
    }
    for problem in &problems {
        println!("  the server refused {problem}");
    }
    if problems.is_empty() {
        println!("  every property was accepted");
    }

    logon.disconnect().await?;
    Ok(())
}

/// The properties [MS-OXOFLAG] §3.1.4.1.1 sets for a colour flag, minus the two the named-property
/// catalogue explains are deliberately absent.
///
/// `PidTagFollowupIcon` is the only optional one: without it the flag has no colour, which
/// §3.1.4.1.2 calls a basic flag.
fn flagging(
    tag: &impl Fn(NamedProperty) -> Result<PropertyTag, Failure>,
    text: &str,
    colour: Option<FollowupIcon>,
) -> Result<Vec<TaggedValue>, Failure> {
    let mut values = vec![
        TaggedValue::new(
            PropertyTag::FLAG_STATUS,
            PropertyValue::Integer32(FlagStatus::Flagged.as_u32()),
        )?,
        TaggedValue::new(tag(NamedProperty::FlagRequest)?, string(text))?,
        TaggedValue::new(PropertyTag::REPLY_REQUESTED, PropertyValue::Boolean(true))?,
        TaggedValue::new(
            PropertyTag::RESPONSE_REQUESTED,
            PropertyValue::Boolean(true),
        )?,
    ];
    if let Some(colour) = colour {
        values.push(TaggedValue::new(
            PropertyTag::FOLLOWUP_ICON,
            PropertyValue::Integer32(colour.as_u32()),
        )?);
    }
    Ok(values)
}

/// The properties [MS-OXOFLAG] §3.1.4.1.4 sets for a complete flag.
///
/// The four task properties are not decoration: a message whose `PidTagFlagStatus` says
/// `followupComplete` while `PidLidTaskComplete` is still false reads as done in one pane of a
/// client and as outstanding in another.
fn completing(
    tag: &impl Fn(NamedProperty) -> Result<PropertyTag, Failure>,
    text: &str,
    now: FileTime,
) -> Result<Vec<TaggedValue>, Failure> {
    Ok(vec![
        TaggedValue::new(
            PropertyTag::FLAG_STATUS,
            PropertyValue::Integer32(FlagStatus::Complete.as_u32()),
        )?,
        // The one property in this crate with a resolution constraint: [MS-OXOFLAG] §2.2.1.3
        // requires a whole number of minutes, which a FILETIME taken from a clock is not.
        TaggedValue::new(
            PropertyTag::FLAG_COMPLETE_TIME,
            PropertyValue::Time(now.to_whole_minutes()),
        )?,
        TaggedValue::new(
            PropertyTag::TODO_ITEM_FLAGS,
            PropertyValue::Integer32(TODO_TIME_FLAGGED),
        )?,
        TaggedValue::new(PropertyTag::REPLY_REQUESTED, PropertyValue::Boolean(false))?,
        TaggedValue::new(
            PropertyTag::RESPONSE_REQUESTED,
            PropertyValue::Boolean(false),
        )?,
        TaggedValue::new(tag(NamedProperty::FlagRequest)?, string(text))?,
        TaggedValue::new(tag(NamedProperty::ToDoTitle)?, string(text))?,
        TaggedValue::new(
            tag(NamedProperty::ToDoOrdinalDate)?,
            PropertyValue::Time(now),
        )?,
        TaggedValue::new(tag(NamedProperty::ToDoSubOrdinal)?, string(NO_SUB_ORDINAL))?,
        TaggedValue::new(
            tag(NamedProperty::TaskStatus)?,
            PropertyValue::Integer32(TASK_COMPLETE),
        )?,
        TaggedValue::new(
            tag(NamedProperty::TaskComplete)?,
            PropertyValue::Boolean(true),
        )?,
        TaggedValue::new(
            tag(NamedProperty::PercentComplete)?,
            PropertyValue::Floating64(Floating64::new(1.0)),
        )?,
        TaggedValue::new(
            tag(NamedProperty::TaskDateCompleted)?,
            PropertyValue::Time(now),
        )?,
    ])
}

/// What [MS-OXOFLAG] §3.1.4.2.3 *sets* when a flag is cleared, as against what it deletes.
///
/// The section has the properties that were set for the flag deleted "with the following
/// exceptions", and these are the exceptions — each with the value the table gives it. Everything
/// else goes through [`cleared_away`], and both travel in one round trip.
///
/// `PidTagFlagStatus` is the one place this departs from the table, which does not name it and so
/// would have it deleted. It is written as `0x00000000` because [MS-OXOFLAG] §2.2.1.1 documents
/// that value, and because a client whose *own* reader treats the property's absence as "not
/// flagged" gets the same answer either way while a store that keeps the zero stays readable by
/// one that does not.
fn clearing(
    tag: &impl Fn(NamedProperty) -> Result<PropertyTag, Failure>,
) -> Result<Vec<TaggedValue>, Failure> {
    Ok(vec![
        TaggedValue::new(
            PropertyTag::FLAG_STATUS,
            PropertyValue::Integer32(FlagStatus::NotFlagged.as_u32()),
        )?,
        // Bit-for-bit this should clear only todoTimeFlagged and todoRecipientFlagged: §2.2.1.6
        // requires every other bit to be ignored *and preserved*. Zero is right here only because
        // this tool sets no other bit, and a client that did would have to read before writing.
        TaggedValue::new(
            PropertyTag::TODO_ITEM_FLAGS,
            PropertyValue::Integer32(0x0000_0000),
        )?,
        TaggedValue::new(PropertyTag::REPLY_REQUESTED, PropertyValue::Boolean(false))?,
        TaggedValue::new(
            PropertyTag::RESPONSE_REQUESTED,
            PropertyValue::Boolean(false),
        )?,
        TaggedValue::new(tag(NamedProperty::FlagRequest)?, string(""))?,
        TaggedValue::new(tag(NamedProperty::ToDoSubOrdinal)?, string(""))?,
        TaggedValue::new(
            tag(NamedProperty::TaskStatus)?,
            PropertyValue::Integer32(TASK_NOT_STARTED),
        )?,
        TaggedValue::new(
            tag(NamedProperty::TaskComplete)?,
            PropertyValue::Boolean(false),
        )?,
        TaggedValue::new(
            tag(NamedProperty::PercentComplete)?,
            PropertyValue::Floating64(Floating64::new(0.0)),
        )?,
    ])
}

/// How a property set answers "is this flagged, and is the flag done".
///
/// Absent is the third answer and the commonest one: [MS-OXOFLAG] §2.2.1.1 has `PidTagFlagStatus`
/// present only on a flagged message, so a fetch of an ordinary one comes back with nothing here.
pub(super) fn status_of(properties: &mapi_client::PropertySet) -> String {
    let status = properties
        .get(PropertyTag::FLAG_STATUS)
        .and_then(PropertyValue::as_u32)
        .map(FlagStatus::new);
    let colour = properties
        .get(PropertyTag::FOLLOWUP_ICON)
        .and_then(PropertyValue::as_u32)
        .map(FollowupIcon::new);

    match (status, colour) {
        (None, _) => "not set, which is the absence of the property rather than a zero".to_owned(),
        // A zero is what a clear leaves behind here, and it means the same as absent. Reporting the
        // colour alongside it would read as a flag that is somehow both off and red.
        (Some(FlagStatus::NotFlagged), _) => {
            "not flagged (the property is present and zero)".to_owned()
        }
        (Some(status), None) => format!("{status}, no colour — a basic flag"),
        (Some(status), Some(colour)) => format!("{status}, {colour}"),
    }
}

/// What clearing a flag *deletes*, which [MS-OXOFLAG] §3.1.4.2.3 asks for and no value can do.
///
/// The three the exception table does not name. Leaving them behind is the failure this exists to
/// prevent, and it is visible rather than subtle: a message with `PidTagFlagStatus` zero and
/// `PidTagFollowupIcon` still red reads as "not flagged, red", which is what `mapi-cli state`
/// printed before this list was here.
///
/// [MS-OXOFLAG] §2.2.1.3 — `PidTagFlagCompleteTime` exists only while the flag is complete
fn cleared_away(
    tag: &impl Fn(NamedProperty) -> Result<PropertyTag, Failure>,
) -> Result<Vec<PropertyTag>, Failure> {
    Ok(vec![
        PropertyTag::FOLLOWUP_ICON,
        PropertyTag::FLAG_COMPLETE_TIME,
        tag(NamedProperty::ToDoTitle)?,
        tag(NamedProperty::TaskDateCompleted)?,
    ])
}

/// Turns `--colour red` into the value `PidTagFollowupIcon` carries.
fn parse_colour(value: &str) -> Result<FollowupIcon, Failure> {
    let wanted = value.trim().to_ascii_lowercase();
    FollowupIcon::ALL
        .into_iter()
        .find(|colour| colour.name() == Some(wanted.as_str()))
        .ok_or_else(|| {
            Failure::from(format!(
                "`{value}` is not a flag colour. [MS-OXOFLAG] §2.2.1.2 names six: {}",
                FollowupIcon::ALL
                    .into_iter()
                    .filter_map(FollowupIcon::name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_colour_parses_from_its_name_and_says_what_the_names_are() {
        assert_eq!(parse_colour("red").unwrap(), FollowupIcon::Red);
        assert_eq!(parse_colour("  Purple ").unwrap(), FollowupIcon::Purple);

        let refused = parse_colour("chartreuse").expect_err("not a flag colour");
        assert!(refused.to_string().contains("purple"), "{refused}");
        assert!(refused.to_string().contains("red"), "{refused}");
    }

    /// The clock feeds `PidTagFlagCompleteTime`, whose value [MS-OXOFLAG] §2.2.1.3 requires to be a
    /// whole number of minutes. A `FILETIME` taken from a clock never is.
    #[test]
    fn a_completion_time_is_truncated_to_the_minute_the_document_requires() {
        let at = FileTime::from_unix_seconds(1_789_030_845).expect("after 1601");
        let minute = at.to_whole_minutes();
        assert_eq!(minute.to_unix_seconds(), Some(1_789_030_800));
        assert_eq!(minute.to_whole_minutes(), minute);
    }

    /// Absent is the third answer to "is this flagged", and the commonest — so it has to read as an
    /// answer rather than as a value the tool failed to fetch.
    #[test]
    fn an_unflagged_message_reads_as_unflagged_rather_than_as_nothing() {
        let none = mapi_client::PropertySet::default();
        assert!(status_of(&none).contains("not set"));
    }
}
