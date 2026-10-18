use super::*;
use crate::error::{Error, ErrorCode};
use crate::ics::GlobCnt;
use crate::oxcdata::{Guid, PropertyName, PropertySetId};

mod example;
mod recovery;

use example::EXAMPLE;

/// Feeds a whole stream, `chunk` bytes at a time, and collects every event.
fn events_of(stream: &[u8], chunk: usize) -> Vec<SyncEvent> {
    let mut sync = ContentsSync::new();
    let mut events = Vec::new();
    for piece in stream.chunks(chunk) {
        sync.feed(piece);
        while let Some(event) = sync.next_event().unwrap() {
            events.push(event);
        }
    }
    sync.finish().unwrap();
    events
}

/// The GLOBCNT of a MID: its last six wire bytes, most significant first.
fn counter(id: u64) -> u64 {
    let [_, _, b0, b1, b2, b3, b4, b5] = id.to_le_bytes();
    u64::from_be_bytes([0, 0, b0, b1, b2, b3, b4, b5])
}

fn subject(content: &MessageContent) -> String {
    content
        .property(PropertyTag::SUBJECT)
        .and_then(PropertyValue::as_string)
        .unwrap()
        .as_str()
        .to_owned()
}

/// [MS-OXCFXICS] §4.5, every byte of it: the events come out in the order its outline lists, and
/// each carries what its table says.
#[test]
fn the_documents_example_stream_reads_as_its_outline_says() {
    let events = events_of(&EXAMPLE, EXAMPLE.len());
    let kinds: Vec<&str> = events
        .iter()
        .map(|event| match event {
            SyncEvent::Progress(_) => "progress",
            SyncEvent::Message(_) => "message",
            SyncEvent::Deletions(_) => "deletions",
            SyncEvent::ReadStates(_) => "read states",
            SyncEvent::State(_) => "state",
            SyncEvent::End => "end",
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "progress",
            "message",
            "deletions",
            "read states",
            "state",
            "end"
        ]
    );

    let SyncEvent::Message(change) = &events[1] else {
        panic!("the outline fixes this event's kind")
    };
    assert!(!change.is_partial());
    assert_eq!(change.announced(), Some((56, false)));
    let header = change.header();
    assert_eq!(header.source_key().len(), 22);
    assert!(!header.is_associated());
    assert_eq!(counter(header.id().unwrap().as_u64()), 0x78_2E21);
    assert_eq!(
        header.change_number().unwrap().counter().as_u64(),
        0x78_4D1C
    );

    let content = change.content();
    assert!(subject(content).starts_with("Test"));
    assert_eq!(content.recipients().len(), 1);
    assert_eq!(
        content.recipients()[0].first().map(StreamProperty::tag),
        Some(PropertyTag::ROW_ID),
        "PidTagRowid comes first in a recipient"
    );
    let [attachment] = content.attachments() else {
        panic!("one attachment")
    };
    assert_eq!(attachment.number(), 0);
    let embedded = attachment.embedded().expect("an embedded message");
    assert_eq!(subject(embedded), "Test 1");
    assert_eq!(embedded.recipients().len(), 1);

    let SyncEvent::Deletions(deletions) = &events[2] else {
        panic!("the outline fixes this event's kind")
    };
    let deleted: Vec<u64> = deletions
        .deleted()
        .message_ids()
        .map(|id| counter(id.as_u64()))
        .collect();
    assert_eq!(deleted, [0x78_2E23]);

    let SyncEvent::ReadStates(read) = &events[3] else {
        panic!("the outline fixes this event's kind")
    };
    assert_eq!(
        read.marked_read()
            .message_ids()
            .map(|id| counter(id.as_u64()))
            .collect::<Vec<_>>(),
        [0x78_2E1F]
    );
    assert_eq!(
        read.marked_unread()
            .message_ids()
            .map(|id| counter(id.as_u64()))
            .collect::<Vec<_>>(),
        [0x78_2E20]
    );

    let SyncEvent::State(state) = &events[4] else {
        panic!("the outline fixes this event's kind")
    };
    let replica = Guid::from_bytes([
        0x19, 0xD7, 0xFB, 0x0F, 0x06, 0x16, 0xA1, 0x41, 0xBF, 0xF6, 0x91, 0xC7, 0x63, 0xDA, 0xA8,
        0x66,
    ]);
    assert!(
        state
            .cnset_seen()
            .contains(replica, GlobCnt::from_u64(0x78_4D1D).unwrap())
    );
    assert!(
        state
            .idset_given()
            .contains(replica, GlobCnt::from_u64(0x78_2E22).unwrap())
    );
    assert!(!state.cnset_read().is_empty());
}

/// The server may split a stream at any point inside a value, so the same events come out however
/// the bytes are cut — including one byte at a time.
#[test]
fn the_example_reads_the_same_however_it_is_split() {
    let whole = events_of(&EXAMPLE, EXAMPLE.len());
    for chunk in [1, 2, 3, 7, 64, 1000] {
        assert_eq!(events_of(&EXAMPLE, chunk), whole, "{chunk}-byte buffers");
    }
}

#[test]
fn a_stream_that_ends_early_is_reported_at_the_end() {
    let mut sync = ContentsSync::new();
    sync.feed(&EXAMPLE[..EXAMPLE.len() - 4]);
    while sync.next_event().unwrap().is_some() {}
    assert!(!sync.is_finished());
    assert!(matches!(
        sync.finish(),
        Err(Error::MalformedFastTransfer { .. })
    ));
}

/// A stream assembled element by element, for the cases the document's example does not cover.
#[derive(Default)]
struct Stream(Vec<u8>);

impl Stream {
    fn marker(mut self, marker: Marker) -> Self {
        self.0.extend_from_slice(&marker.as_u32().to_le_bytes());
        self
    }

    fn u32(mut self, tag: PropertyTag, value: u32) -> Self {
        self.0.extend_from_slice(&tag.as_u32().to_le_bytes());
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn u64(mut self, tag: PropertyTag, value: u64) -> Self {
        self.0.extend_from_slice(&tag.as_u32().to_le_bytes());
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn binary(mut self, tag: PropertyTag, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(&tag.as_u32().to_le_bytes());
        self.0
            .extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_le_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    fn string(self, tag: PropertyTag, text: &str) -> Self {
        let mut bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        bytes.extend_from_slice(&[0, 0]);
        self.binary(tag, &bytes)
    }

    /// A message change header with a source key and a MID and CN whose counters are `n`.
    fn header(self, n: u8) -> Self {
        self.binary(PropertyTag::SOURCE_KEY, &[n; 22])
            .u64(
                PropertyTag::MID,
                u64::from_le_bytes([1, 0, 0, 0, 0, 0, 0, n]),
            )
            .u64(
                PropertyTag::CHANGE_NUMBER,
                u64::from_le_bytes([1, 0, 0, 0, 0, 0, 1, n]),
            )
    }

    fn full_change(self, n: u8, subject: &str) -> Self {
        self.marker(Marker::IncrSyncChange)
            .header(n)
            .marker(Marker::IncrSyncMessage)
            .string(PropertyTag::SUBJECT, subject)
    }

    fn end(self) -> Vec<u8> {
        self.marker(Marker::IncrSyncStateBegin)
            .marker(Marker::IncrSyncStateEnd)
            .marker(Marker::IncrSyncEnd)
            .0
    }
}

fn messages(events: &[SyncEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            SyncEvent::Message(change) => Some(subject(change.content())),
            _ => None,
        })
        .collect()
}

/// `errorInfo` part way through a message: what came of the message is dropped, the failure is
/// reported with the message it names, and the next message is read as usual.
///
/// [MS-OXCFXICS] §2.2.4.3.4 — unwind to the closest element that supports recovery
#[test]
fn an_object_the_server_could_not_produce_is_reported_and_stepped_over() {
    let mut info = vec![0, 0, 0, 0];
    info.extend_from_slice(&0x8004_0102_u32.to_le_bytes());
    info.extend_from_slice(&[0; 22 + 2]);
    // The failing message's GID: the source key `header(2)` gives the interrupted change.
    info.extend_from_slice(&[2; 22]);
    info.extend_from_slice(&[0, 0]);
    info.extend_from_slice(&[0; 24]);
    info.extend_from_slice(&[0; 8]);

    let stream = Stream::default()
        .full_change(1, "first")
        .marker(Marker::IncrSyncChange)
        .header(2)
        .marker(Marker::IncrSyncMessage)
        .marker(Marker::ErrorInfo)
        .binary(PropertyTag::new(0x0000_0102), &info)
        .full_change(3, "third")
        .end();
    let events = events_of(&stream, 5);

    assert_eq!(messages(&events), ["first", "third"]);
    let failed = events
        .iter()
        .find_map(|event| match event {
            SyncEvent::Failed(info) => Some(info),
            _ => None,
        })
        .expect("the failure is reported");
    assert_eq!(failed.code(), ErrorCode::new(0x8004_0102));
    assert_eq!(failed.folder(), None);
    assert_eq!(
        failed.message(),
        Some((Guid::from_bytes([2; 16]), GlobCnt::from_bytes([2; 6])))
    );
}

/// An error about an object the server never began arrives straight after one that was whole —
/// and that one is delivered, because the error names something else.
#[test]
fn an_error_about_another_object_does_not_cost_the_one_before_it() {
    let mut info = vec![0, 0, 0, 0];
    info.extend_from_slice(&0x8004_0102_u32.to_le_bytes());
    info.extend_from_slice(&[0; 22 + 2]);
    info.extend_from_slice(&[9; 22]);
    info.extend_from_slice(&[0; 2 + 24 + 8]);

    let stream = Stream::default()
        .full_change(1, "first")
        .marker(Marker::ErrorInfo)
        .binary(PropertyTag::new(0x0000_0102), &info)
        .full_change(3, "third")
        .end();
    assert_eq!(messages(&events_of(&stream, 7)), ["first", "third"]);
}

/// A message whose elements do not fit the grammar is reported with its header and stepped over.
#[test]
fn a_message_that_does_not_fit_the_grammar_costs_only_itself() {
    let stream = Stream::default()
        .full_change(1, "first")
        // No IncrSyncMessage between the header and the properties.
        .marker(Marker::IncrSyncChange)
        .header(2)
        .string(PropertyTag::SUBJECT, "broken")
        .full_change(3, "third")
        .end();
    let events = events_of(&stream, stream.len());

    assert_eq!(messages(&events), ["first", "third"]);
    let header = events
        .iter()
        .find_map(|event| match event {
            SyncEvent::Unreadable { header, .. } => header.clone(),
            _ => None,
        })
        .expect("the unreadable change is named");
    assert_eq!(header.source_key(), [2; 22]);
}

/// A partial change: the mapping is defined once, the change names groups by index, and the
/// group with nothing left in it arrives as the placeholder `0x00000003`, which is dropped.
#[test]
fn a_partial_change_reports_which_groups_changed() {
    let keywords = PropertyName::from_stream(PropertySetId::PUBLIC_STRINGS, "Keywords".to_owned());
    let mut mapping = Vec::new();
    mapping.extend_from_slice(&7_u32.to_le_bytes()); // GroupId
    mapping.extend_from_slice(&0_u32.to_le_bytes()); // Reserved
    mapping.extend_from_slice(&2_u32.to_le_bytes()); // GroupCount
    mapping.extend_from_slice(&1_u32.to_le_bytes()); // group 0: one tag
    mapping.extend_from_slice(&PropertyTag::SUBJECT.as_u32().to_le_bytes());
    mapping.extend_from_slice(&1_u32.to_le_bytes()); // group 1: one named tag
    mapping.extend_from_slice(&0x8001_101F_u32.to_le_bytes());
    mapping.extend_from_slice(PropertySetId::PUBLIC_STRINGS.as_guid().as_bytes());
    mapping.extend_from_slice(&1_u32.to_le_bytes()); // Kind: name
    let name: Vec<u8> = "Keywords\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    mapping.extend_from_slice(&u32::try_from(name.len()).unwrap().to_le_bytes());
    mapping.extend_from_slice(&name);

    let stream = Stream::default()
        .marker(Marker::IncrSyncGroupInfo)
        .binary(PropertyTag::new(0x0000_0102), &mapping)
        .u32(PropertyTag::META_TAG_INCR_SYNC_GROUP_ID, 7)
        .marker(Marker::IncrSyncChangePartial)
        .header(4)
        .u32(PropertyTag::META_TAG_INCREMENTAL_SYNC_MESSAGE_PARTIAL, 1)
        .u32(PropertyTag::new(0x0000_0003), 0)
        .end();
    let events = events_of(&stream, 3);

    let change = events
        .iter()
        .find_map(|event| match event {
            SyncEvent::Message(change) => Some(change),
            _ => None,
        })
        .unwrap();
    assert!(change.is_partial());
    let [group] = change.groups() else {
        panic!("one group")
    };
    assert_eq!(group.index(), 1);
    assert!(group.properties().is_empty(), "every Keyword was removed");
    let mapping = change.group_mapping().unwrap();
    assert_eq!(mapping.group_of_name(&keywords), Some(1));
    assert_eq!(mapping.group_of_tag(PropertyTag::SUBJECT), Some(0));
}

/// The two encodings a ROP buffer does not have: a two-byte boolean, and a string under a code-page
/// type, reported under the ordinary string type with the code page kept.
#[test]
fn a_stream_value_is_decoded_by_the_streams_own_rules() {
    let mut stream = Stream::default().marker(Marker::IncrSyncChange).header(5);
    stream.0.extend_from_slice(&0x67AA_000B_u32.to_le_bytes());
    stream.0.extend_from_slice(&[0x01, 0x00]);
    stream = stream.marker(Marker::IncrSyncMessage);
    stream.0.extend_from_slice(&0x0037_84B0_u32.to_le_bytes());
    let text: Vec<u8> = "cp\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    stream
        .0
        .extend_from_slice(&u32::try_from(text.len()).unwrap().to_le_bytes());
    stream.0.extend_from_slice(&text);
    let events = events_of(&stream.end(), 4);

    let SyncEvent::Message(change) = &events[0] else {
        panic!("{:?}", events[0])
    };
    assert!(change.header().is_associated(), "01 00 is TRUE");
    let property = &change.content().properties()[0];
    assert_eq!(property.tag(), PropertyTag::SUBJECT);
    assert_eq!(property.code_page(), Some(1200));
    assert_eq!(subject(change.content()), "cp");
}

/// A type whose length nobody knows cannot be stepped over, so it stops the download.
#[test]
fn an_unknown_property_type_stops_the_stream() {
    let mut stream = Stream::default().full_change(1, "first");
    stream.0.extend_from_slice(&0x0001_00FD_u32.to_le_bytes());
    stream.0.extend_from_slice(&[0; 8]);
    let mut sync = ContentsSync::new();
    sync.feed(&stream.0);
    let error = loop {
        match sync.next_event() {
            Ok(Some(_)) => {}
            Ok(None) => panic!("the unknown type was waited on rather than refused"),
            Err(error) => break error,
        }
    };
    assert!(matches!(
        error,
        Error::UnsupportedPropertyType {
            property_type: 0x00FD,
            ..
        }
    ));
}

/// The document's progress element: its version is `0x0026`, not the `0x0000` §2.2.2.7 calls the
/// only one, and its counts are the recognisable values it was built from.
#[test]
fn the_documents_progress_reads_whatever_its_version_says() {
    let events = events_of(&EXAMPLE, EXAMPLE.len());
    let SyncEvent::Progress(progress) = &events[0] else {
        panic!("progress comes first")
    };
    assert_eq!(progress.fai_count(), 0x9876_5432);
    assert_eq!(progress.fai_size(), 0xBABE_BABE_BABE_BABE);
    assert_eq!(progress.normal_count(), 0x00AB_CDEF);
    assert_eq!(progress.normal_size(), 0x1234_5678_90AB_CDEF);

    let SyncEvent::Message(change) = &events[1] else {
        panic!("a message follows")
    };
    let content = change.content();
    // The example puts MetaTagFXDelProp before both lists, naming PidTagMessageRecipients and
    // PidTagMessageAttachments: replace what the client holds with what follows.
    assert!(content.replaces_recipients() && content.replaces_attachments());
    let attachment = &content.attachments()[0];
    assert!(!attachment.properties().is_empty());
    assert!(attachment.property(PropertyTag::ATTACH_METHOD).is_some());
    assert!(change.property(PropertyTag::SUBJECT).is_some());
    assert!(change.groups().is_empty() && change.group_mapping().is_none());
    assert!(change.header().last_modified().is_some());
    assert!(!change.header().change_key().is_empty());
    assert!(!change.header().predecessor_change_list().is_empty());
    assert_eq!(
        change.header().size(),
        None,
        "MessageSize was not configured"
    );

    let SyncEvent::Deletions(deletions) = &events[2] else {
        panic!("deletions follow")
    };
    assert!(deletions.no_longer_in_scope().is_empty() && deletions.expired().is_empty());
}

/// An error element with diagnostic bytes, which sit at the offset the structure names.
#[test]
fn an_error_elements_diagnostic_bytes_are_found_by_their_offset() {
    let mut info = vec![0, 0, 0, 0];
    info.extend_from_slice(&0x8004_0102_u32.to_le_bytes());
    info.extend_from_slice(&[0x44; 22]);
    info.extend_from_slice(&[0; 2 + 22 + 2 + 24]);
    info.extend_from_slice(&3_u32.to_le_bytes());
    info.extend_from_slice(&88_u32.to_le_bytes());
    info.extend_from_slice(&[0xD1, 0xD2, 0xD3]);
    let failed = ErrorInfo::read(&info).unwrap();
    assert_eq!(failed.diagnostic(), [0xD1, 0xD2, 0xD3]);
    assert_eq!(failed.message(), None);
    assert!(failed.folder().is_some());

    let mut beyond = info.clone();
    beyond[84] = 0xFF;
    assert!(matches!(
        ErrorInfo::read(&beyond),
        Err(Error::MalformedFastTransfer { .. })
    ));
    let mut versioned = info;
    versioned[0] = 1;
    assert!(ErrorInfo::read(&versioned).is_err());
}

/// A group mapping naming a property by LID, and the refusals its reader makes.
#[test]
fn a_group_mapping_can_name_by_lid_and_refuses_what_it_cannot_read() {
    let mut mapping = Vec::new();
    for word in [3_u32, 0, 1, 1, 0x8005_000B] {
        mapping.extend_from_slice(&word.to_le_bytes());
    }
    mapping.extend_from_slice(PropertySetId::COMMON.as_guid().as_bytes());
    mapping.extend_from_slice(&0_u32.to_le_bytes());
    mapping.extend_from_slice(&0x8503_u32.to_le_bytes());
    let info = PropertyGroupInfo::read(&mapping).unwrap();
    assert_eq!(info.id(), 3);
    assert_eq!(info.len(), 1);
    assert!(!info.is_empty());
    let group = info.group(0).unwrap();
    assert_eq!(group[0].tag(), PropertyTag::new(0x8005_000B));
    assert_eq!(
        info.group_of_name(&PropertyName::lid(PropertySetId::COMMON, 0x8503)),
        Some(0)
    );
    assert_eq!(info.group(1), None);
    assert_eq!(info.group_of_tag(PropertyTag::SUBJECT), None);

    let mut trailing = mapping.clone();
    trailing.push(0);
    assert!(PropertyGroupInfo::read(&trailing).is_err());
    let mut kind = mapping;
    let at = kind.len() - 8;
    kind[at] = 9;
    assert!(PropertyGroupInfo::read(&kind).is_err());
}

#[test]
fn a_parser_reports_when_it_is_finished_and_markers_print_their_values() {
    let mut sync = ContentsSync::new();
    sync.feed(&Stream::default().end());
    while sync.next_event().unwrap().is_some() {}
    assert!(sync.is_finished());
    assert_eq!(sync.next_event().unwrap(), None);
    assert_eq!(Marker::IncrSyncEnd.to_string(), "IncrSyncEnd (0x40140003)");

    let mut extra = ContentsSync::new();
    extra.feed(&[Stream::default().end(), vec![0x01]].concat());
    while extra.next_event().unwrap().is_some() {}
    assert!(matches!(
        extra.finish(),
        Err(Error::MalformedFastTransfer { .. })
    ));
}
