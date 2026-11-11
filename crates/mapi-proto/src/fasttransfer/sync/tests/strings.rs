//! A change holding a string that cannot be read as text: lost on its own, and nothing with it.

use super::*;

/// A change whose subject is in code page 437, which has no decoder (`0x8000 | 437`).
fn undecodable_change(stream: Stream, n: u8) -> Stream {
    stream
        .marker(Marker::IncrSyncChange)
        .header(n)
        .marker(Marker::IncrSyncMessage)
        .binary(PropertyTag::new(0x0037_81B5), b"x\0")
}

fn lost(events: &[SyncEvent]) -> Vec<(Option<Vec<u8>>, String)> {
    events
        .iter()
        .filter_map(|event| match event {
            SyncEvent::Unreadable { header, reason } => Some((
                header.as_ref().map(|header| header.source_key().to_vec()),
                reason.clone(),
            )),
            _ => None,
        })
        .collect()
}

/// The change is reported as unreadable with its header and the reason, and the changes either
/// side of it read as usual — however the stream is split, since the string can straddle buffers.
#[test]
fn a_change_with_an_undecodable_string_is_lost_alone() {
    let stream = undecodable_change(Stream::default().full_change(1, "first"), 2)
        .full_change(3, "third")
        .end();
    for chunk in [1, 5, 1000] {
        let events = events_of(&stream, chunk);
        assert_eq!(messages(&events), ["first", "third"], "{chunk}-byte pieces");
        let lost = lost(&events);
        assert_eq!(lost.len(), 1, "{chunk}-byte pieces");
        assert_eq!(lost[0].0.as_deref(), Some(&[2; 22][..]));
        assert!(lost[0].1.contains("437"), "{}", lost[0].1);
    }
}

/// The size announced for a change it cannot read goes with it, as it does for a change an
/// `errorInfo` drops — and a change an error interrupts that held such a string is still lost
/// for the string when the error names another object.
#[test]
fn what_an_undecodable_change_takes_with_it() {
    let mut announced = Stream::default()
        .marker(Marker::IncrSyncProgressPerMessage)
        .u32(PropertyTag::MESSAGE_SIZE, 100);
    announced
        .0
        .extend_from_slice(&PropertyTag::ASSOCIATED.as_u32().to_le_bytes());
    announced.0.extend_from_slice(&[0, 0]);
    let stream = undecodable_change(announced, 2)
        .full_change(3, "unannounced")
        .end();
    let events = events_of(&stream, 4);
    let announced: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            SyncEvent::Message(change) => Some(change.announced()),
            _ => None,
        })
        .collect();
    assert_eq!(announced, [None]);

    let mut info = vec![0, 0, 0, 0];
    info.extend_from_slice(&0x8004_0102_u32.to_le_bytes());
    info.extend_from_slice(&[0; 22 + 2]);
    info.extend_from_slice(&[9; 22]);
    info.extend_from_slice(&[0; 2 + 24 + 8]);
    let stream = undecodable_change(Stream::default(), 2)
        .marker(Marker::ErrorInfo)
        .binary(PropertyTag::new(0x0000_0102), &info)
        .full_change(3, "third")
        .end();
    let events = events_of(&stream, 1000);
    assert_eq!(messages(&events), ["third"]);
    assert_eq!(lost(&events).len(), 1);
}

/// Only a change is lost for a value it could not read. A state holding one still ends the
/// download, so the next one can begin from it.
#[test]
fn a_state_with_an_undecodable_value_still_ends_the_download() {
    let stream = Stream::default()
        .full_change(1, "first")
        .marker(Marker::IncrSyncStateBegin)
        .binary(PropertyTag::new(0x0037_81B5), b"x\0")
        .marker(Marker::IncrSyncStateEnd)
        .marker(Marker::IncrSyncEnd)
        .0;
    let events = events_of(&stream, 3);
    assert_eq!(messages(&events), ["first"]);
    assert!(lost(&events).is_empty());
    assert!(
        events
            .iter()
            .any(|event| matches!(event, SyncEvent::State(_)))
    );
    assert!(matches!(events.last(), Some(SyncEvent::End)));
}
