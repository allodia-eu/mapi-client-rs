//! What an `errorInfo` leaves of the change it follows, when errors and announcements pile up.
//!
//! [MS-OXCFXICS] §2.2.4.3.4 — `errorInfo`, and unwinding past the object it names

use super::*;

/// An `ExtendedErrorInfo` naming the message whose source key is `[n; 22]`.
fn error_naming(n: u8) -> Vec<u8> {
    let mut info = vec![0, 0, 0, 0];
    info.extend_from_slice(&0x8004_0102_u32.to_le_bytes());
    info.extend_from_slice(&[0; 22 + 2]);
    info.extend_from_slice(&[n; 22]);
    info.extend_from_slice(&[0; 2 + 24 + 8]);
    info
}

fn failures(events: &[SyncEvent]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, SyncEvent::Failed(_)))
        .count()
}

/// Two errors in a row, the first about an object the server never began. The change before
/// them was whole and named by neither, so it is delivered; the second error must not take the
/// first one's place as what was interrupted and lose it.
#[test]
fn two_errors_in_a_row_do_not_lose_the_change_before_them() {
    let stream = Stream::default()
        .full_change(1, "first")
        .marker(Marker::ErrorInfo)
        .binary(PropertyTag::new(0x0000_0102), &error_naming(8))
        .marker(Marker::ErrorInfo)
        .binary(PropertyTag::new(0x0000_0102), &error_naming(9))
        .full_change(3, "third")
        .end();
    for chunk in [1, 5, 1000] {
        let events = events_of(&stream, chunk);
        assert_eq!(messages(&events), ["first", "third"], "{chunk}-byte pieces");
        assert_eq!(failures(&events), 2);
    }
}

/// An error that cannot itself be read names nothing, so the change it followed is delivered and
/// the error is reported as unreadable.
#[test]
fn an_unreadable_error_does_not_cost_the_change_before_it() {
    let stream = Stream::default()
        .full_change(1, "first")
        .marker(Marker::ErrorInfo)
        .binary(PropertyTag::new(0x0000_0102), &[1, 0])
        .full_change(3, "third")
        .end();
    let events = events_of(&stream, 7);
    assert_eq!(messages(&events), ["first", "third"]);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, SyncEvent::Unreadable { header: None, .. }))
    );
}

/// A per-message announcement belongs to the change after it. When that change is dropped, the
/// announcement goes with it rather than being reported as the size of the next one.
#[test]
fn an_announcement_goes_with_the_change_it_announced() {
    let announce = |stream: Stream, size: u32| {
        let mut stream = stream
            .marker(Marker::IncrSyncProgressPerMessage)
            .u32(PropertyTag::MESSAGE_SIZE, size);
        // PidTagAssociated, false: a boolean is two bytes in a stream.
        stream
            .0
            .extend_from_slice(&PropertyTag::ASSOCIATED.as_u32().to_le_bytes());
        stream.0.extend_from_slice(&[0, 0]);
        stream
    };
    let stream = announce(Stream::default(), 100)
        .full_change(2, "dropped")
        .marker(Marker::ErrorInfo)
        .binary(PropertyTag::new(0x0000_0102), &error_naming(2))
        .full_change(3, "unannounced")
        .end();
    let events = events_of(&stream, 3);
    let announced: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            SyncEvent::Message(change) => Some(change.announced()),
            _ => None,
        })
        .collect();
    assert_eq!(announced, [None]);
}
