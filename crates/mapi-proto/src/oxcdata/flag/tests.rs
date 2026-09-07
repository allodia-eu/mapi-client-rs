use super::*;

/// Every flag, with the value [MS-OXCMSG] §2.2.1.6's two tables give it — transcribed from the
/// document rather than from the constants above, so a typo in one is not confirmed by the other.
#[test]
fn the_message_flags_are_the_ones_the_two_tables_list() {
    for (flag, value, name) in [
        (MessageFlags::READ, 0x0000_0001, "mfRead"),
        (MessageFlags::UNMODIFIED, 0x0000_0002, "mfUnmodified"),
        (MessageFlags::SUBMITTED, 0x0000_0004, "mfSubmitted"),
        (MessageFlags::UNSENT, 0x0000_0008, "mfUnsent"),
        (MessageFlags::HAS_ATTACHMENT, 0x0000_0010, "mfHasAttach"),
        (MessageFlags::FROM_ME, 0x0000_0020, "mfFromMe"),
        (MessageFlags::ASSOCIATED, 0x0000_0040, "mfFAI"),
        (MessageFlags::RESEND, 0x0000_0080, "mfResend"),
        (MessageFlags::NOTIFY_READ, 0x0000_0100, "mfNotifyRead"),
        (MessageFlags::NOTIFY_UNREAD, 0x0000_0200, "mfNotifyUnread"),
        (MessageFlags::EVER_READ, 0x0000_0400, "mfEverRead"),
    ] {
        assert_eq!(flag, value, "{name}");
        assert!(MessageFlags::new(flag).has(flag), "{name}");
        assert!(MessageFlags::new(flag).to_string().contains(name));
    }
}

/// The four readings the crate offers, against the combination a freshly saved draft carries:
/// unsent and unmodified, neither read nor submitted.
#[test]
fn a_draft_reads_as_a_draft_and_a_delivered_message_does_not() {
    let draft = MessageFlags::new(MessageFlags::UNSENT | MessageFlags::UNMODIFIED);
    assert!(draft.is_draft());
    assert!(!draft.is_read());
    assert!(!draft.is_submitted());
    assert!(!draft.is_associated());

    // What the same message looks like once the server has accepted the submit: mfUnsent gone,
    // mfSubmitted on. Getting these two the wrong way round would report a sent message as a
    // draft, which is exactly the answer a caller would act on.
    let sent = MessageFlags::new(MessageFlags::SUBMITTED | MessageFlags::UNMODIFIED);
    assert!(!sent.is_draft());
    assert!(sent.is_submitted());

    assert_eq!(MessageFlags::default().to_string(), "none (0x00000000)");
    assert_eq!(MessageFlags::new(0x0000_0009).as_u32(), 0x0000_0009);
    assert_eq!(
        MessageFlags::new(0x0000_0009).to_string(),
        "mfRead|mfUnsent (0x00000009)"
    );
}

/// [MS-OXOFLAG] §2.2.1.1 lists two values and calls the property absent otherwise, so `0x00` is
/// modelled as "not flagged" rather than left unknown — and `is_flagged` has to agree with that.
#[test]
fn a_flag_status_maps_both_ways() {
    for (raw, status, shown) in [
        (0x0000_0000, FlagStatus::NotFlagged, "not flagged"),
        (0x0000_0001, FlagStatus::Complete, "followupComplete"),
        (0x0000_0002, FlagStatus::Flagged, "followupFlagged"),
    ] {
        assert_eq!(FlagStatus::new(raw), status);
        assert_eq!(status.as_u32(), raw);
        assert_eq!(status.to_string(), shown);
    }

    assert!(!FlagStatus::NotFlagged.is_flagged());
    assert!(FlagStatus::Complete.is_flagged());
    assert!(FlagStatus::Flagged.is_flagged());
    assert_eq!(FlagStatus::default(), FlagStatus::NotFlagged);

    let odd = FlagStatus::new(0x0000_0007);
    assert_eq!(odd, FlagStatus::Unknown(0x0000_0007));
    assert_eq!(odd.as_u32(), 0x0000_0007);
    assert!(!odd.is_flagged());
    assert_eq!(odd.to_string(), "unmodelled flag status 0x00000007");
}

/// The six colours [MS-OXOFLAG] §2.2.1.2's table gives, in its order, and the one a time flag is
/// required to use.
#[test]
fn the_flag_colours_are_the_six_the_table_lists() {
    for (raw, colour, name) in [
        (0x0000_0001, FollowupIcon::Purple, "purple"),
        (0x0000_0002, FollowupIcon::Orange, "orange"),
        (0x0000_0003, FollowupIcon::Green, "green"),
        (0x0000_0004, FollowupIcon::Yellow, "yellow"),
        (0x0000_0005, FollowupIcon::Blue, "blue"),
        (0x0000_0006, FollowupIcon::Red, "red"),
    ] {
        assert_eq!(FollowupIcon::new(raw), colour);
        assert_eq!(colour.as_u32(), raw);
        assert_eq!(colour.name(), Some(name));
        assert_eq!(colour.to_string(), name);
    }

    assert_eq!(FollowupIcon::ALL.len(), 6);
    assert_eq!(FollowupIcon::ALL.last(), Some(&FollowupIcon::Red));
    assert_eq!(FollowupIcon::Red.as_u32(), 0x0000_0006);

    let odd = FollowupIcon::new(0x0000_0009);
    assert_eq!(odd, FollowupIcon::Unknown(0x0000_0009));
    assert_eq!(odd.name(), None);
    assert_eq!(odd.to_string(), "unmodelled colour 0x00000009");
}
