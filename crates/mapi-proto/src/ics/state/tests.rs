use super::*;
use crate::oxcdata::{FileTime, PropertyValue, RelationalOperator, TaggedValue};

const MAILBOX: Guid = Guid::from_bytes([0x11; 16]);
const REPLICA_GUID: Guid = Guid::from_bytes([0x22; 16]);
const INBOX: FolderId = FolderId::new(0x0100_0000_0000_0004);

fn floor(time: u64) -> Restriction {
    Restriction::property(
        RelationalOperator::GreaterThanOrEqual,
        TaggedValue::new(
            PropertyTag::MESSAGE_DELIVERY_TIME,
            PropertyValue::Time(FileTime::new(time)),
        )
        .unwrap(),
    )
}

fn scope(restriction: Option<&Restriction>) -> SyncScope {
    SyncScope::contents(MAILBOX, INBOX, restriction).unwrap()
}

fn state() -> IcsState {
    let mut state = IcsState::initial(scope(None));
    state.map_replica(ReplicaId::new(1), REPLICA_GUID);
    state
}

/// The case §3.3.5.5 warns about and the server cannot catch: a state obtained under one date floor
/// replayed under another. Widening it and narrowing it are both refused, as are another folder and
/// another mailbox.
#[test]
fn a_state_is_refused_for_any_scope_but_its_own() {
    let state = IcsState::initial(scope(Some(&floor(100))));
    state.check_scope(&scope(Some(&floor(100)))).unwrap();

    for (other, differs) in [
        (scope(Some(&floor(50))), "the restriction"),
        (scope(Some(&floor(200))), "the restriction"),
        (scope(None), "the restriction"),
        (
            SyncScope::contents(
                MAILBOX,
                FolderId::new(0x0100_0000_0000_0005),
                Some(&floor(100)),
            )
            .unwrap(),
            "the folder",
        ),
        (
            SyncScope::contents(Guid::from_bytes([0x33; 16]), INBOX, Some(&floor(100))).unwrap(),
            "the mailbox instance GUID",
        ),
        (
            SyncScope::hierarchy(MAILBOX, INBOX),
            "the synchronization type",
        ),
    ] {
        assert_eq!(
            state.check_scope(&other),
            Err(Error::IcsScopeMismatch { differs }),
            "{other:?}"
        );
    }
}

#[test]
fn a_first_state_is_initial_and_uploads_nothing() {
    let state = state();
    assert!(state.is_initial());
    assert!(state.state_properties().is_empty());
}

/// Checkpointing: each delivered message goes into `MetaTagIdsetGiven` by its MID and into the
/// right one of the two seen sets by its change number, translated from REPLID to REPLGUID.
#[test]
fn a_checkpoint_folds_each_message_into_given_and_the_right_seen_set() {
    let mut state = state();
    let mid = MessageId::new(u64::from_le_bytes([0x01, 0x00, 0, 0, 0, 0x78, 0x2E, 0x21]));
    let cn = ChangeNumber::new(u64::from_le_bytes([0x01, 0x00, 0, 0, 0, 0x78, 0x4D, 0x1C]));
    let fai_mid = MessageId::new(u64::from_le_bytes([0x01, 0x00, 0, 0, 0, 0x78, 0x2E, 0x30]));
    let fai_cn = ChangeNumber::new(u64::from_le_bytes([0x01, 0x00, 0, 0, 0, 0x78, 0x4D, 0x40]));

    assert!(state.record_message(mid, cn, false));
    assert!(state.record_message(fai_mid, fai_cn, true));

    assert!(
        state
            .idset_given()
            .contains(REPLICA_GUID, split(mid.as_u64()).1)
    );
    assert!(
        state
            .idset_given()
            .contains(REPLICA_GUID, split(fai_mid.as_u64()).1)
    );
    assert!(state.cnset_seen().contains(REPLICA_GUID, cn.counter()));
    assert!(!state.cnset_seen().contains(REPLICA_GUID, fai_cn.counter()));
    assert!(
        state
            .cnset_seen_fai()
            .contains(REPLICA_GUID, fai_cn.counter())
    );
    assert!(
        state.cnset_read().is_empty(),
        "nothing in a message change names a read CN"
    );

    let tags: Vec<PropertyTag> = state
        .state_properties()
        .into_iter()
        .map(|(t, _)| t)
        .collect();
    assert_eq!(
        tags,
        [
            PropertyTag::META_TAG_IDSET_GIVEN,
            PropertyTag::META_TAG_CNSET_SEEN,
            PropertyTag::META_TAG_CNSET_SEEN_FAI,
        ]
    );
}

/// An id from a replica nobody has mapped cannot be named by REPLGUID, so it is left out — and
/// the message is downloaded again after a resume, the safe way round. Once mapped, it folds.
#[test]
fn an_id_from_another_replica_is_not_folded() {
    let mut state = state();
    let foreign = MessageId::new(u64::from_le_bytes([0x02, 0x00, 0, 0, 0, 0, 0, 0x01]));
    let cn = ChangeNumber::new(u64::from_le_bytes([0x01, 0x00, 0, 0, 0, 0, 0, 0x01]));
    assert!(!state.record_message(foreign, cn, false));
    assert!(state.is_initial());

    let other = Guid::from_bytes([0x77; 16]);
    state.map_replica(ReplicaId::new(2), other);
    assert_eq!(state.replica_guid(ReplicaId::new(2)), Some(other));
    assert!(state.record_message(foreign, cn, false));
    assert!(
        state
            .idset_given()
            .contains(other, GlobCnt::from_u64(1).unwrap())
    );
    assert!(
        state
            .cnset_seen()
            .contains(REPLICA_GUID, GlobCnt::from_u64(1).unwrap())
    );

    state.map_replica(ReplicaId::new(2), REPLICA_GUID);
    assert_eq!(
        state.replica_guid(ReplicaId::new(2)),
        Some(REPLICA_GUID),
        "a remapping replaces"
    );
}

/// The mapping the logon reports is not the one to fold with — which is why a state starts with
/// none and is told by the server.
#[test]
fn a_new_state_maps_no_replica_and_folds_nothing() {
    let mut state = IcsState::initial(scope(None));
    assert_eq!(state.replica_guid(ReplicaId::new(1)), None);
    let id = MessageId::new(u64::from_le_bytes([1, 0, 0, 0, 0, 0, 0, 1]));
    let cn = ChangeNumber::new(u64::from_le_bytes([1, 0, 0, 0, 0, 0, 0, 2]));
    assert!(!state.record_message(id, cn, false));
}

#[test]
fn a_state_survives_its_own_encoding_scope_and_all() {
    let mut state = IcsState::initial(scope(Some(&floor(100))));
    state.map_replica(ReplicaId::new(1), REPLICA_GUID);
    state.map_replica(ReplicaId::new(5), Guid::from_bytes([0x55; 16]));
    for low in [0x10_u8, 0x11, 0x20] {
        state.record_message(
            MessageId::new(u64::from_le_bytes([1, 0, 0, 0, 0, 0, 0, low])),
            ChangeNumber::new(u64::from_le_bytes([1, 0, 0, 0, 0, 0, 1, low])),
            false,
        );
    }
    let bytes = state.to_bytes();
    let decoded = IcsState::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, state);
    decoded.check_scope(&scope(Some(&floor(100)))).unwrap();
}

#[test]
fn bytes_that_are_not_an_encoded_state_are_refused_by_name() {
    let good = state().to_bytes();

    let mut wrong_magic = good.clone();
    wrong_magic[0] = b'X';
    assert!(matches!(
        IcsState::from_bytes(&wrong_magic),
        Err(Error::InvalidIcsState { reason }) if reason.contains("not an ICS state")
    ));

    let mut later = good.clone();
    later[4] = VERSION + 1;
    assert!(matches!(
        IcsState::from_bytes(&later),
        Err(Error::InvalidIcsState { reason }) if reason.contains("version")
    ));

    let mut trailing = good.clone();
    trailing.push(0);
    assert!(matches!(
        IcsState::from_bytes(&trailing),
        Err(Error::InvalidIcsState { .. })
    ));

    for end in 0..good.len() {
        assert!(IcsState::from_bytes(&good[..end]).is_err(), "{end} bytes");
    }
}

#[test]
fn a_change_number_splits_like_any_other_id() {
    let cn = ChangeNumber::new(u64::from_le_bytes([0x01, 0x00, 0, 0, 0, 0x78, 0x4D, 0x1C]));
    assert_eq!(cn.replica_id(), ReplicaId::new(1));
    assert_eq!(cn.counter().as_u64(), 0x78_4D1C);
    assert_eq!(cn.to_string(), "1-000000784D1C");
}
