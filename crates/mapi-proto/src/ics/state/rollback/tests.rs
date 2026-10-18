use super::*;
use crate::ics::{ChangeNumber, IdSet, SyncScope};
use crate::oxcdata::{FolderId, Guid, MessageId, ReplicaId};

const REPLICA: Guid = Guid::from_bytes([0x76; 16]);

/// A counter of replica 1 as a change number or message id carries it: REPLID, then the GLOBCNT.
fn id(counter: u64) -> u64 {
    let g = GlobCnt::from_u64(counter).unwrap().as_bytes();
    u64::from_le_bytes([1, 0, g[0], g[1], g[2], g[3], g[4], g[5]])
}

/// A state that has seen a normal message at change `normal` and, if given, an FAI message at
/// change `fai`.
fn state(normal: u64, fai: Option<u64>) -> IcsState {
    let scope = SyncScope::contents(Guid::from_bytes([1; 16]), FolderId::new(id(4)), None).unwrap();
    let mut state = IcsState::initial(scope);
    state.map_replica(ReplicaId::new(1), REPLICA);
    assert!(state.record_message(MessageId::new(id(10)), ChangeNumber::new(id(normal)), false));
    if let Some(fai) = fai {
        assert!(state.record_message(MessageId::new(id(11)), ChangeNumber::new(id(fai)), true));
    }
    state
}

/// A final state whose sets run to `normal` and, if given, `fai`.
fn server(normal: u64, fai: Option<u64>) -> FinalState {
    let set = |high: u64| {
        let mut set = IdSet::new();
        set.insert(REPLICA, GlobCnt::from_u64(1).unwrap());
        set.insert(REPLICA, GlobCnt::from_u64(high).unwrap());
        set
    };
    FinalState {
        cnset_seen: set(normal),
        cnset_seen_fai: fai.map(set).unwrap_or_default(),
        ..FinalState::default()
    }
}

/// The figures measured on Exchange Server SE `15.02.2562.056`: a state claiming `0x32B37B2E`
/// against a server whose final state ran to `0x32B37A6B`.
#[test]
fn a_server_behind_the_state_is_refused_with_both_numbers() {
    let refused = state(0x32B3_7B2E, None)
        .check_not_ahead_of(&server(0x32B3_7A6B, None))
        .unwrap_err();
    assert_eq!(
        refused,
        Error::IcsStateAheadOfServer {
            replica: REPLICA,
            seen: GlobCnt::from_u64(0x32B3_7B2E).unwrap(),
            newest: GlobCnt::from_u64(0x32B3_7A6B).unwrap(),
        }
    );
    assert!(
        refused.to_string().contains("gone back in time"),
        "{refused}"
    );
}

#[test]
fn a_server_level_with_or_past_the_state_is_not() {
    let ours = state(0x32B3_7A66, Some(0x50));
    assert_eq!(
        ours.check_not_ahead_of(&server(0x32B3_7A66, Some(0x50))),
        Ok(())
    );
    assert_eq!(
        ours.check_not_ahead_of(&server(0x32B3_7A6B, Some(0x60))),
        Ok(())
    );
    let first = IcsState::initial(ours.scope().clone());
    assert_eq!(
        first.check_not_ahead_of(&server(1, None)),
        Ok(()),
        "nothing seen"
    );
}

#[test]
fn associated_messages_are_compared_too() {
    assert!(matches!(
        state(0x10, Some(0x90)).check_not_ahead_of(&server(0x100, Some(0x80))),
        Err(Error::IcsStateAheadOfServer { .. })
    ));
}

/// A final state for normal messages carries no `CnsetSeenFAI`, and a replica it does not name
/// cannot be compared: neither is a rollback.
#[test]
fn a_set_or_replica_the_server_does_not_report_is_not_compared() {
    assert_eq!(
        state(0x10, Some(0x90)).check_not_ahead_of(&server(0x100, None)),
        Ok(())
    );
    let mut elsewhere = server(0x05, None);
    elsewhere.cnset_seen = {
        let mut set = IdSet::new();
        set.insert(Guid::from_bytes([0x99; 16]), GlobCnt::from_u64(5).unwrap());
        set
    };
    assert_eq!(state(0x10, None).check_not_ahead_of(&elsewhere), Ok(()));
}
