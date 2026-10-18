use super::*;

fn cnt(value: u64) -> GlobCnt {
    GlobCnt::from_u64(value).unwrap()
}

/// The GUID [MS-OXCFXICS] §4.5 prints as `0ffbd719-1606-41a1-bff6-91c763daa866`, as its bytes go on
/// the wire.
const EXAMPLE_GUID: [u8; 16] = [
    0x19, 0xD7, 0xFB, 0x0F, 0x06, 0x16, 0xA1, 0x41, 0xBF, 0xF6, 0x91, 0xC7, 0x63, 0xDA, 0xA8, 0x66,
];

/// The second replica of §4.5's `MetaTagIdsetGiven`, printed as
/// `79670cd2-4cac-4250-892c-245d2d1ae3a4`.
const SECOND_GUID: [u8; 16] = [
    0xD2, 0x0C, 0x67, 0x79, 0xAC, 0x4C, 0x50, 0x42, 0x89, 0x2C, 0x24, 0x5D, 0x2D, 0x1A, 0xE3, 0xA4,
];

/// [MS-OXCFXICS] §4.4 in full: four message ids in two replicas, REPLID-based.
#[test]
fn the_documents_replid_based_idset_decodes_to_its_four_ids() {
    let bytes = [
        0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x05, 0x06, 0x01, 0x10, 0x50, 0x00,
        0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
    ];
    let set = read::<ReplicaId>(&bytes).unwrap();
    let ids: Vec<u64> = set.message_ids().map(MessageId::as_u64).collect();
    // The document writes these as `01 00 00 00 00 00 00 05` and so on: wire bytes, which a
    // little-endian u64 reads with the REPLID low and the GLOBCNT's last byte highest.
    assert_eq!(
        ids,
        [
            u64::from_le_bytes([0x01, 0, 0, 0, 0, 0, 0, 0x05]),
            u64::from_le_bytes([0x01, 0, 0, 0, 0, 0, 0, 0x06]),
            u64::from_le_bytes([0x01, 0, 0, 0, 0, 0, 0, 0x10]),
            u64::from_le_bytes([0x02, 0, 0, 0, 0, 0, 0, 0x09]),
        ]
    );
    for id in &ids {
        assert!(set.contains_message(MessageId::new(*id)));
    }
}

/// §4.5's `MetaTagIdsetDeleted` names a second replica with an empty GLOBSET — an End and nothing
/// else. It decodes, and holds nothing for that replica.
#[test]
fn a_replica_with_an_empty_globset_holds_nothing() {
    let bytes = [
        0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x78, 0x2E, 0x23, 0x00, 0x04, 0x00, 0x00,
    ];
    let set = read::<ReplicaId>(&bytes).unwrap();
    let ids: Vec<u64> = set.message_ids().map(MessageId::as_u64).collect();
    assert_eq!(
        ids,
        [u64::from_le_bytes([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x78, 0x2E, 0x23
        ])]
    );
    assert_eq!(
        set.get(ReplicaId::new(4)),
        None,
        "a replica holding nothing is not kept"
    );
}

/// §4.5's `MetaTagIdsetGiven`: REPLGUID-based, two replicas, the second encoded with a Bitmask and
/// a one-byte Push.
#[test]
fn the_documents_replguid_based_idset_given_decodes_to_its_printout() {
    let mut bytes = EXAMPLE_GUID.to_vec();
    bytes.extend_from_slice(&[
        0x05, 0x00, 0x00, 0x00, 0x78, 0x2E, 0x52, 0x1D, 0x22, 0x50, 0x00,
    ]);
    bytes.extend_from_slice(&SECOND_GUID);
    bytes.extend_from_slice(&[
        0x05, 0x00, 0x00, 0x00, 0x78, 0x06, 0x42, 0x01, 0x01, 0x01, 0x0C, 0x50, 0x00,
    ]);
    assert_eq!(bytes.len(), 0x38, "the length the document gives");

    let set = read::<Guid>(&bytes).unwrap();
    let ranges = |guid: [u8; 16]| -> Vec<(u64, u64)> {
        set.get(Guid::from_bytes(guid))
            .unwrap()
            .ranges()
            .map(|(low, high)| (low.as_u64(), high.as_u64()))
            .collect()
    };
    assert_eq!(ranges(EXAMPLE_GUID), [(0x78_2E1D, 0x78_2E22)]);
    assert_eq!(
        ranges(SECOND_GUID),
        [(0x78_0601, 0x78_0602), (0x78_060C, 0x78_060C)]
    );

    let replicas: Vec<Guid> = set.replicas().map(|(guid, _)| guid).collect();
    assert_eq!(
        replicas,
        [
            Guid::from_bytes(EXAMPLE_GUID),
            Guid::from_bytes(SECOND_GUID)
        ],
        "ascending by byte-to-byte comparison, which is the order the document serialises in"
    );
}

/// Read in the wrong form, the first GUID's bytes are taken as a REPLID and the rest as commands:
/// the type parameter exists because nothing in the bytes would catch this reliably.
#[test]
fn the_two_forms_are_not_interchangeable() {
    let mut set = IdSet::<Guid>::new();
    set.insert(Guid::from_bytes(EXAMPLE_GUID), cnt(1));
    let bytes = to_bytes(&set);
    assert!(
        read::<ReplicaId>(&bytes).is_err(),
        "the GUID's third byte is no GLOBSET command"
    );
}

#[test]
fn an_idset_survives_an_encode_and_decode_in_either_form() {
    let mut by_guid = IdSet::<Guid>::new();
    by_guid.insert(Guid::from_bytes(SECOND_GUID), cnt(0x78_0601));
    by_guid.insert(Guid::from_bytes(EXAMPLE_GUID), cnt(0x78_2E1D));
    by_guid.insert(Guid::from_bytes(EXAMPLE_GUID), cnt(0x78_2E1E));
    assert_eq!(read::<Guid>(&to_bytes(&by_guid)).unwrap(), by_guid);

    let mut by_id = IdSet::<ReplicaId>::new();
    by_id.insert_message(MessageId::new(0x0500_0000_0000_0001));
    by_id.insert(ReplicaId::new(2), cnt(9));
    assert_eq!(read::<ReplicaId>(&to_bytes(&by_id)).unwrap(), by_id);
    assert_eq!(to_bytes(&IdSet::<ReplicaId>::new()), Vec::<u8>::new());
}

#[test]
fn a_replica_named_twice_has_its_counters_merged() {
    let bytes = [
        0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0x01, 0x00, 0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0x02, 0x00,
    ];
    let set = read::<ReplicaId>(&bytes).unwrap();
    assert_eq!(set.message_ids().count(), 2);
}

#[test]
fn a_truncated_idset_errors_rather_than_panicking() {
    let mut bytes = EXAMPLE_GUID.to_vec();
    bytes.extend_from_slice(&[
        0x05, 0x00, 0x00, 0x00, 0x78, 0x2E, 0x52, 0x1D, 0x22, 0x50, 0x00,
    ]);
    for end in 1..bytes.len() {
        assert!(read::<Guid>(&bytes[..end]).is_err(), "{end} bytes");
    }
}

#[test]
fn splitting_and_joining_an_id_round_trips_and_matches_the_document() {
    // §4.5's PidTagMid: `01 00 00 00 00 78 2E 21`, REPLID 1 and GLOBCNT 0x782E21.
    let raw = u64::from_le_bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x78, 0x2E, 0x21]);
    let (replica, counter) = split(raw);
    assert_eq!(replica, ReplicaId::new(1));
    assert_eq!(counter.as_u64(), 0x78_2E21);
    assert_eq!(join(replica, counter), raw);
}

#[test]
fn message_ids_walk_a_range_without_expanding_it_first() {
    let mut set = IdSet::<ReplicaId>::new();
    let mut globset = GlobSet::new();
    globset.insert_range(cnt(1), GlobCnt::MAX);
    if let Some(entry) = set.entry(ReplicaId::new(1)) {
        entry.extend(&globset);
    }
    let first: Vec<u64> = set
        .message_ids()
        .take(3)
        .map(|id| split(id.as_u64()).1.as_u64())
        .collect();
    assert_eq!(first, [1, 2, 3]);
}

/// A replica named with an empty GLOBSET holds nothing, so it is not kept: otherwise two sets
/// holding the same ids would compare unequal, and so would the states made of them.
#[test]
fn a_replica_holding_nothing_is_not_kept() {
    let decoded = read::<ReplicaId>(&[0x01, 0x00, 0x00]).unwrap();
    assert_eq!(decoded, IdSet::new());
    assert_eq!(decoded.replicas().count(), 0);

    let mut set = IdSet::<ReplicaId>::new();
    set.extend(&decoded);
    assert_eq!(set, IdSet::new());

    let mut set = IdSet::<ReplicaId>::new();
    assert!(set.insert(ReplicaId::new(2), cnt(5)));
    assert!(set.insert(ReplicaId::new(1), cnt(5)));
    assert!(set.contains(ReplicaId::new(2), cnt(5)));
    assert!(!set.insert(ReplicaId::new(1), cnt(5)));
}
