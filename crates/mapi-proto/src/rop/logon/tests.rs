use super::*;
use crate::error::Error;
use crate::oxcdata::LegacyDn;
use crate::testing::logon_response_body;

#[test]
fn logon_request_matches_the_spec_layout() {
    let mut w = Writer::new();
    encode_logon(&mut w, 0, "/o=X");

    #[rustfmt::skip]
    let expected = vec![
        0xFE,                   // RopId
        0x00,                   // LogonId
        0x00,                   // OutputHandleIndex
        0x01,                   // LogonFlags = Private
        0x00, 0x00, 0x00, 0x01, // OpenFlags = USE_PER_MDB_REPLID_MAPPING, little-endian
        0x00, 0x00, 0x00, 0x00, // StoreState
        0x05, 0x00,             // EssdnSize = 4 + NUL
        b'/', b'o', b'=', b'X', 0x00,
    ];
    assert_eq!(w.finish(), expected);
}

/// `EssdnSize` counts the terminator. Getting it wrong makes the server read past the name.
#[test]
fn essdn_size_includes_the_null_terminator() {
    let dn = LegacyDn::new("/o=First/ou=Exchange Administrative Group/cn=alice").unwrap();
    let mut w = Writer::new();
    encode_logon(&mut w, 0, dn.as_str());
    let bytes = w.finish();

    let size = bytes
        .get(12..14)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .unwrap();
    assert_eq!(usize::from(size), dn.as_str().len() + 1);
    assert_eq!(bytes.len(), 14 + dn.as_str().len() + 1);
}

/// The measured size of a real private-mailbox logon response, and the assertion that caught
/// `LogonTime` being eight bytes rather than thirteen: counting it wrong overruns by five and
/// turns a perfectly good response into a truncation error.
#[test]
fn a_private_mailbox_logon_response_is_exactly_166_bytes() {
    // 6 bytes of RopId, OutputHandleIndex and ReturnValue precede the body this test builds.
    assert_eq!(logon_response_body().len() + 6, 166);
}

#[test]
fn decodes_thirteen_folder_ids_with_the_inbox_at_slot_four() {
    let body = logon_response_body();
    let mut r = Reader::new(&body);
    let logon = LogonResponse::read(&mut r).unwrap();

    assert_eq!(logon.folder_ids().len(), 13);
    assert_eq!(
        logon.folder(WellKnownFolder::Inbox),
        Some(FolderId::new(0x0100_0000_0000_0004))
    );
    assert_eq!(
        logon.folder(WellKnownFolder::IpmSubtree),
        Some(FolderId::new(0x0100_0000_0000_0003))
    );
    assert_eq!(logon.replica_id(), ReplicaId::new(1));
    assert_eq!(logon.mailbox_guid(), Guid::from_bytes([0xAB; 16]));
    assert_eq!(logon.replica_guid(), Guid::from_bytes([0xCD; 16]));
    assert_eq!(logon.logon_flags(), LOGON_FLAG_PRIVATE);
    assert!(r.is_empty(), "the whole response must be consumed");
}

#[test]
fn every_well_known_folder_has_a_distinct_slot_and_name() {
    for (position, folder) in WellKnownFolder::ALL.iter().enumerate() {
        assert_eq!(folder.index(), position);
        assert!(!folder.name().is_empty());
        assert_eq!(folder.to_string(), folder.name());
    }
    assert_eq!(WellKnownFolder::Inbox.index(), 4);
    assert_eq!(WellKnownFolder::IpmSubtree.name(), "IPM subtree");
}

#[test]
fn a_truncated_logon_response_is_an_error_not_a_panic() {
    let body = logon_response_body();
    for length in [0, 1, 20, 100, body.len() - 1] {
        let partial = body.get(..length).unwrap_or_default();
        assert!(matches!(
            LogonResponse::read(&mut Reader::new(partial)),
            Err(Error::Truncated { .. })
        ));
    }
}
