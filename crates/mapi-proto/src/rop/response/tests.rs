use super::*;
use crate::oxcdata::{HIERARCHY_COLUMNS, PropertyTag};
use crate::testing::{logon_response, query_rows_response};
use crate::wire::Writer;

fn no_columns() -> Vec<Option<Vec<PropertyTag>>> {
    vec![None; 4]
}

fn hierarchy_columns_at(slot: usize) -> Vec<Option<Vec<PropertyTag>>> {
    let mut columns = no_columns();
    if let Some(entry) = columns.get_mut(slot) {
        *entry = Some(HIERARCHY_COLUMNS.to_vec());
    }
    columns
}

#[test]
fn decodes_a_logon_response() {
    let responses = decode_all(&logon_response(0), &no_columns()).unwrap();
    let [RopResponse::Logon(logon)] = responses.as_slice() else {
        panic!("expected exactly one logon response, got {responses:?}");
    };
    assert_eq!(logon.folder_ids().len(), 13);
}

/// The whole four-ROP chain in one buffer, decoded by taking each `RopId` off the stream.
#[test]
fn decodes_the_whole_folder_chain_in_order() {
    let mut w = Writer::new();
    w.u8(RopId::OPEN_FOLDER.as_u8()).u8(1).u32(0).u8(0).u8(0);
    w.u8(RopId::GET_HIERARCHY_TABLE.as_u8())
        .u8(2)
        .u32(0)
        .u32(15);
    w.u8(RopId::SET_COLUMNS.as_u8()).u8(2).u32(0).u8(0);
    w.bytes(&query_rows_response(
        2,
        &[(0x11, "Inbox"), (0x22, "Sent Items")],
    ));

    let responses = decode_all(&w.finish(), &hierarchy_columns_at(2)).unwrap();
    assert_eq!(responses.len(), 4);

    assert!(matches!(
        responses.first(),
        Some(RopResponse::OpenFolder(folder)) if !folder.is_ghosted()
    ));
    assert!(matches!(
        responses.get(1),
        Some(RopResponse::GetTable(table)) if table.row_count() == 15
    ));
    assert!(matches!(
        responses.get(2),
        Some(RopResponse::SetColumns(columns)) if columns.status().is_complete()
    ));

    let rows = responses
        .get(3)
        .and_then(RopResponse::as_query_rows)
        .unwrap();
    assert_eq!(rows.rows().len(), 2);
    assert_eq!(
        rows.rows()
            .first()
            .unwrap()
            .string(PropertyTag::DISPLAY_NAME)
            .unwrap()
            .as_str(),
        "Inbox"
    );
}

/// The failure shape that breaks naive decoders: everything the success layout promises is simply
/// absent, and the next ROP's response starts immediately after `ReturnValue`.
#[test]
fn a_failed_rop_stops_after_its_return_value() {
    let mut w = Writer::new();
    w.u8(RopId::LOGON.as_u8())
        .u8(0)
        .u32(ErrorCode::UNKNOWN_USER.as_u32());
    w.u8(RopId::SET_COLUMNS.as_u8()).u8(2).u32(0).u8(0);

    let responses = decode_all(&w.finish(), &no_columns()).unwrap();
    assert_eq!(
        responses.first(),
        Some(&RopResponse::Failed {
            rop: RopId::LOGON,
            code: ErrorCode::UNKNOWN_USER
        })
    );
    assert_eq!(
        responses.first().and_then(RopResponse::failure),
        Some(ErrorCode::UNKNOWN_USER)
    );
    assert!(matches!(responses.get(1), Some(RopResponse::SetColumns(_))));
}

/// The one failure that does *not* stop after `ReturnValue`. Treating it as a bare failure leaves
/// `LogonFlags`, `ServerNameSize` and `ServerName` in the stream, and the next `RopId` is then read
/// out of the middle of a server name.
///
/// [MS-OXCSTOR] §2.2.1.1.2
#[test]
fn a_logon_redirect_is_read_past_its_server_name() {
    // LogonFlags, then a ServerNameSize that counts the terminating NUL.
    const LOGON_FLAGS: u8 = 0x01;
    const SERVER_NAME_SIZE: u8 = 11;

    let mut w = Writer::new();
    w.u8(RopId::LOGON.as_u8())
        .u8(0)
        .u32(ErrorCode::WRONG_SERVER.as_u32())
        .u8(LOGON_FLAGS)
        .u8(SERVER_NAME_SIZE)
        .ascii_z("EXCHANGE-B");
    w.u8(RopId::SET_COLUMNS.as_u8()).u8(2).u32(0).u8(0);

    let responses = decode_all(&w.finish(), &no_columns()).unwrap();
    assert_eq!(
        responses.first(),
        Some(&RopResponse::LogonRedirect {
            server_name: "EXCHANGE-B".to_owned()
        })
    );
    assert_eq!(
        responses.first().and_then(RopResponse::redirect_server),
        Some("EXCHANGE-B")
    );
    assert_eq!(
        responses.first().and_then(RopResponse::failure),
        Some(ErrorCode::WRONG_SERVER),
        "a redirect is still a refusal"
    );
    assert!(
        matches!(responses.get(1), Some(RopResponse::SetColumns(_))),
        "the ROP after a redirect must still decode"
    );
    assert_eq!(
        responses.get(1).and_then(RopResponse::redirect_server),
        None,
        "only a redirect names a server"
    );
}

#[test]
fn buffer_too_small_carries_the_size_needed_and_ends_the_stream() {
    let mut w = Writer::new();
    w.u8(RopId::BUFFER_TOO_SMALL.as_u8()).u16(4096);
    w.bytes(&[0xDE, 0xAD, 0xBE, 0xEF]); // the request buffers that were not executed

    let responses = decode_all(&w.finish(), &no_columns()).unwrap();
    assert_eq!(
        responses,
        vec![RopResponse::BufferTooSmall { size_needed: 4096 }]
    );
}

#[test]
fn a_backoff_is_decoded_past_its_variable_length_tail() {
    let mut w = Writer::new();
    w.u8(RopId::BACKOFF.as_u8()).u8(0).u32(30_000).u8(1);
    w.u8(RopId::QUERY_ROWS.as_u8()).u32(5_000); // one BackoffRop
    w.u16(2).bytes(&[0xAA, 0xBB]); // AdditionalData
    w.u8(RopId::SET_COLUMNS.as_u8()).u8(2).u32(0).u8(0);

    let responses = decode_all(&w.finish(), &no_columns()).unwrap();
    assert_eq!(
        responses.first(),
        Some(&RopResponse::Backoff {
            duration_ms: 30_000
        })
    );
    assert!(
        matches!(responses.get(1), Some(RopResponse::SetColumns(_))),
        "the ROP after a backoff must still decode"
    );
}

/// Rows are undecodable without the column set, so this stops rather than guessing.
#[test]
fn rows_for_an_unknown_column_set_are_refused() {
    let stream = query_rows_response(3, &[(0x11, "Inbox")]);
    assert_eq!(
        decode_all(&stream, &no_columns()),
        Err(Error::UnknownColumns { handle_index: 3 })
    );
}

#[test]
fn an_unmodelled_rop_stops_the_decode_rather_than_desynchronising() {
    let mut w = Writer::new();
    w.u8(0x07).u8(0).u32(0); // RopGetPropertiesSpecific: valid, but not modelled here
    assert_eq!(
        decode_all(&w.finish(), &no_columns()),
        Err(Error::UnmodelledRop {
            rop: RopId::new(0x07),
            at: 6
        })
    );
}

#[test]
fn accessors_answer_only_for_their_own_response() {
    let responses = decode_all(&logon_response(0), &no_columns()).unwrap();
    let logon = responses.first().unwrap();
    assert!(logon.as_logon().is_some());
    assert!(logon.as_query_rows().is_none());
    assert!(logon.failure().is_none());
}

#[test]
fn hostile_rop_streams_never_panic() {
    for stream in [
        &b""[..],
        &[0xFE][..],
        &[0xFE, 0x00][..],
        &[0xFE, 0x00, 0x00, 0x00][..],
        &[0xF9, 0x00][..],
        &[0xFF][..],
        &[0xFF; 40][..],
    ] {
        let _ = decode_all(stream, &no_columns());
        let _ = decode_all(stream, &hierarchy_columns_at(0));
    }
}
