use super::*;
use crate::oxcdata::{HIERARCHY_COLUMNS, PropertyName, PropertyTag, PropertyValue, TableString};
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

/// The context a batch would have supplied, for a stream that contains no property fetch.
fn against(columns: &[Option<Vec<PropertyTag>>]) -> Decoding<'_> {
    Decoding {
        columns,
        property_tags: &[],
    }
}

#[test]
fn decodes_a_logon_response() {
    let columns = no_columns();
    let responses = decode_all(&logon_response(0), against(&columns)).unwrap();
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

    let responses = decode_all(&w.finish(), against(&hierarchy_columns_at(2))).unwrap();
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

    let responses = decode_all(&w.finish(), against(&no_columns())).unwrap();
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

    let responses = decode_all(&w.finish(), against(&no_columns())).unwrap();
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

    let responses = decode_all(&w.finish(), against(&no_columns())).unwrap();
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

    let responses = decode_all(&w.finish(), against(&no_columns())).unwrap();
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
        decode_all(&stream, against(&no_columns())),
        Err(Error::UnknownColumns { handle_index: 3 })
    );
}

/// A `RopGetPropertiesSpecific` response carries values and no tags, so it can only be decoded
/// against the tags of the request that asked for them — which live in the batch, not the stream.
#[test]
fn a_property_fetch_decodes_against_the_tags_its_request_carried() {
    let mut w = Writer::new();
    w.u8(RopId::GET_PROPERTIES_SPECIFIC.as_u8())
        .u8(0)
        .u32(0)
        .u8(0x00)
        .utf16_z("Developer");

    let tags = vec![vec![PropertyTag::DISPLAY_NAME]];
    let responses = decode_all(
        &w.finish(),
        Decoding {
            columns: &no_columns(),
            property_tags: &tags,
        },
    )
    .unwrap();

    assert_eq!(
        responses
            .first()
            .and_then(RopResponse::as_properties)
            .and_then(|set| set.string(PropertyTag::DISPLAY_NAME))
            .map(TableString::as_str),
        Some("Developer")
    );
}

/// **Two fetches on one object in one batch are two different questions.** The tag lists are
/// consumed in order rather than looked up by handle, because the handle is the same for both and
/// answering the second against the first's tags would decode a plausible-looking wrong value.
#[test]
fn two_fetches_on_one_handle_each_decode_against_their_own_tags() {
    let mut w = Writer::new();
    w.u8(RopId::GET_PROPERTIES_SPECIFIC.as_u8())
        .u8(0)
        .u32(0)
        .u8(0x00)
        .utf16_z("Developer");
    w.u8(RopId::GET_PROPERTIES_SPECIFIC.as_u8())
        .u8(0)
        .u32(0)
        .u8(0x00)
        .u32(42);

    let tags = vec![
        vec![PropertyTag::DISPLAY_NAME],
        vec![PropertyTag::CONTENT_COUNT],
    ];
    let responses = decode_all(
        &w.finish(),
        Decoding {
            columns: &no_columns(),
            property_tags: &tags,
        },
    )
    .unwrap();

    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses
            .get(1)
            .and_then(RopResponse::as_properties)
            .and_then(|set| set.get(PropertyTag::CONTENT_COUNT)),
        Some(&PropertyValue::Integer32(42))
    );
}

/// A refused fetch consumed its request's tags all the same. Leaving them in the queue would hand
/// them to the *next* fetch, which is the desynchronisation this queue exists to avoid.
#[test]
fn a_refused_fetch_still_consumes_the_tags_its_request_carried() {
    let mut w = Writer::new();
    w.u8(RopId::GET_PROPERTIES_SPECIFIC.as_u8())
        .u8(0)
        .u32(ErrorCode::ACCESS_DENIED.as_u32());
    w.u8(RopId::GET_PROPERTIES_SPECIFIC.as_u8())
        .u8(0)
        .u32(0)
        .u8(0x00)
        .u32(42);

    let tags = vec![
        vec![PropertyTag::DISPLAY_NAME],
        vec![PropertyTag::CONTENT_COUNT],
    ];
    let responses = decode_all(
        &w.finish(),
        Decoding {
            columns: &no_columns(),
            property_tags: &tags,
        },
    )
    .unwrap();

    assert_eq!(
        responses.first().and_then(RopResponse::failure),
        Some(ErrorCode::ACCESS_DENIED)
    );
    assert_eq!(
        responses
            .get(1)
            .and_then(RopResponse::as_properties)
            .and_then(|set| set.get(PropertyTag::CONTENT_COUNT)),
        Some(&PropertyValue::Integer32(42)),
        "the second fetch decoded against its own tags, not the first's"
    );
}

#[test]
fn a_fetch_response_with_no_request_behind_it_is_refused() {
    let mut w = Writer::new();
    w.u8(RopId::GET_PROPERTIES_SPECIFIC.as_u8())
        .u8(0)
        .u32(0)
        .u8(0x00);
    assert!(matches!(
        decode_all(&w.finish(), against(&no_columns())),
        Err(Error::UnrequestedProperties { .. })
    ));
}

/// `RopGetPropertiesAll` needs no such help: the tags are on the wire.
#[test]
fn an_all_fetch_needs_nothing_from_the_request() {
    let mut w = Writer::new();
    w.u8(RopId::GET_PROPERTIES_ALL.as_u8())
        .u8(0)
        .u32(0)
        .u16(1)
        .u32(PropertyTag::CONTENT_COUNT.as_u32())
        .u32(9);

    let responses = decode_all(&w.finish(), against(&no_columns())).unwrap();
    assert_eq!(
        responses
            .first()
            .and_then(RopResponse::as_properties)
            .and_then(|set| set.get(PropertyTag::CONTENT_COUNT)),
        Some(&PropertyValue::Integer32(9))
    );
}

#[test]
fn a_write_reports_its_problems_through_the_response_stream() {
    let mut w = Writer::new();
    w.u8(RopId::SET_PROPERTIES.as_u8()).u8(0).u32(0).u16(0);
    w.u8(RopId::DELETE_PROPERTIES.as_u8())
        .u8(0)
        .u32(0)
        .u16(1)
        .u16(0)
        .u32(PropertyTag::COMMENT.as_u32())
        .u32(ErrorCode::ACCESS_DENIED.as_u32());

    let responses = decode_all(&w.finish(), against(&no_columns())).unwrap();
    assert_eq!(responses.len(), 2);
    assert!(
        responses
            .first()
            .and_then(RopResponse::as_property_problems)
            .is_some_and(PropertyProblemsResponse::is_clean)
    );

    let deleted = responses
        .get(1)
        .and_then(RopResponse::as_property_problems)
        .unwrap();
    assert_eq!(deleted.rop(), RopId::DELETE_PROPERTIES);
    assert_eq!(deleted.problems().len(), 1);
}

#[test]
fn an_unmodelled_rop_stops_the_decode_rather_than_desynchronising() {
    let mut w = Writer::new();
    w.u8(0x09).u8(0).u32(0); // RopGetPropertiesList: valid, but not modelled here
    assert_eq!(
        decode_all(&w.finish(), against(&no_columns())),
        Err(Error::UnmodelledRop {
            rop: RopId::new(0x09),
            at: 6
        })
    );
}

#[test]
fn accessors_answer_only_for_their_own_response() {
    let responses = decode_all(&logon_response(0), against(&no_columns())).unwrap();
    let logon = responses.first().unwrap();
    assert!(logon.as_logon().is_some());
    assert!(logon.as_query_rows().is_none());
    assert!(logon.as_properties().is_none());
    assert!(logon.as_property_problems().is_none());
    assert!(logon.as_short_term_id().is_none());
    assert!(logon.as_long_term_id().is_none());
    assert!(logon.failure().is_none());

    // The two conversions answer for themselves and not for each other. They are the one pair here
    // whose payloads are both bare identifiers, so a caller reaching for the wrong accessor would
    // otherwise get a plausible number rather than nothing.
    let mut w = Writer::new();
    w.u8(RopId::ID_FROM_LONG_TERM_ID.as_u8())
        .u8(0)
        .u32(0)
        .u64(0x0001_0000_0000_1234);
    let short = decode_all(&w.finish(), against(&no_columns())).unwrap();
    let short = short.first().unwrap();
    assert_eq!(
        short.as_short_term_id().map(ShortTermId::as_u64),
        Some(0x0001_0000_0000_1234)
    );
    assert!(short.as_long_term_id().is_none());
    assert!(short.as_logon().is_none());
}

/// The two name ROPs answer in one stream, and each is decoded from its own `RopId` rather than
/// from its position — which is what lets a batch ask both questions of one object at once.
#[test]
fn both_name_ropes_decode_from_one_stream() {
    let name = PropertyName::lid(crate::oxcdata::PropertySetId::APPOINTMENT, 0x0000_8208);

    let mut w = Writer::new();
    w.u8(RopId::GET_PROPERTY_IDS_FROM_NAMES.as_u8())
        .u8(0)
        .u32(0)
        .u16(2)
        .u16(0x8205)
        // `0x0000` is what a name the server would not map comes back as, alongside a ROP that
        // succeeded. A caller that only checked the return value would read it as a property id.
        .u16(0x0000);
    w.u8(RopId::GET_NAMES_FROM_PROPERTY_IDS.as_u8())
        .u8(0)
        .u32(0)
        .u16(1);
    name.write(&mut w);

    let responses = decode_all(&w.finish(), against(&no_columns())).unwrap();
    assert_eq!(responses.len(), 2);

    let ids = responses.first().and_then(RopResponse::as_property_ids);
    assert_eq!(ids.map(PropertyIdsResponse::ids), Some(&[0x8205, 0][..]));

    let names = responses.get(1).and_then(RopResponse::as_property_names);
    assert_eq!(
        names.map(PropertyNamesResponse::names),
        Some(&[Some(name)][..])
    );

    // Neither answers for the other, and neither is a failure.
    assert!(responses.first().unwrap().as_property_names().is_none());
    assert!(responses.get(1).unwrap().as_property_ids().is_none());
    assert!(responses.iter().all(|r| r.failure().is_none()));
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
        let _ = decode_all(stream, against(&no_columns()));
        let _ = decode_all(stream, against(&hierarchy_columns_at(0)));
    }
}
