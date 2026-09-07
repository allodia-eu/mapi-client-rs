//! The responses that break a positional decoder: the ones that arrive out of turn, and the two
//! refusals that carry a body where a refusal is supposed to stop.
//!
//! Its own file because these are the reason [`decode`](super::super::decode) is not a `match` on
//! a request list, and because each of them fails the same way — not with an error, but with every
//! later response in the buffer decoded against bytes that belong to this one.

use super::super::*;
use super::{against, no_columns};
use crate::rop::response::decode::decode_all;
use crate::wire::Writer;

/// The second refusal that does not stop after `ReturnValue`, and the one that costs five bytes
/// rather than a whole server name. Its `DestHandleIndex` is four bytes where the request's field
/// is one, so a decoder that treated it as an ordinary failure would take the next `RopId` from
/// the middle of it — and `0x00` is not a modelled ROP, so the failure would arrive as
/// `UnmodelledRop` several responses later with nothing pointing back here.
///
/// [MS-OXCROPS] §2.2.4.6.3
#[test]
fn a_null_destination_move_is_read_past_its_handle_index() {
    // `DestHandleIndex` is four bytes and `PartialCompletion` is one, which is the whole of the
    // body a refusal is not supposed to have.
    const DESTINATION: u32 = 2;
    const PARTIAL: u8 = 1;

    let mut w = Writer::new();
    w.u8(RopId::MOVE_COPY_MESSAGES.as_u8())
        .u8(1)
        .u32(ErrorCode::NULL_DESTINATION_OBJECT.as_u32())
        .u32(DESTINATION)
        .u8(PARTIAL);
    w.u8(RopId::SET_COLUMNS.as_u8()).u8(2).u32(0).u8(0);

    let responses = decode_all(&w.finish(), against(&no_columns())).unwrap();
    assert_eq!(responses.len(), 2);
    assert!(
        responses
            .first()
            .and_then(RopResponse::as_moved_messages)
            .is_some_and(MoveCopyMessagesResponse::is_partial)
    );
    assert!(
        matches!(responses.get(1), Some(RopResponse::SetColumns(_))),
        "the ROP after a null-destination refusal must still decode"
    );

    // Every other refusal of the same ROP stops where refusals stop. `ecNullObject` is four codes
    // away from `ecDstNullObject` and is about the *source* handle, so it is the one most likely
    // to be treated as the special case by mistake.
    let mut w = Writer::new();
    w.u8(RopId::MOVE_COPY_MESSAGES.as_u8())
        .u8(1)
        .u32(0x0000_04B9);
    w.u8(RopId::SET_COLUMNS.as_u8()).u8(2).u32(0).u8(0);

    let responses = decode_all(&w.finish(), against(&no_columns())).unwrap();
    assert_eq!(
        responses.first().and_then(RopResponse::failure),
        Some(ErrorCode::new(0x0000_04B9))
    );
    assert!(matches!(responses.get(1), Some(RopResponse::SetColumns(_))));
}

/// Nothing here asks for an asynchronous run — every ROP that could is sent with
/// `WantAsynchronous = 0` — so this is about a server that sends one anyway. Nine bytes are read
/// where none was expected, and the ROP after it still has to decode.
///
/// [MS-OXCROPS] §2.2.8.13.2
#[test]
fn an_unasked_for_progress_response_does_not_desynchronise_the_buffer() {
    // A `LogonId`, then the two counts — nine bytes where a decoder that did not know this ROP
    // would expect none.
    const LOGON_ID: u8 = 0;
    const COMPLETED: u32 = 3;
    const TOTAL: u32 = 7;

    let mut w = Writer::new();
    w.u8(RopId::PROGRESS.as_u8())
        .u8(1)
        .u32(0)
        .u8(LOGON_ID)
        .u32(COMPLETED)
        .u32(TOTAL);
    w.u8(RopId::SET_COLUMNS.as_u8()).u8(2).u32(0).u8(0);

    let responses = decode_all(&w.finish(), against(&no_columns())).unwrap();
    assert_eq!(responses.len(), 2);
    let progress = responses
        .first()
        .and_then(RopResponse::as_progress)
        .expect("a progress response");
    assert_eq!(progress.completed(), 3);
    assert_eq!(progress.total(), 7);
    assert!(matches!(responses.get(1), Some(RopResponse::SetColumns(_))));
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
