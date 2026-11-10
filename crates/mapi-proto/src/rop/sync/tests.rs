use super::*;
use crate::error::ErrorCode;
use crate::oxcdata::{FileTime, PropertyValue, RelationalOperator, TaggedValue};
use crate::rop::{Decoding, RopResponse, decode_all};

fn encoded(encode: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut w = Writer::new();
    encode(&mut w);
    w.finish()
}

fn decode(rops: &[u8]) -> Vec<RopResponse> {
    decode_all(
        rops,
        Decoding {
            columns: &[],
            property_tags: &[],
        },
    )
    .unwrap()
}

/// The default download, field by field against [MS-OXCROPS] §2.2.13.1.1: contents; `Unicode`,
/// `RecoverMode` and `ForceUnicode`; `Unicode`, `ReadState`, `Normal` and `NoForeignIdentifiers`;
/// no restriction; `Eid`, `MessageSize` and `CN`; no property list.
#[test]
fn the_default_download_sets_what_checkpointing_and_unicode_need() {
    let bytes = encoded(|w| encode_configure(w, 1, 2, &ContentsDownload::new()).unwrap());
    assert_eq!(
        bytes,
        [
            0x70, 0x00, 0x01, 0x02, // RopId, LogonId, InputHandleIndex, OutputHandleIndex
            0x01, // SynchronizationType: Contents
            0x0D, // SendOptions: Unicode | RecoverMode | ForceUnicode
            0x29,
            0x01, // SynchronizationFlags: Unicode | ReadState | Normal | NoForeignIdentifiers
            0x00, 0x00, // RestrictionDataSize
            0x07, 0x00, 0x00, 0x00, // SynchronizationExtraFlags: Eid | MessageSize | CN
            0x00, 0x00, // PropertyTagCount
        ]
    );
}

/// Every choice, each landing on the bit its section names, and a restriction and a property list
/// counted by their 16-bit fields.
#[test]
fn every_choice_lands_on_its_own_bit() {
    let floor = Restriction::property(
        RelationalOperator::GreaterThanOrEqual,
        TaggedValue::new(
            PropertyTag::MESSAGE_DELIVERY_TIME,
            PropertyValue::Time(FileTime::new(1)),
        )
        .unwrap(),
    );
    let download = ContentsDownload::new()
        .restriction(floor.clone())
        .properties(PropertyFilter::Only(vec![PropertyTag::SUBJECT]))
        .messages(MessageKinds::Both)
        .read_state(false)
        .partial_items(true)
        .progress(true)
        .newest_first(true);
    assert_eq!(download.restriction_ref(), Some(&floor));
    let bytes = encoded(|w| encode_configure(w, 0, 1, &download).unwrap());

    assert_eq!(bytes[5], 0x1D, "PartialItem joins the three always set");
    assert_eq!(
        u16::from_le_bytes([bytes[6], bytes[7]]),
        0x0001 | 0x0010 | 0x0020 | 0x0080 | 0x0100 | 0x8000,
        "FAI, Normal, OnlySpecifiedProperties and Progress; no ReadState"
    );
    let restriction_size = usize::from(u16::from_le_bytes([bytes[8], bytes[9]]));
    let mut packet = Writer::new();
    floor.write(&mut packet, ValueContext::Object).unwrap();
    assert_eq!(
        &bytes[10..10 + restriction_size],
        packet.finish().as_slice()
    );
    let after = 10 + restriction_size;
    assert_eq!(
        u32::from_le_bytes(bytes[after..after + 4].try_into().unwrap()),
        0x0000_000F,
        "OrderByDeliveryTime joins Eid, MessageSize and CN"
    );
    assert_eq!(&bytes[after + 4..], [0x01, 0x00, 0x1F, 0x00, 0x37, 0x00]);

    let except = ContentsDownload::new()
        .properties(PropertyFilter::Except(vec![PropertyTag::BODY]))
        .messages(MessageKinds::Associated);
    let bytes = encoded(|w| encode_configure(w, 0, 1, &except).unwrap());
    assert_eq!(
        u16::from_le_bytes([bytes[6], bytes[7]]) & (0x0080 | 0x0020 | 0x0010),
        0x0010,
        "an exclusion list does not set OnlySpecifiedProperties"
    );
}

/// The state upload and the buffer request, against [MS-OXCROPS] §2.2.13.9.1 to §2.2.13.11.1 and
/// §2.2.12.4.1.
#[test]
fn the_upload_and_fetch_requests_match_their_layouts() {
    assert_eq!(
        encoded(|w| encode_upload_state_begin(w, 2, PropertyTag::META_TAG_CNSET_SEEN, 29)),
        [
            0x75, 0x00, 0x02, 0x02, 0x01, 0x96, 0x67, 0x1D, 0x00, 0x00, 0x00
        ]
    );
    assert_eq!(
        encoded(|w| encode_upload_state_continue(w, 2, &[0xAA, 0xBB]).unwrap()),
        [0x76, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB]
    );
    assert_eq!(
        encoded(|w| encode_upload_state_end(w, 2)),
        [0x77, 0x00, 0x02]
    );
    assert_eq!(
        encoded(|w| encode_get_transfer_state(w, 2, 3)),
        [0x82, 0x00, 0x02, 0x03]
    );
    assert_eq!(
        encoded(|w| encode_get_buffer(w, 2)),
        [0x4E, 0x00, 0x02, 0xBE, 0xBA, 0xFF, 0xFF],
        "BufferSize is the 0xBABE sentinel, so MaximumBufferSize follows"
    );
}

/// A buffer, then the two configure-side ROPs that answer with a bare `ReturnValue`.
#[test]
fn a_buffer_decodes_with_its_status_and_bytes() {
    let mut rops = vec![0x4E, 0x02, 0x00, 0x00, 0x00, 0x00];
    rops.extend_from_slice(&[0x01, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00]);
    rops.extend_from_slice(&[0xC0, 0xFF, 0xEE]);
    rops.extend_from_slice(&[0x70, 0x01, 0x00, 0x00, 0x00, 0x00]);
    rops.extend_from_slice(&[0x77, 0x01, 0x00, 0x00, 0x00, 0x00]);
    let responses = decode(&rops);

    let buffer = responses[0].as_fast_transfer_buffer().unwrap();
    assert_eq!(buffer.status(), TransferStatus::Partial);
    assert!(!buffer.status().is_final());
    assert_eq!(buffer.in_progress(), 5);
    assert_eq!(buffer.total_steps(), 1);
    assert_eq!(buffer.data(), [0xC0, 0xFF, 0xEE]);
    assert_eq!(buffer.clone().into_data(), vec![0xC0, 0xFF, 0xEE]);
    assert!(responses[1].succeeded(RopId::SYNCHRONIZATION_CONFIGURE));
    assert!(responses[2].succeeded(RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_END));
}

/// `ServerBusy` is the refusal that carries a body: the transfer fields and a `BackoffTime`. Read
/// as a bare failure, those bytes would be taken as the next ROP.
#[test]
fn a_busy_server_says_how_long_to_wait_and_the_next_rop_still_decodes() {
    let mut rops = vec![0x4E, 0x02, 0x80, 0x04, 0x00, 0x00];
    rops.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    rops.extend_from_slice(&5_000_u32.to_le_bytes());
    rops.extend_from_slice(&[0x77, 0x01, 0x00, 0x00, 0x00, 0x00]);
    let responses = decode(&rops);

    assert_eq!(
        responses[0],
        RopResponse::FastTransferBusy { backoff_ms: 5_000 }
    );
    assert_eq!(responses[0].failure(), Some(ErrorCode::SERVER_BUSY));
    assert!(responses[1].succeeded(RopId::SYNCHRONIZATION_UPLOAD_STATE_STREAM_END));
}

/// Any other refusal carries the transfer fields and a buffer too, unlike almost every other ROP's.
/// These are the bytes Exchange Server SE `15.02.2562.056` sent for a `GetBuffer` aimed at a folder
/// handle: `ecNotSupported`, nine zero bytes, and the next ROP.
#[test]
fn another_refusal_carries_the_transfer_fields_and_the_next_rop_still_decodes() {
    let mut rops = vec![0x4E, 0x02, 0x02, 0x01, 0x04, 0x80];
    rops.extend_from_slice(&[0x00; 9]);
    rops.extend_from_slice(&[0x70, 0x01, 0x00, 0x00, 0x00, 0x00]);
    let responses = decode(&rops);
    assert_eq!(
        responses[0],
        RopResponse::Failed {
            rop: RopId::FAST_TRANSFER_SOURCE_GET_BUFFER,
            code: ErrorCode::NOT_SUPPORTED,
        }
    );
    assert!(responses[1].succeeded(RopId::SYNCHRONIZATION_CONFIGURE));

    // Should a server ever put bytes in a refusal's buffer, they are skipped, not decoded as ROPs.
    let mut rops = vec![0x4E, 0x02, 0x0F, 0x01, 0x04, 0x80];
    rops.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xAB, 0xCD,
    ]);
    rops.extend_from_slice(&[0x70, 0x01, 0x00, 0x00, 0x00, 0x00]);
    let responses = decode(&rops);
    assert_eq!(responses[0].failure(), Some(ErrorCode::NOT_FOUND));
    assert!(responses[1].succeeded(RopId::SYNCHRONIZATION_CONFIGURE));
}

#[test]
fn transfer_statuses_are_the_four_the_document_lists() {
    for (raw, status, last) in [
        (0, TransferStatus::Error, true),
        (1, TransferStatus::Partial, false),
        (2, TransferStatus::NoRoom, false),
        (3, TransferStatus::Done, true),
        (9, TransferStatus::Other(9), false),
    ] {
        assert_eq!(TransferStatus::from_u16(raw), status);
        assert_eq!(status.is_final(), last);
    }
}

#[test]
fn truncated_buffers_never_panic() {
    let whole = [
        0x01, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0xC0, 0xFF, 0xEE,
    ];
    for end in 0..whole.len() {
        assert!(GetBufferResponse::read(&mut Reader::new(&whole[..end])).is_err());
        let _ = read_refusal(&mut Reader::new(&whole[..end]), ErrorCode::SERVER_BUSY);
        let _ = read_refusal(&mut Reader::new(&whole[..end]), ErrorCode::NOT_FOUND);
    }
}
