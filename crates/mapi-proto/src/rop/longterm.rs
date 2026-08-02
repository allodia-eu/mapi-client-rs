//! The two ROPs that convert between short-term and long-term identifiers.
//!
//! A folder's entry id names it by a 16-byte database GUID; `RopOpenFolder` takes a 2-byte replica
//! id. **Only the server holds the mapping between them**, so this pair is a round trip and not
//! arithmetic — which is why reaching the Calendar folder costs a request that reaching the Inbox
//! does not.
//!
//! Both operate on the Logon object, and both are cheap enough to batch: eight conversions travel
//! in one `Execute`.
//!
//! [MS-OXCROPS] §2.2.3.8 — `RopLongTermIdFromId`
//! [MS-OXCROPS] §2.2.3.9 — `RopIdFromLongTermId`
//! [MS-OXCSTOR] §2.2.1.8, §2.2.1.9 — semantics

use crate::error::Result;
use crate::oxcdata::{LongTermId, ShortTermId};
use crate::rop::RopId;
use crate::rop::batch::LOGON_ID;
use crate::wire::{Reader, Writer};

/// The short-term identifier `RopIdFromLongTermId` answered with.
///
/// [MS-OXCROPS] §2.2.3.9.2 — success response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdFromLongTermIdResponse {
    id: ShortTermId,
}

impl IdFromLongTermIdResponse {
    /// The identifier, which is a folder id or a message id depending on what was converted.
    #[must_use]
    pub const fn id(self) -> ShortTermId {
        self.id
    }

    /// Reads the response body, after `RopId`, `InputHandleIndex` and a zero `ReturnValue`.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            id: ShortTermId::new(r.u64()?),
        })
    }
}

/// The long-term identifier `RopLongTermIdFromId` answered with.
///
/// [MS-OXCROPS] §2.2.3.8.2 — success response buffer
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongTermIdFromIdResponse {
    id: LongTermId,
}

impl LongTermIdFromIdResponse {
    /// The long-term identifier.
    #[must_use]
    pub const fn id(self) -> LongTermId {
        self.id
    }

    /// Reads the response body, after `RopId`, `InputHandleIndex` and a zero `ReturnValue`.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            id: LongTermId::read(r)?,
        })
    }
}

/// Encodes a `RopIdFromLongTermId` request.
///
/// [MS-OXCROPS] §2.2.3.9.1 — request buffer
pub(crate) fn encode_id_from_long_term_id(w: &mut Writer, input: u8, id: &LongTermId) {
    w.u8(RopId::ID_FROM_LONG_TERM_ID.as_u8())
        .u8(LOGON_ID)
        .u8(input);
    id.write(w);
}

/// Encodes a `RopLongTermIdFromId` request.
///
/// [MS-OXCROPS] §2.2.3.8.1 — request buffer
pub(crate) fn encode_long_term_id_from_id(w: &mut Writer, input: u8, id: ShortTermId) {
    w.u8(RopId::LONG_TERM_ID_FROM_ID.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u64(id.as_u64());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oxcdata::{FolderId, Guid};

    fn long_term_id() -> LongTermId {
        LongTermId::new(
            Guid::from_bytes([
                0x02, 0x27, 0x39, 0x56, 0x14, 0x8B, 0xEF, 0x4F, 0x98, 0x14, 0x81, 0x7E, 0x2C, 0x82,
                0xBD, 0xC2,
            ]),
            [0x00, 0x00, 0x01, 0x50, 0x4D, 0xF6],
        )
    }

    /// [MS-OXOSFLD] §4.1.1 shows a client asking for exactly this conversion; the request is
    /// `RopId`, `LogonId`, `InputHandleIndex` and then the 24 bytes verbatim.
    #[test]
    fn id_from_long_term_id_carries_the_structure_unchanged() {
        let mut w = Writer::new();
        encode_id_from_long_term_id(&mut w, 0, &long_term_id());
        let bytes = w.finish();

        assert_eq!(bytes.len(), 3 + LongTermId::SIZE);
        assert_eq!(&bytes[..3], &[0x44, 0x00, 0x00]);
        #[rustfmt::skip]
        assert_eq!(
            &bytes[3..],
            &[
                0x02, 0x27, 0x39, 0x56, 0x14, 0x8B, 0xEF, 0x4F,
                0x98, 0x14, 0x81, 0x7E, 0x2C, 0x82, 0xBD, 0xC2,
                0x00, 0x00, 0x01, 0x50, 0x4D, 0xF6,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn long_term_id_from_id_carries_an_eight_byte_object_id() {
        let mut w = Writer::new();
        encode_long_term_id_from_id(
            &mut w,
            2,
            ShortTermId::from(FolderId::new(0x0001_0000_0000_1234)),
        );

        #[rustfmt::skip]
        assert_eq!(
            w.finish(),
            vec![
                0x43, 0x00, 0x02,
                0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            ]
        );
    }

    /// Encode then decode, which is what proves the 24 bytes this crate writes are the 24 it can
    /// read — the property tail goes onto the wire and comes back through the other ROP.
    #[test]
    fn the_two_rops_round_trip_through_each_others_shapes() {
        let mut w = Writer::new();
        encode_id_from_long_term_id(&mut w, 0, &long_term_id());
        let request = w.finish();

        let mut r = Reader::new(&request[3..]);
        assert_eq!(
            LongTermIdFromIdResponse::read(&mut r),
            Ok(LongTermIdFromIdResponse { id: long_term_id() })
        );
        assert!(r.is_empty());
    }

    #[test]
    fn a_short_term_id_response_is_eight_bytes() {
        let buf = [0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xEE];
        let mut r = Reader::new(&buf);
        let response = IdFromLongTermIdResponse::read(&mut r).expect("an object id");
        assert_eq!(
            response.id().as_folder_id(),
            FolderId::new(0x0001_0000_0000_1234)
        );
        assert_eq!(r.rest(), &[0xEE]);
    }

    #[test]
    fn truncated_conversion_responses_never_panic() {
        for length in 0..LongTermId::SIZE {
            let buf = vec![0_u8; length];
            assert!(LongTermIdFromIdResponse::read(&mut Reader::new(&buf)).is_err());
        }
        for length in 0..8 {
            let buf = vec![0_u8; length];
            assert!(IdFromLongTermIdResponse::read(&mut Reader::new(&buf)).is_err());
        }
    }
}
