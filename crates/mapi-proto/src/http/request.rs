//! Request types, their bodies, and the headers that have to go with them.
//!
//! The auxiliary buffer is sent **empty** throughout. [MS-OXCRPC] §3.1.4.1 fails a request only
//! when the auxiliary length is between 1 and 7 — "you claimed a buffer too short to hold an
//! `RPC_HEADER_EXT`". Zero is outside that band, which defers the whole auxiliary-block layer.
//! Measured against Exchange Server SE `15.02.2562.045`: accepted on `Connect`, `Execute` and
//! `Disconnect` alike, `X-ResponseCode: 0` from all three.
//!
//! [MS-OXCMAPIHTTP] §2.2.2.1 — common request format
//! [MS-OXCMAPIHTTP] §2.2.4 — request types for the mailbox server endpoint

use crate::http::Headers;
use crate::oxcdata::LegacyDn;
use crate::wire::Writer;

/// `Connect`'s `Flags`, where `0x00000000` requests a connection **without** administrator
/// privilege.
///
/// A trap worth naming: `Connect`'s `Flags` is not `Execute`'s. Here bit 0 asks for
/// administrator privilege ([MS-OXCRPC] §3.1.4.1 `ulFlags`); on `Execute` the low bits mean "do
/// not compress" and "do not obfuscate". Setting `1` here — which at least one widely-copied
/// reference client does, under a comment about compression — gets an ordinary user's logon
/// refused with `LoginPermission`, which reads like an authentication failure and is not one.
const CONNECT_NO_ADMIN_PRIVILEGE: u32 = 0x0000_0000;

/// `DefaultCodePage`: Windows-1252. Requesting `PtypString` columns means text comes back as
/// UTF-16 regardless, so this never decides an encoding in practice.
const CONNECT_CODE_PAGE: u32 = 1252;

/// A language code identifier: the locale a Session Context runs under.
///
/// `Connect` carries two of these and neither is negotiated. The success response body
/// ([MS-OXCMAPIHTTP] §2.2.4.1.2) reports no locale back, and no ROP changes one afterwards, so
/// whatever is sent at `Connect` is what the Session Context uses until it is torn down. That is
/// why this is a connect-time decision rather than something read off the mailbox later.
///
/// This is *not* the mailbox's own configured locale, and does not become it. That one is a
/// property of the Logon object — `PidTagLocaleId` for system-generated messages,
/// `PidTagSortLocaleId` for table sorting — and is read after logon rather than set here.
/// Connecting to an en-US mailbox under nl-NL was measured against Exchange Server SE
/// `15.02.2562.045`: the hierarchy came back with its fifteen folder names byte-for-byte identical
/// to the en-US session's, `Inbox` still `Inbox`. The locale sent here asks for the session's
/// treatment of data; it does not translate what the mailbox already holds.
///
/// ```
/// use mapi_proto::Lcid;
///
/// assert_eq!(Lcid::default(), Lcid::EN_US);
/// assert_eq!(Lcid::new(0x0413).as_u32(), 0x0413); // nl-NL
/// ```
///
/// [MS-LCID] — the identifier values themselves
/// [MS-OXCMAPIHTTP] §2.2.4.1.1 — `LcidSort`, `LcidString`
/// [MS-OXCSTOR] §2.2.2.1.1.12, §2.2.2.1.1.14 — `PidTagLocaleId`, `PidTagSortLocaleId`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lcid(u32);

impl Lcid {
    /// en-US, `0x0409` — this crate's default.
    pub const EN_US: Self = Self(0x0000_0409);

    /// Wraps a raw LCID as it appears on the wire.
    ///
    /// No validation happens here — [MS-LCID] assigns hundreds of values and which of them a
    /// deployment supports is not a question a client can answer offline — and, measured, none
    /// happens at the far end either: Exchange Server SE `15.02.2562.045` accepted `Connect` with
    /// `0xDEADBEEF` and with `0` exactly as readily as with en-US, `X-ResponseCode: 0` every time.
    ///
    /// So a wrong identifier is not reported at connect time, and no ROP in [MS-OXCROPS] revisits
    /// the subject. If it surfaces at all it surfaces wherever the server eventually consults it,
    /// far from the call that set it. Send one you mean.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The identifier as the little-endian `u32` the wire carries.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl Default for Lcid {
    fn default() -> Self {
        Self::EN_US
    }
}

/// `Execute`'s `Flags`: do not compress the response payload.
///
/// [MS-OXCMAPIHTTP] §2.2.4.2.1 — `Flags`
const EXECUTE_NO_COMPRESSION: u32 = 0x0000_0001;

/// `Execute`'s `Flags`: do not obfuscate the response payload with the 0xA5 XOR.
const EXECUTE_NO_XOR_MAGIC: u32 = 0x0000_0002;

/// `MaxRopOut`: the largest ROP output buffer the server may return, 64 KiB.
///
/// Too small a value comes back as `RopBufferTooSmall` carrying the size actually needed.
///
/// [MS-OXCMAPIHTTP] §2.2.4.2.1 — `MaxRopOut`
const MAX_ROP_OUT: u32 = 0x0001_0000;

/// `AuxiliaryBufferSize`: none. See the module documentation for why zero is safe where 1 to 7
/// is not.
const EMPTY_AUXILIARY_BUFFER: u32 = 0;

/// A MAPI/HTTP request type, as the `X-RequestType` header names it.
///
/// [MS-OXCMAPIHTTP] §2.2.3.3.1 — `X-RequestType`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RequestType {
    /// Establishes a Session Context. [MS-OXCMAPIHTTP] §2.2.4.1
    Connect,
    /// Runs a ROP buffer. [MS-OXCMAPIHTTP] §2.2.4.2
    Execute,
    /// Ends the Session Context. [MS-OXCMAPIHTTP] §2.2.4.3
    Disconnect,
    /// Asks whether the endpoint is reachable. [MS-OXCMAPIHTTP] §2.2.6
    Ping,
}

impl RequestType {
    /// The `X-RequestType` header value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "Connect",
            Self::Execute => "Execute",
            Self::Disconnect => "Disconnect",
            Self::Ping => "PING",
        }
    }
}

impl core::fmt::Display for RequestType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A request for the caller to send: which request type it is, the headers it needs, and the body.
///
/// This crate never sends anything. POST the body to the endpoint with these headers, by whatever
/// means the application already uses, and hand the response back to
/// [`Session::on_response`](crate::Session::on_response).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    kind: RequestType,
    headers: Headers,
    body: Vec<u8>,
}

impl Request {
    pub(crate) const fn new(kind: RequestType, headers: Headers, body: Vec<u8>) -> Self {
        Self {
            kind,
            headers,
            body,
        }
    }

    /// Which request type this is.
    #[must_use]
    pub const fn request_type(&self) -> RequestType {
        self.kind
    }

    /// The headers to send, including `Content-Type`, `X-RequestType`, `X-RequestId` and — once a
    /// Session Context exists — `Cookie`.
    #[must_use]
    pub const fn headers(&self) -> &Headers {
        &self.headers
    }

    /// The body to POST.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Takes the body, for a transport that wants to own it.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// Encodes a `Connect` request body.
///
/// The two locales are written in the order the structure declares them: sorting first, everything
/// else second. They are separate fields because they answer separate questions, and a client that
/// swaps them sorts in one language and reads in another.
///
/// [MS-OXCMAPIHTTP] §2.2.4.1.1 — request body
pub(crate) fn connect_body(user_dn: &LegacyDn, lcid_sort: Lcid, lcid_string: Lcid) -> Vec<u8> {
    let mut w = Writer::new();
    w.ascii_z(user_dn.as_str())
        .u32(CONNECT_NO_ADMIN_PRIVILEGE)
        .u32(CONNECT_CODE_PAGE)
        .u32(lcid_sort.as_u32())
        .u32(lcid_string.as_u32())
        .u32(EMPTY_AUXILIARY_BUFFER);
    w.finish()
}

/// Encodes an `Execute` request body around a serialised ROP buffer.
///
/// [MS-OXCMAPIHTTP] §2.2.4.2.1 — request body
pub(crate) fn execute_body(rop_buffer: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(EXECUTE_NO_COMPRESSION | EXECUTE_NO_XOR_MAGIC)
        .u32(u32::try_from(rop_buffer.len()).unwrap_or(u32::MAX))
        .bytes(rop_buffer)
        .u32(MAX_ROP_OUT)
        .u32(EMPTY_AUXILIARY_BUFFER);
    w.finish()
}

/// Encodes a `Disconnect` request body: an empty auxiliary buffer and nothing else.
///
/// [MS-OXCMAPIHTTP] §2.2.4.3.1 — request body
pub(crate) fn disconnect_body() -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(EMPTY_AUXILIARY_BUFFER);
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector, hand-computed from §2.2.4.1.1. Locking the layout offline is what makes a
    /// live failure mean "the server disagrees" rather than "we cannot serialise".
    #[test]
    fn connect_body_matches_the_spec_layout() {
        let dn = LegacyDn::new("/o=X").unwrap();
        let body = connect_body(&dn, Lcid::EN_US, Lcid::EN_US);

        #[rustfmt::skip]
        let expected = vec![
            b'/', b'o', b'=', b'X', 0x00,   // UserDn, null-terminated
            0x00, 0x00, 0x00, 0x00,         // Flags = 0, no administrator privilege
            0xE4, 0x04, 0x00, 0x00,         // DefaultCodePage = 1252
            0x09, 0x04, 0x00, 0x00,         // LcidSort = 0x0409
            0x09, 0x04, 0x00, 0x00,         // LcidString = 0x0409
            0x00, 0x00, 0x00, 0x00,         // AuxiliaryBufferSize = 0
        ];
        assert_eq!(body, expected);
        assert_eq!(body.len(), 5 + 20);
    }

    /// Two fields of the same type, side by side, is exactly the shape a swap hides in. Distinct
    /// values on each side is what makes the order testable at all.
    #[test]
    fn connect_body_writes_sort_before_string() {
        let dn = LegacyDn::new("/o=X").unwrap();
        let body = connect_body(&dn, Lcid::new(0x0413), Lcid::new(0x0407));

        assert_eq!(&body[13..17], &[0x13, 0x04, 0x00, 0x00]); // LcidSort = nl-NL
        assert_eq!(&body[17..21], &[0x07, 0x04, 0x00, 0x00]); // LcidString = de-DE
    }

    #[test]
    fn an_lcid_round_trips_its_raw_value() {
        assert_eq!(Lcid::default(), Lcid::EN_US);
        assert_eq!(Lcid::EN_US.as_u32(), 0x0000_0409);
        assert_eq!(Lcid::new(0x0413).as_u32(), 0x0000_0413);
    }

    #[test]
    fn execute_body_matches_the_spec_layout() {
        #[rustfmt::skip]
        let expected = vec![
            0x03, 0x00, 0x00, 0x00, // Flags = NoCompression | NoXorMagic
            0x02, 0x00, 0x00, 0x00, // RopBufferSize
            0xAA, 0xBB,             // RopBuffer
            0x00, 0x00, 0x01, 0x00, // MaxRopOut = 0x00010000
            0x00, 0x00, 0x00, 0x00, // AuxiliaryBufferSize = 0
        ];
        assert_eq!(execute_body(&[0xAA, 0xBB]), expected);
    }

    #[test]
    fn disconnect_body_is_just_an_empty_auxiliary_buffer() {
        assert_eq!(disconnect_body(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn request_types_carry_their_header_values() {
        for (request_type, value) in [
            (RequestType::Connect, "Connect"),
            (RequestType::Execute, "Execute"),
            (RequestType::Disconnect, "Disconnect"),
            (RequestType::Ping, "PING"),
        ] {
            assert_eq!(request_type.as_str(), value);
            assert_eq!(request_type.to_string(), value);
        }
    }

    #[test]
    fn a_request_hands_over_its_parts() {
        let mut headers = Headers::new();
        headers.append("X-RequestType", "Connect");
        let request = Request::new(RequestType::Connect, headers, vec![0x01, 0x02]);

        assert_eq!(request.request_type(), RequestType::Connect);
        assert_eq!(request.headers().get("x-requesttype"), Some("Connect"));
        assert_eq!(request.body(), &[0x01, 0x02]);
        assert_eq!(request.into_body(), vec![0x01, 0x02]);
    }
}
