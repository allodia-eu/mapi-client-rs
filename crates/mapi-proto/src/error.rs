//! What can go wrong, and the server's own vocabulary for saying no.
//!
//! Two different things are called "an error" in MAPI, and keeping them apart is what lets a
//! caller tell a bug from a fact:
//!
//! * [`Error`] — these bytes could not be made sense of, or the caller asked for something the
//!   protocol does not allow at that point. Always actionable.
//! * [`ErrorCode`] — the server understood the request perfectly and refused it. `UnknownUser` is
//!   not a parser failure; it means the mailbox does not exist.
//!
//! [MS-OXCDATA] §2.4 — error codes
//! [MS-OXCDATA] §2.4.1 — additional error codes

use crate::http::ResponseCode;
use crate::oxcdata::{LegacyDn, PropertyTag, PropertyType};
use crate::rop::RopId;

/// The result of decoding or encoding MAPI wire data.
pub type Result<T> = core::result::Result<T, Error>;

/// Something this crate could not do.
///
/// Every variant carries the context needed to act on it — the offset a read ran off the end of,
/// the tag whose type is not modelled, the distinguished name a logon was refused for. A code
/// without its context turns a five-minute fix into an afternoon.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A field ran past the end of the buffer.
    #[error("truncated at {at}: need {need} bytes, {have} remain")]
    Truncated {
        /// Byte offset the read started at.
        at: usize,
        /// Bytes the field required.
        need: usize,
        /// Bytes actually left.
        have: usize,
    },

    /// A null-terminated string ran to the end of the buffer without its terminator.
    #[error("unterminated string at {at}")]
    Unterminated {
        /// Byte offset the string started at.
        at: usize,
    },

    /// A `PtypString` value held an unpaired UTF-16 surrogate.
    ///
    /// [MS-OXCDATA] §2.11.1 — `PtypString` is UTF-16LE
    #[error("invalid UTF-16 at {at}")]
    InvalidUtf16 {
        /// Byte offset the string started at.
        at: usize,
    },

    /// The server compressed or obfuscated a ROP buffer after being asked not to.
    ///
    /// Refused rather than decoded, because this crate implements neither the LZ77+DIRECT2 codec
    /// nor the 0xA5 obfuscation, and silently decoding the result as plain bytes yields garbage
    /// that looks like a protocol bug somewhere else entirely.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.2.1 — `NoCompression` / `NoXorMagic`
    #[error("ROP buffer is compressed or obfuscated (RPC_HEADER_EXT flags 0x{flags:04X})")]
    ObfuscatedRopBuffer {
        /// The `RPC_HEADER_EXT.Flags` value as received.
        flags: u16,
    },

    /// A property type this crate does not model.
    ///
    /// Values are not self-describing, so an unmodelled type cannot be skipped: its length is
    /// unknown and every later column in the row would decode against the wrong bytes.
    ///
    /// [MS-OXCDATA] §2.11.1 — property data types
    #[error("unsupported property type 0x{property_type:04X} at {at}")]
    UnsupportedPropertyType {
        /// The `PropertyType` half of the tag.
        property_type: u16,
        /// Byte offset of the value.
        at: usize,
    },

    /// A property fetch answered with a `PtypObject`, which is not a value.
    ///
    /// Its content is another Server object, reached with `RopOpenStream` or
    /// `RopOpenEmbeddedMessage`. There are no value bytes to consume, so decoding stops here
    /// rather than reading the next property's bytes as this one's.
    ///
    /// [MS-OXCDATA] §2.11.1.5 — `PtypObject` and `PtypEmbeddedTable` types
    #[error("PtypObject at {at} is not a value: read it with RopOpenStream")]
    ObjectPropertyValue {
        /// Byte offset where the value would have started.
        at: usize,
    },

    /// A value this crate will not put on the wire.
    ///
    /// Refused rather than written approximately. Every one of these would produce a buffer the
    /// server reads as something other than what was meant, and a silently wrong
    /// `RopSetProperties` sets a silently wrong property — which surfaces much later, somewhere
    /// else.
    #[error("cannot encode {value}: {reason}")]
    UnencodableValue {
        /// What was offered.
        value: &'static str,
        /// Why it cannot be carried.
        reason: &'static str,
    },

    /// A value was longer than its own COUNT field can describe.
    ///
    /// [MS-OXCDATA] §2.11.1.1 — COUNT data type values
    #[error("a {property_type} value holds {count}, past the {limit} its COUNT field can express")]
    ValueTooLarge {
        /// The type being written.
        property_type: PropertyType,
        /// What was offered.
        count: usize,
        /// The largest the COUNT field can express in this context.
        limit: usize,
    },

    /// A value was paired with a tag whose type half says something else.
    ///
    /// The two halves of a tag are the property's name and its layout, so a mismatch here does not
    /// produce a wrong answer — it produces a buffer the server parses as a different shape, and
    /// every field after it moves.
    ///
    /// [MS-OXCDATA] §2.9 — `PropertyTag` structure
    #[error(
        "{tag} declares {} but was given {}",
        .tag.property_type(),
        .value_type.map_or_else(|| "an absent value".to_owned(), |ptyp| ptyp.to_string())
    )]
    PropertyTypeMismatch {
        /// The tag that was named.
        tag: PropertyTag,
        /// The type of the value offered for it, or `None` if the value was absent.
        value_type: Option<PropertyType>,
    },

    /// A binary property value was not the Folder `EntryID` structure it was read as.
    ///
    /// The object-type check inside it is the one worth having: a folder's entry id and a
    /// message's are the same 46 bytes but for that field, so without it a mistyped tag opens
    /// something plausible rather than failing.
    ///
    /// [MS-OXCDATA] §2.2.4.1 — Folder `EntryID` structure
    #[error("not a folder EntryID ({length} bytes): {reason}")]
    InvalidEntryId {
        /// How long the value actually was.
        length: usize,
        /// Which of the structure's rules it broke.
        reason: &'static str,
    },

    /// A `PropertyName` carried a `Kind` other than `0x00`, `0x01` or `0xFF`.
    ///
    /// Which of the three it is decides whether a LID, a counted string or nothing follows, so an
    /// unrecognised kind leaves no way to know where this structure ends and the next begins.
    ///
    /// [MS-OXCDATA] §2.6.1 — `Kind`
    #[error("invalid PropertyName kind 0x{kind:02X} at {at}")]
    InvalidPropertyNameKind {
        /// The `Kind` byte as received.
        kind: u8,
        /// Byte offset the structure started at.
        at: usize,
    },

    /// A `TypedString` carried a `StringType` outside `0x00`–`0x04`.
    ///
    /// The byte says both whether a string follows and how wide its characters are, so an
    /// unrecognised value leaves no way to know where the field ends — and a `RopOpenMessage`
    /// response continues with a recipient table that would then be read from the wrong offset.
    ///
    /// [MS-OXCDATA] §2.11.7 — `TypedString` structure
    #[error("invalid TypedString StringType 0x{kind:02X} at {at}")]
    InvalidStringType {
        /// The `StringType` byte as received.
        kind: u8,
        /// Byte offset the structure started at.
        at: usize,
    },

    /// A stream read asked for more bytes than one `RopReadStream` response can carry.
    ///
    /// `DataSize` is two bytes ([MS-OXCROPS] §2.2.9.2.2), so a request for more than 65,535 could
    /// not be answered in full and the shortfall would look exactly like the end of the stream.
    #[error("a stream read of {wanted} bytes exceeds the {limit} one response can carry")]
    StreamReadTooLarge {
        /// How many bytes were asked for.
        wanted: usize,
        /// The most one response can hold.
        limit: usize,
    },

    /// A stream write offered more bytes than one `RopWriteStream` request can carry.
    ///
    /// `DataSize` is two bytes ([MS-OXCROPS] §2.2.9.3.1), so the surplus would simply not be sent —
    /// and a short write succeeds, so nothing downstream would say the value is incomplete.
    #[error("a stream write of {wanted} bytes exceeds the {limit} one request can carry")]
    StreamWriteTooLarge {
        /// How many bytes were offered.
        wanted: usize,
        /// The most one request can hold.
        limit: usize,
    },

    /// A sort was asked for on a column the table has not been given.
    ///
    /// [MS-OXCTABL] §2.2.2.3 requires every property sorted on to have been named in
    /// `RopSetColumns`. A server refuses the sort rather than sorting on something else, but the
    /// refusal does not say which column — so this is caught before the round trip, where it can.
    #[error("cannot sort on {tag}: it is not among the columns this table was given")]
    SortColumnNotSet {
        /// The column the sort key named and the column set did not.
        tag: PropertyTag,
    },

    /// A `FlaggedPropertyRow` carried a value flag other than `0x00`, `0x01` or `0x0A`.
    ///
    /// [MS-OXCDATA] §2.11.5 — `FlaggedPropertyValue`
    #[error("invalid flagged-value flag 0x{flag:02X} at {at}")]
    InvalidValueFlag {
        /// The flag byte as received.
        flag: u8,
        /// Byte offset of the flag.
        at: usize,
    },

    /// Rows arrived for a table whose column set is not known.
    ///
    /// Rows carry values only; the types come entirely from the last `RopSetColumns` on that
    /// table. Without the column set the bytes are undecodable, so this stops rather than guesses.
    ///
    /// [MS-OXCROPS] §2.2.5.4.2 — `RowData` uses the columns previously set on the table
    #[error("no column set known for handle index {handle_index}: send RopSetColumns first")]
    UnknownColumns {
        /// The `InputHandleIndex` the rows came back on.
        handle_index: u8,
    },

    /// More `RopGetPropertiesSpecific` responses arrived than the batch asked for.
    ///
    /// Its response is a `PropertyRow`, which carries values and no tags, so it can only be
    /// decoded against the tags of the request it answers. A response with no request behind it
    /// has no such list, and reusing the previous one would decode plausible-looking wrong values
    /// rather than fail.
    ///
    /// [MS-OXCROPS] §2.2.8.3.2 — `RowData` uses the tags from the request
    #[error("a RopGetPropertiesSpecific response at {at} matches no request in this batch")]
    UnrequestedProperties {
        /// Byte offset within the ROP response stream.
        at: usize,
    },

    /// A ROP buffer grew past what its own length fields can describe.
    ///
    /// [MS-OXCROPS] §2.2.1 — `RopSize` is 2 bytes and counts itself
    #[error("ROP buffer is {bytes} bytes, past the {limit}-byte limit of its length field")]
    RopBufferTooLarge {
        /// Size the buffer reached.
        bytes: usize,
        /// The largest size the length field can express.
        limit: usize,
    },

    /// A ROP referenced a handle slot index this batch never allocated.
    ///
    /// Slots belong to the batch that produced them; one from another batch would address an
    /// unrelated handle. Note that this catches an index out of range, not provenance: a foreign
    /// slot whose index happens to be in range is indistinguishable from a native one.
    #[error("handle slot {index} does not belong to this batch")]
    UnknownHandleSlot {
        /// The index that was referenced.
        index: u8,
    },

    /// A batch asked for more handle slots than a 1-byte index can address.
    ///
    /// [MS-OXCROPS] §2.2.1 — ROPs address the handle table by a 1-byte index
    #[error("a ROP batch cannot hold more than {limit} handle slots")]
    TooManyHandles {
        /// The largest number of slots a batch can hold.
        limit: usize,
    },

    /// The response carried no `X-ResponseCode` header.
    ///
    /// Worth its own variant: a MAPI endpoint answering an incomplete URL returns HTTP 400 with
    /// no such header at all, which reads like "MAPI is disabled" rather than "the URL is missing
    /// its `MailboxId` query parameter".
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.3 — `X-ResponseCode`
    #[error(
        "response carried no X-ResponseCode header (an incomplete endpoint URL looks like this)"
    )]
    MissingResponseCode,

    /// The transport refused the request before looking at its body.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.3.3.3 — `X-ResponseCode`
    #[error(
        "transport refused the request: {code}, {}",
        .diagnostic.as_deref().unwrap_or("no diagnostic")
    )]
    Transport {
        /// The `X-ResponseCode` value, reported as received.
        code: ResponseCode,
        /// Whatever diagnostic text the server put in the body, if any.
        diagnostic: Option<String>,
    },

    /// The server rejected the `Connect`.
    ///
    /// Names the distinguished name that was sent, because the common failure is a DN the server
    /// cannot map to a mailbox, and `UnknownUser` on its own reads like a credential problem.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.2 — `StatusCode`, `ErrorCode`
    #[error("Connect refused for {user_dn} (StatusCode 0x{status:08X}): {code}")]
    ConnectFailed {
        /// The request-type-level status. Non-zero means the body stops right after it, so `code`
        /// is then `Success` for want of anything else — the status is the whole verdict.
        status: u32,
        /// What the server said, when the status allowed one.
        code: ErrorCode,
        /// The distinguished name that was sent.
        user_dn: LegacyDn,
    },

    /// The server rejected the `Execute` itself, before running any ROP in it.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.2.2 — `StatusCode`, `ErrorCode`
    #[error("Execute refused (StatusCode 0x{status:08X}): {code}")]
    ExecuteFailed {
        /// The request-type-level status. Non-zero means the body stops right after it.
        status: u32,
        /// What the server said, when the status allowed one.
        code: ErrorCode,
    },

    /// A distinguished name could not be carried by the `UserDn` field without corrupting it.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.1 — `UserDn` is a null-terminated 8-bit string
    #[error("invalid legacyExchangeDN: {reason}")]
    InvalidLegacyDn {
        /// Which rule the name broke.
        reason: &'static str,
    },

    /// A response arrived that the session was not waiting for.
    #[error("no request is in flight, so there is no response to interpret")]
    NoRequestInFlight,

    /// A request was built that the session's current state does not allow.
    #[error("cannot {attempted}: {reason}")]
    InvalidState {
        /// What was attempted, as a verb phrase.
        attempted: &'static str,
        /// Why the session refused it.
        reason: &'static str,
    },

    /// The response stream held a ROP this crate does not model.
    ///
    /// ROP responses are variable-length and not self-describing, so decoding cannot continue
    /// past one whose layout is unknown.
    ///
    /// [MS-OXCROPS] §2.2.2 — the table of `RopId` values
    #[error("unmodelled ROP {rop} in the response stream at {at}")]
    UnmodelledRop {
        /// The `RopId` as received.
        rop: RopId,
        /// Byte offset within the ROP response stream.
        at: usize,
    },
}

/// An error code as the server transmits it — a `u32` in little-endian order.
///
/// A newtype rather than an enum because the set is open: [MS-OXCDATA] §2.4 lists over a hundred
/// codes, servers add their own, and a code this crate has never heard of must still survive being
/// received, compared and printed. Known codes are associated constants, so matching stays typed.
///
/// [MS-OXCDATA] §2.4 — error codes
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ErrorCode(u32);

impl ErrorCode {
    /// The caller has insufficient rights. `0x80070005`, also written `ecAccessDenied`.
    pub const ACCESS_DENIED: Self = Self(0x8007_0005);
    /// The operation failed for an unspecified reason. `0x80004005`, also written `ecError`.
    pub const GENERAL_FAILURE: Self = Self(0x8000_4005);
    /// The user has no access rights to the mailbox. `0x000003F2`, also written `ecLoginPerm`.
    ///
    /// Worth recognising by name: asking for administrator privilege on `Connect` provokes exactly
    /// this for an ordinary user, and it reads like an authentication failure.
    /// [MS-OXCDATA] §2.4.1
    pub const LOGIN_PERMISSION: Self = Self(0x0000_03F2);
    /// The client could not log on. `0x80040111`, also written `ecLoginFailure`.
    pub const LOGON_FAILED: Self = Self(0x8004_0111);
    /// The call failed for a network reason. `0x80040115`, also written `ecRpcFailed`.
    pub const NETWORK_ERROR: Self = Self(0x8004_0115);
    /// The value is too large to return this way. `0x8007000E`, also written `ecMAPIOOM`.
    ///
    /// Routine rather than exceptional, and the reason the stream ROPs exist: [MS-OXCDATA] §2.4.2
    /// says of it "on get, indicates that the property or column value is too large to be retrieved
    /// by the request, and the property value needs to be accessed with the `RopOpenStream` ROP".
    /// Observed on Exchange Server SE `15.02.2562.045` for a 116,996-byte `PidTagBody` asked for
    /// through `RopGetPropertiesSpecific`.
    ///
    /// [MS-OXCDATA] §2.4 lists the same numeric value under `OutOfMemory`, which is the general
    /// meaning; §2.4.2 gives the specific one, and the specific one is what a property fetch means
    /// by it.
    pub const NOT_ENOUGH_MEMORY: Self = Self(0x8007_000E);
    /// The requested object could not be found. `0x8004010F`, also written `ecNotFound`.
    pub const NOT_FOUND: Self = Self(0x8004_010F);
    /// The server does not support this call. `0x80040102`, also written `ecNotSupported`.
    pub const NOT_SUPPORTED: Self = Self(0x8004_0102);
    /// A string exceeded the maximum permitted length. `0x80040105`, `ecStringTooLarge`.
    pub const STRING_TOO_LONG: Self = Self(0x8004_0105);
    /// The operation succeeded. `0x00000000`, also written `ecSuccess`.
    pub const SUCCESS: Self = Self(0x0000_0000);
    /// The result set is too big to return. `0x80040305`, also written `ecTooBig`.
    ///
    /// Routine rather than exceptional in a table: it is how a column too large for a row comes
    /// back. [MS-OXCDATA] §2.4.2
    pub const TOO_BIG: Self = Self(0x8004_0305);
    /// No home Store object could be identified for the given distinguished name.
    /// `0x000003EB`, also written `ecUnknownUser`. [MS-OXCDATA] §2.4.1
    pub const UNKNOWN_USER: Self = Self(0x0000_03EB);
    /// Client and server versions are not compatible. `0x80040110`, `ecVersionMismatch`.
    pub const VERSION_MISMATCH: Self = Self(0x8004_0110);
    /// The mailbox is not on this server. `0x00000478`, also written `ecWrongServer`.
    ///
    /// Unlike every other refusal, a `RopLogon` that returns this carries a *redirect* body naming
    /// the server to log on to instead — see [MS-OXCSTOR] §2.2.1.1.2.
    pub const WRONG_SERVER: Self = Self(0x0000_0478);

    /// Wraps a raw code from the wire.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The code as it appears on the wire.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Whether this is [`ErrorCode::SUCCESS`].
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 == Self::SUCCESS.0
    }

    /// The specification's name for this code, if it is one this crate knows.
    ///
    /// The names are [MS-OXCDATA] §2.4's, not the `ecXxx` aliases, because the aliases are not
    /// unique — one numeric value can carry three of them.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::SUCCESS => "Success",
            Self::UNKNOWN_USER => "UnknownUser",
            Self::WRONG_SERVER => "WrongServer",
            Self::LOGIN_PERMISSION => "LoginPermission",
            Self::GENERAL_FAILURE => "GeneralFailure",
            Self::NOT_SUPPORTED => "NotSupported",
            Self::STRING_TOO_LONG => "StringTooLong",
            Self::NOT_FOUND => "NotFound",
            Self::NOT_ENOUGH_MEMORY => "NotEnoughMemory",
            Self::VERSION_MISMATCH => "VersionMismatch",
            Self::LOGON_FAILED => "LogonFailed",
            Self::NETWORK_ERROR => "NetworkError",
            Self::TOO_BIG => "TooBig",
            Self::ACCESS_DENIED => "AccessDenied",
            _ => return None,
        })
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} (0x{:08X})", self.0),
            None => write!(f, "unrecognised error code 0x{:08X}", self.0),
        }
    }
}

impl From<u32> for ErrorCode {
    fn from(raw: u32) -> Self {
        Self(raw)
    }
}

impl Default for ErrorCode {
    /// [`ErrorCode::SUCCESS`], so a default-constructed response carries no complaint.
    fn default() -> Self {
        Self::SUCCESS
    }
}

#[cfg(test)]
mod tests;
