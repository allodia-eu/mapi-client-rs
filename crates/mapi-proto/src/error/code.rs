//! The server's own vocabulary for saying no.
//!
//! Its own file because [`Error`](super::Error) and [`ErrorCode`] are different things that both
//! get called an error, and because this one is a catalogue that grows with every operation while
//! the other is a fixed list of ways this crate can fail.
//!
//! **A code here is not a bug.** The server understood the request perfectly and refused it:
//! `UnknownUser` means the mailbox does not exist, `TooManyRecips` means none of the recipients got
//! the message, and `InvalidRecipients` is what a submit with no recipients at all earns.
//!
//! [MS-OXCDATA] §2.4 — error codes
//! [MS-OXCDATA] §2.4.1 — additional error codes
//! [MS-OXCDATA] §2.4.2 — additional error codes, continued

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
    /// The message could not be delivered to a recipient. `0x00000467`, `ecInvalidRecips`.
    ///
    /// **What Exchange answers a `RopSubmitMessage` on a message with no recipients at all**,
    /// measured on Exchange Server SE `15.02.2562.045` — which the name does not lead a reader to
    /// expect, and which [MS-OXOMSG] §3.3.5.1.1 does not list among the refusals. The message is
    /// left exactly as it was: `mfUnsent` still set, `mfSubmitted` clear, and still deletable.
    ///
    /// [MS-OXCDATA] §2.4.2
    pub const INVALID_RECIPIENTS: Self = Self(0x0000_0467);
    /// The user has no access rights to the mailbox. `0x000003F2`, also written `ecLoginPerm`.
    ///
    /// Worth recognising by name: asking for administrator privilege on `Connect` provokes exactly
    /// this for an ordinary user, and it reads like an authentication failure.
    /// [MS-OXCDATA] §2.4.1
    pub const LOGIN_PERMISSION: Self = Self(0x0000_03F2);
    /// The client could not log on. `0x80040111`, also written `ecLoginFailure`.
    pub const LOGON_FAILED: Self = Self(0x8004_0111);
    /// A message was too large to submit. `0x000004DA`, also written `ecMaxSubmissionExceeded`.
    ///
    /// The limit is `PidTagMaximumSubmitMessageSize` on the Store object, which
    /// [`MAILBOX_PROPERTIES`](crate::MAILBOX_PROPERTIES) already reads — so this is a refusal a
    /// client can predict rather than only report. [MS-OXCDATA] §2.4.2
    pub const MAX_SUBMISSION_EXCEEDED: Self = Self(0x0000_04DA);
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
    /// A destination handle could not be resolved. `0x00000503`, also written `ecDstNullObject`.
    ///
    /// The one refusal in this crate whose response body does **not** stop after `ReturnValue`:
    /// `RopMoveCopyMessages` answering it appends a `DestHandleIndex` and a `PartialCompletion`
    /// ([MS-OXCROPS] §2.2.4.6.3). Not to be confused with `ecNullObject`, `0x000004B9`, which is
    /// about a *source* handle and stops where every other failure does.
    ///
    /// [MS-OXCDATA] §2.4.2
    pub const NULL_DESTINATION_OBJECT: Self = Self(0x0000_0503);
    /// The operation would have exceeded a quota. `0x000004D9`, also written `ecQuotaExceeded`.
    ///
    /// One of the refusals [MS-OXOMSG] §3.3.5.1.1 lists for `RopSubmitMessage`. [MS-OXCDATA] §2.4.2
    pub const QUOTA_EXCEEDED: Self = Self(0x0000_04D9);
    /// A string exceeded the maximum permitted length. `0x80040105`, `ecStringTooLarge`.
    pub const STRING_TOO_LONG: Self = Self(0x8004_0105);
    /// The operation succeeded. `0x00000000`, also written `ecSuccess`.
    pub const SUCCESS: Self = Self(0x0000_0000);
    /// The result set is too big to return. `0x80040305`, also written `ecTooBig`.
    ///
    /// Routine rather than exceptional in a table: it is how a column too large for a row comes
    /// back. [MS-OXCDATA] §2.4.2
    pub const TOO_BIG: Self = Self(0x8004_0305);
    /// More recipients than the server allows. `0x00000505`, also written `ecTooManyRecips`.
    ///
    /// **None of them receive the message.** [MS-OXOMSG] §3.3.5.1 says so explicitly, which makes
    /// this a refusal rather than a partial send. [MS-OXCDATA] §2.4.2
    pub const TOO_MANY_RECIPIENTS: Self = Self(0x0000_0505);
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
            Self::QUOTA_EXCEEDED => "QuotaExceeded",
            Self::MAX_SUBMISSION_EXCEEDED => "MaxSubmissionExceeded",
            Self::NULL_DESTINATION_OBJECT => "NullDestinationObject",
            Self::INVALID_RECIPIENTS => "InvalidRecipients",
            Self::TOO_MANY_RECIPIENTS => "TooManyRecips",
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
