//! The two things "flag a message" can mean, kept apart because they are not the same operation.
//!
//! JMAP's `$flagged` keyword and IMAP's `\Flagged` are one bit. MAPI has two mechanisms that a
//! client has to offer separately or conflate wrongly:
//!
//! * **The read state** is a bit of `PidTagMessageFlags` ([MS-OXCMSG] §2.2.1.6). It has its own ROP
//!   — `RopSetReadFlags` — because the server does more than write the property: it sends the read
//!   receipt the sender asked for. See [`MessageFlags`].
//! * **The follow-up flag** is a set of ordinary properties ([MS-OXOFLAG]), written with
//!   `RopSetProperties` like any others. See [`FlagStatus`] and [`FollowupIcon`].
//!
//! A client that answered "is this flagged?" from the read bit would report every unread message
//! as flagged, and one that answered "is this unread?" from `PidTagFlagStatus` would report every
//! message as read. Both are plausible wrong answers, which is the reason for the file.
//!
//! [MS-OXCMSG] §2.2.1.6 — `PidTagMessageFlags`
//! [MS-OXOFLAG] §2.2.1 — the flagging properties

/// The status of a message, as `PidTagMessageFlags` reports it.
///
/// A bitfield rather than an enum: the flags are independent, and [MS-OXCMSG] §2.2.1.6 splits them
/// into the three a client may set and the several that are the server's. Only the readings this
/// crate has a use for are named; the raw value is always available.
///
/// [MS-OXCMSG] §2.2.1.6 — `PidTagMessageFlags`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageFlags(u32);

impl MessageFlags {
    /// `mfFAI`, `0x00000040` — a folder associated information message, which no contents table
    /// lists and `RopSubmitMessage` refuses with `ecAccessDenied`. Read-only.
    pub const ASSOCIATED: u32 = 0x0000_0040;
    /// `mfEverRead`, `0x00000400` — read at least once.
    ///
    /// [MS-OXCMSG] §2.2.1.6 says clients SHOULD ignore this, and names Exchange 2007 as a server
    /// that does not set it alongside `mfRead`. It is here to be named in a diagnostic, not acted
    /// on.
    ///
    /// **It is set and never cleared**, which the same sentence does not allow: "This flag is set
    /// or cleared by the server whenever the mfRead flag is set or cleared." Measured on Exchange
    /// Server SE `15.02.2562.045` — a seeded message at `0x0002` went to `0x0403` when marked read
    /// and back to `0x0402`, not `0x0002`, when marked unread. The behaviour is what the flag's own
    /// description says it should be ("read at least once"), so the document contradicts itself
    /// rather than the server contradicting the document; the consequence for a client is that
    /// marking a message unread does not restore the flags it had.
    pub const EVER_READ: u32 = 0x0000_0400;
    /// `mfFromMe`, `0x00000020` — the recipient also sent it. Read-only.
    pub const FROM_ME: u32 = 0x0000_0020;
    /// `mfHasAttach`, `0x00000010` — at least one attachment. Read-only.
    pub const HAS_ATTACHMENT: u32 = 0x0000_0010;
    /// `mfNotifyRead`, `0x00000100` — the sender asked to be told when it is first read.
    pub const NOTIFY_READ: u32 = 0x0000_0100;
    /// `mfNotifyUnread`, `0x00000200` — the sender asked to be told if it is deleted unread.
    pub const NOTIFY_UNREAD: u32 = 0x0000_0200;
    /// `mfRead`, `0x00000001` — the message has been read.
    pub const READ: u32 = 0x0000_0001;
    /// `mfResend`, `0x00000080` — a resend with a non-delivery report.
    pub const RESEND: u32 = 0x0000_0080;
    /// `mfSubmitted`, `0x00000004` — marked for sending by `RopSubmitMessage`. Read-only.
    pub const SUBMITTED: u32 = 0x0000_0004;
    /// `mfUnmodified`, `0x00000002` — unchanged since it was saved or delivered. Read-only.
    pub const UNMODIFIED: u32 = 0x0000_0002;
    /// `mfUnsent`, `0x00000008` — still being composed, so a draft.
    ///
    /// **Cleared by the server when a `RopSubmitMessage` succeeds**, which makes it the one field
    /// that distinguishes a draft from a message on its way out.
    pub const UNSENT: u32 = 0x0000_0008;

    /// Wraps the value of `PidTagMessageFlags`.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The value as the property carries it.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Whether a flag is set.
    #[must_use]
    pub const fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Whether the message has been read — `mfRead`.
    #[must_use]
    pub const fn is_read(self) -> bool {
        self.has(Self::READ)
    }

    /// Whether the message is still a draft — `mfUnsent`.
    ///
    /// The server clears this on a successful submit, so it answers "did the submit take" for a
    /// message that is still where it was left.
    #[must_use]
    pub const fn is_draft(self) -> bool {
        self.has(Self::UNSENT)
    }

    /// Whether the message has been handed to the transport — `mfSubmitted`.
    #[must_use]
    pub const fn is_submitted(self) -> bool {
        self.has(Self::SUBMITTED)
    }

    /// Whether this is a folder associated information message — `mfFAI`.
    ///
    /// Worth checking before a submit: [MS-OXOMSG] §3.3.5.1.1 refuses one with `ecAccessDenied`,
    /// which reads like a permission problem and is not.
    #[must_use]
    pub const fn is_associated(self) -> bool {
        self.has(Self::ASSOCIATED)
    }
}

impl core::fmt::Display for MessageFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for (flag, name) in [
            (Self::READ, "mfRead"),
            (Self::UNMODIFIED, "mfUnmodified"),
            (Self::SUBMITTED, "mfSubmitted"),
            (Self::UNSENT, "mfUnsent"),
            (Self::HAS_ATTACHMENT, "mfHasAttach"),
            (Self::FROM_ME, "mfFromMe"),
            (Self::ASSOCIATED, "mfFAI"),
            (Self::RESEND, "mfResend"),
            (Self::NOTIFY_READ, "mfNotifyRead"),
            (Self::NOTIFY_UNREAD, "mfNotifyUnread"),
            (Self::EVER_READ, "mfEverRead"),
        ] {
            if self.has(flag) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("none")?;
        }
        write!(f, " (0x{:08X})", self.0)
    }
}

/// Whether a message carries a follow-up flag, and whether that flag is done.
///
/// **Not flagged is the absence of the property, not a value of it.** [MS-OXOFLAG] §2.2.1.1 has
/// `PidTagFlagStatus` "present on the Message object only if the object has been flagged and ...
/// not present otherwise", so clearing a flag is a `RopDeleteProperties` and not a write of zero.
/// [`NotFlagged`](Self::NotFlagged) exists because a server can be observed sending the zero
/// anyway, and reporting that as an unmodelled value would be less useful than naming it.
///
/// [MS-OXOFLAG] §2.2.1.1 — `PidTagFlagStatus`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum FlagStatus {
    /// `0x00000000` — no follow-up flag. Written by deleting the property, not by setting this.
    #[default]
    NotFlagged,
    /// `followupComplete`, `0x00000001` — flagged, and marked done.
    Complete,
    /// `followupFlagged`, `0x00000002` — flagged for follow-up.
    Flagged,
    /// A value [MS-OXOFLAG] §2.2.1.1 does not list.
    Unknown(u32),
}

impl FlagStatus {
    /// Reads the value of `PidTagFlagStatus`.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        match raw {
            0x0000_0000 => Self::NotFlagged,
            0x0000_0001 => Self::Complete,
            0x0000_0002 => Self::Flagged,
            other => Self::Unknown(other),
        }
    }

    /// The value as the property carries it.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::NotFlagged => 0x0000_0000,
            Self::Complete => 0x0000_0001,
            Self::Flagged => 0x0000_0002,
            Self::Unknown(raw) => raw,
        }
    }

    /// Whether the message carries a flag at all, done or not.
    #[must_use]
    pub const fn is_flagged(self) -> bool {
        matches!(self, Self::Complete | Self::Flagged)
    }
}

impl core::fmt::Display for FlagStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFlagged => f.write_str("not flagged"),
            Self::Complete => f.write_str("followupComplete"),
            Self::Flagged => f.write_str("followupFlagged"),
            Self::Unknown(raw) => write!(f, "unmodelled flag status 0x{raw:08X}"),
        }
    }
}

/// The colour a follow-up flag is drawn in — `PidTagFollowupIcon`.
///
/// A flagged message without one has a flag with no colour, which [MS-OXOFLAG] §3.1.4.1.2 calls a
/// *basic flag*. A time flag and a recipient flag are both required to be
/// [`Red`](Self::Red).
///
/// [MS-OXOFLAG] §2.2.1.2 — `PidTagFollowupIcon`
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum FollowupIcon {
    /// `0x00000001`.
    Purple,
    /// `0x00000002`.
    Orange,
    /// `0x00000003`.
    Green,
    /// `0x00000004`.
    Yellow,
    /// `0x00000005`.
    Blue,
    /// `0x00000006` — and the only value a time flag or a recipient flag may carry.
    Red,
    /// A value [MS-OXOFLAG] §2.2.1.2 does not list.
    Unknown(u32),
}

impl FollowupIcon {
    /// Every colour the document names, in the order it names them.
    pub const ALL: [Self; 6] = [
        Self::Purple,
        Self::Orange,
        Self::Green,
        Self::Yellow,
        Self::Blue,
        Self::Red,
    ];

    /// Reads the value of `PidTagFollowupIcon`.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        match raw {
            0x0000_0001 => Self::Purple,
            0x0000_0002 => Self::Orange,
            0x0000_0003 => Self::Green,
            0x0000_0004 => Self::Yellow,
            0x0000_0005 => Self::Blue,
            0x0000_0006 => Self::Red,
            other => Self::Unknown(other),
        }
    }

    /// The value as the property carries it.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Purple => 0x0000_0001,
            Self::Orange => 0x0000_0002,
            Self::Green => 0x0000_0003,
            Self::Yellow => 0x0000_0004,
            Self::Blue => 0x0000_0005,
            Self::Red => 0x0000_0006,
            Self::Unknown(raw) => raw,
        }
    }

    /// The colour's name in lower case, for a diagnostic and for a command line.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::Purple => "purple",
            Self::Orange => "orange",
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Blue => "blue",
            Self::Red => "red",
            Self::Unknown(_) => return None,
        })
    }
}

impl core::fmt::Display for FollowupIcon {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "unmodelled colour 0x{:08X}", self.as_u32()),
        }
    }
}

#[cfg(test)]
mod tests;
