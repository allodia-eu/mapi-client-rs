//! How an attachment's content is reached.
//!
//! The one fact about an attachment a reader cannot skip. `PidTagAttachMethod` decides which of two
//! entirely different reads is correct, and the failure is silent in the direction that matters: an
//! `afEmbeddedMessage` attachment holds no `PidTagAttachDataBinary` at all, so a client that only
//! ever reads that property reports a forwarded mail as an empty attachment rather than as an
//! error.
//!
//! [MS-OXCMSG] §2.2.2.9 — `PidTagAttachMethod`

/// The value of `PidTagAttachMethod`, which says where an attachment's content actually is.
///
/// [MS-OXCMSG] §2.2.2.9
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AttachMethod {
    /// `afNone`, `0x00000000` — the attachment has just been created and holds nothing yet.
    None,
    /// `afByValue`, `0x00000001` — the bytes are in `PidTagAttachDataBinary`.
    ///
    /// The ordinary case, and the only one where reading that property is right.
    ByValue,
    /// `afByReference`, `0x00000002` — `PidTagAttachLongPathname` names a file on a shared server.
    ByReference,
    /// `afByReferenceOnly`, `0x00000004` — as [`ByReference`](Self::ByReference), without the
    /// promise that recipients can reach it.
    ByReferenceOnly,
    /// `afEmbeddedMessage`, `0x00000005` — the payload is another Message object.
    ///
    /// Reached with `RopOpenEmbeddedMessage` and by no other means. There is no
    /// `PidTagAttachDataBinary` to read.
    EmbeddedMessage,
    /// `afStorage`, `0x00000006` — `PidTagAttachDataObject` holds an application-specific format.
    Storage,
    /// `afByWebReference`, `0x00000007` — `PidTagAttachLongPathname` is a URL.
    ByWebReference,
    /// A value [MS-OXCMSG] §2.2.2.9 does not list.
    Other(u32),
}

impl AttachMethod {
    /// Reads the value as the wire carries it.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        match raw {
            0x0000_0000 => Self::None,
            0x0000_0001 => Self::ByValue,
            0x0000_0002 => Self::ByReference,
            0x0000_0004 => Self::ByReferenceOnly,
            0x0000_0005 => Self::EmbeddedMessage,
            0x0000_0006 => Self::Storage,
            0x0000_0007 => Self::ByWebReference,
            other => Self::Other(other),
        }
    }

    /// The value as the wire carries it.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::None => 0x0000_0000,
            Self::ByValue => 0x0000_0001,
            Self::ByReference => 0x0000_0002,
            Self::ByReferenceOnly => 0x0000_0004,
            Self::EmbeddedMessage => 0x0000_0005,
            Self::Storage => 0x0000_0006,
            Self::ByWebReference => 0x0000_0007,
            Self::Other(raw) => raw,
        }
    }

    /// The `afXxx` name, if this is one the document lists.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::None => "afNone",
            Self::ByValue => "afByValue",
            Self::ByReference => "afByReference",
            Self::ByReferenceOnly => "afByReferenceOnly",
            Self::EmbeddedMessage => "afEmbeddedMessage",
            Self::Storage => "afStorage",
            Self::ByWebReference => "afByWebReference",
            Self::Other(_) => return None,
        })
    }

    /// Whether the content is in `PidTagAttachDataBinary`, and therefore streamable.
    #[must_use]
    pub const fn has_binary_content(self) -> bool {
        matches!(self, Self::ByValue)
    }

    /// Whether the content is another message, reached with `RopOpenEmbeddedMessage`.
    #[must_use]
    pub const fn is_embedded_message(self) -> bool {
        matches!(self, Self::EmbeddedMessage)
    }
}

impl core::fmt::Display for AttachMethod {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => f.pad(name),
            None => write!(f, "unrecognised method 0x{:08X}", self.as_u32()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transcribed from [MS-OXCMSG] §2.2.2.9's own table. Note that `0x00000003` is not in it —
    /// the values are not contiguous, which is exactly the kind of thing a hand-written `match`
    /// gets wrong.
    #[test]
    fn every_method_matches_the_documented_table() {
        for (raw, method, name) in [
            (0x0000_0000_u32, AttachMethod::None, "afNone"),
            (0x0000_0001, AttachMethod::ByValue, "afByValue"),
            (0x0000_0002, AttachMethod::ByReference, "afByReference"),
            (
                0x0000_0004,
                AttachMethod::ByReferenceOnly,
                "afByReferenceOnly",
            ),
            (
                0x0000_0005,
                AttachMethod::EmbeddedMessage,
                "afEmbeddedMessage",
            ),
            (0x0000_0006, AttachMethod::Storage, "afStorage"),
            (
                0x0000_0007,
                AttachMethod::ByWebReference,
                "afByWebReference",
            ),
        ] {
            assert_eq!(AttachMethod::new(raw), method, "{name}");
            assert_eq!(method.as_u32(), raw, "{name}");
            assert_eq!(method.name(), Some(name));
            assert_eq!(method.to_string(), name);
        }
    }

    /// `0x00000003` is a gap in the table, so it has to survive being received rather than being
    /// folded into whichever neighbour a range check would have chosen.
    #[test]
    fn a_value_the_table_does_not_list_survives() {
        let gap = AttachMethod::new(0x0000_0003);
        assert_eq!(gap, AttachMethod::Other(0x0000_0003));
        assert_eq!(gap.as_u32(), 0x0000_0003);
        assert_eq!(gap.name(), None);
        assert_eq!(gap.to_string(), "unrecognised method 0x00000003");
        assert!(!gap.has_binary_content());
        assert!(!gap.is_embedded_message());
    }

    /// The distinction the whole type exists for: exactly one method puts bytes in
    /// `PidTagAttachDataBinary`, and exactly one puts a message behind
    /// `RopOpenEmbeddedMessage`.
    #[test]
    fn only_one_method_has_bytes_and_only_one_has_a_message() {
        let all = [
            AttachMethod::None,
            AttachMethod::ByValue,
            AttachMethod::ByReference,
            AttachMethod::ByReferenceOnly,
            AttachMethod::EmbeddedMessage,
            AttachMethod::Storage,
            AttachMethod::ByWebReference,
        ];
        assert_eq!(all.iter().filter(|m| m.has_binary_content()).count(), 1);
        assert_eq!(all.iter().filter(|m| m.is_embedded_message()).count(), 1);
        assert!(AttachMethod::ByValue.has_binary_content());
        assert!(AttachMethod::EmbeddedMessage.is_embedded_message());
        assert!(!AttachMethod::EmbeddedMessage.has_binary_content());
    }
}
