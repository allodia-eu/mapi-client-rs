//! The markers that give a `FastTransfer` stream its structure.
//!
//! A marker is four bytes with the shape of a property tag and no value, which is the whole of the
//! lexer's difficulty: nothing in the four bytes says "marker", so the only way to tell
//! `StartMessage` from a property is to know the table. These are that table.
//!
//! [MS-OXCFXICS] §2.2.4.1.4 — markers

/// One marker, by its place in the table.
///
/// [MS-OXCFXICS] §2.2.4.1.4 — the complete list
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Marker {
    /// `StartTopFld`, `0x40090003` — the start of a folder's data.
    StartTopFolder,
    /// `StartSubFld`, `0x400A0003` — the start of a subfolder's data.
    StartSubFolder,
    /// `EndFolder`, `0x400B0003` — the end of a folder or subfolder.
    EndFolder,
    /// `StartMessage`, `0x400C0003` — the start of a normal message.
    StartMessage,
    /// `StartFAIMsg`, `0x40100003` — the start of an FAI message.
    StartFaiMessage,
    /// `EndMessage`, `0x400D0003` — the end of a message.
    EndMessage,
    /// `StartEmbed`, `0x40010003` — the start of an embedded message.
    StartEmbed,
    /// `EndEmbed`, `0x40020003` — the end of an embedded message.
    EndEmbed,
    /// `StartRecip`, `0x40030003` — the start of a recipient.
    StartRecipient,
    /// `EndToRecip`, `0x40040003` — the end of a recipient.
    EndRecipient,
    /// `NewAttach`, `0x40000003` — the start of an attachment.
    NewAttachment,
    /// `EndAttach`, `0x400E0003` — the end of an attachment.
    EndAttachment,
    /// `IncrSyncChg`, `0x40120003` — a message change, delivered whole.
    IncrSyncChange,
    /// `IncrSyncChgPartial`, `0x407D0003` — a message change, delivered by property group.
    IncrSyncChangePartial,
    /// `IncrSyncDel`, `0x40130003` — the deletions.
    IncrSyncDeletions,
    /// `IncrSyncEnd`, `0x40140003` — the end of the synchronization data.
    IncrSyncEnd,
    /// `IncrSyncRead`, `0x402F0003` — the read-state changes.
    IncrSyncRead,
    /// `IncrSyncStateBegin`, `0x403A0003` — the start of the final ICS state.
    IncrSyncStateBegin,
    /// `IncrSyncStateEnd`, `0x403B0003` — the end of the final ICS state.
    IncrSyncStateEnd,
    /// `IncrSyncProgressMode`, `0x4074000B` — the size of everything to come.
    IncrSyncProgressMode,
    /// `IncrSyncProgressPerMsg`, `0x4075000B` — the size of the next message.
    IncrSyncProgressPerMessage,
    /// `IncrSyncMessage`, `0x40150003` — the start of a full change's message data.
    IncrSyncMessage,
    /// `IncrSyncGroupInfo`, `0x407B0102` — a property group mapping.
    IncrSyncGroupInfo,
    /// `FXErrorInfo`, `0x40180003` — an object the server could not produce.
    ErrorInfo,
}

/// The table, as the four bytes each marker is written in.
const TABLE: [(u32, Marker); 24] = [
    (0x4009_0003, Marker::StartTopFolder),
    (0x400A_0003, Marker::StartSubFolder),
    (0x400B_0003, Marker::EndFolder),
    (0x400C_0003, Marker::StartMessage),
    (0x4010_0003, Marker::StartFaiMessage),
    (0x400D_0003, Marker::EndMessage),
    (0x4001_0003, Marker::StartEmbed),
    (0x4002_0003, Marker::EndEmbed),
    (0x4003_0003, Marker::StartRecipient),
    (0x4004_0003, Marker::EndRecipient),
    (0x4000_0003, Marker::NewAttachment),
    (0x400E_0003, Marker::EndAttachment),
    (0x4012_0003, Marker::IncrSyncChange),
    (0x407D_0003, Marker::IncrSyncChangePartial),
    (0x4013_0003, Marker::IncrSyncDeletions),
    (0x4014_0003, Marker::IncrSyncEnd),
    (0x402F_0003, Marker::IncrSyncRead),
    (0x403A_0003, Marker::IncrSyncStateBegin),
    (0x403B_0003, Marker::IncrSyncStateEnd),
    (0x4074_000B, Marker::IncrSyncProgressMode),
    (0x4075_000B, Marker::IncrSyncProgressPerMessage),
    (0x4015_0003, Marker::IncrSyncMessage),
    (0x407B_0102, Marker::IncrSyncGroupInfo),
    (0x4018_0003, Marker::ErrorInfo),
];

impl Marker {
    /// The marker these four bytes are, or `None` for a property tag.
    #[must_use]
    pub fn from_u32(raw: u32) -> Option<Self> {
        TABLE
            .iter()
            .find(|(value, _)| *value == raw)
            .map(|(_, marker)| *marker)
    }

    /// The four bytes, as a `u32`.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        TABLE
            .iter()
            .find(|(_, marker)| *marker == self)
            .map_or(0, |(value, _)| *value)
    }
}

impl core::fmt::Display for Marker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?} (0x{:08X})", self.as_u32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transcribed from §2.2.4.1.4 a second time, so that a typo in the table is not confirmed by
    /// the table.
    #[test]
    fn every_marker_has_the_value_the_document_gives_it() {
        for (raw, marker) in [
            (0x4009_0003, Marker::StartTopFolder),
            (0x400C_0003, Marker::StartMessage),
            (0x4003_0003, Marker::StartRecipient),
            (0x4000_0003, Marker::NewAttachment),
            (0x4012_0003, Marker::IncrSyncChange),
            (0x407D_0003, Marker::IncrSyncChangePartial),
            (0x4074_000B, Marker::IncrSyncProgressMode),
            (0x407B_0102, Marker::IncrSyncGroupInfo),
            (0x4018_0003, Marker::ErrorInfo),
        ] {
            assert_eq!(Marker::from_u32(raw), Some(marker));
            assert_eq!(marker.as_u32(), raw);
        }
        let mut values: Vec<u32> = TABLE.iter().map(|(value, _)| *value).collect();
        values.sort_unstable();
        values.dedup();
        assert_eq!(values.len(), TABLE.len(), "no two markers share a value");
    }

    /// A property tag is not a marker, however marker-shaped: `PidTagSubject` is not in the table.
    #[test]
    fn a_property_tag_is_not_a_marker() {
        assert_eq!(Marker::from_u32(0x0037_001F), None);
        assert_eq!(
            Marker::from_u32(0x4017_0003),
            None,
            "MetaTagIdsetGiven is a property"
        );
    }
}
