//! The meta-properties incremental synchronization carries its identifier sets in.
//!
//! None of these is a property of any object. They exist only inside an ICS state or a
//! `FastTransfer` stream, which is why they are `MetaTag` rather than `PidTag` and why
//! [MS-OXCFXICS] rather than [MS-OXPROPS] defines them. Each holds a serialized IDSET, and **which
//! form** — by REPLGUID or by REPLID — is fixed per property and not stated in the bytes: the four
//! state properties are REPLGUID-based, the five that describe a download's differences are
//! REPLID-based. See [`IdSet`](crate::ics::IdSet).
//!
//! [MS-OXCFXICS] §2.2.1.1 — ICS state properties
//! [MS-OXCFXICS] §2.2.1.3 — meta-properties for encoding differences in replica content
//! [MS-OXCFXICS] §3.1.5.4.2 — which IDSET form each property uses

use crate::oxcdata::PropertyTag;

impl PropertyTag {
    /// `MetaTagCnsetRead`, `0x67D20102` — the read-state changes a client has. REPLGUID-based.
    ///
    /// [MS-OXCFXICS] §2.2.1.1.4
    pub const META_TAG_CNSET_READ: Self = Self(0x67D2_0102);
    /// `MetaTagCnsetSeen`, `0x67960102` — the changes to normal messages, or to folders, a client
    /// has. REPLGUID-based.
    ///
    /// [MS-OXCFXICS] §2.2.1.1.2
    pub const META_TAG_CNSET_SEEN: Self = Self(0x6796_0102);
    /// `MetaTagCnsetSeenFAI`, `0x67DA0102` — the changes to FAI messages a client has.
    /// REPLGUID-based.
    ///
    /// [MS-OXCFXICS] §2.2.1.1.3
    pub const META_TAG_CNSET_SEEN_FAI: Self = Self(0x67DA_0102);
    /// `MetaTagIdsetDeleted`, `0x67E50102` — the objects deleted since the last synchronization.
    /// REPLID-based.
    ///
    /// [MS-OXCFXICS] §2.2.1.3.1
    pub const META_TAG_IDSET_DELETED: Self = Self(0x67E5_0102);
    /// `MetaTagIdsetExpired`, `0x67930102` — messages in a *public folder* that expired.
    /// REPLID-based.
    ///
    /// Note `<1>`: not supported in Exchange 2013, 2016 and 2019. Named so that a stream carrying
    /// it is read rather than refused, not because a private mailbox can produce one.
    ///
    /// [MS-OXCFXICS] §2.2.1.3.3
    pub const META_TAG_IDSET_EXPIRED: Self = Self(0x6793_0102);
    /// `MetaTagIdsetGiven`, `0x40170003` — the objects a client holds. REPLGUID-based.
    ///
    /// **The type half of this tag is wrong, deliberately.** [MS-OXCFXICS] §2.2.1.1.1 gives it
    /// `PtypInteger32`, and §3.3.5.13 says a client SHOULD send it with that tag; its value is an
    /// IDSET all the same, which "MUST be handled as `PtypBinary`". A `FastTransfer` stream carries
    /// it with a length, like any binary — §4.5's own final state does, at `0x38` bytes.
    ///
    /// [MS-OXCFXICS] §2.2.1.1.1
    /// [MS-OXCFXICS] §3.2.5.2.1 — "the data MUST be handled as `PtypBinary`"
    pub const META_TAG_IDSET_GIVEN: Self = Self(0x4017_0003);
    /// `MetaTagIdsetNoLongerInScope`, `0x40210102` — messages that moved out of a restricted
    /// scope. REPLID-based.
    ///
    /// [MS-OXCFXICS] §2.2.1.3.2
    pub const META_TAG_IDSET_NO_LONGER_IN_SCOPE: Self = Self(0x4021_0102);
    /// `MetaTagIdsetRead`, `0x402D0102` — messages marked read since the last synchronization.
    /// REPLID-based.
    ///
    /// [MS-OXCFXICS] §2.2.1.3.4
    pub const META_TAG_IDSET_READ: Self = Self(0x402D_0102);
    /// `MetaTagIdsetUnread`, `0x402E0102` — messages marked unread since the last
    /// synchronization. REPLID-based.
    ///
    /// [MS-OXCFXICS] §2.2.1.3.5
    pub const META_TAG_IDSET_UNREAD: Self = Self(0x402E_0102);
}
