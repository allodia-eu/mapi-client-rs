//! The tags incremental synchronization reads: the meta-properties it carries its identifier sets
//! and its structure in, and the change-tracking properties every object it delivers has.
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
    /// `PidTagAssociated`, `0x67AA000B` — whether a message is an FAI message.
    ///
    /// [MS-OXCFXICS] §2.2.1.5
    pub const ASSOCIATED: Self = Self(0x67AA_000B);
    /// `PidTagChangeKey`, `0x65E20102` — which version of an object this is.
    ///
    /// [MS-OXCFXICS] §2.2.1.2.7
    pub const CHANGE_KEY: Self = Self(0x65E2_0102);
    /// `PidTagChangeNumber`, `0x67A40014` — the change number of an object's current version.
    ///
    /// [MS-OXCFXICS] §2.2.1.2.3
    pub const CHANGE_NUMBER: Self = Self(0x67A4_0014);
    /// `PidTagMessageAttachments`, `0x0E13000D` — names a message's attachments as a subobject.
    ///
    /// [MS-OXCFXICS] §2.2.1.7
    pub const MESSAGE_ATTACHMENTS: Self = Self(0x0E13_000D);
    /// `PidTagMessageRecipients`, `0x0E12000D` — names a message's recipients as a subobject.
    ///
    /// [MS-OXCFXICS] §2.2.1.7
    pub const MESSAGE_RECIPIENTS: Self = Self(0x0E12_000D);
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
    /// `MetaTagDnPrefix`, `0x4008001E` — a prefix a stream may carry and a client MUST ignore.
    ///
    /// [MS-OXCFXICS] §2.2.4.1.5.6
    pub const META_TAG_DN_PREFIX: Self = Self(0x4008_001E);
    /// `MetaTagEcWarning`, `0x400F0003` — a warning about the element in context.
    ///
    /// [MS-OXCFXICS] §2.2.4.1.5.2
    pub const META_TAG_EC_WARNING: Self = Self(0x400F_0003);
    /// `MetaTagFXDelProp`, `0x40160003` — a directive to discard the subobjects its value names.
    ///
    /// [MS-OXCFXICS] §2.2.4.1.5.1
    pub const META_TAG_FX_DEL_PROP: Self = Self(0x4016_0003);
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
    /// `MetaTagIncrementalSyncMessagePartial`, `0x407A0003` — the index of the property group whose
    /// properties follow.
    ///
    /// [MS-OXCFXICS] §2.2.4.1.5.5
    pub const META_TAG_INCREMENTAL_SYNC_MESSAGE_PARTIAL: Self = Self(0x407A_0003);
    /// `MetaTagIncrSyncGroupId`, `0x407C0003` — which property group mapping the partial changes
    /// that follow use.
    ///
    /// [MS-OXCFXICS] §2.2.4.1.5.4
    pub const META_TAG_INCR_SYNC_GROUP_ID: Self = Self(0x407C_0003);
    /// `MetaTagNewFXFolder`, `0x40110102` — the replicas of a public folder whose content is not on
    /// the server.
    ///
    /// [MS-OXCFXICS] §2.2.4.1.5.3
    pub const META_TAG_NEW_FX_FOLDER: Self = Self(0x4011_0102);
    /// `PidTagParentSourceKey`, `0x65E10102` — the source key of the folder an object is in.
    ///
    /// [MS-OXCFXICS] §2.2.1.2.6
    pub const PARENT_SOURCE_KEY: Self = Self(0x65E1_0102);
    /// `PidTagPredecessorChangeList`, `0x65E30102` — the versions an object's current version
    /// supersedes.
    ///
    /// [MS-OXCFXICS] §2.2.1.2.8
    pub const PREDECESSOR_CHANGE_LIST: Self = Self(0x65E3_0102);
    /// `PidTagRowid`, `0x30000003` — a recipient's row number, first in every recipient a stream
    /// carries.
    ///
    /// [MS-OXCFXICS] §2.2.4.3.23
    pub const ROW_ID: Self = Self(0x3000_0003);
    /// `PidTagSourceKey`, `0x65E00102` — an object's identity across replicas.
    ///
    /// [MS-OXCFXICS] §2.2.1.2.5
    pub const SOURCE_KEY: Self = Self(0x65E0_0102);
}
