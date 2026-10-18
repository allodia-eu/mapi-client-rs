//! The meta-properties [`tag::sync`](crate::PropertyTag) declares, with the id and type
//! [MS-OXCFXICS] §2.2.1.1 and §2.2.1.3 give each.

use crate::oxcdata::{PropertyTag, PropertyType};

pub(in crate::oxcdata::tag::tests) const SYNC_CATALOGUE: [(PropertyTag, u16, PropertyType, &str);
    9] = [
    (
        PropertyTag::META_TAG_CNSET_READ,
        0x67D2,
        PropertyType::Binary,
        "MetaTagCnsetRead",
    ),
    (
        PropertyTag::META_TAG_CNSET_SEEN,
        0x6796,
        PropertyType::Binary,
        "MetaTagCnsetSeen",
    ),
    (
        PropertyTag::META_TAG_CNSET_SEEN_FAI,
        0x67DA,
        PropertyType::Binary,
        "MetaTagCnsetSeenFAI",
    ),
    (
        PropertyTag::META_TAG_IDSET_DELETED,
        0x67E5,
        PropertyType::Binary,
        "MetaTagIdsetDeleted",
    ),
    (
        PropertyTag::META_TAG_IDSET_EXPIRED,
        0x6793,
        PropertyType::Binary,
        "MetaTagIdsetExpired",
    ),
    // PtypInteger32, as §2.2.1.1.1 gives it, though the value is an IDSET.
    (
        PropertyTag::META_TAG_IDSET_GIVEN,
        0x4017,
        PropertyType::Integer32,
        "MetaTagIdsetGiven",
    ),
    (
        PropertyTag::META_TAG_IDSET_NO_LONGER_IN_SCOPE,
        0x4021,
        PropertyType::Binary,
        "MetaTagIdsetNoLongerInScope",
    ),
    (
        PropertyTag::META_TAG_IDSET_READ,
        0x402D,
        PropertyType::Binary,
        "MetaTagIdsetRead",
    ),
    (
        PropertyTag::META_TAG_IDSET_UNREAD,
        0x402E,
        PropertyType::Binary,
        "MetaTagIdsetUnread",
    ),
];
