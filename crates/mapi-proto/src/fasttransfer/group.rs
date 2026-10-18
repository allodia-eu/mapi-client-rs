//! Property groups: how a partial change says which part of a message changed.
//!
//! A server that downloads partial changes divides a message's properties into groups, defines the
//! division once with a `groupInfo` element, and from then on names groups by index. Knowing which
//! groups a change touched is what lets a client tell a change of categories from a change of body
//! without refetching the message.
//!
//! [MS-OXCFXICS] §2.2.2.8 — `PropertyGroupInfo`
//! [MS-OXCFXICS] §3.2.5.7 — property groups

use crate::error::Result;
use crate::fasttransfer::content::malformed;
use crate::fasttransfer::lexer::utf16_text;
use crate::oxcdata::{Guid, PropertyName, PropertySetId, PropertyTag};
use crate::wire::Reader;

/// One property a group names: its tag, and its name if it is a named property.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupProperty {
    tag: PropertyTag,
    name: Option<PropertyName>,
}

impl GroupProperty {
    /// The tag. For a named property the id is the store's.
    #[must_use]
    pub const fn tag(&self) -> PropertyTag {
        self.tag
    }

    /// The portable name of a named property.
    #[must_use]
    pub const fn name(&self) -> Option<&PropertyName> {
        self.name.as_ref()
    }
}

/// A property group mapping: which properties belong to which group.
///
/// [MS-OXCFXICS] §2.2.2.8 — `PropertyGroupInfo`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyGroupInfo {
    id: u32,
    groups: Vec<Vec<GroupProperty>>,
}

impl PropertyGroupInfo {
    /// Reads the structure a `groupInfo` element carries.
    pub(crate) fn read(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let id = r.u32()?;
        let _reserved = r.u32()?;
        let count = r.u32()?;
        let mut groups = Vec::new();
        for _ in 0..count {
            let tags = r.u32()?;
            let mut group = Vec::new();
            for _ in 0..tags {
                let tag = PropertyTag::new(r.u32()?);
                let name = if tag.id() >= 0x8000 {
                    Some(read_group_name(&mut r)?)
                } else {
                    None
                };
                group.push(GroupProperty { tag, name });
            }
            groups.push(group);
        }
        if !r.is_empty() {
            return Err(malformed(
                "PropertyGroupInfo",
                "bytes follow the last group",
            ));
        }
        Ok(Self { id, groups })
    }

    /// The id that `MetaTagIncrSyncGroupId` refers to this mapping by.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// The properties of the group at `index`.
    #[must_use]
    pub fn group(&self, index: u32) -> Option<&[GroupProperty]> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.groups.get(index))
            .map(Vec::as_slice)
    }

    /// How many groups the mapping defines.
    #[must_use]
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Whether the mapping defines none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// The index of the group a named property belongs to.
    #[must_use]
    pub fn group_of_name(&self, name: &PropertyName) -> Option<u32> {
        self.position(|property| property.name.as_ref() == Some(name))
    }

    /// The index of the group a tagged property belongs to, by its id.
    #[must_use]
    pub fn group_of_tag(&self, tag: PropertyTag) -> Option<u32> {
        self.position(|property| property.name.is_none() && property.tag.id() == tag.id())
    }

    fn position(&self, matches: impl Fn(&GroupProperty) -> bool) -> Option<u32> {
        self.groups
            .iter()
            .position(|group| group.iter().any(&matches))
            .and_then(|index| u32::try_from(index).ok())
    }
}

/// A named property's identity in a group mapping. Unlike the stream's own `namedPropInfo`, the
/// kind is four bytes and a name is counted rather than terminated.
///
/// [MS-OXCFXICS] §2.2.2.8.1.1 — `GroupPropertyName`
fn read_group_name(r: &mut Reader<'_>) -> Result<PropertyName> {
    let set = PropertySetId::from_guid(Guid::from_bytes(r.array::<16>()?));
    match r.u32()? {
        0 => Ok(PropertyName::lid(set, r.u32()?)),
        1 => {
            let size = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
            let name = utf16_text(r.bytes(size)?)
                .ok_or_else(|| malformed("GroupPropertyName", "a name that is not UTF-16"))?;
            Ok(PropertyName::from_stream(set, name))
        }
        _ => Err(malformed(
            "GroupPropertyName",
            "a kind other than LID or name",
        )),
    }
}
