//! What one store calls each named property, remembered for the length of the session.
//!
//! The cache lives here rather than in `mapi-proto` for one reason: nothing in the codec needs it.
//! A column set has to be remembered by the session because the rows that come back are undecodable
//! without it; a named-property id is not like that. Every response carrying one is
//! self-describing, and the id is only wanted by the layer that decides which properties to ask for
//! — so keeping it here leaves the codec's state exactly what decoding requires and no more.
//!
//! **A map is bound to the store that answered it.** It carries the mailbox GUID from the logon,
//! and there is no way to put an id from another mailbox into one, which is the strongest form the
//! per-store rule can take: not a check that can be skipped, but a value that cannot be built.
//!
//! [MS-OXCPRPT] §3.1.2 — an id is valid on any object within the logon, and is not guaranteed to
//! survive a new session
//! [MS-OXCDATA] §2.4.2 — `ecUnexpectedId`, what using one against the wrong store earns

use core::slice;

use mapi_proto::{Guid, NamedProperty, NamedPropertyId, PropertyName, PropertyTag, PropertyType};

/// One named property, and what this store said about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedPropertyEntry {
    name: PropertyName,
    id: Option<NamedPropertyId>,
}

impl NamedPropertyEntry {
    pub(crate) const fn new(name: PropertyName, id: Option<NamedPropertyId>) -> Self {
        Self { name, id }
    }

    /// The property that was asked about, which means the same thing in every mailbox.
    #[must_use]
    pub const fn name(&self) -> &PropertyName {
        &self.name
    }

    /// The id this store uses for it, or `None` if the store would not map it.
    ///
    /// A server that will not map a name answers `0x0000` **alongside a successful ROP**
    /// ([MS-OXCPRPT] §2.2.12.2), so this is a refusal reported as a value rather than as an error.
    /// The documented reasons are that the name is not registered and the request did not ask for
    /// it to be, that the user may not register new ones, or that the store has used all 32,767
    /// ids it has.
    #[must_use]
    pub const fn id(&self) -> Option<NamedPropertyId> {
        self.id
    }

    /// Whether this store has an id for it.
    #[must_use]
    pub const fn is_mapped(&self) -> bool {
        self.id.is_some()
    }
}

impl core::fmt::Display for NamedPropertyEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.id {
            Some(id) => write!(f, "{} = {id}", self.name),
            None => write!(f, "{} = not mapped in this store", self.name),
        }
    }
}

/// Every named property one logon has resolved, and the ids that store uses for them.
///
/// Held by the [`Logon`](crate::Logon) and grown as names are asked for, so resolving the same
/// property twice in a session costs one round trip rather than two.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedProperties {
    store: Guid,
    entries: Vec<NamedPropertyEntry>,
}

impl NamedProperties {
    pub(crate) const fn new(store: Guid) -> Self {
        Self {
            store,
            entries: Vec::new(),
        }
    }

    /// The mailbox whose ids these are.
    #[must_use]
    pub const fn store(&self) -> Guid {
        self.store
    }

    /// The id this store uses for one property, if it has been resolved and the store maps it.
    ///
    /// `None` covers both "never asked" and "the store would not map it". Use
    /// [`entry`](Self::entry) when the two need telling apart — a property nobody asked about is a
    /// gap in the request, and one the store refused is a fact about the mailbox.
    #[must_use]
    pub fn get(&self, name: &PropertyName) -> Option<NamedPropertyId> {
        self.entry(name).and_then(NamedPropertyEntry::id)
    }

    /// What this store said about one property, or `None` if it was never asked about.
    #[must_use]
    pub fn entry(&self, name: &PropertyName) -> Option<&NamedPropertyEntry> {
        self.entries.iter().find(|entry| entry.name() == name)
    }

    /// The tag that reads or writes one property here, given the type its value is carried in.
    ///
    /// The type has to come from somewhere: a resolved id says nothing about it, and a tag pairing
    /// the right id with the wrong type makes the server parse the value as a different shape.
    /// [`tag_of`](Self::tag_of) supplies it from [MS-OXPROPS] for the catalogued properties.
    #[must_use]
    pub fn tag(&self, name: &PropertyName, property_type: PropertyType) -> Option<PropertyTag> {
        self.get(name).map(|id| id.tag(property_type))
    }

    /// The tag for one of the properties this crate knows, type included.
    ///
    /// ```no_run
    /// # use mapi_client::{APPOINTMENT_PROPERTIES, Logon, NamedProperty};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let named = logon.resolve_names(APPOINTMENT_PROPERTIES).await?;
    /// let start = named.tag_of(NamedProperty::AppointmentStartWhole);
    /// println!("{start:?}");
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn tag_of(&self, property: NamedProperty) -> Option<PropertyTag> {
        self.tag(&property.name(), property.property_type())
    }

    /// Every property asked about, in the order it was first asked about.
    #[must_use]
    pub fn iter(&self) -> NamedPropertiesIter<'_> {
        NamedPropertiesIter {
            inner: self.entries.iter(),
        }
    }

    /// How many properties have been asked about.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing has been resolved yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many of them this store actually has an id for.
    #[must_use]
    pub fn mapped(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.is_mapped())
            .count()
    }

    /// The names not yet resolved, in the order given and without repeats.
    ///
    /// What decides whether a round trip is needed at all, and what it should ask for.
    pub(crate) fn missing(&self, names: &[PropertyName]) -> Vec<PropertyName> {
        let mut wanted: Vec<PropertyName> = Vec::new();
        for name in names {
            if self.entry(name).is_none() && !wanted.contains(name) {
                wanted.push(name.clone());
            }
        }
        wanted
    }

    /// Records what the store answered, pairing each id with the name it was asked in place of.
    ///
    /// The pairing is positional, because a `RopGetPropertyIdsFromNames` response carries nothing
    /// that says which name each id belongs to — [MS-OXCPRPT] §2.2.12.2 requires one entry per name
    /// asked for, in the same order. A server that answers with a different number of ids has
    /// broken that promise, and the surplus names are recorded as unmapped rather than being paired
    /// with somebody else's id.
    pub(crate) fn absorb(&mut self, names: Vec<PropertyName>, ids: &[u16]) {
        for (index, name) in names.into_iter().enumerate() {
            let id = ids
                .get(index)
                .copied()
                .filter(|id| *id != 0)
                .map(|id| NamedPropertyId::new(self.store, id));
            self.entries.push(NamedPropertyEntry::new(name, id));
        }
    }
}

impl<'a> IntoIterator for &'a NamedProperties {
    type IntoIter = NamedPropertiesIter<'a>;
    type Item = &'a NamedPropertyEntry;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Every entry in a [`NamedProperties`], in the order each was first asked about.
///
/// A named type rather than `impl Iterator`, so a caller can store one in a struct.
#[derive(Clone, Debug)]
pub struct NamedPropertiesIter<'a> {
    inner: slice::Iter<'a, NamedPropertyEntry>,
}

impl<'a> Iterator for NamedPropertiesIter<'a> {
    type Item = &'a NamedPropertyEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for NamedPropertiesIter<'_> {}

impl DoubleEndedIterator for NamedPropertiesIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

#[cfg(test)]
mod tests {
    use mapi_proto::PropertySetId;

    use super::*;

    fn store() -> Guid {
        Guid::from_bytes([0x11; 16])
    }

    fn resolved() -> NamedProperties {
        let mut map = NamedProperties::new(store());
        map.absorb(
            vec![
                NamedProperty::AppointmentStartWhole.name(),
                NamedProperty::Location.name(),
            ],
            &[0x8206, 0x0000],
        );
        map
    }

    #[test]
    fn an_id_comes_back_bound_to_the_store_that_issued_it() {
        let map = resolved();
        let start = map
            .get(&NamedProperty::AppointmentStartWhole.name())
            .expect("a resolved id");

        assert_eq!(start.as_u16(), 0x8206);
        assert!(start.belongs_to(store()));
        assert!(!start.belongs_to(Guid::from_bytes([0x22; 16])));
        assert_eq!(map.store(), store());
    }

    /// The type comes from [MS-OXPROPS] rather than from the wire, and the resulting tag is a
    /// named tag whose id is the store's and whose type is the property's.
    #[test]
    fn a_resolved_property_becomes_a_tag_with_the_documented_type() {
        let map = resolved();
        let tag = map
            .tag_of(NamedProperty::AppointmentStartWhole)
            .expect("a tag");

        assert_eq!(tag, PropertyTag::new(0x8206_0040));
        assert!(tag.is_named());
        assert_eq!(tag.property_type(), PropertyType::Time);
        assert_eq!(
            map.tag(
                &NamedProperty::AppointmentStartWhole.name(),
                PropertyType::String
            ),
            Some(PropertyTag::new(0x8206_001F)),
            "the caller's type is the one used"
        );
    }

    /// `0x0000` is a refusal the server reports as a value. It has to stay distinguishable from
    /// "nobody asked", because one is a fact about the mailbox and the other is a gap in the
    /// request.
    #[test]
    fn a_name_the_store_refused_is_not_the_same_as_one_never_asked_about() {
        let map = resolved();
        let refused = NamedProperty::Location.name();
        let never = NamedProperty::BusyStatus.name();

        assert_eq!(map.get(&refused), None);
        assert_eq!(map.get(&never), None);

        assert!(map.entry(&refused).is_some_and(|e| !e.is_mapped()));
        assert!(map.entry(&never).is_none());
        assert_eq!(map.tag_of(NamedProperty::Location), None);

        assert_eq!(map.len(), 2);
        assert_eq!(map.mapped(), 1);
        assert!(!map.is_empty());
    }

    /// A refused name is still resolved: asking again would spend a round trip to be told the same
    /// thing.
    #[test]
    fn only_the_names_with_no_answer_yet_are_asked_for_again() {
        let map = resolved();
        let missing = map.missing(&[
            NamedProperty::AppointmentStartWhole.name(),
            NamedProperty::Location.name(),
            NamedProperty::BusyStatus.name(),
            NamedProperty::BusyStatus.name(),
        ]);

        assert_eq!(missing, vec![NamedProperty::BusyStatus.name()]);
        assert!(NamedProperties::new(store()).missing(&[]).is_empty());
    }

    /// A server that answers with fewer ids than names has broken [MS-OXCPRPT] §2.2.12.2's
    /// ordering promise. The names past the end are recorded as unmapped rather than shifted onto
    /// ids belonging to earlier names.
    #[test]
    fn a_short_answer_leaves_the_surplus_names_unmapped() {
        let mut map = NamedProperties::new(store());
        map.absorb(
            vec![
                NamedProperty::BusyStatus.name(),
                NamedProperty::Recurring.name(),
            ],
            &[0x8205],
        );

        assert_eq!(
            map.get(&NamedProperty::BusyStatus.name())
                .map(NamedPropertyId::as_u16),
            Some(0x8205)
        );
        assert_eq!(map.get(&NamedProperty::Recurring.name()), None);
        assert_eq!(map.mapped(), 1);
    }

    #[test]
    fn every_entry_prints_something_a_person_can_act_on() {
        let lines: Vec<String> = resolved().iter().map(ToString::to_string).collect();
        assert!(
            lines.first().is_some_and(|line| line.ends_with("= 0x8206")),
            "{lines:?}"
        );
        assert!(
            lines.get(1).is_some_and(|line| line.contains("not mapped")),
            "{lines:?}"
        );
    }

    #[test]
    fn the_iterator_is_exact_sized_and_double_ended() {
        let map = resolved();
        let mut iter = map.iter();
        assert_eq!(iter.len(), 2);
        assert_eq!(
            iter.next().map(NamedPropertyEntry::name),
            Some(&NamedProperty::AppointmentStartWhole.name())
        );
        assert_eq!(
            iter.next_back().map(NamedPropertyEntry::name),
            Some(&NamedProperty::Location.name())
        );
        assert_eq!((&map).into_iter().count(), 2);
    }

    /// A string-named property is cached by the same key as a LID-named one, so a client's own
    /// property is no different from a documented one.
    #[test]
    fn a_string_named_property_caches_like_any_other() {
        let name = PropertyName::named(PropertySetId::PUBLIC_STRINGS, "x-mine").expect("a name");
        let mut map = NamedProperties::new(store());
        map.absorb(vec![name.clone()], &[0x8501]);

        assert_eq!(map.get(&name).map(NamedPropertyId::as_u16), Some(0x8501));
        assert!(map.missing(&[name]).is_empty());
    }
}
