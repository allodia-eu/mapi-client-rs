//! What one replay of a captured session observed, and every claim made about it.
//!
//! Split out of `replay.rs` so that the file driving the corpus stays about *driving* it: this one
//! is the list of things the bytes Exchange sent are asserted to mean. Both are one test binary.

use mapi_client::{
    ContainerClass, ErrorCode, FOLDER_PROPERTIES, FolderId, MAILBOX_PROPERTIES, NamedProperties,
    NamedProperty, PropertyName, PropertyProblem, PropertyRow, PropertySet, PropertySetId,
    PropertyTag, PropertyValue, SpecialFolder, SpecialFolderState, SpecialFolders, StoreObjectType,
    TableString,
};

/// Everything one replay observed.
pub(crate) struct Replayed {
    pub(crate) display_name: String,
    pub(crate) folder_ids: Vec<FolderId>,
    pub(crate) inbox: FolderId,
    pub(crate) subtree: FolderId,
    pub(crate) mailbox: PropertySet,
    pub(crate) refused: Vec<PropertyProblem>,
    pub(crate) named: NamedProperties,
    pub(crate) named_back: Vec<Option<PropertyName>>,
    pub(crate) folders: Vec<(FolderId, String)>,
    pub(crate) folder_count: Option<u32>,
    pub(crate) descendants: Vec<PropertyRow>,
    pub(crate) special: SpecialFolders,
    pub(crate) calendar_properties: PropertySet,
    pub(crate) messages: Vec<(String, bool)>,
    pub(crate) message_count: Option<u32>,
}

impl Replayed {
    /// What every mailbox has, whatever language it speaks.
    ///
    /// The message count is a parameter because the two lab mailboxes hold different numbers of
    /// them, which is rather the point: what is being tested is the paging, not the seed data.
    pub(crate) fn assert_shape_is_a_mailbox(&self, messages: u32) {
        assert_eq!(self.folder_ids.len(), 13, "a private logon names thirteen");
        assert_eq!(self.folder_count, Some(15));
        assert_eq!(self.folders.len(), 15, "read across two pages of eight");
        assert_eq!(self.message_count, Some(messages));
        assert_eq!(
            u32::try_from(self.messages.len()).unwrap(),
            messages,
            "every row the server reported arrived, across pages of two"
        );

        // The Inbox is found by the id the logon gave, not by its name — which is the whole point
        // of having a second mailbox in a second language.
        assert!(
            self.folders.iter().any(|(id, _)| *id == self.inbox),
            "the Inbox is not in the hierarchy: {:?}",
            self.folders
        );

        // Exactly one seeded subject is long enough for the table to cut it at 255 characters, and
        // the table says so nowhere except in the value's own length.
        let truncated: Vec<&String> = self
            .messages
            .iter()
            .filter(|(_, truncated)| *truncated)
            .map(|(subject, _)| subject)
            .collect();
        assert_eq!(truncated.len(), 1, "{:?}", self.messages);
        assert_eq!(truncated[0].chars().count(), 255);

        self.assert_shape_of_the_store_object();
        self.assert_shape_of_the_named_properties();
        self.assert_shape_of_the_folder_tree();
        self.assert_shape_of_the_special_folders();
    }

    /// What the store numbered the catalogued properties as, and what it said those numbers are.
    ///
    /// No number is asserted here. The ids are a fact about the lab mailbox that produced the
    /// capture — they differ between the two session directories, which is the whole point — so
    /// what is checked is everything about them that *is* a claim about the protocol.
    ///
    /// [MS-OXCPRPT] §2.2.12.2 — one id per name, in order, `0x0000` for what could not be mapped
    fn assert_shape_of_the_named_properties(&self) {
        assert_eq!(
            self.named.len(),
            NamedProperty::ALL.len() + 1,
            "one entry per name asked for, the unregistered one included"
        );
        assert_eq!(
            self.named.mapped(),
            NamedProperty::ALL.len(),
            "every catalogued property resolves and the invented one does not"
        );

        for property in NamedProperty::ALL {
            let id = self
                .named
                .get(&property.name())
                .unwrap_or_else(|| panic!("{property} did not resolve"));
            // [MS-OXCPRPT] §3.1.4.1: a named property's id has its most significant bit set.
            assert!(id.as_u16() >= 0x8000, "{property} = {id}");
            assert!(
                id.belongs_to(self.named.store()),
                "{property} came back bound to another store"
            );
        }

        // `0x0000` alongside a successful ROP: a refusal reported as a value, and the reason an
        // entry is not an `Option<u16>`. Asked for, answered, and not mapped.
        let invented = PropertyName::named(PropertySetId::PUBLIC_STRINGS, crate::UNREGISTERED_NAME)
            .expect("a name this crate can carry");
        assert!(
            self.named
                .entry(&invented)
                .is_some_and(|entry| !entry.is_mapped()),
            "the server registered a name the capture asked it not to create"
        );

        // The inverse ROP, which is the only witness to the pairing that does not come from the
        // ordering being checked. Every catalogued id has to come back as the name it was resolved
        // for, in place.
        assert_eq!(
            self.named_back.len(),
            NamedProperty::ALL.len() + 2,
            "one name per id asked about, the two extras included"
        );
        for (index, property) in NamedProperty::ALL.into_iter().enumerate() {
            assert_eq!(
                self.named_back.get(index).and_then(Option::as_ref),
                Some(&property.name()),
                "{property} resolved to an id the store calls something else"
            );
        }

        // An id below `0x8000` is not a named property, and the server answers out of `PS_MAPI`
        // rather than refusing. [MS-OXCPRPT] §2.2.13
        let fixed = self
            .named_back
            .get(NamedProperty::ALL.len())
            .and_then(Option::as_ref)
            .expect("PS_MAPI names the fixed ids");
        assert_eq!(fixed.set(), PropertySetId::MAPI, "{fixed}");
        assert_eq!(fixed.as_lid(), Some(u32::from(crate::FIXED_ID)), "{fixed}");

        // **The deviation.** [MS-OXCDATA] §2.6.1's diagram marks `GUID` as not optional, so an
        // entry with no name would still carry sixteen bytes of property set. Exchange sends the
        // `0xFF` and stops. This entry decoding at all — and the `Disconnect` after it replaying —
        // is the assertion; reading the specification's sixteen bytes here runs off the buffer.
        assert_eq!(
            self.named_back.last(),
            Some(&None),
            "the measurement this assertion records has changed; re-measure it rather than \
             deleting it"
        );
    }

    /// What the `Depth` flag answered, and the column that makes its answer a tree.
    ///
    /// The recursive read has to find at least what the immediate one did, and the rows have to
    /// carry parent ids that are not all the subtree — a flat list in which every folder claims
    /// the root as its parent would decode identically and mean nothing.
    ///
    /// [MS-OXCFOLD] §2.2.1.13.1 — `TableFlags`, `Depth`
    fn assert_shape_of_the_folder_tree(&self) {
        assert!(
            self.descendants.len() > self.folders.len(),
            "a recursive read found {} folders and the immediate one found {}",
            self.descendants.len(),
            self.folders.len()
        );

        let immediate: Vec<FolderId> = self.folders.iter().map(|(id, _)| *id).collect();
        let deep: Vec<FolderId> = self
            .descendants
            .iter()
            .filter_map(PropertyRow::folder_id)
            .collect();
        for id in &immediate {
            assert!(deep.contains(id), "{id} is missing from the recursive read");
        }

        let parents: Vec<FolderId> = self
            .descendants
            .iter()
            .filter_map(|row| {
                row.get(PropertyTag::PARENT_FOLDER_ID)
                    .and_then(PropertyValue::as_u64)
                    .map(FolderId::new)
            })
            .collect();
        assert_eq!(
            parents.len(),
            self.descendants.len(),
            "PidTagParentFolderId is absent from a row, so this listing is not a tree"
        );
        assert!(
            parents.iter().any(|parent| *parent != self.subtree),
            "every folder claims the subtree as its parent, so nothing here is nested"
        );

        // The column a class-tagged listing exists for: without it a calendar and a mail folder
        // are two names in a language the reader may not have.
        assert!(
            self.descendants.iter().any(|row| {
                row.string(PropertyTag::CONTAINER_CLASS)
                    .is_some_and(|class| class.as_str() == "IPF.Appointment")
            }),
            "no folder in this capture is a calendar"
        );
    }

    /// The entry-id chain: what the Inbox named, and that the Calendar it found really is one.
    ///
    /// [MS-OXOSFLD] §2.2.3 — the binary identification properties
    fn assert_shape_of_the_special_folders(&self) {
        for folder in [
            SpecialFolder::Calendar,
            SpecialFolder::Contacts,
            SpecialFolder::Drafts,
            SpecialFolder::Tasks,
        ] {
            assert!(
                self.special.get(folder).is_some(),
                "{folder} did not resolve: {:?}",
                self.special.state(folder)
            );
        }

        // Absent rather than refused, and the difference is the point of having both states: this
        // mailbox has never had an archive, so the Inbox carries no property naming one.
        assert_eq!(
            self.special.state(SpecialFolder::Archive),
            Some(&SpecialFolderState::Absent),
            "the measurement that the lab mailboxes have no Archive folder has changed"
        );

        // The Calendar, opened. A folder that answers `IPF.Appointment` is the calendar whatever
        // it is called in this mailbox's language — which is the whole reason the chain exists.
        let class = self
            .calendar_properties
            .string(PropertyTag::CONTAINER_CLASS)
            .map(TableString::as_str)
            .unwrap_or_default();
        assert_eq!(
            ContainerClass::new(class),
            ContainerClass::Appointment,
            "the folder the entry-id chain found is not a calendar"
        );
        assert_eq!(
            self.calendar_properties.len(),
            FOLDER_PROPERTIES.len(),
            "a property fetch answers for every tag it was given"
        );

        // Every entry id names the mailbox that issued it. This is the only thing that would catch
        // an id belonging to another store, which converts cleanly and opens the wrong folder.
        for entry in &self.special {
            if let SpecialFolderState::Found { entry_id, .. } = entry.state() {
                assert_eq!(
                    entry_id.object_type(),
                    StoreObjectType::PRIVATE_FOLDER,
                    "{}",
                    entry.folder()
                );
            }
        }
    }

    /// What a real Store object answered, and what it refused.
    ///
    /// Both halves are claims about bytes Exchange actually sent: a `RopGetPropertiesSpecific`
    /// answering for every tag it was given, two of them with an error in place of a value, and a
    /// `RopSetProperties` that succeeded while the property inside it did not.
    fn assert_shape_of_the_store_object(&self) {
        assert_eq!(
            self.mailbox.len(),
            MAILBOX_PROPERTIES.len(),
            "a property fetch answers for every tag it was given, present or not"
        );

        // A binary value, which is the corpus's only evidence that a `PtypBinary` COUNT is 16 bits
        // wide inside a ROP buffer. Read it as 32 and the two bytes that follow are swallowed, so
        // this decoding at all is the assertion.
        let owner = self
            .mailbox
            .get(PropertyTag::MAILBOX_OWNER_ENTRY_ID)
            .and_then(PropertyValue::as_binary)
            .expect("the owner's address book EntryID");
        assert!(owner.len() > 100, "{} bytes", owner.len());

        // Documented as read-only properties of every private mailbox logon, and answered with
        // `ecNotFound` by the server that produced this corpus. Recorded rather than smoothed
        // over: "not set" and "the server would not say" are different facts.
        //
        // [MS-OXCSTOR] §2.2.2.1.1.5, §2.2.2.1.1.12
        for absent in [PropertyTag::STORE_STATE, PropertyTag::LOCALE_ID] {
            assert_eq!(
                self.mailbox.error(absent),
                Some(ErrorCode::NOT_FOUND),
                "{absent}"
            );
        }

        // The write that succeeded as a ROP and failed as a property. A caller that only looked at
        // the ROP's return value would report this as a completed write.
        //
        // [MS-OXCSTOR] §7 note 14 — Exchange 2013 SP1 and later refuse this one
        assert_eq!(
            self.refused
                .iter()
                .map(|problem| (problem.tag(), problem.code()))
                .collect::<Vec<_>>(),
            vec![(PropertyTag::COMMENT, ErrorCode::ACCESS_DENIED)]
        );
    }

    /// The name of the folder with a given id.
    pub(crate) fn folder(&self, id: FolderId) -> &str {
        self.folders
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .map(|(_, name)| &**name)
            .unwrap_or_default()
    }
}
