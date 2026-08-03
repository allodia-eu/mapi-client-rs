//! A mailbox that has been logged on to, and the folders in it.

use core::borrow::Borrow;

use mapi_proto::{
    Connected, FolderEntryId, FolderId, LogonResponse, LongTermId, NameRegistration, ObjectHandle,
    PropertyIdsResponse, PropertyName, PropertySet, PropertyValue, RopBatch, RopResponse,
    SPECIAL_FOLDER_PROPERTIES, ShortTermId, SpecialFolder, WellKnownFolder,
};

use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::folder::Folder;
use crate::named::NamedProperties;
use crate::properties::Properties;
use crate::special::{SpecialFolderEntry, SpecialFolderState, SpecialFolders};

/// A mailbox, logged on and ready to be read.
///
/// Owns the [`Connection`] it was made from: there is one logon per Session Context, so the two
/// have exactly the same lifetime and separating them would only make it possible to outlive the
/// session the handle belongs to.
#[derive(Debug)]
pub struct Logon {
    connection: Connection,
    handle: ObjectHandle,
    response: LogonResponse,
    named: NamedProperties,
}

impl Logon {
    pub(crate) const fn new(
        connection: Connection,
        handle: ObjectHandle,
        response: LogonResponse,
    ) -> Self {
        Self {
            named: NamedProperties::new(response.mailbox_guid()),
            connection,
            handle,
            response,
        }
    }

    /// Everything the logon reported: all thirteen special folder ids, the mailbox GUID and the
    /// replica identifiers.
    ///
    /// [MS-OXCSTOR] §2.2.1.1.3 — success response buffer for a private mailbox
    #[must_use]
    pub const fn mailbox(&self) -> &LogonResponse {
        &self.response
    }

    /// What the server reported when the Session Context was established.
    #[must_use]
    pub const fn server(&self) -> &Connected {
        self.connection.server()
    }

    /// The id of one of the thirteen special folders.
    ///
    /// This is why reaching the Inbox costs nothing: a private-mailbox logon hands back every
    /// special folder's id, so no `RopGetReceiveFolder` and no `EntryID` parsing is needed.
    ///
    /// # Errors
    ///
    /// [`Error::MissingFolder`] if the logon response did not carry that folder, which a
    /// conforming private-mailbox logon always does.
    ///
    /// [MS-OXCSTOR] §2.2.1.1.3 — `FolderIds`
    pub fn folder_id(&self, folder: WellKnownFolder) -> Result<FolderId> {
        self.response
            .folder(folder)
            .ok_or(Error::MissingFolder { folder })
    }

    /// The Store object's own properties: what the mailbox knows about itself.
    ///
    /// [`mailbox`](Self::mailbox) reports what the logon *response* carried, which is folder ids
    /// and identifiers and nothing else. Display name, owner, size and quotas are properties of
    /// the Store object and take a round trip to read.
    ///
    /// ```no_run
    /// # use mapi_client::{Logon, MAILBOX_PROPERTIES, PropertyTag, TableString};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let mailbox = logon.store().read(MAILBOX_PROPERTIES).await?;
    /// println!(
    ///     "{:?}",
    ///     mailbox
    ///         .string(PropertyTag::MAILBOX_OWNER_NAME)
    ///         .map(TableString::as_str)
    /// );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [MS-OXCSTOR] §2.2.2.1 — private mailbox logon properties
    #[must_use]
    pub fn store(&mut self) -> Properties<'_> {
        Properties::new(&mut self.connection, self.handle)
    }

    /// A folder to read, by id.
    ///
    /// Nothing is sent yet: the folder is opened by the first request the returned builder makes,
    /// in the same round trip as the read itself.
    #[must_use]
    pub fn folder(&mut self, id: FolderId) -> Folder<'_> {
        Folder::new(&mut self.connection, self.handle, id)
    }

    /// One of the thirteen special folders, ready to read.
    ///
    /// ```no_run
    /// # use mapi_client::{Logon, WellKnownFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let messages = logon
    ///     .well_known(WellKnownFolder::Inbox)?
    ///     .contents()
    ///     .collect()
    ///     .await?;
    /// # let _ = messages;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingFolder`], as [`folder_id`](Self::folder_id).
    pub fn well_known(&mut self, folder: WellKnownFolder) -> Result<Folder<'_>> {
        let id = self.folder_id(folder)?;
        Ok(self.folder(id))
    }

    /// Finds the folders the logon does *not* name: Calendar, Contacts, Drafts and the rest.
    ///
    /// **Two round trips, whatever is asked for.** The entry ids live in binary properties on the
    /// Inbox, and an entry id is long-term while `RopOpenFolder` takes a short-term id — so this
    /// reads all eight properties in one `Execute` and converts all eight in the next. Asking for
    /// one folder costs exactly the same, which is why this resolves everything and hands back a
    /// lookup rather than offering a cheaper-looking per-folder call.
    ///
    /// A folder this mailbox has never had is reported as
    /// [`SpecialFolderState::Absent`](crate::SpecialFolderState::Absent) rather than failing the
    /// call: Exchange creates most of them on demand, so a fresh mailbox has no Journal and that
    /// is not an error.
    ///
    /// ```no_run
    /// # use mapi_client::{Logon, SpecialFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let special = logon.special_folders().await?;
    /// for entry in &special {
    ///     println!("{entry}");
    /// }
    ///
    /// if let Some(calendar) = special.get(SpecialFolder::Calendar) {
    ///     let events = logon.folder(calendar).contents().collect().await?;
    ///     println!("{} events", events.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::MissingFolder`] if the logon named no Inbox, and whatever either round trip failed
    /// with. A server that refuses one conversion does not fail the call — that folder is reported
    /// as [`SpecialFolderState::Refused`](crate::SpecialFolderState::Refused).
    ///
    /// [MS-OXOSFLD] §2.2.3 — the properties, and that they are read from the Inbox for an owner
    /// [MS-OXOSFLD] §4.1 — the procedure
    pub async fn special_folders(&mut self) -> Result<SpecialFolders> {
        let inbox = self.folder_id(WellKnownFolder::Inbox)?;
        let named = self
            .folder(inbox)
            .properties()
            .read(SPECIAL_FOLDER_PROPERTIES)
            .await?;
        self.convert(&named).await
    }

    /// One special folder's id.
    ///
    /// Costs the same two round trips as [`special_folders`](Self::special_folders), which
    /// resolves every one of them — reach for that when more than one is wanted.
    ///
    /// # Errors
    ///
    /// [`Error::MissingSpecialFolder`] if this mailbox does not have it, carrying what the mailbox
    /// said about it, plus whatever the round trips failed with.
    pub async fn special_folder(&mut self, folder: SpecialFolder) -> Result<FolderId> {
        let resolved = self.special_folders().await?;
        resolved
            .get(folder)
            .ok_or_else(|| Error::MissingSpecialFolder {
                folder,
                state: resolved
                    .state(folder)
                    .map_or_else(|| "it was not asked for".to_owned(), ToString::to_string),
            })
    }

    /// What this store calls each of these named properties, resolving whatever it has not
    /// already.
    ///
    /// **One round trip for however many are new, and none at all when they are all known.** The
    /// ids are cached against this logon, so the second call for the same properties is free — and
    /// that is not an optimisation but the difference between one extra round trip per session and
    /// one per calendar read.
    ///
    /// The returned map is bound to this mailbox. An id resolved here means nothing in another
    /// mailbox: ids are allocated per store as each first needs a property, and using one against
    /// the wrong store reads a *different* property and reports no error.
    ///
    /// Only already-registered names are resolved; nothing is created. A property this store has
    /// never held comes back unmapped, which is an answer rather than a failure — see
    /// [`NamedPropertyEntry::id`](crate::NamedPropertyEntry::id).
    ///
    /// ```no_run
    /// # use mapi_client::{APPOINTMENT_PROPERTIES, Logon, NamedProperty};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let named = logon.resolve_names(APPOINTMENT_PROPERTIES).await?;
    /// for entry in named {
    ///     println!("{entry}");
    /// }
    ///
    /// let start = logon.names().tag_of(NamedProperty::AppointmentStartWhole);
    /// println!("{start:?}");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the lookup — `ecAccessDenied` for a user who may not
    /// read the mapping table — plus whatever the round trip failed with.
    ///
    /// [MS-OXCROPS] §2.2.8.1 — `RopGetPropertyIdsFromNames`
    /// [MS-OXCPRPT] §3.1.2 — an id may be cached for the session, and is a fact about one store
    pub async fn resolve_names<I>(&mut self, names: I) -> Result<&NamedProperties>
    where
        I: IntoIterator,
        I::Item: Into<PropertyName>,
    {
        let asked: Vec<PropertyName> = names.into_iter().map(Into::into).collect();
        let wanted = self.named.missing(&asked);
        if wanted.is_empty() {
            return Ok(&self.named);
        }

        let mut batch = RopBatch::new();
        let logon = batch.bind(self.handle);
        batch.property_ids_from_names(logon, &wanted, NameRegistration::Existing);

        let execution = self
            .connection
            .execute(batch, "resolving named properties")
            .await?;
        let ids = execution
            .responses()
            .iter()
            .find_map(RopResponse::as_property_ids)
            .ok_or(Error::Unexpected {
                expected: "a RopGetPropertyIdsFromNames response",
                found: "no property ids in the batch's responses",
            })?;

        self.named.absorb(wanted, PropertyIdsResponse::ids(ids));
        Ok(&self.named)
    }

    /// The named properties resolved so far, without sending anything.
    #[must_use]
    pub const fn names(&self) -> &NamedProperties {
        &self.named
    }

    /// What this store calls each of these property ids — the inverse question.
    ///
    /// The only way to say what a `0x8005` in a property dump actually *is*. One round trip, and
    /// deliberately not cached: unlike a name, an id is what a caller already has in hand, and the
    /// answer is a diagnostic rather than something a later request is built from.
    ///
    /// An id below `0x8000` is answered from the `PS_MAPI` set rather than refused, and one this
    /// store has never registered comes back as `None` rather than being left out — so the answers
    /// stay positional against the ids asked about.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the lookup, plus whatever the round trip failed with.
    ///
    /// [MS-OXCROPS] §2.2.8.2 — `RopGetNamesFromPropertyIds`
    pub async fn names_of<I>(&mut self, ids: I) -> Result<Vec<Option<PropertyName>>>
    where
        I: IntoIterator,
        I::Item: Borrow<u16>,
    {
        let ids: Vec<u16> = ids.into_iter().map(|id| *id.borrow()).collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut batch = RopBatch::new();
        let logon = batch.bind(self.handle);
        batch.names_from_property_ids(logon, &ids);

        let execution = self
            .connection
            .execute(batch, "asking what property ids are named")
            .await?;
        execution
            .responses()
            .iter()
            .find_map(RopResponse::as_property_names)
            .map(|response| response.names().to_vec())
            .ok_or(Error::Unexpected {
                expected: "a RopGetNamesFromPropertyIds response",
                found: "no property names in the batch's responses",
            })
    }

    /// Converts a long-term id into the short-term one `RopOpenFolder` takes.
    ///
    /// One round trip, and it has to be: the mapping between a 16-byte database GUID and the
    /// 2-byte replica id that stands for it lives on the server and nowhere else.
    /// [`special_folders`](Self::special_folders) is this call in bulk and is what most callers
    /// want; this is for an entry id that came from somewhere else.
    ///
    /// **The answer is only meaningful in the store this logon named.** Converting an entry id
    /// issued by another mailbox yields a valid-looking id for the wrong folder, which
    /// [`FolderEntryId::belongs_to`](mapi_proto::FolderEntryId::belongs_to) is the check against.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server would not convert it, plus whatever the round trip failed
    /// with.
    ///
    /// [MS-OXCROPS] §2.2.3.9 — `RopIdFromLongTermId`
    pub async fn short_term_id(&mut self, id: &LongTermId) -> Result<ShortTermId> {
        let mut batch = RopBatch::new();
        let logon = batch.bind(self.handle);
        batch.id_from_long_term_id(logon, id);

        let execution = self
            .connection
            .execute(batch, "converting a long-term id")
            .await?;
        execution
            .responses()
            .iter()
            .find_map(RopResponse::as_short_term_id)
            .ok_or(Error::Unexpected {
                expected: "a RopIdFromLongTermId response",
                found: "no converted id in the batch's responses",
            })
    }

    /// Converts a folder or message id into one that survives leaving the store.
    ///
    /// The inverse of [`short_term_id`](Self::short_term_id), and what writing an entry-id
    /// property needs.
    ///
    /// # Errors
    ///
    /// As [`short_term_id`](Self::short_term_id).
    ///
    /// [MS-OXCROPS] §2.2.3.8 — `RopLongTermIdFromId`
    pub async fn long_term_id(&mut self, id: ShortTermId) -> Result<LongTermId> {
        let mut batch = RopBatch::new();
        let logon = batch.bind(self.handle);
        batch.long_term_id_from_id(logon, id);

        let execution = self
            .connection
            .execute(batch, "converting a short-term id")
            .await?;
        execution
            .responses()
            .iter()
            .find_map(RopResponse::as_long_term_id)
            .ok_or(Error::Unexpected {
                expected: "a RopLongTermIdFromId response",
                found: "no converted id in the batch's responses",
            })
    }

    /// Turns the Inbox's entry-id properties into folder ids, in one round trip.
    ///
    /// The conversions are matched to the folders they answer **by position**: a ROP response
    /// carries nothing that says which request it belongs to, so the list of folders whose entry
    /// ids were readable is kept in the order they were issued and walked alongside the responses.
    /// A refusal takes its place in that order like any other answer, which is why a refused
    /// conversion cannot shift the ones after it onto the wrong folder.
    async fn convert(&mut self, named: &PropertySet) -> Result<SpecialFolders> {
        let mut batch = RopBatch::new();
        let logon = batch.bind(self.handle);

        let slots: Vec<(SpecialFolder, Slot)> = SpecialFolder::ALL
            .into_iter()
            .map(|folder| {
                let slot = classify(named, folder);
                if let Slot::Convert(entry_id) = &slot {
                    batch.id_from_long_term_id(logon, &entry_id.long_term_id());
                }
                (folder, slot)
            })
            .collect();

        // No round trip when the Inbox named nothing convertible, which is what a mailbox with no
        // special folders at all looks like.
        let responses = if slots.iter().any(|(_, slot)| slot.is_pending()) {
            self.connection
                .execute_allowing_refusals(batch)
                .await?
                .responses()
                .to_vec()
        } else {
            Vec::new()
        };
        let mut answers = responses.iter().filter(|response| {
            matches!(
                response,
                RopResponse::IdFromLongTermId(_) | RopResponse::Failed { .. }
            )
        });

        let mut entries = Vec::with_capacity(slots.len());
        for (folder, slot) in slots {
            let state = match slot {
                Slot::Settled(state) => state,
                Slot::Convert(entry_id) => match answers.next() {
                    Some(RopResponse::IdFromLongTermId(converted)) => SpecialFolderState::Found {
                        id: converted.id().as_folder_id(),
                        entry_id,
                    },
                    Some(RopResponse::Failed { code, .. }) => SpecialFolderState::Refused(*code),
                    _ => {
                        return Err(Error::Unexpected {
                            expected: "one RopIdFromLongTermId response per entry id sent",
                            found: "fewer responses than the batch asked for",
                        });
                    }
                },
            };
            entries.push(SpecialFolderEntry::new(folder, state));
        }
        Ok(SpecialFolders::new(entries))
    }

    /// Tears the Session Context down.
    ///
    /// # Errors
    ///
    /// Whatever the round trip failed with. The server times an abandoned Session Context out on
    /// its own, so a failure here costs nothing but the diagnostic.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.3 — `Disconnect`
    pub async fn disconnect(self) -> Result<()> {
        self.connection.disconnect().await
    }
}

/// What the Inbox's answer about one special folder amounts to, before the server is asked.
#[derive(Clone, Debug)]
enum Slot {
    /// Nothing to convert: this is already the whole answer.
    Settled(SpecialFolderState),
    /// A readable entry id, whose conversion is in flight.
    Convert(FolderEntryId),
}

impl Slot {
    const fn is_pending(&self) -> bool {
        matches!(self, Self::Convert(_))
    }
}

/// Reads one entry-id property and says what it amounts to.
///
/// `NotFound` is folded into "absent" deliberately: [MS-OXCPRPT] §3.2.5.1 has a server answer a
/// fetch for a property an object does not hold with that code rather than with nothing, so the
/// two are one fact wearing two hats. Any other code is a refusal, which is a different fact.
fn classify(named: &PropertySet, folder: SpecialFolder) -> Slot {
    let value = named.get(folder.tag());
    let bytes = match value {
        Some(PropertyValue::Binary(bytes)) => bytes,
        Some(PropertyValue::Error(code)) if *code != mapi_proto::ErrorCode::NOT_FOUND => {
            return Slot::Settled(SpecialFolderState::Refused(*code));
        }
        _ => return Slot::Settled(SpecialFolderState::Absent),
    };

    match FolderEntryId::parse(bytes) {
        Ok(entry_id) => Slot::Convert(entry_id),
        Err(mapi_proto::Error::InvalidEntryId { reason, .. }) => {
            Slot::Settled(SpecialFolderState::Unreadable { reason })
        }
        Err(_) => Slot::Settled(SpecialFolderState::Unreadable {
            reason: "the value could not be read as a Folder EntryID",
        }),
    }
}
