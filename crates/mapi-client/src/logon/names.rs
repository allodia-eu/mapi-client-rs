//! What this store calls each named property, and the inverse question.
//!
//! Its own file for the reason the ids themselves exist: a named property has no fixed id, so
//! reaching one costs a round trip a `PidTag` does not, and everything about *when* that round trip
//! happens and *what it is allowed to change* lives here.
//!
//! **Resolving and registering are different operations against the same ROP.**
//! [`resolve_names`](Logon::resolve_names) asks only for what the store already has;
//! [`register_names`](Logon::register_names) asks it to allocate an id for anything it does not.
//! The second is a **write to the store's mapping table** from a call that reads like a lookup, and
//! it is what writing a property nothing has written before requires.
//!
//! [MS-OXCROPS] §2.2.8.1 — `RopGetPropertyIdsFromNames`
//! [MS-OXCROPS] §2.2.8.2 — `RopGetNamesFromPropertyIds`
//! [MS-OXCPRPT] §3.1.2 — an id may be cached for the session, and is a fact about one store

use core::borrow::Borrow;

use mapi_proto::{NameRegistration, PropertyIdsResponse, PropertyName, RopBatch, RopResponse};

use crate::error::{Error, Result};
use crate::logon::Logon;
use crate::named::NamedProperties;

impl Logon {
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
    /// [`NamedPropertyEntry::id`](crate::NamedPropertyEntry::id). **That is the right question for
    /// a read and the wrong one for a write**: see [`register_names`](Self::register_names).
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
        self.ask(wanted, NameRegistration::Existing).await
    }

    /// The same question, with the store asked to allocate an id for anything it does not have.
    ///
    /// **What writing a named property needs.** [`resolve_names`](Self::resolve_names) asks only
    /// about names the store has already registered, and a store registers one the first time
    /// something writes it — so a mailbox that has never held a flagged message answers `0x0000`
    /// for `PidLidToDoTitle`, and there is no tag to write it under. Measured on Exchange Server SE
    /// `15.02.2562.045`: a lab mailbox seeded through EWS with appointments and contacts had ids
    /// for all sixteen of those properties and for none of the eight flagging ones.
    ///
    /// **This writes to the store.** [MS-OXCPRPT] §2.2.12.1's `Flags` value `0x02` has the server
    /// allocate an id and keep it, from a call that reads like a lookup — which is why it is a
    /// separate method rather than a parameter with a default. A store has 32,767 ids to give out
    /// and never reclaims one.
    ///
    /// Names the store *does* already have cost nothing here: they are answered from the same
    /// cache [`resolve_names`](Self::resolve_names) fills, and only the unregistered ones are
    /// asked about.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused — `ecAccessDenied` for a user who may not register a
    /// new name — plus whatever the round trip failed with.
    ///
    /// [MS-OXCPRPT] §2.2.12.1 — `Flags`
    pub async fn register_names<I>(&mut self, names: I) -> Result<&NamedProperties>
    where
        I: IntoIterator,
        I::Item: Into<PropertyName>,
    {
        let asked: Vec<PropertyName> = names.into_iter().map(Into::into).collect();
        let wanted = self.named.unregistered(&asked);
        // A name the store answered `0x0000` for is cached as an entry with no id. Left there, the
        // id this call is about to be given would be invisible to every later lookup.
        self.named.forget(&wanted);
        self.ask(wanted, NameRegistration::CreateIfMissing).await
    }

    /// Asks the store about `wanted`, and records what it said.
    ///
    /// Nothing is sent when the list is empty, which is what makes a second `resolve_names` for the
    /// same properties free.
    async fn ask(
        &mut self,
        wanted: Vec<PropertyName>,
        registration: NameRegistration,
    ) -> Result<&NamedProperties> {
        if wanted.is_empty() {
            return Ok(&self.named);
        }

        let mut batch = RopBatch::new();
        let logon = batch.bind(self.handle);
        batch.property_ids_from_names(logon, &wanted, registration);

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
}
