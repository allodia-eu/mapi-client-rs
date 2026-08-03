//! The property ROPs a batch can issue: reading an object's properties, writing them, deleting
//! them, and resolving the named ones.
//!
//! [MS-OXCROPS] §2.2.8 — the property ROPs
//! [MS-OXCPRPT] §2.2.2 — semantics

use crate::oxcdata::{PropertyName, PropertyTag, TaggedValue};
use crate::rop::batch::{HandleSlot, RopBatch};
use crate::rop::named::{
    NameRegistration, encode_names_from_property_ids, encode_property_ids_from_names,
};
use crate::rop::property::{
    encode_delete_properties, encode_get_properties_all, encode_get_properties_specific,
    encode_set_properties,
};

impl RopBatch {
    /// Reads the named properties of an object — a logon, a folder, a message, an attachment.
    ///
    /// The response carries values and no tags, exactly as a table row does, so the tags are
    /// remembered here and handed to the decoder when the answer arrives. They are remembered
    /// **per ROP rather than per handle**: two fetches on one object in one batch are two
    /// different questions, and answering the second against the first's tags would decode a
    /// plausible-looking wrong value rather than fail.
    ///
    /// [MS-OXCROPS] §2.2.8.3 — `RopGetPropertiesSpecific`
    pub fn get_properties(&mut self, object: HandleSlot, tags: &[PropertyTag]) -> &mut Self {
        if self.check(object) {
            self.push(|w| encode_get_properties_specific(w, object.index(), tags));
            self.property_tags.push(tags.to_vec());
        }
        self
    }

    /// Reads every property an object has.
    ///
    /// Each value arrives beside its own tag, so nothing has to be known in advance — which is
    /// what makes this the ROP that answers "tell me about this mailbox".
    ///
    /// **"All" is not every readable property.** The server returns the values for all properties
    /// *on* the object ([MS-OXCPRPT] §3.2.5.2), while an explicit `RopGetPropertiesSpecific`
    /// returns computed properties as well ([MS-OXCPRPT] §3.2.5.1) — so a computed property is
    /// simply absent here. Measured on Exchange Server SE `15.02.2562.045`, where a private
    /// mailbox logon answered with 113 properties and `PidTagMailboxOwnerEntryId` was not among
    /// them, yet was 151 bytes long when asked for by name.
    ///
    /// A value too large for the response buffer comes back under its own id with the type
    /// changed to `PtypErrorCode`, carrying `NotEnoughMemory`; [`PropertySet::get`] is written to
    /// hand that back rather than report the property as unset.
    ///
    /// [MS-OXCROPS] §2.2.8.4 — `RopGetPropertiesAll`
    /// [MS-OXCPRPT] §2.2.3.2 — an oversized value becomes `NotEnoughMemory`
    ///
    /// [`PropertySet::get`]: crate::PropertySet::get
    pub fn get_all_properties(&mut self, object: HandleSlot) -> &mut Self {
        if self.check(object) {
            self.push(|w| encode_get_properties_all(w, object.index()));
        }
        self
    }

    /// Writes properties to an object.
    ///
    /// **This persists immediately on a Folder or Logon object**, with no save ROP to follow; on a
    /// Message or Attachment object it does not, and needs `RopSaveChangesMessage`. Individual
    /// properties can fail while the ROP as a whole succeeds — see
    /// [`PropertyProblemsResponse`](crate::PropertyProblemsResponse).
    ///
    /// [MS-OXCROPS] §2.2.8.6 — `RopSetProperties`
    /// [MS-OXCPRPT] §3.2.5.4 — when the change is persisted
    pub fn set_properties(&mut self, object: HandleSlot, values: &[TaggedValue]) -> &mut Self {
        if self.check(object) {
            self.try_push(|w| encode_set_properties(w, object.index(), values));
        }
        self
    }

    /// Deletes properties from an object.
    ///
    /// A server that succeeds here must afterwards answer `NotFound` when asked for the value,
    /// rather than an empty one.
    ///
    /// [MS-OXCROPS] §2.2.8.8 — `RopDeleteProperties`
    /// [MS-OXCPRPT] §3.2.5.5 — `NotFound` in place of a value afterwards
    pub fn delete_properties(&mut self, object: HandleSlot, tags: &[PropertyTag]) -> &mut Self {
        if self.check(object) {
            self.push(|w| encode_delete_properties(w, object.index(), tags));
        }
        self
    }

    /// Asks what this store calls each of these named properties.
    ///
    /// The step every calendar read needs before it can begin: `PidLidAppointmentStartWhole` has no
    /// property id of its own, and the one this store uses for it is not the one the mailbox next
    /// door uses. The answer is positional — one id per name, in order, `0x0000` for any the server
    /// would not map — and nothing in the response says which name each belongs to, so the caller
    /// keeps the list it asked with.
    ///
    /// **`CreateIfMissing` writes to the store.** A name that is not registered gets an id
    /// allocated for it, which is what writing a new named property needs and is not what a read
    /// wants. See [`NameRegistration`].
    ///
    /// Valid on a Logon, Folder, Message or Attachment object; the answer is the same whichever is
    /// used, because the mapping belongs to the store rather than the object
    /// ([MS-OXCPRPT] §3.1.2).
    ///
    /// [MS-OXCROPS] §2.2.8.1 — `RopGetPropertyIdsFromNames`
    pub fn property_ids_from_names(
        &mut self,
        object: HandleSlot,
        names: &[PropertyName],
        registration: NameRegistration,
    ) -> &mut Self {
        if self.check(object) {
            self.push(|w| encode_property_ids_from_names(w, object.index(), names, registration));
        }
        self
    }

    /// Asks what named property each of these ids stands for in this store.
    ///
    /// The inverse, and the only way to say what a `0x8005` in a property dump actually is. An id
    /// below `0x8000` is answered from the `PS_MAPI` set rather than refused, and one this store
    /// has never registered comes back with no name rather than being left out of the answer.
    ///
    /// [MS-OXCROPS] §2.2.8.2 — `RopGetNamesFromPropertyIds`
    /// [MS-OXCPRPT] §2.2.13 — `PS_MAPI` is used for ids that are not named properties
    pub fn names_from_property_ids(&mut self, object: HandleSlot, ids: &[u16]) -> &mut Self {
        if self.check(object) {
            self.push(|w| encode_names_from_property_ids(w, object.index(), ids));
        }
        self
    }
}
