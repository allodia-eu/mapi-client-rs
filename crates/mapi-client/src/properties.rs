//! Reading and writing an object's own properties.
//!
//! One round trip each. Unlike a table read there is no cursor, no column set to keep alive and no
//! paging — a property fetch is a question and an answer, and the only thing it cannot do is
//! exceed the response buffer, which the server reports per property rather than by failing.
//!
//! [MS-OXCROPS] §2.2.8 — the property ROPs
//! [MS-OXCPRPT] §2.2.2 — semantics

use core::borrow::Borrow;

use mapi_proto::{
    ObjectHandle, PropertyProblem, PropertySet, PropertyTag, RopBatch, RopResponse, TaggedValue,
};

use crate::connection::Connection;
use crate::error::{Error, Result};

/// The properties of one object, ready to be read or written.
///
/// Borrows the [`Logon`](crate::Logon) it came from, so nothing here can outlive the Session
/// Context whose handle it holds.
#[derive(Debug)]
pub struct Properties<'a> {
    connection: &'a mut Connection,
    object: ObjectHandle,
}

impl<'a> Properties<'a> {
    pub(crate) fn new(connection: &'a mut Connection, object: ObjectHandle) -> Self {
        Self { connection, object }
    }

    /// Reads every property the object has.
    ///
    /// Each value arrives with its own tag, so nothing has to be known in advance — which is what
    /// makes this the call that answers "tell me about this mailbox".
    ///
    /// A value too large for the response buffer comes back as an error rather than a value; see
    /// [`PropertySet::error`]. It is reported per property, so one oversized value does not cost
    /// the rest of the answer.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the fetch, plus whatever the round trip failed with.
    /// [`Error::Protocol`] carrying `UnsupportedPropertyType` if the object holds a property of a
    /// type this crate does not model — a decode that stopped rather than guessing at a length.
    ///
    /// [MS-OXCROPS] §2.2.8.4 — `RopGetPropertiesAll`
    pub async fn read_all(self) -> Result<PropertySet> {
        let mut batch = RopBatch::new();
        let object = batch.bind(self.object);
        batch.get_all_properties(object);
        self.fetch(batch).await
    }

    /// Reads the named properties, in the order they were asked for.
    ///
    /// A property the object does not hold comes back as [`PropertyValue::Absent`] rather than
    /// being missing from the answer, so "not set" and "not asked for" stay distinguishable.
    ///
    /// # Errors
    ///
    /// As [`read_all`](Self::read_all).
    ///
    /// [MS-OXCROPS] §2.2.8.3 — `RopGetPropertiesSpecific`
    ///
    /// [`PropertyValue::Absent`]: mapi_proto::PropertyValue::Absent
    pub async fn read<I>(self, tags: I) -> Result<PropertySet>
    where
        I: IntoIterator,
        I::Item: Borrow<PropertyTag>,
    {
        let tags: Vec<PropertyTag> = tags.into_iter().map(|tag| *tag.borrow()).collect();
        let mut batch = RopBatch::new();
        let object = batch.bind(self.object);
        batch.get_properties(object, &tags);
        self.fetch(batch).await
    }

    /// Writes properties to the object.
    ///
    /// **On a Logon or Folder object this persists immediately**, with no save ROP to follow. On a
    /// Message or Attachment object it does not.
    ///
    /// The returned list names the properties the server refused. It is empty in the ordinary
    /// case — but an empty list is not proof that every property was written: a server may
    /// disregard one that is read-only for the client and say nothing at all about it
    /// ([MS-OXCPRPT] §3.2.5.4). Read the value back if it has to be certain.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the ROP outright, and [`Error::Protocol`] if a value
    /// could not be encoded without corrupting the buffer — a string with an interior NUL, or one
    /// longer than its own COUNT field can describe.
    ///
    /// [MS-OXCROPS] §2.2.8.6 — `RopSetProperties`
    pub async fn write(self, values: &[TaggedValue]) -> Result<Vec<PropertyProblem>> {
        let mut batch = RopBatch::new();
        let object = batch.bind(self.object);
        batch.set_properties(object, values);
        self.report(batch, "setting properties").await
    }

    /// Deletes properties from the object.
    ///
    /// A server that succeeds here must afterwards answer `NotFound` when asked for the value,
    /// rather than an empty one. As with [`write`](Self::write), the returned list is what the
    /// server chose to report.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the ROP, plus whatever the round trip failed with.
    ///
    /// [MS-OXCROPS] §2.2.8.8 — `RopDeleteProperties`
    /// [MS-OXCPRPT] §3.2.5.5 — `NotFound` in place of a value afterwards
    pub async fn delete<I>(self, tags: I) -> Result<Vec<PropertyProblem>>
    where
        I: IntoIterator,
        I::Item: Borrow<PropertyTag>,
    {
        let tags: Vec<PropertyTag> = tags.into_iter().map(|tag| *tag.borrow()).collect();
        let mut batch = RopBatch::new();
        let object = batch.bind(self.object);
        batch.delete_properties(object, &tags);
        self.report(batch, "deleting properties").await
    }

    async fn fetch(self, batch: RopBatch) -> Result<PropertySet> {
        let execution = self.connection.execute(batch, "reading properties").await?;

        execution
            .responses()
            .iter()
            .find_map(RopResponse::as_properties)
            .cloned()
            .ok_or(Error::Unexpected {
                expected: "a property fetch response",
                found: "no properties in the batch's responses",
            })
    }

    async fn report(self, batch: RopBatch, during: &'static str) -> Result<Vec<PropertyProblem>> {
        let execution = self.connection.execute(batch, during).await?;

        execution
            .property_problems()
            .map(|response| response.problems().to_vec())
            .ok_or(Error::Unexpected {
                expected: "a property write response",
                found: "no property problems report in the batch's responses",
            })
    }
}
