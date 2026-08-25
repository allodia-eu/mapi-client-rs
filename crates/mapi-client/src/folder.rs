//! A folder that has been named, and the four questions that can be asked of it.
//!
//! Nothing here sends anything on its own. A [`Folder`] is a folder id and a borrow of the
//! [`Logon`](crate::Logon) it came from; the ROP that opens it travels in the same buffer as the
//! read that follows, so naming a folder costs nothing and reading one costs a single round trip.

use mapi_proto::{
    DeleteMessagesResponse, FolderDepth, FolderId, MessageClass, MessageId, ObjectHandle, RopBatch,
    RopResponse,
};

use crate::connection::Connection;
use crate::draft::NewMessage;
use crate::error::{Error, Result};
use crate::message::Message;
use crate::properties::Properties;
use crate::table::{TableKind, TableRead};
use crate::target::Target;

/// A folder that has been named but not yet opened.
///
/// Borrows the [`Logon`](crate::Logon) rather than copying anything out of it, which is what stops
/// a folder being read on a session that has already been disconnected.
#[derive(Debug)]
pub struct Folder<'a> {
    pub(crate) connection: &'a mut Connection,
    pub(crate) logon: ObjectHandle,
    pub(crate) id: FolderId,
}

impl<'a> Folder<'a> {
    pub(crate) fn new(connection: &'a mut Connection, logon: ObjectHandle, id: FolderId) -> Self {
        Self {
            connection,
            logon,
            id,
        }
    }

    /// This folder's id.
    #[must_use]
    pub const fn id(&self) -> FolderId {
        self.id
    }

    /// The messages in this folder — its contents table.
    ///
    /// [MS-OXCROPS] §2.2.4.14 — `RopGetContentsTable`
    #[must_use]
    pub fn contents(self) -> TableRead<'a> {
        let target = self.target();
        TableRead::new(self.connection, target, TableKind::Contents)
    }

    /// One message in this folder, ready to be opened.
    ///
    /// The id comes from a row of [`contents`](Self::contents) — `PidTagMid`, which
    /// [`PropertyRow::message_id`](mapi_proto::PropertyRow::message_id) reads.
    ///
    /// ```no_run
    /// # use mapi_client::{Logon, MESSAGE_PROPERTIES, PropertyRow, WellKnownFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let inbox = logon.folder_id(WellKnownFolder::Inbox)?;
    /// let rows = logon.folder(inbox).contents().collect().await?;
    /// if let Some(id) = rows.first().and_then(PropertyRow::message_id) {
    ///     let details = logon
    ///         .folder(inbox)
    ///         .message(id)
    ///         .properties()
    ///         .read(MESSAGE_PROPERTIES)
    ///         .await?;
    ///     println!("{} propert(y/ies)", details.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [MS-OXCROPS] §2.2.6.1 — `RopOpenMessage`
    #[must_use]
    pub fn message(self, id: MessageId) -> Message<'a> {
        Message::new(self.connection, self.logon, self.id, id)
    }

    /// A new item to create in this folder. Nothing is sent until it is saved.
    ///
    /// The class is a parameter rather than a property because it is what decides what the item
    /// *is*: [MS-OXOCAL] §2.2.2.1 requires a calendar entry's to be `IPM.Appointment` or a
    /// refinement of it, and an appointment written into a calendar with the class left at its
    /// default is a mail message sitting in a calendar folder.
    ///
    /// ```no_run
    /// # use mapi_client::{Logon, MessageClass, PropertyTag, PropertyValue, SpecialFolder,
    /// #                   TaggedValue};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let contacts = logon.special_folder(SpecialFolder::Contacts).await?;
    /// let saved = logon
    ///     .folder(contacts)
    ///     .create_message(MessageClass::Contact)
    ///     .set([TaggedValue::new(
    ///         PropertyTag::DISPLAY_NAME,
    ///         PropertyValue::String("Ada Lovelace".into()),
    ///     )?])
    ///     .save()
    ///     .await?;
    /// println!("{:#018x}", saved.id().as_u64());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [MS-OXCROPS] §2.2.6.2 — `RopCreateMessage`
    #[must_use]
    pub fn create_message(self, class: MessageClass) -> NewMessage<'a> {
        NewMessage::new(self.connection, self.logon, self.id, class)
    }

    /// Deletes messages from this folder, by id.
    ///
    /// A **soft** delete: [MS-OXCFOLD] §1.1 has the server keep a back-up copy that a client can
    /// restore or delete permanently. It does not move the message to Deleted Items — that is a
    /// `RopMoveCopyMessages` a client does first — so a message deleted this way disappears from
    /// every folder listing at once.
    ///
    /// **The answer is not the return value.** `RopDeleteMessages` succeeds whether or not it
    /// deleted everything it was given, and reports the difference in a flag — so this hands back
    /// whether the deletion was complete, and a caller that ignores it can believe a message it
    /// still has is gone.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the delete — `ecAccessDenied` for a folder this account
    /// may not write to — plus whatever the round trip failed with.
    ///
    /// [MS-OXCROPS] §2.2.4.11 — `RopDeleteMessages`
    pub async fn delete_messages(self, messages: &[MessageId]) -> Result<bool> {
        let mut batch = RopBatch::new();
        let logon = batch.bind(self.logon);
        let folder = batch.open_folder(logon, self.id);
        batch.delete_messages(folder, messages).release(folder);

        let execution = self.connection.execute(batch, "deleting messages").await?;
        execution
            .responses()
            .iter()
            .find_map(RopResponse::as_deleted_messages)
            .map(|response| !DeleteMessagesResponse::is_partial(response))
            .ok_or(Error::Unexpected {
                expected: "a RopDeleteMessages response",
                found: "no deletion result in the batch's responses",
            })
    }

    /// The folders directly inside this one — its hierarchy table.
    ///
    /// Immediate children only. For everything below, at every level, see
    /// [`descendants`](Self::descendants).
    ///
    /// [MS-OXCROPS] §2.2.4.13 — `RopGetHierarchyTable`
    #[must_use]
    pub fn subfolders(self) -> TableRead<'a> {
        let target = self.target();
        TableRead::new(
            self.connection,
            target,
            TableKind::Hierarchy(FolderDepth::Immediate),
        )
    }

    /// Every folder below this one, at every level, in one table.
    ///
    /// The `Depth` flag on `RopGetHierarchyTable`. One round trip per page instead of one per
    /// folder, which is what makes a whole-mailbox listing cheap — but the rows arrive **flat**,
    /// with nothing in them saying where each folder sits, so
    /// [`PidTagParentFolderId`](mapi_proto::PropertyTag::PARENT_FOLDER_ID) has to be among the
    /// columns for a tree to be rebuilt. [`HIERARCHY_COLUMNS`](crate::HIERARCHY_COLUMNS) includes
    /// it; a caller passing its own columns has to.
    ///
    /// ```no_run
    /// # use mapi_client::{Logon, PropertyTag, WellKnownFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let all = logon
    ///     .well_known(WellKnownFolder::IpmSubtree)?
    ///     .descendants()
    ///     .collect()
    ///     .await?;
    /// for row in &all {
    ///     println!(
    ///         "{:?} in {:?}",
    ///         row.string(PropertyTag::DISPLAY_NAME),
    ///         row.get(PropertyTag::PARENT_FOLDER_ID)
    ///     );
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [MS-OXCFOLD] §2.2.1.13.1 — `TableFlags`, `Depth`
    #[must_use]
    pub fn descendants(self) -> TableRead<'a> {
        let target = self.target();
        TableRead::new(
            self.connection,
            target,
            TableKind::Hierarchy(FolderDepth::Recursive),
        )
    }

    /// This folder's own properties — what it is, what it holds, and where it sits.
    ///
    /// One round trip: the folder is opened, read and released in a single `Execute`. Reading
    /// [`FOLDER_PROPERTIES`](crate::FOLDER_PROPERTIES) is *"get calendar details"* — a calendar is
    /// a folder, so the two are the same question.
    ///
    /// ```no_run
    /// # use mapi_client::{FOLDER_PROPERTIES, Logon, SpecialFolder};
    /// # async fn example(logon: &mut Logon) -> Result<(), mapi_client::Error> {
    /// let calendar = logon.special_folder(SpecialFolder::Calendar).await?;
    /// let details = logon
    ///     .folder(calendar)
    ///     .properties()
    ///     .read(FOLDER_PROPERTIES)
    ///     .await?;
    /// for cell in &details {
    ///     println!("{cell}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [MS-OXCFOLD] §2.2.2.2 — Folder object properties
    #[must_use]
    pub fn properties(self) -> Properties<'a> {
        Properties::for_folder(self.connection, self.logon, self.id)
    }

    const fn target(&self) -> Target {
        Target::Folder {
            logon: self.logon,
            id: self.id,
        }
    }
}
