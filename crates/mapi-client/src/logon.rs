//! A mailbox that has been logged on to, and the folders in it.

use mapi_proto::{Connected, FolderId, LogonResponse, ObjectHandle, WellKnownFolder};

use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::properties::Properties;
use crate::table::{TableKind, TableRead};

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
}

impl Logon {
    pub(crate) const fn new(
        connection: Connection,
        handle: ObjectHandle,
        response: LogonResponse,
    ) -> Self {
        Self {
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
        Folder {
            connection: &mut self.connection,
            logon: self.handle,
            id,
        }
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

/// A folder that has been named but not yet opened.
///
/// Borrows the [`Logon`] rather than copying anything out of it, which is what stops a folder
/// being read on a session that has already been disconnected.
#[derive(Debug)]
pub struct Folder<'a> {
    pub(crate) connection: &'a mut Connection,
    pub(crate) logon: ObjectHandle,
    pub(crate) id: FolderId,
}

impl<'a> Folder<'a> {
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
        TableRead::new(self, TableKind::Contents)
    }

    /// The folders directly inside this one — its hierarchy table.
    ///
    /// Immediate children only: the `Depth` flag that would make it recursive is not set.
    ///
    /// [MS-OXCROPS] §2.2.4.13 — `RopGetHierarchyTable`
    #[must_use]
    pub fn subfolders(self) -> TableRead<'a> {
        TableRead::new(self, TableKind::Hierarchy)
    }
}
