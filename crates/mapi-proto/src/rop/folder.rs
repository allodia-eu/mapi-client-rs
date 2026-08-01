//! `RopOpenFolder` — turning a folder id into a folder handle.
//!
//! [MS-OXCROPS] §2.2.4.1 — `RopOpenFolder`
//! [MS-OXCFOLD] §2.2.1.1 — semantics

use crate::error::Result;
use crate::oxcdata::FolderId;
use crate::rop::RopId;
use crate::rop::batch::LOGON_ID;
use crate::wire::{Reader, Writer};

/// `OpenModeFlags`: open an existing folder. The only defined bit, `OpenSoftDeleted` (`0x04`),
/// is deliberately not set.
///
/// [MS-OXCFOLD] §2.2.1.1.1 — `OpenModeFlags`
const OPEN_MODE_EXISTING: u8 = 0x00;

/// What opening a folder reports about it.
///
/// [MS-OXCROPS] §2.2.4.1.2 — success response buffer
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenFolderResponse {
    has_rules: bool,
    replica_servers: Option<Vec<String>>,
}

impl OpenFolderResponse {
    /// Whether rules are associated with the folder.
    #[must_use]
    pub const fn has_rules(&self) -> bool {
        self.has_rules
    }

    /// Whether the folder is ghosted — its contents live on other servers.
    #[must_use]
    pub const fn is_ghosted(&self) -> bool {
        self.replica_servers.is_some()
    }

    /// The servers holding replicas, for a ghosted folder.
    #[must_use]
    pub fn replica_servers(&self) -> Option<&[String]> {
        self.replica_servers.as_deref()
    }

    /// Reads the response body, after `RopId`, `OutputHandleIndex` and a zero `ReturnValue`.
    ///
    /// The tail is conditional: `ServerCount`, `CheapServerCount` and `Servers` are present only
    /// when `IsGhosted` is non-zero, so skipping them unconditionally would decode the next ROP's
    /// response against the wrong bytes.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let has_rules = r.u8()? != 0;
        let is_ghosted = r.u8()? != 0;

        let replica_servers = if is_ghosted {
            let count = r.u16()?;
            let _cheap_server_count = r.u16()?;
            let mut servers = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                servers.push(r.ascii_z()?);
            }
            Some(servers)
        } else {
            None
        };

        Ok(Self {
            has_rules,
            replica_servers,
        })
    }
}

/// Encodes a `RopOpenFolder` request.
///
/// [MS-OXCROPS] §2.2.4.1.1 — request buffer
pub(crate) fn encode_open_folder(w: &mut Writer, input: u8, output: u8, folder: FolderId) {
    w.u8(RopId::OPEN_FOLDER.as_u8())
        .u8(LOGON_ID)
        .u8(input)
        .u8(output)
        .u64(folder.as_u64())
        .u8(OPEN_MODE_EXISTING);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_folder_request_matches_the_spec_layout() {
        let mut w = Writer::new();
        encode_open_folder(&mut w, 0, 1, FolderId::new(0x0D00_0000_0000_0001));

        #[rustfmt::skip]
        let expected = vec![
            0x02,                   // RopId
            0x00,                   // LogonId
            0x00,                   // InputHandleIndex
            0x01,                   // OutputHandleIndex
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, // FolderId, little-endian
            0x00,                   // OpenModeFlags
        ];
        assert_eq!(w.finish(), expected);
    }

    #[test]
    fn an_ordinary_folder_has_no_replica_list() {
        let mut r = Reader::new(&[0x01, 0x00]);
        let response = OpenFolderResponse::read(&mut r).unwrap();
        assert!(response.has_rules());
        assert!(!response.is_ghosted());
        assert_eq!(response.replica_servers(), None);
        assert!(r.is_empty());
    }

    /// A ghosted folder carries a server list. Skipping it would leave the reader pointing into
    /// the middle of a string when the next ROP response is decoded.
    #[test]
    fn a_ghosted_folder_carries_its_replica_servers() {
        let mut w = Writer::new();
        w.u8(0x00).u8(0x01).u16(2).u16(1);
        w.ascii_z("EXCHANGE-A").ascii_z("EXCHANGE-B");
        w.u8(0xEE); // the next ROP response starts here
        let buf = w.finish();

        let mut r = Reader::new(&buf);
        let response = OpenFolderResponse::read(&mut r).unwrap();
        assert!(!response.has_rules());
        assert!(response.is_ghosted());
        assert_eq!(
            response.replica_servers(),
            Some(&["EXCHANGE-A".to_owned(), "EXCHANGE-B".to_owned()][..])
        );
        assert_eq!(r.rest(), &[0xEE]);
    }

    #[test]
    fn truncated_open_folder_responses_never_panic() {
        for buf in [&b""[..], &[0x00][..], &[0x00, 0x01][..], &[0xFF; 8][..]] {
            let _ = OpenFolderResponse::read(&mut Reader::new(buf));
        }
    }
}
