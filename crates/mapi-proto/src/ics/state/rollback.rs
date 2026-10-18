//! Back-in-time detection: refusing a final state from a server that is behind the client.
//!
//! [MS-OXCFXICS] §3.3.5.3 has the client "MUST implement some mechanism to detect server rollback",
//! and names a restored backup as one source. For a client that downloads, a rollback costs more
//! than a resynchronization. The server numbers its next changes from where the backup left off, so
//! it re-issues change numbers the state already has in `MetaTagCnsetSeen`, and every change made
//! with one of them is skipped as already seen.
//!
//! A final state shows when that has happened. Measured on Exchange Server SE `15.02.2562.056`, a
//! final state's `MetaTagCnsetSeen` runs to the server's own newest change number, whatever the
//! uploaded state claimed. A download started from a state claiming change numbers up to
//! `0x32B37B2E`, while the server's newest was `0x32B37A66`, did not report a message created
//! before it. Its final state ran to `0x32B37A6B`, below the claim, and listed the unreported
//! message in `MetaTagIdsetGiven` as delivered. That final state is the one thing a client must not
//! keep, because nothing downloaded from it would ever report that message.

use super::IcsState;
use crate::error::{Error, Result};
use crate::fasttransfer::FinalState;
use crate::ics::{GlobCnt, GlobSet};

impl IcsState {
    /// Refuses a final state that is behind this one: a server whose newest change number, for some
    /// replica, is older than one this state has already seen.
    ///
    /// Call it before [`complete`](Self::complete). `Download` in `mapi-client` does, and reports
    /// the refusal instead of the state.
    ///
    /// Only `MetaTagCnsetSeen` and `MetaTagCnsetSeenFAI` are compared, replica by replica, and only
    /// for a replica both name: a final state for normal messages alone carries no
    /// `CnsetSeenFAI`. The check catches a rollback as long as the server's counter has not yet
    /// passed the client's newest change. Checking at every download keeps that window short, and
    /// a folder whose [`FolderStamp`](crate::ics::FolderStamp) went backwards is one to download.
    ///
    /// # Errors
    ///
    /// [`Error::IcsStateAheadOfServer`], naming the replica and both change numbers. Abandon this
    /// state, and the folder's local copy with it, and synchronize afresh: §3.3.5.3 says of a
    /// rolled-back replica that it "is abandoned".
    ///
    /// [MS-OXCFXICS] §3.3.5.3 — back-in-time detection
    pub fn check_not_ahead_of(&self, server: &FinalState) -> Result<()> {
        for (ours, theirs) in [
            (&self.cnset_seen, server.cnset_seen()),
            (&self.cnset_seen_fai, server.cnset_seen_fai()),
        ] {
            for (replica, set) in ours.replicas() {
                let (Some(seen), Some(newest)) =
                    (newest(set), theirs.get(replica).and_then(newest))
                else {
                    continue;
                };
                if seen > newest {
                    return Err(Error::IcsStateAheadOfServer {
                        replica,
                        seen,
                        newest,
                    });
                }
            }
        }
        Ok(())
    }
}

/// The highest counter in a set.
fn newest(set: &GlobSet) -> Option<GlobCnt> {
    set.ranges().last().map(|(_, high)| high)
}

#[cfg(test)]
mod tests;
