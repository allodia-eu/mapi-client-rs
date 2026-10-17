//! Incremental change synchronization: the state a client keeps, and the identifier sets it is
//! made of.
//!
//! A synchronization download answers one question — *what changed since this state?* — and the
//! state is the whole of how the client asks it. It is four sets of identifiers, each a set of
//! counters per replica, and two facts about it decide most of this module's shape:
//!
//! * **The server cannot tell which scope a state belongs to**, so the state carries its
//!   [`SyncScope`] and refuses any other. See [`IcsState`].
//! * **On Exchange, a resumable state is the client's to build.** The server hands back its own
//!   only once a download has finished, so a client that wants to survive being killed half way
//!   folds each message into the state as it arrives — client-side checkpointing, which is why
//!   insertion into a [`GlobSet`] is cheap.
//!
//! [MS-OXCFXICS] — Bulk Data Transfer Protocol: ICS and `FastTransfer`

mod globset;
mod idset;
mod state;

pub use globset::{GlobCnt, GlobSet, GlobSetRanges};
pub use idset::{IdSet, IdSetReplicas, MessageIds, ReplicaKey};
pub use state::{ChangeNumber, IcsState, SyncKind, SyncScope};
