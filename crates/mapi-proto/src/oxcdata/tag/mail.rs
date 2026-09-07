//! The tags a message carries because it is *mail*: who sent it, what became of the submission,
//! and the follow-up flag a reader puts on it.
//!
//! Its own file rather than a fourth section of [`tag`](super), for the reason the parent module
//! already gives for the other splits: the catalogue grows with every operation and the file limit
//! is what keeps each part readable. The division is not arbitrary — not one property here appears
//! on a Folder, a Store or an Attachment object.
//!
//! Two things worth knowing before reaching for any of them.
//!
//! **The sender properties are the server's to write, and the client's to set anyway.**
//! [MS-OXOMSG] §3.2.4.1.2 has the client set the actual sender properties before submitting;
//! §3.3.5.1.3.2 has the server set them from the mailbox owner. Both are `MUST`, they are about
//! the same five properties, and they do not contradict each other so much as leave a client free
//! to omit what the server will supply — which is a thing to measure against a real server rather
//! than to decide from the document.
//!
//! **The follow-up flag is not one property.** [MS-OXOFLAG] §3.1.4.1.1 lists seven for a colour
//! flag and thirteen for a complete one, and a message carrying some of them is a message whose
//! flag renders differently in every client that reads it. The lists are in
//! [`columns`](crate::PropertyTag) rather than in a caller's head for that reason.
//!
//! [MS-OXOMSG] §2.2.1 — the sender and represented-sender properties
//! [MS-OXOFLAG] §2.2.1 — the flagging properties

use crate::oxcdata::PropertyTag;

impl PropertyTag {
    /// `PidTagClientSubmitTime`, `0x00390040` — when the message was submitted, in UTC.
    ///
    /// Written by the server rather than by the client ([MS-OXOMSG] §3.3.5.1.3).
    ///
    /// **It is not evidence that anything was submitted.** [MS-OXOMSG] §2.2.3.11 has the server set
    /// it "when the e-mail message is submitted", which invites reading its presence as a send. On
    /// Exchange Server SE `15.02.2562.045` a draft created by `RopCreateMessage` and committed by
    /// `RopSaveChangesMessage`, with no `RopSubmitMessage` anywhere near it, already carries one —
    /// so the property is set at save time. `mfUnsent` and `mfSubmitted` in
    /// [`MESSAGE_FLAGS`](Self::MESSAGE_FLAGS) are what actually answer the question; see
    /// [`MessageFlags::is_submitted`](crate::MessageFlags::is_submitted).
    ///
    /// [MS-OXOMSG] §2.2.3.11
    pub const CLIENT_SUBMIT_TIME: Self = Self(0x0039_0040);
    /// `PidTagFlagCompleteTime`, `0x10910040` — when the follow-up flag was completed, in UTC.
    ///
    /// Present only while [`FLAG_STATUS`](Self::FLAG_STATUS) is `followupComplete`, and required
    /// to be a whole number of minutes: [MS-OXOFLAG] §2.2.1.3 has the value be a multiple of
    /// 600,000,000 hundred-nanosecond units. A time carrying seconds is not one the document
    /// allows, which is why [`FileTime::to_whole_minutes`](crate::FileTime::to_whole_minutes)
    /// exists.
    ///
    /// [MS-OXOFLAG] §2.2.1.3
    pub const FLAG_COMPLETE_TIME: Self = Self(0x1091_0040);
    /// `PidTagFlagStatus`, `0x10900003` — whether the message is flagged, and whether it is done.
    ///
    /// **Absent rather than zero when nothing is flagged.** [MS-OXOFLAG] §2.2.1.1: the property
    /// "is present on the Message object only if the object has been flagged and is not present
    /// otherwise", so clearing a flag means deleting it. See [`FlagStatus`](crate::FlagStatus).
    ///
    /// [MS-OXOFLAG] §2.2.1.1
    pub const FLAG_STATUS: Self = Self(0x1090_0003);
    /// `PidTagFollowupIcon`, `0x10950003` — which colour the flag is drawn in.
    ///
    /// Optional for a colour flag and fixed at red for a time flag or a recipient flag.
    /// A flagged message without it has a flag with no colour, which is a basic flag.
    ///
    /// [MS-OXOFLAG] §2.2.1.2
    pub const FOLLOWUP_ICON: Self = Self(0x1095_0003);
    /// `PidTagReplyRequested`, `0x0C17000B` — the sender asked for a reply.
    ///
    /// Set alongside [`RESPONSE_REQUESTED`](Self::RESPONSE_REQUESTED), which [MS-OXOFLAG] §2.2.1.5
    /// gives identical semantics: the two are updated together or not at all.
    ///
    /// **Never set this on a meeting-related object.** [MS-OXOCAL] gives it a different meaning
    /// there, so the same `true` says something else entirely.
    ///
    /// [MS-OXOFLAG] §2.2.1.4
    pub const REPLY_REQUESTED: Self = Self(0x0C17_000B);
    /// `PidTagResponseRequested`, `0x0063000B` — the twin of
    /// [`REPLY_REQUESTED`](Self::REPLY_REQUESTED).
    ///
    /// [MS-OXOFLAG] §2.2.1.5
    pub const RESPONSE_REQUESTED: Self = Self(0x0063_000B);
    /// `PidTagSenderAddressType`, `0x0C1E001F` — `SMTP` for anything this crate can address.
    ///
    /// [MS-OXOMSG] §2.2.1.48
    pub const SENDER_ADDRESS_TYPE: Self = Self(0x0C1E_001F);
    /// `PidTagSenderEntryId`, `0x0C190102` — the sender as an identifier rather than as text.
    ///
    /// [MS-OXOMSG] §2.2.1.50
    pub const SENDER_ENTRY_ID: Self = Self(0x0C19_0102);
    /// `PidTagSenderSearchKey`, `0x0C1D0102` — the sender's address as the store indexes it.
    ///
    /// `ADDRESSTYPE:ADDRESS`, uppercased, with a trailing NUL — not a hash, despite the name.
    ///
    /// [MS-OXOMSG] §2.2.1.52
    pub const SENDER_SEARCH_KEY: Self = Self(0x0C1D_0102);
    /// `PidTagSentMailSvrEID`, `0x674000FB` — the folder a copy of the sent message goes into.
    ///
    /// **Absent means no copy is kept.** [MS-OXOMSG] §2.2.3.10 makes the copy conditional on the
    /// property being present, so a client that submits without it sends mail nothing records —
    /// which is a surprise to a user and not to the protocol. See
    /// [`ServerEntryId`](crate::ServerEntryId) for the value.
    ///
    /// [MS-OXOMSG] §2.2.3.10
    pub const SENT_MAIL_SVR_EID: Self = Self(0x6740_00FB);
    /// `PidTagSentRepresentingAddressType`, `0x0064001F`.
    ///
    /// [MS-OXOMSG] §2.2.1.54
    pub const SENT_REPRESENTING_ADDRESS_TYPE: Self = Self(0x0064_001F);
    /// `PidTagSentRepresentingEmailAddress`, `0x0065001F`.
    ///
    /// [MS-OXOMSG] §2.2.1.55
    pub const SENT_REPRESENTING_EMAIL_ADDRESS: Self = Self(0x0065_001F);
    /// `PidTagSentRepresentingEntryId`, `0x00410102`.
    ///
    /// [MS-OXOMSG] §2.2.1.56
    pub const SENT_REPRESENTING_ENTRY_ID: Self = Self(0x0041_0102);
    /// `PidTagSentRepresentingName`, `0x0042001F`.
    ///
    /// [MS-OXOMSG] §2.2.1.57
    pub const SENT_REPRESENTING_NAME: Self = Self(0x0042_001F);
    /// `PidTagSentRepresentingSearchKey`, `0x003B0102`.
    ///
    /// [MS-OXOMSG] §2.2.1.58
    pub const SENT_REPRESENTING_SEARCH_KEY: Self = Self(0x003B_0102);
    /// `PidTagToDoItemFlags`, `0x0E2B0003` — which *kind* of flag is set.
    ///
    /// `todoTimeFlagged` (`0x01`) for a time or complete flag, `todoRecipientFlagged` (`0x08`) for
    /// a recipient or sender flag. [MS-OXOFLAG] §2.2.1.6 requires every other bit to be ignored
    /// **and preserved**, so clearing a flag clears one bit rather than writing zero.
    ///
    /// [MS-OXOFLAG] §2.2.1.6
    pub const TODO_ITEM_FLAGS: Self = Self(0x0E2B_0003);
}
