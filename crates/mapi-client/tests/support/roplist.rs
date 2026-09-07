//! Walking a ROP input buffer back into the ROPs a batch put in it.
//!
//! Its own file because the table below grows with every ROP the crate learns to send, and the
//! rest of the harness does not.
//!
//! [MS-OXCROPS] §2.2.1 — ROP input buffer

/// Splits a ROP list into one entry per ROP: its opcode, and the whole ROP including its header.
///
/// ROPs are variable-length and not self-describing, so this walks them with the layouts of the
/// ones this crate actually sends. A test can then say "the batch was open, table, columns, rows,
/// release" instead of counting bytes, and an accidental change to any encoding shows up here as a
/// wrong opcode rather than as a silently shifted offset.
///
/// # Panics
///
/// On a ROP this crate does not send, which in a test means the batch builder has changed and this
/// walker has not.
// One arm per ROP, each named. Several are the same length by coincidence, and merging those
// patterns would file RopRelease with RopCommitStream for no reason but the lint.
#[allow(clippy::match_same_arms, reason = "a lookup table, one row per opcode")]
pub(crate) fn rop_list(rops: &[u8]) -> Vec<(u8, &[u8])> {
    let u16_at = |at: usize| usize::from(u16::from_le_bytes([rops[at], rops[at + 1]]));

    let mut out = Vec::new();
    let mut at = 0;
    while at < rops.len() {
        let opcode = rops[at];
        let length = match opcode {
            0x01 => 3,                      // RopRelease
            0x02 => 13,                     // RopOpenFolder: FolderId is 8 of them
            0x03 => 23,                     // RopOpenMessage: a FolderId, a flag and a MessageId
            0x04 | 0x05 => 5,               // RopGetHierarchyTable / RopGetContentsTable
            0x06 => 15,                     // RopCreateMessage: CodePageId, FolderId, Associated
            0x07 => 9 + 4 * u16_at(at + 7), // RopGetPropertiesSpecific: limit, unicode, then tags
            0x0B => 5 + 4 * u16_at(at + 3), // RopDeleteProperties: PropertyTagCount, then the tags
            0x12 => 6 + 4 * u16_at(at + 4), // RopSetColumns: PropertyTagCount, then the tags
            // RopGetPropertiesAll (limit and unicode) and RopQueryRows (flags, direction, count)
            // are the same length by coincidence rather than by kinship.
            0x08 | 0x15 => 7,
            // RopSetProperties: `PropertyValueSize` counts the values *and* the two-byte count in
            // front of them, which is the field an implementation gets wrong by exactly two.
            0x0A => 5 + u16_at(at + 3),
            0x0C | 0x25 => 5, // RopSaveChangesMessage / RopSaveChangesAttachment
            0x0D => 7,        // RopRemoveAllRecipients: a four-byte Reserved the server ignores
            0x0E => modify_recipients(rops, at),
            0x1E => 7 + 8 * u16_at(at + 5), // RopDeleteMessages: MessageIdCount, then the ids
            0x23 => 4,                      // RopCreateAttachment
            0x2B => 9,                      // RopOpenStream: a PropertyTag and an OpenModeFlags
            0x2C => 5,                      // RopReadStream: a two-byte ByteCount
            0x2D => 5 + u16_at(at + 3),     // RopWriteStream: DataSize, then the data
            0x32 => 4,                      // RopSubmitMessage: a SubmitFlags byte
            // RopMoveCopyMessages: two handle indices, MessageIdCount, the ids, then
            // WantAsynchronous and WantCopy at the *end* rather than in front of the list.
            0x33 => 8 + 8 * u16_at(at + 4),
            0x43 => 11,                     // RopLongTermIdFromId: an 8-byte ObjectId
            0x44 => 27,                     // RopIdFromLongTermId: a 24-byte LongTermID
            0x5D => 3,                      // RopCommitStream
            0x66 => 7 + 8 * u16_at(at + 5), // RopSetReadFlags: ReadFlags, a count, then the ids
            0xFE => 14 + u16_at(at + 12),   // RopLogon: EssdnSize counts the NUL
            other => panic!("ROP 0x{other:02X} is not one this crate sends"),
        };
        out.push((opcode, &rops[at..at + length]));
        at += length;
    }
    out
}

/// The length of a `RopModifyRecipients`, whose rows are the one variable-length list here that
/// carries its own per-item size rather than a fixed stride.
///
/// [MS-OXCROPS] §2.2.6.5.1.1 — `ModifyRecipientRow`
fn modify_recipients(rops: &[u8], at: usize) -> usize {
    let u16_at = |at: usize| usize::from(u16::from_le_bytes([rops[at], rops[at + 1]]));

    // RopId, LogonId, InputHandleIndex, ColumnCount, RowCount — and ColumnCount is always zero
    // here, so no PropertyTags follow it.
    let mut length = 7;
    for _ in 0..u16_at(at + 5) {
        // RowId, RecipientType, RecipientRowSize, then the row itself.
        length += 7 + u16_at(at + length + 5);
    }
    length
}

/// The opcodes of a ROP list, in order.
pub(crate) fn opcodes(rops: &[u8]) -> Vec<u8> {
    rop_list(rops)
        .into_iter()
        .map(|(opcode, _)| opcode)
        .collect()
}
