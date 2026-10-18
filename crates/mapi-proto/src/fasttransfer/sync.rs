//! Reading a content synchronization download: the `contentsSync` element, one event at a time.
//!
//! [MS-OXCFXICS] §2.2.4.2:
//!
//! ```text
//! contentsSync = [progressTotal] *( [progressPerMessage] messageChange )
//!                [deletions] [readStateChanges] state IncrSyncEnd
//! ```
//!
//! **Each part of the stream is read as a unit once it is whole**, and a unit is whole when the
//! marker that begins the next one arrives. A message change ends where the next change, the
//! deletions or the state begins, never inside itself — no marker that starts a unit can occur in a
//! message — so the parser holds one unit at a time and memory is bounded by the largest message,
//! not by the download.
//!
//! **One unreadable object never fails the download.** Two things can go wrong with one: the server
//! fails to produce it and says so with an `errorInfo` element, which [MS-OXCFXICS] §2.2.4.3.4 has
//! the reader unwind to `contentsSync` and carry on from; or the elements it sent do not fit the
//! grammar. Both become an event naming what was lost, and the next unit is read as though nothing
//! had happened. Only a stream that cannot be split into elements at all — an unknown property
//! type, whose length nobody knows — stops the download.

use std::collections::VecDeque;

use crate::error::Result;
use crate::fasttransfer::content::{Cursor, MessageContent, find, malformed};
use crate::fasttransfer::group::PropertyGroupInfo;
use crate::fasttransfer::{Element, Lexer, Marker, StreamProperty};
use crate::ics::{IdSet, WireKey, read_idset};
use crate::oxcdata::{PropertyTag, PropertyValue};

mod events;

pub use events::{
    ChangeHeader, Deletions, ErrorInfo, FinalState, MessageChange, PartialGroup, Progress,
    ReadStates, SyncEvent,
};

/// Reads the events of one content synchronization download from its `FastTransfer` stream.
///
/// Sans-io like everything in this crate: [`feed`](Self::feed) it each
/// `RopFastTransferSourceGetBuffer` buffer as it arrives, and take events with
/// [`next_event`](Self::next_event) until it answers `None` — which means "send another
/// `GetBuffer`", until [`is_finished`](Self::is_finished).
#[derive(Clone, Debug, Default)]
pub struct ContentsSync {
    lexer: Lexer,
    unit: Vec<Element>,
    events: VecDeque<SyncEvent>,
    groups: Vec<PropertyGroupInfo>,
    group: Option<u32>,
    progress: Option<(u32, bool)>,
    /// The unit an `errorInfo` interrupted, held until the error says whether it was the object
    /// that failed.
    interrupted: Option<Vec<Element>>,
    finished: bool,
}

impl ContentsSync {
    /// A parser that has seen nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hands the parser the next buffer of the stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.lexer.feed(bytes);
    }

    /// Whether `IncrSyncEnd` has been read: the download is over.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// The next event, or `None` until more of the stream arrives.
    ///
    /// # Errors
    ///
    /// A decoding error from the lexer — a stream that cannot be split into elements, which nothing
    /// after it can be read past.
    pub fn next_event(&mut self) -> Result<Option<SyncEvent>> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
            if self.finished {
                return Ok(None);
            }
            let Some(element) = self.lexer.next_element()? else {
                return Ok(None);
            };
            self.accept(element);
        }
    }

    /// Checks that the stream ended where it should, once the server reports `Done`.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedFastTransfer`](crate::Error::MalformedFastTransfer) if the stream ended
    /// before `IncrSyncEnd`, or inside an element.
    pub fn finish(&self) -> Result<()> {
        if !self.finished {
            return Err(malformed(
                "contentsSync",
                "the stream ended before IncrSyncEnd",
            ));
        }
        if self.lexer.pending() > 0 {
            return Err(malformed("contentsSync", "bytes follow IncrSyncEnd"));
        }
        Ok(())
    }

    /// Takes one element: either it continues the unit being read, or it begins the next one and
    /// the unit before it is complete.
    fn accept(&mut self, element: Element) {
        if begins_unit(&element) && !self.unit.is_empty() {
            let unit = core::mem::take(&mut self.unit);
            // Only a message change can be the object an error interrupted. Anything else —
            // the previous error among them, which settles the change *it* interrupted — is
            // read as usual, so that two errors in a row never leave a change behind unread.
            if matches!(element, Element::Marker(Marker::ErrorInfo)) && is_change(&unit) {
                self.interrupted = Some(unit);
            } else {
                self.complete(&unit);
            }
        }
        let ends_now = matches!(
            element,
            Element::Marker(Marker::IncrSyncStateEnd | Marker::IncrSyncEnd)
        );
        self.unit.push(element);
        if ends_now {
            let unit = core::mem::take(&mut self.unit);
            self.complete(&unit);
        }
    }

    /// Reads a complete unit, queueing whatever event it produces.
    fn complete(&mut self, unit: &[Element]) {
        match self.read_unit(unit) {
            Ok(Some(event)) => self.events.push_back(event),
            Ok(None) => {}
            Err(error) => self.events.push_back(SyncEvent::Unreadable {
                header: header_of(unit),
                reason: error.to_string(),
            }),
        }
    }

    fn read_unit(&mut self, unit: &[Element]) -> Result<Option<SyncEvent>> {
        let mut cursor = Cursor::new(unit);
        let event = match cursor.peek() {
            Some(Element::Marker(Marker::IncrSyncProgressMode)) => {
                cursor.advance();
                Some(SyncEvent::Progress(Progress::read(single_binary(
                    &mut cursor,
                )?)?))
            }
            Some(Element::Marker(Marker::IncrSyncProgressPerMessage)) => {
                cursor.advance();
                let properties = cursor.properties();
                let size = properties.first().and_then(|p| p.value().as_u32());
                let fai = properties.get(1).and_then(|p| p.value().as_bool());
                self.progress = size.zip(fai);
                None
            }
            Some(Element::Marker(Marker::IncrSyncGroupInfo)) => {
                cursor.advance();
                let info = PropertyGroupInfo::read(single_binary(&mut cursor)?)?;
                self.groups.retain(|known| known.id() != info.id());
                self.groups.push(info);
                None
            }
            Some(Element::Property(property))
                if property.tag() == PropertyTag::META_TAG_INCR_SYNC_GROUP_ID =>
            {
                cursor.advance();
                self.group = property.value().as_u32();
                None
            }
            // The announcement belongs to this change whether or not it reads, so it is taken
            // first: left behind, it would be reported as the size of the next one.
            Some(Element::Marker(Marker::IncrSyncChange)) => {
                cursor.advance();
                let progress = self.progress.take();
                Some(Self::full_change(&mut cursor, progress)?)
            }
            Some(Element::Marker(Marker::IncrSyncChangePartial)) => {
                cursor.advance();
                let progress = self.progress.take();
                Some(self.partial_change(&mut cursor, progress)?)
            }
            Some(Element::Marker(Marker::IncrSyncDeletions)) => {
                cursor.advance();
                Some(SyncEvent::Deletions(Deletions::read(&cursor.properties())?))
            }
            Some(Element::Marker(Marker::IncrSyncRead)) => {
                cursor.advance();
                Some(SyncEvent::ReadStates(ReadStates::read(
                    &cursor.properties(),
                )?))
            }
            Some(Element::Marker(Marker::IncrSyncStateBegin)) => {
                cursor.advance();
                let state = FinalState::read(&cursor.properties())?;
                cursor.expect(Marker::IncrSyncStateEnd, "the state")?;
                Some(SyncEvent::State(state))
            }
            Some(Element::Marker(Marker::IncrSyncEnd)) => {
                cursor.advance();
                self.finished = true;
                Some(SyncEvent::End)
            }
            Some(Element::Marker(Marker::ErrorInfo)) => {
                cursor.advance();
                let interrupted = self.interrupted.take();
                match single_binary(&mut cursor).and_then(ErrorInfo::read) {
                    Ok(info) => {
                        self.resolve_interrupted(interrupted, &info);
                        Some(SyncEvent::Failed(info))
                    }
                    Err(error) => {
                        // An error that cannot be read names nothing, so the change it followed
                        // is delivered: dropping it would lose a message without a word.
                        if let Some(unit) = interrupted {
                            self.complete(&unit);
                        }
                        return Err(error);
                    }
                }
            }
            _ => {
                return Err(malformed(
                    "contentsSync",
                    "a unit begins with no element that starts one",
                ));
            }
        };
        if !cursor.is_empty() {
            return Err(malformed(
                "contentsSync",
                "elements follow the end of a unit",
            ));
        }
        Ok(event)
    }

    /// Decides what the unit an `errorInfo` interrupted was.
    ///
    /// [MS-OXCFXICS] §2.2.4.3.4: the server "might have already output some part of the data
    /// pertaining to that object", and the reader unwinds past it. But an error can also arrive
    /// straight after an object that was whole, about one the server never began. The error names
    /// its object by GID, and a message's `PidTagSourceKey` is the same 22 bytes — so the unit is
    /// dropped when it is the one named, and delivered as usual when it is not. A dropped change
    /// takes the progress announced for it along.
    fn resolve_interrupted(&mut self, interrupted: Option<Vec<Element>>, info: &ErrorInfo) {
        let Some(unit) = interrupted else {
            return;
        };
        let failed = info.message().map(|(guid, counter)| {
            let mut gid = guid.as_bytes().to_vec();
            gid.extend_from_slice(&counter.as_bytes());
            gid
        });
        let named =
            header_of(&unit).is_some_and(|header| failed.as_deref() == Some(header.source_key()));
        if named {
            self.progress = None;
        } else {
            self.complete(&unit);
        }
    }

    /// `messageChangeFull`, after its `IncrSyncChg`.
    fn full_change(cursor: &mut Cursor<'_>, progress: Option<(u32, bool)>) -> Result<SyncEvent> {
        let header = ChangeHeader::read(&cursor.properties())?;
        cursor.expect(Marker::IncrSyncMessage, "a message change")?;
        let content = cursor.message_content()?;
        Ok(SyncEvent::Message(MessageChange::full(
            header, content, progress,
        )))
    }

    /// `messageChangePartial`, after its `IncrSyncChgPartial`.
    ///
    /// Every group's `propList` "is the complete content of a property group": a property the
    /// group's mapping names and the list omits is to be deleted, which is why the groups are kept
    /// apart rather than merged into one property list.
    ///
    /// [MS-OXCFXICS] §2.2.4.3.15 — `messageChangePartial`
    fn partial_change(
        &self,
        cursor: &mut Cursor<'_>,
        progress: Option<(u32, bool)>,
    ) -> Result<SyncEvent> {
        let header = ChangeHeader::read(&cursor.properties())?;
        let mut groups = Vec::new();
        while let Some(index) = cursor.meta(PropertyTag::META_TAG_INCREMENTAL_SYNC_MESSAGE_PARTIAL)
        {
            let index = index.as_u32().ok_or_else(|| {
                malformed("a partial change", "a group index that is not an integer")
            })?;
            let properties = cursor
                .properties()
                .into_iter()
                // "MUST be present if and only if a property group is empty, but was still
                // marked as changed", and "MUST be ignored by clients".
                .filter(|property| property.tag() != PropertyTag::new(0x0000_0003))
                .collect();
            groups.push(PartialGroup::new(index, properties));
        }
        let mut content = MessageContent::default();
        cursor.message_children(&mut content)?;
        let mapping = self
            .group
            .and_then(|id| self.groups.iter().find(|info| info.id() == id))
            .cloned();
        Ok(SyncEvent::Message(MessageChange::partial(
            header, groups, content, mapping, progress,
        )))
    }
}

/// Whether an element starts a unit of `contentsSync`, and so completes the one before it.
fn begins_unit(element: &Element) -> bool {
    match element {
        Element::Marker(marker) => matches!(
            marker,
            Marker::IncrSyncProgressMode
                | Marker::IncrSyncProgressPerMessage
                | Marker::IncrSyncGroupInfo
                | Marker::IncrSyncChange
                | Marker::IncrSyncChangePartial
                | Marker::IncrSyncDeletions
                | Marker::IncrSyncRead
                | Marker::IncrSyncStateBegin
                | Marker::IncrSyncEnd
                | Marker::ErrorInfo
        ),
        Element::Property(property) => property.tag() == PropertyTag::META_TAG_INCR_SYNC_GROUP_ID,
    }
}

/// Whether a unit is a message change: the only kind an `errorInfo` can be about.
fn is_change(unit: &[Element]) -> bool {
    matches!(
        unit.first(),
        Some(Element::Marker(
            Marker::IncrSyncChange | Marker::IncrSyncChangePartial
        ))
    )
}

/// The one `PtypBinary` property, id zero, that a progress, group or error element carries.
fn single_binary<'a>(cursor: &mut Cursor<'a>) -> Result<&'a [u8]> {
    match cursor.peek() {
        Some(Element::Property(property)) => {
            cursor.advance();
            property
                .value()
                .as_binary()
                .ok_or_else(|| malformed("a special property", "its value is not binary"))
        }
        _ => Err(malformed("a special property", "it is missing")),
    }
}

/// Whatever header a unit that could not be read had got as far as, so the event can name it.
fn header_of(unit: &[Element]) -> Option<ChangeHeader> {
    let mut cursor = Cursor::new(unit);
    if cursor.eat(Marker::IncrSyncChange) || cursor.eat(Marker::IncrSyncChangePartial) {
        ChangeHeader::read(&cursor.properties()).ok()
    } else {
        None
    }
}

/// An IDSET property from a list, decoded in the form its tag implies.
pub(crate) fn idset<K: WireKey>(
    properties: &[StreamProperty],
    tag: PropertyTag,
) -> Result<IdSet<K>> {
    match find(properties, tag) {
        Some(PropertyValue::Binary(bytes)) => read_idset(bytes),
        Some(_) => Err(malformed("an IDSET property", "its value is not binary")),
        None => Ok(IdSet::new()),
    }
}

/// Reads the eight bytes of a `PtypInteger64` id property.
pub(crate) fn id(properties: &[StreamProperty], tag: PropertyTag) -> Option<u64> {
    find(properties, tag).and_then(PropertyValue::as_u64)
}

#[cfg(test)]
mod tests;
