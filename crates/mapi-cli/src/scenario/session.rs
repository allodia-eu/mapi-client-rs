//! The whole conversation, in one Session Context.
//!
//! A fixture set is only as good as what it covers, and the thing it has to cover is the *whole*
//! path this workspace claims to implement — including the paging that a small mailbox would
//! otherwise never exercise.
//!
//! Page sizes here are deliberately far smaller than the default fifty. A lab mailbox has fifteen
//! folders and five messages; at the default both tables would arrive in one round trip and the
//! committed corpus would contain no evidence that a second page decodes against the column set the
//! first one established.
//!
//! Split out of `scenario.rs` so that the file taking the arguments stays about *taking* them: this
//! one is the conversation, and it is the half that grows with every phase.

use mapi_client::{
    FOLDER_PROPERTIES, FolderId, Logon, MAILBOX_PROPERTIES, MapiClient, NamedProperty,
    PropertyName, PropertySetId, PropertyTag, PropertyValue, SpecialFolder, TaggedValue,
    WellKnownFolder,
};

use crate::Failure;
use crate::capture::Recorder;

/// Folders per round trip, chosen so that a fifteen-folder mailbox needs three of them.
const HIERARCHY_PAGE: u16 = 8;

/// Messages per round trip, chosen so that a five-message inbox needs three of them.
const CONTENTS_PAGE: u16 = 2;

/// Folders per round trip for the recursive read, chosen so that a lab mailbox's twenty-six needs
/// two of them.
///
/// Larger than [`HIERARCHY_PAGE`] on purpose: what the recursive capture is evidence *for* is the
/// `Depth` flag and the parent ids that make its flat rows a tree, and four pages of that would
/// treble the corpus to re-prove paging the immediate read already proves.
const DEEP_PAGE: u16 = 20;

/// The comment the capture tries to set on the Store object, and never does.
///
/// [MS-OXCSTOR] §2.2.2.1.2.1 note 14 says Exchange 2013 SP1 and later answer `ecAccessDenied` when
/// a client sets `PidTagComment`, and the lab confirms it — so this write is captured precisely
/// *because* it changes nothing, and it gives the corpus its only evidence of what a refused
/// property looks like: a ROP that succeeded, carrying a `PropertyProblem` that says the property
/// did not.
///
/// If a future server ever accepted it, the mailbox would gain this comment and
/// `Verify-Fixtures.ps1` would report the changed response. Both are visible; neither is quiet.
const COMMENT_PROBE: &str = "mapi-client-rs probe";

/// A property name no store has ever registered, asked for with the create flag off.
///
/// Captured because its answer is `0x0000` — a refusal the server reports **alongside a successful
/// ROP** — and because it is the corpus's only `Kind` `0x01` request, the form whose `NameSize`
/// counts its own terminator. Nothing is created: [MS-OXCPRPT] §2.2.12.1's `Flags` is `0x00`, and
/// the live suite asserts across two sessions that the name stays unregistered.
const UNREGISTERED_NAME: &str = "mapi-client-rs-no-such-property";

/// `PidTagSubject`'s id, which is not a named property at all.
///
/// [MS-OXCPRPT] §2.2.13 has the server answer for an id below `0x8000` out of the `PS_MAPI` set
/// rather than refusing, which is a response shape nothing else in the corpus carries.
const FIXED_ID: u16 = 0x0037;

/// An id from the named range that no lab store has reached.
///
/// The one that matters most. Exchange answers a `Kind` of `0xFF` and **stops** — no property set,
/// though [MS-OXCDATA] §2.6.1's diagram marks the `GUID` field as not optional. Reading the
/// specification's sixteen bytes there consumes whatever follows, so this is in the corpus to keep
/// CI checking the deviation rather than the diagram. It is last in the request for the same
/// reason: a decoder that got it wrong runs off the end of the buffer rather than quietly reading
/// the next entry wrongly.
const UNREGISTERED_ID: u16 = 0xFFFE;

/// Everything this workspace implements, in one Session Context.
pub(super) async fn session(client: &MapiClient, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("");
    client.ping().await?;

    recorder.label("");
    let connection = client.connect().await?;
    println!("  connected as {:?}", connection.server().display_name());

    recorder.label("logon");
    let mut logon = connection.logon().await?;
    let subtree = logon.folder_id(WellKnownFolder::IpmSubtree)?;

    store_object(&mut logon, recorder).await?;
    named_properties(&mut logon, recorder).await?;
    hierarchy(&mut logon, recorder, subtree).await?;
    special_folders(&mut logon, recorder).await?;

    recorder.label("contents");
    let mut rows = logon
        .well_known(WellKnownFolder::Inbox)?
        .contents()
        .page_size(CONTENTS_PAGE)
        .rows();
    let mut messages = 0_usize;
    while rows.try_next().await?.is_some() {
        messages = messages.saturating_add(1);
    }
    recorder.label("contents-release");
    rows.close().await?;
    println!("  {messages} message(s) in the Inbox");

    recorder.label("");
    logon.disconnect().await?;
    Ok(())
}

/// The Store object read, and the write the server refuses.
///
/// `RopGetPropertiesAll` is deliberately *not* captured: its answer on the lab carries a dozen
/// server clocks that move on every logon, so a fixture of it would make `Verify-Fixtures.ps1`
/// report a difference every single run and the one difference that mattered would be lost in the
/// noise. Normalising a tagged property list is its own piece of work, and it belongs with the
/// rest of the write-fixture harness.
async fn store_object(logon: &mut Logon, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("properties");
    let mailbox = logon.store().read(MAILBOX_PROPERTIES).await?;
    println!(
        "  {} store properties, {} of them refused by the server",
        mailbox.len(),
        mailbox
            .iter()
            .filter(|cell| cell.value().as_error().is_some())
            .count()
    );

    // A write the server refuses, which is why it is safe to capture. See `COMMENT_PROBE`.
    recorder.label("properties-refused");
    let problems = logon
        .store()
        .write(&[TaggedValue::new(
            PropertyTag::COMMENT,
            PropertyValue::String(COMMENT_PROBE.into()),
        )?])
        .await?;
    println!(
        "  setting PidTagComment reported {} problem(s)",
        problems.len()
    );
    if problems.is_empty() {
        return Err(Failure::from(
            "the server accepted a write to PidTagComment. [MS-OXCSTOR] §2.2.2.1.2.1 note 14 says \
             it will not, and this capture is only safe to run because of that — the mailbox now \
             carries the probe comment. Remove it, and re-think this scenario before committing."
                .to_owned(),
        ));
    }
    Ok(())
}

/// Both name ROPs: what this store numbers the catalogued properties as, and what it says those
/// numbers are.
///
/// Two exchanges, because the second's request is built from the first's answer. The pair is worth
/// committing for a reason no single capture has: the ids in the first response are meaningful only
/// as an ordered list, so the second is the corpus's only evidence that this client pairs them with
/// the right names.
///
/// **The ids differ between the two lab mailboxes** — all ten of them — so the two session fixtures
/// are not copies of each other here, and a replay that mixed them up would fail on the bytes
/// rather than pass quietly.
///
/// The one shape this does not carry is a `Kind` `0x01` in a *response*: every catalogued property
/// is named by a LID, and the string-named properties a store holds are numbered differently in
/// each mailbox, so there is no id to ask about that would be stable enough to commit. The encoder
/// for that form is covered against [MS-OXCPRPT] §4.1.1's own bytes instead.
async fn named_properties(logon: &mut Logon, recorder: &Recorder) -> Result<(), Failure> {
    let unregistered = PropertyName::named(PropertySetId::PUBLIC_STRINGS, UNREGISTERED_NAME)?;
    let mut wanted: Vec<PropertyName> = NamedProperty::ALL.iter().map(|p| p.name()).collect();
    wanted.push(unregistered.clone());

    recorder.label("named-properties");
    let resolved = logon.resolve_names(wanted).await?;
    println!(
        "  {} of {} named propert(y/ies) mapped by this store",
        resolved.mapped(),
        resolved.len()
    );
    if resolved.get(&unregistered).is_some() {
        return Err(Failure::from(format!(
            "the server mapped `{UNREGISTERED_NAME}`, which no store should have registered. \
             Either this capture just created a named property or the name is not as unlikely as \
             it looks — pick another before committing."
        )));
    }

    let mut ids: Vec<u16> = resolved
        .iter()
        .filter_map(|entry| Some(entry.id()?.as_u16()))
        .collect();
    if ids.len() != NamedProperty::ALL.len() {
        return Err(Failure::from(format!(
            "this store maps only {} of the {} catalogued named properties, so the capture would \
             carry no evidence that the rest resolve. Open the mailbox in Outlook or OWA once and \
             re-run.",
            ids.len(),
            NamedProperty::ALL.len()
        )));
    }
    ids.push(FIXED_ID);
    ids.push(UNREGISTERED_ID);

    recorder.label("named-properties-inverse");
    let names = logon.names_of(&ids).await?;
    println!(
        "  the store named {} of the {} ids asked about",
        names.iter().flatten().count(),
        names.len()
    );
    if names.last() != Some(&None) {
        return Err(Failure::from(format!(
            "0x{UNREGISTERED_ID:04X} has a name in this store, so the capture carries no unnamed \
             entry — which is the one response shape [MS-OXCDATA] §2.6.1 describes wrongly. Pick \
             an id this store has not reached."
        )));
    }
    Ok(())
}

/// Both hierarchy reads: the immediate children, paged, and then everything below at every level.
///
/// The first is where the paging evidence lives — the opening round trip sets the columns and every
/// later one is a bare `RopQueryRows` against a handle that still remembers them. The second is the
/// `Depth` flag, captured because the flat rows it produces are only a tree by way of
/// `PidTagParentFolderId`, and a corpus with no recursive read in it would prove nothing about
/// either.
async fn hierarchy(
    logon: &mut Logon,
    recorder: &Recorder,
    subtree: FolderId,
) -> Result<(), Failure> {
    recorder.label("hierarchy");
    let mut rows = logon
        .folder(subtree)
        .subfolders()
        .page_size(HIERARCHY_PAGE)
        .rows();
    let mut folders = 0_usize;
    while rows.try_next().await?.is_some() {
        folders = folders.saturating_add(1);
    }
    recorder.label("hierarchy-release");
    rows.close().await?;
    println!("  {folders} subfolder(s)");

    recorder.label("hierarchy-deep");
    let mut rows = logon
        .folder(subtree)
        .descendants()
        .page_size(DEEP_PAGE)
        .rows();
    let mut descendants = 0_usize;
    while rows.try_next().await?.is_some() {
        descendants = descendants.saturating_add(1);
    }
    recorder.label("hierarchy-deep-release");
    rows.close().await?;
    println!("  {descendants} folder(s) below the IPM subtree, at every level");
    Ok(())
}

/// The entry-id chain, and then the Calendar's own properties.
///
/// Three exchanges: the Inbox's binary properties, the conversion of every one of them that parsed,
/// and a property read on the folder that conversion found. The middle one is the corpus's only
/// evidence of what a `RopIdFromLongTermId` request and response look like, and the last is its
/// only `RopGetPropertiesSpecific` against something other than the Logon object.
async fn special_folders(logon: &mut Logon, recorder: &Recorder) -> Result<(), Failure> {
    recorder.label("special-folders");
    let special = logon.special_folders().await?;
    println!(
        "  {} of {} special folder(s) present",
        special.found(),
        SpecialFolder::ALL.len()
    );

    let Some(calendar) = special.get(SpecialFolder::Calendar) else {
        return Err(Failure::from(
            "this mailbox has no Calendar folder, so the capture would carry no evidence that the \
             entry-id chain reaches one. Open the mailbox in Outlook or OWA once and re-run."
                .to_owned(),
        ));
    };

    recorder.label("folder-properties");
    let details = logon
        .folder(calendar)
        .properties()
        .read(FOLDER_PROPERTIES)
        .await?;
    println!(
        "  the Calendar at {:#018x} answered with {} propert(y/ies)",
        calendar.as_u64(),
        details.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page sizes exist to force paging on a small lab mailbox, so a change that quietly
    /// raised them would empty the corpus of its only multi-page evidence.
    #[test]
    fn the_page_sizes_are_small_enough_to_force_paging() {
        const { assert!(HIERARCHY_PAGE < 15, "a lab mailbox has fifteen folders") }
        const { assert!(CONTENTS_PAGE < 5, "a seeded inbox has five messages") }
        const {
            assert!(
                DEEP_PAGE < 26,
                "a lab mailbox has twenty-six folders below the IPM subtree"
            );
        }
    }

    /// The two extras the inverse lookup asks about are the two response shapes nothing else in the
    /// corpus carries, and neither is a named property of this store's.
    #[test]
    fn the_extra_ids_are_outside_what_a_lookup_would_have_resolved() {
        const { assert!(FIXED_ID < 0x8000, "a fixed id is answered from PS_MAPI") }
        const {
            assert!(
                UNREGISTERED_ID >= 0x8000,
                "the unnamed one is in the named range"
            );
        }
    }
}
