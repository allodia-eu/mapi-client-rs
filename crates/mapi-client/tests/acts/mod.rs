//! Acting on items in a real mailbox: sending mail between the two lab accounts, archiving a
//! message, and marking one read.
//!
//! Every test here is **self-cleaning**, as the `writes` suite is and for the same reason: the
//! counts the `items` suite asserts are exact, so anything left behind breaks a different test on
//! the next run. Sending makes that harder rather than easier — a sent message lands in *another*
//! mailbox — so the send test logs on as the recipient to take it away again, which is the one
//! place in this workspace that holds two Session Contexts at once.
//!
//! What these prove that no fixture can. A submit, a move and a read-flag change answer with
//! nothing, one byte and one byte respectively, so a replay proves only that the request bytes were
//! accepted. Whether the message was delivered, whether it is in the folder it was moved to, and
//! whether `mfRead` is actually set are questions only a mailbox can answer — and three of the four
//! documented deviations this suite carries were found by asking them.
//!
//! [MS-OXCROPS] §2.2.7.1 — `RopSubmitMessage`
//! [MS-OXCROPS] §2.2.4.6 — `RopMoveCopyMessages`
//! [MS-OXCROPS] §2.2.6.10 — `RopSetReadFlags`

use core::time::Duration;

use mapi_client::{
    FolderId, Logon, MessageClass, MessageFlags, MessageId, PropertyRow, PropertyTag,
    PropertyValue, ReadFlags, Recipient, STATE_PROPERTIES, SpecialFolder, TaggedValue,
    WellKnownFolder,
};

use crate::writes::{MARKER, string};
use crate::{LIVE_TIMEOUT, client, required};

/// The second lab mailbox, for the one test that needs to read what the first one sent.
///
/// Its own set of variables rather than a second value in the existing ones, because the two are
/// used at the same time: the send test logs on to both at once, which nothing else in this suite
/// does. `None` when they are not set, so a lab with one mailbox can still run everything else.
struct SecondMailbox {
    endpoint: String,
    user_dn: String,
    address: String,
    password: String,
}

/// The second mailbox's details, or `None` if this lab has only one.
fn second_mailbox() -> Option<SecondMailbox> {
    Some(SecondMailbox {
        endpoint: std::env::var("MAPI_LIVE_SECOND_ENDPOINT").ok()?,
        user_dn: std::env::var("MAPI_LIVE_SECOND_USER_DN").ok()?,
        address: std::env::var("MAPI_LIVE_SECOND_USERNAME").ok()?,
        // Deliberately the same password variable: the lab's two mailboxes share one, and adding a
        // second place for a password to be typed is not an improvement.
        password: required("MAPI_LIVE_PASSWORD"),
    })
}

/// A client for the second mailbox.
fn client_for(mailbox: &SecondMailbox) -> mapi_client::MapiClient {
    mapi_client::MapiClient::builder()
        .endpoint(&mailbox.endpoint)
        .user_dn(mapi_client::LegacyDn::new(&mailbox.user_dn).expect("a usable legacyExchangeDN"))
        .credentials(mapi_client::Credentials::basic(
            &mailbox.address,
            &mailbox.password,
        ))
        .timeout(LIVE_TIMEOUT)
        .build()
        .expect("a client for the second mailbox")
}

/// The subject the sent message carries, so anything a failed run leaves in the *other* mailbox is
/// identifiable by eye rather than by date.
const SENT_MARKER: &str = "mapi-client-rs send test";

/// How long to keep asking the recipient's Inbox for the message before giving up.
///
/// Delivery is not synchronous with the submit and nothing in the response says when it will
/// happen, so this is a poll rather than a wait. Ten seconds is generous for a lab where the
/// transport is the same box; a failure here means the message did not arrive, not that the timeout
/// was tight.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to leave between attempts.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Mail actually sent from one lab mailbox to the other, found in the recipient's Inbox, and taken
/// out of both mailboxes again.
///
/// The one test in this workspace that opens two Session Contexts, and it has to: the evidence that
/// a submit did anything is in a mailbox the sender cannot read.
#[tokio::test]
#[ignore = "needs a live Exchange Server and two mailboxes; run scripts\\Test-Live.ps1"]
async fn mail_sent_to_the_other_mailbox_arrives_in_it() {
    let Some(recipient) = second_mailbox() else {
        panic!(
            "MAPI_LIVE_SECOND_ENDPOINT and its siblings are not set. This test needs the second \
             lab mailbox, because the evidence that a submit worked is in the mailbox it was sent \
             to. scripts\\Test-Live.ps1 sets them."
        );
    };

    let mut sender = logged_on(client()).await;
    let drafts = sender
        .special_folder(SpecialFolder::Drafts)
        .await
        .expect("a Drafts folder");
    let sent_items = sender
        .folder_id(WellKnownFolder::SentItems)
        .expect("a Sent Items folder");

    let saved = sender
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([
            TaggedValue::new(PropertyTag::SUBJECT, string(SENT_MARKER)).expect("a string tag"),
            TaggedValue::new(PropertyTag::BODY, string("Sent by the live suite.\n"))
                .expect("a string tag"),
        ])
        .to([Recipient::to(&recipient.address, &recipient.address).expect("a recipient")])
        .keep_copy_in(sent_items)
        .send()
        .await
        .expect("RopSubmitMessage");
    assert!(saved.is_sent());

    // The id the save reported is not the id the message has once the server has filed it, so the
    // Sent Items copy is found by subject. That is not laziness: nothing in any response carries
    // the new one.
    let filed = wait_for(&mut sender, sent_items, SENT_MARKER).await;
    let left_in_drafts = contains(&mut sender, drafts, saved.id()).await;

    let mut received = logged_on(client_for(&recipient)).await;
    let inbox = received
        .folder_id(WellKnownFolder::Inbox)
        .expect("an Inbox");
    let delivered = wait_for(&mut received, inbox, SENT_MARKER).await;

    // Both mailboxes are cleaned before anything is asserted, so a failure does not leave mail in
    // somebody else's Inbox — and everything below has to be readable from values taken first.
    if let Some(id) = delivered {
        received
            .folder(inbox)
            .delete_messages(&[id])
            .await
            .expect("deleting the delivered message");
    }
    for (folder, id) in [(sent_items, filed), (drafts, Some(saved.id()))] {
        if let Some(id) = id.filter(|_| folder != drafts || left_in_drafts) {
            sender
                .folder(folder)
                .delete_messages(&[id])
                .await
                .expect("cleaning up after the send");
        }
    }

    received.disconnect().await.expect("Disconnect");
    sender.disconnect().await.expect("Disconnect");

    assert!(
        delivered.is_some(),
        "the message did not reach {} within {DELIVERY_TIMEOUT:?}. RopSubmitMessage succeeding \
         says the server accepted it and nothing more, so this is where a delivery problem shows \
         up.",
        recipient.address
    );
    let filed = filed.expect("the sent message was filed in Sent Items");
    assert_ne!(
        filed,
        saved.id(),
        "filing a submitted message mints a new id, which is the thing worth asserting here"
    );
    assert!(
        !left_in_drafts,
        "PidTagSentMailSvrEID moves the message rather than copying it, so Drafts should be empty"
    );
}

/// A message moved between folders leaves the first, arrives in the second, and arrives under a
/// **different id** — which is the finding, and the reason this looks the message up by subject.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_moved_message_leaves_one_folder_and_arrives_in_the_other_renamed() {
    let mut logon = logged_on(client()).await;
    let drafts = logon
        .special_folder(SpecialFolder::Drafts)
        .await
        .expect("a Drafts folder");
    let deleted = logon
        .folder_id(WellKnownFolder::DeletedItems)
        .expect("a Deleted Items folder");

    let saved = logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([TaggedValue::new(PropertyTag::SUBJECT, string(MARKER)).expect("a string tag")])
        .save()
        .await
        .expect("RopSaveChangesMessage");

    let complete = logon
        .folder(drafts)
        .move_messages(&[saved.id()], deleted)
        .await
        .expect("RopMoveCopyMessages");

    let moved = find_by_subject(&mut logon, deleted, MARKER).await;
    if let Some(id) = moved {
        logon
            .folder(deleted)
            .delete_messages(&[id])
            .await
            .expect("deleting the moved message");
    }
    let left_behind = contains(&mut logon, drafts, saved.id()).await;
    if left_behind {
        logon
            .folder(drafts)
            .delete_messages(&[saved.id()])
            .await
            .expect("deleting a message the move left behind");
    }
    logon.disconnect().await.expect("Disconnect");

    assert!(complete, "PartialCompletion said the move was incomplete");
    assert!(!left_behind, "the message is still in Drafts");
    let moved = moved.expect("the message is in Deleted Items");
    assert_ne!(
        moved,
        saved.id(),
        "a move mints a new id, and no response reports it — the claim this test exists for"
    );
}

/// Marking a message read sets `mfRead`, and marking it unread clears it — but **`mfEverRead` stays
/// set**, which [MS-OXCMSG] §2.2.1.6 says the server clears alongside `mfRead`.
///
/// Run against a message this test made, because that flag cannot be put back: a seeded message
/// used here would leave the corpus's baseline permanently changed.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn marking_a_message_read_sets_a_flag_that_marking_it_unread_does_not_clear() {
    let mut logon = logged_on(client()).await;
    let drafts = logon
        .special_folder(SpecialFolder::Drafts)
        .await
        .expect("a Drafts folder");

    let saved = logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([TaggedValue::new(PropertyTag::SUBJECT, string(MARKER)).expect("a string tag")])
        .save()
        .await
        .expect("RopSaveChangesMessage");

    let outcome = read_flag_sequence(&mut logon, drafts, saved.id()).await;

    logon
        .folder(drafts)
        .delete_messages(&[saved.id()])
        .await
        .expect("deleting the message");
    logon.disconnect().await.expect("Disconnect");

    let (read, unread) = outcome;
    assert!(read.is_read(), "mfRead after marking read: {read}");
    assert!(!unread.is_read(), "mfRead after marking unread: {unread}");
    assert!(
        read.has(MessageFlags::EVER_READ),
        "mfEverRead after marking read: {read}"
    );
    assert!(
        unread.has(MessageFlags::EVER_READ),
        "mfEverRead survives being marked unread, which §2.2.1.6's second sentence forbids and its \
         first sentence requires: {unread}"
    );
}

/// Marks the message read, then unread, reporting `PidTagMessageFlags` after each.
async fn read_flag_sequence(
    logon: &mut Logon,
    folder: FolderId,
    id: MessageId,
) -> (MessageFlags, MessageFlags) {
    // Quietly: this is a message the test made, so there is no receipt to send, but asking for one
    // on a message that had a sender would be a side effect nobody asked for.
    assert!(
        logon
            .folder(folder)
            .set_read(&[id], ReadFlags::ReadQuietly)
            .await
            .expect("RopSetReadFlags"),
        "PartialCompletion said the read flag was not set"
    );
    let read = flags_of(logon, folder, id).await;

    assert!(
        logon
            .folder(folder)
            .set_read(&[id], ReadFlags::Unread)
            .await
            .expect("RopSetReadFlags"),
        "PartialCompletion said the read flag was not cleared"
    );
    (read, flags_of(logon, folder, id).await)
}

/// One message's `PidTagMessageFlags`.
async fn flags_of(logon: &mut Logon, folder: FolderId, id: MessageId) -> MessageFlags {
    let state = logon
        .message(folder, id)
        .properties()
        .read(STATE_PROPERTIES)
        .await
        .expect("reading the message's state");
    state
        .get(PropertyTag::MESSAGE_FLAGS)
        .and_then(PropertyValue::as_u32)
        .map(MessageFlags::new)
        .expect("PidTagMessageFlags")
}

/// Polls a folder until a message with this subject turns up, or the timeout runs out.
///
/// **Both things a submit sets in motion are asynchronous**, which the first version of this file
/// got half right: it polled for delivery and looked for the Sent Items copy at once, and the copy
/// was not there yet. `RopSubmitMessage` answers as soon as the server has accepted the message and
/// says nothing about when it will be delivered *or* when it will be filed, so both are polls.
async fn wait_for(logon: &mut Logon, folder: FolderId, subject: &str) -> Option<MessageId> {
    let started = std::time::Instant::now();
    loop {
        if let Some(id) = find_by_subject(logon, folder, subject).await {
            return Some(id);
        }
        if started.elapsed() >= DELIVERY_TIMEOUT {
            return None;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The first message in a folder with this subject.
///
/// By subject rather than by id, because both of the operations this suite is about hand the
/// message a new one and tell nobody.
async fn find_by_subject(logon: &mut Logon, folder: FolderId, subject: &str) -> Option<MessageId> {
    let rows = logon
        .folder(folder)
        .contents()
        .collect()
        .await
        .expect("reading a contents table");
    rows.iter()
        .find(|row| {
            row.string(PropertyTag::SUBJECT)
                .is_some_and(|found| found.as_str() == subject)
        })
        .and_then(PropertyRow::message_id)
}

/// Whether a folder still holds a message.
async fn contains(logon: &mut Logon, folder: FolderId, id: MessageId) -> bool {
    logon
        .folder(folder)
        .contents()
        .collect()
        .await
        .expect("reading a contents table")
        .iter()
        .filter_map(PropertyRow::message_id)
        .any(|found| found == id)
}

/// A logged-on session, for a test that has already decided which mailbox it wants.
async fn logged_on(client: mapi_client::MapiClient) -> Logon {
    client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon")
}
