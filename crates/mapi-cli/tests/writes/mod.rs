//! Replaying the write corpus: a draft created, filled, read back and deleted.
//!
//! The claim this makes is the one the other replays make, and it is worth more here. For a read,
//! "every request body matches what Exchange accepted" is a check on encoding. For a write it is
//! the *only* offline check there is: the outcome of a create lives in a mailbox CI cannot see, so
//! the bytes that produced it are all that can be re-examined.
//!
//! Six shapes exist nowhere else in the corpus:
//!
//! * `RopCreateMessage`, whose response is a Boolean and an optional identifier.
//! * `RopSetProperties` that the server *accepted* — the session corpus has one and Exchange
//!   refused it, so this is the first evidence that the encoder produces something a server takes.
//! * `RopModifyRecipients`, whose `RecipientRow` is a conditional bitfield built from a one-off
//!   entry id, and whose one-byte `PropertyRow` flag at the end is what an entire `Execute` fails
//!   over if it is missing.
//! * `RopCreateAttachment`, `RopOpenStream` in `Create` mode and `RopWriteStream` twice — the write
//!   side of the chunking loop.
//! * `RopSaveChangesAttachment` before `RopSaveChangesMessage`, which is the order that does not
//!   lose the attachment.
//! * `RopDeleteMessages`, whose request carries the identifier the save minted — and which is why
//!   the capture zeroes that identifier in the response and the request alike.

use mapi_client::{
    ATTACHMENT_COLUMNS, AttachMethod, AttachmentNumber, Credentials, Lcid, MapiClient,
    MessageClass, MessageId, NewAttachment, PropertyTag, PropertyValue, Recipient, SpecialFolder,
    TableString, TaggedValue,
};

use crate::corpus::{assert_requests_match, scenario, server, user_dn};

/// The subject `mapi-cli capture writes` gives the draft, and therefore the exact bytes the
/// captured `RopSetProperties` carries.
const SUBJECT: &str = "mapi-client-rs write scenario";

/// Its body.
const BODY: &str = "Written by mapi-cli capture, and deleted again in the same session.\n";

/// The address it is sent to.
const RECIPIENT: &str = "ada@example.test";

/// The attachment's file name and size, which decide how many `RopWriteStream`s the corpus holds.
const ATTACHMENT_NAME: &str = "capture.bin";
const ATTACHMENT_BYTES: usize = 24_000;

/// How many exchanges one captured write session holds: `Connect`, the logon, both halves of the
/// Drafts entry-id chain, five for the create — the message, two attachment chunks, the attachment
/// save and the message save — the open, the properties, the attachment table and its release,
/// three for the attachment read, the delete, and the `Disconnect`.
const WRITE_EXCHANGES: usize = 18;

/// The identifier every captured message id was replaced with.
///
/// Not a message id the server ever issued: the save mints a fresh one every run, and the capture
/// zeroes it wherever it appears. What matters is that the *replay* reads this value back out of
/// the fake server's answer and then sends it — so the request bodies match, which is the whole
/// claim.
const ZEROED_ID: MessageId = MessageId::new(0);

/// What one replayed write session produced.
struct Written {
    saved: mapi_client::SavedMessage,
    subject: Option<String>,
    recipients: u16,
    class: Option<MessageClass>,
    attachments: Vec<(AttachmentNumber, AttachMethod)>,
    content: Vec<u8>,
    deleted: bool,
}

/// The bytes the scenario attached, rebuilt from the same rule the capture used.
fn attachment_content() -> Vec<u8> {
    (0..ATTACHMENT_BYTES)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

/// Drives one captured write session, then checks every request body against the corpus.
///
/// The order is `mapi-cli capture writes`' order exactly, because that is what produced the corpus.
async fn replay(name: &str, locale: Lcid) -> Written {
    let exchanges = scenario(name);
    assert_eq!(
        exchanges.len(),
        WRITE_EXCHANGES,
        "{name} has the wrong shape"
    );
    let server = server(&exchanges).await;

    let client = MapiClient::builder()
        .endpoint(format!("{}/mapi/emsmdb/", server.uri()))
        .user_dn(user_dn(&exchanges))
        .credentials(Credentials::basic("replay@example.test", "hunter2"))
        .locale(locale)
        .danger_allow_plaintext_http()
        .build()
        .expect("a client");

    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let drafts = logon
        .special_folder(SpecialFolder::Drafts)
        .await
        .expect("a Drafts folder");

    let content = attachment_content();
    let saved = create(&mut logon, drafts, &content).await;
    let id = saved.id();

    let opened = logon
        .message(drafts, id)
        .open()
        .await
        .expect("RopOpenMessage");
    let subject = opened.normalized_subject().map(str::to_owned);
    let recipients = opened.recipient_count();

    let (class, attachments, read) = read_back(&mut logon, drafts, id).await;

    let deleted = logon
        .folder(drafts)
        .delete_messages(&[id])
        .await
        .expect("RopDeleteMessages");

    logon.disconnect().await.expect("Disconnect");
    assert_requests_match(&server, &exchanges).await;

    Written {
        saved,
        subject,
        recipients,
        class,
        attachments,
        content: read,
        deleted,
    }
}

/// The create half, which is five round trips: the message, two attachment chunks, the attachment's
/// save and the message's.
async fn create(
    logon: &mut mapi_client::Logon,
    drafts: mapi_client::FolderId,
    content: &[u8],
) -> mapi_client::SavedMessage {
    logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([
            TaggedValue::new(PropertyTag::SUBJECT, PropertyValue::String(SUBJECT.into()))
                .expect("a string tag"),
            TaggedValue::new(PropertyTag::BODY, PropertyValue::String(BODY.into()))
                .expect("a string tag"),
        ])
        .to([Recipient::to(RECIPIENT, RECIPIENT).expect("a recipient")])
        .attach([NewAttachment::by_value(ATTACHMENT_NAME, content.to_vec()).expect("a file name")])
        .save()
        .await
        .expect("the draft saves")
}

/// The read half, through the ordinary read path.
async fn read_back(
    logon: &mut mapi_client::Logon,
    drafts: mapi_client::FolderId,
    id: MessageId,
) -> (
    Option<MessageClass>,
    Vec<(AttachmentNumber, AttachMethod)>,
    Vec<u8>,
) {
    let properties = logon
        .message(drafts, id)
        .properties()
        .read([
            PropertyTag::MESSAGE_CLASS,
            PropertyTag::SUBJECT,
            PropertyTag::HAS_ATTACHMENTS,
        ])
        .await
        .expect("the draft's properties");
    let class = properties
        .string(PropertyTag::MESSAGE_CLASS)
        .map(TableString::as_str)
        .map(MessageClass::new);

    let rows = logon
        .message(drafts, id)
        .attachments()
        .columns(ATTACHMENT_COLUMNS)
        .collect()
        .await
        .expect("the attachment table");
    let attachments = rows
        .iter()
        .filter_map(|row| {
            Some((
                AttachmentNumber::new(row.get(PropertyTag::ATTACH_NUMBER)?.as_u32()?),
                AttachMethod::new(row.get(PropertyTag::ATTACH_METHOD)?.as_u32()?),
            ))
        })
        .collect();

    let read = logon
        .message(drafts, id)
        .attachment(AttachmentNumber::new(0))
        .content()
        .read()
        .await
        .expect("the attachment's content");
    assert!(read.is_complete(), "the replayed read stopped at its limit");

    (class, attachments, read.into_bytes())
}

impl Written {
    /// Everything both mailboxes' captures say, which is everything except what they are called.
    fn assert_shape_is_a_written_draft(&self) {
        // The identifier the save reported is the zeroed one, because that is what the corpus
        // holds — and the replay then *sent* it, in the open and in the delete, which
        // `assert_requests_match` has already checked byte for byte.
        assert_eq!(self.saved.id(), ZEROED_ID);
        assert!(
            self.saved.is_clean(),
            "the server refused {:?}",
            self.saved.problems()
        );
        assert_eq!(self.saved.attachments(), [AttachmentNumber::new(0)]);

        assert_eq!(self.subject.as_deref(), Some(SUBJECT));
        assert_eq!(self.recipients, 1, "the one recipient that was written");
        assert_eq!(self.class, Some(MessageClass::Note));
        assert_eq!(
            self.attachments,
            [(AttachmentNumber::new(0), AttachMethod::ByValue)]
        );

        // The bytes are the point of the 24,000: they went out in two `RopWriteStream`s and came
        // back in two `RopReadStream`s, and only comparing the whole value says both loops put the
        // pieces together in the right order.
        assert_eq!(self.content.len(), ATTACHMENT_BYTES);
        assert_eq!(self.content, attachment_content());

        assert!(self.deleted, "the delete reported partial completion");
    }
}

/// The en-US mailbox.
#[tokio::test]
async fn an_en_us_write_session_replays_byte_for_byte() {
    replay("writes-en-us", Lcid::EN_US)
        .await
        .assert_shape_is_a_written_draft();
}

/// The nl-NL mailbox.
///
/// A write scenario has no localised strings in it — everything it sends, this crate chose — so
/// what the second mailbox proves here is different from what it proves for a read: the folder the
/// draft goes into is found through the entry-id chain, and the two mailboxes' Drafts folders are a
/// different `FolderId` behind an identical-looking one. A client that had cached the first
/// mailbox's would write into the wrong store and be told nothing.
#[tokio::test]
async fn an_nl_nl_write_session_replays_into_its_own_drafts_folder() {
    replay("writes-nl-nl", Lcid::new(0x0413))
        .await
        .assert_shape_is_a_written_draft();
}

/// The one thing a replay cannot check: that the identifier really was zeroed.
///
/// If a future capture forgot to declare it, the fixtures would still be committed and the replay
/// above would still pass — it would simply be sending whatever id the capture happened to hold.
/// This looks at the committed bytes instead.
#[test]
fn the_captured_delete_names_a_zeroed_message_id() {
    for name in ["writes-en-us", "writes-nl-nl"] {
        let exchanges = scenario(name);
        let delete = exchanges
            .iter()
            .find(|exchange| exchange.stem.ends_with("delete-draft"))
            .unwrap_or_else(|| panic!("{name} has no delete"));

        // `RopDeleteMessages` is `RopId(1) LogonId(1) InputHandleIndex(1) WantAsynchronous(1)
        // NotifyNonRead(1) MessageIdCount(2)`, then the ids. Found by its opcode rather than by a
        // fixed offset, because everything in front of it is variable-length — and matched on
        // every fixed byte of the header rather than on the opcode alone, so that a `0x1E` inside
        // some earlier ROP's payload cannot be mistaken for the delete and send this reading eight
        // unrelated bytes.
        let at = delete
            .request_body
            .windows(7)
            .position(|window| {
                window[0] == 0x1E
                    && window[1] == 0x00
                    && window[3] == 0x00
                    && window[4] == 0x00
                    && window[5..7] == [0x01, 0x00]
            })
            .unwrap_or_else(|| panic!("{name}'s delete carries no RopDeleteMessages"));

        assert_eq!(
            delete.request_body.get(at + 7..at + 15),
            Some(&[0; 8][..]),
            "{name} carries a message id the capture did not zero, so a re-capture will differ"
        );
    }
}
