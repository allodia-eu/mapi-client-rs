//! Replaying the acting corpus: a message whose recipients are replaced, marked read and unread,
//! submitted, moved and swept up.
//!
//! The claim is the write suite's claim — for an operation whose outcome lives in a mailbox, the
//! request bytes are the only thing CI can re-examine — and it is worth more here than anywhere
//! else in the corpus, because these four ROPs report almost nothing. A submit answers with a bare
//! `ReturnValue`. A move and a read-flag change answer with one byte each. There is nothing in a
//! response to check the encoder against, so the encoder is checked against what a real server
//! accepted.
//!
//! Four shapes exist nowhere else:
//!
//! * `RopRemoveAllRecipients`, and the ordering that makes a replacement a replacement: the remove
//!   in front of the `RopModifyRecipients`, in one buffer.
//! * `RopSetReadFlags` twice, differing by the single byte [MS-OXCMSG] §2.2.3.10.1 requires to
//!   carry `rfSuppressReceipt` alongside `rfClearReadFlag`.
//! * `RopSubmitMessage`, **refused**. A successful submit sends real mail on every re-capture, so
//!   the corpus carries the request bytes and a refusal and the live suite carries the send.
//! * `RopMoveCopyMessages`, whose two folder handles are opened in the same buffer as the move —
//!   and whose new message id the capture had to go looking for, because nothing reports it.
//!
//! And one thing the corpus proves that neither a live run nor a unit test can: that **two**
//! server-assigned identifiers were zeroed. A capture that declared only the first would still be
//! committed and would still replay; the request bodies would simply carry whatever id that run
//! happened to be given.

use mapi_client::{
    Credentials, ErrorCode, Lcid, MapiClient, MessageClass, MessageId, PropertyRow, PropertyTag,
    PropertyValue, ReadFlags, Recipient, SpecialFolder, TaggedValue, WellKnownFolder,
};

use crate::corpus::{assert_requests_match, scenario, server, user_dn};

/// The subject `mapi-cli capture acts` gives the message, and therefore the exact bytes the
/// captured `RopSetProperties` carries.
const SUBJECT: &str = "mapi-client-rs acts scenario";

/// The addresses it is created with, and the one that replaces them.
const FIRST: [&str; 2] = ["ada@example.test", "grace@example.test"];
const SECOND: &str = "edsger@example.test";

/// How many exchanges one captured acting session holds: `Connect`, the logon, both halves of the
/// Drafts entry-id chain, two for the create, the replace, the read-back, two read-flag changes,
/// the remove, the refused submit, the move, two for finding the moved message, five for the
/// sweep, and the `Disconnect`.
const ACT_EXCHANGES: usize = 21;

/// The identifier every captured message id was replaced with.
///
/// Both of them: the save mints one and the move mints another, and the capture zeroes each
/// wherever it appears. The replay reads them back out of the fake server's answers and sends the
/// same zeros, which is why the request bodies match.
const ZEROED_ID: MessageId = MessageId::new(0);

/// What one replayed acting session produced.
struct Acted {
    saved: MessageId,
    recipients: u16,
    marked_read: bool,
    marked_unread: bool,
    submit: Option<ErrorCode>,
    moved: bool,
    found: Option<MessageId>,
}

/// Drives one captured acting session, then checks every request body against the corpus.
///
/// The order is `mapi-cli capture acts`' order exactly, because that is what produced the corpus.
async fn replay(name: &str, locale: Lcid) -> Acted {
    let exchanges = scenario(name);
    assert_eq!(exchanges.len(), ACT_EXCHANGES, "{name} has the wrong shape");
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
    let deleted = logon
        .folder_id(WellKnownFolder::DeletedItems)
        .expect("a Deleted Items folder");

    let saved = logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([
            TaggedValue::new(PropertyTag::SUBJECT, PropertyValue::String(SUBJECT.into()))
                .expect("a string tag"),
        ])
        .to([
            Recipient::to(FIRST[0], FIRST[0]).expect("a recipient"),
            Recipient::to(FIRST[1], FIRST[1]).expect("a recipient"),
        ])
        .save()
        .await
        .expect("the message saves");
    let id = saved.id();

    logon
        .folder(drafts)
        .message(id)
        .update()
        .replacing_recipients()
        .to([Recipient::to(SECOND, SECOND).expect("a recipient")])
        .save()
        .await
        .expect("RopRemoveAllRecipients and RopModifyRecipients");

    let recipients = logon
        .folder(drafts)
        .message(id)
        .open()
        .await
        .expect("RopOpenMessage")
        .recipient_count();

    let marked_read = logon
        .folder(drafts)
        .set_read(&[id], ReadFlags::ReadQuietly)
        .await
        .expect("RopSetReadFlags");
    let marked_unread = logon
        .folder(drafts)
        .set_read(&[id], ReadFlags::Unread)
        .await
        .expect("RopSetReadFlags");

    logon
        .folder(drafts)
        .message(id)
        .update()
        .replacing_recipients()
        .save()
        .await
        .expect("RopRemoveAllRecipients");
    let submit = match logon.folder(drafts).message(id).send().await {
        Err(mapi_client::Error::Rop { code, .. }) => Some(code),
        other => panic!("the captured submit was refused, and this replay was not: {other:?}"),
    };

    let moved = logon
        .folder(drafts)
        .move_messages(&[id], deleted)
        .await
        .expect("RopMoveCopyMessages");
    let found = find(&mut logon, deleted).await;

    sweep(&mut logon, drafts, deleted).await;
    logon.disconnect().await.expect("Disconnect");
    assert_requests_match(&server, &exchanges).await;

    Acted {
        saved: id,
        recipients,
        marked_read,
        marked_unread,
        submit,
        moved,
        found,
    }
}

/// The message in a folder, by subject and with the two columns the capture asked for.
async fn find(logon: &mut mapi_client::Logon, folder: mapi_client::FolderId) -> Option<MessageId> {
    let rows = logon
        .folder(folder)
        .contents()
        .columns([PropertyTag::MID, PropertyTag::SUBJECT])
        .collect()
        .await
        .expect("a contents table");
    rows.iter()
        .find(|row| {
            row.string(PropertyTag::SUBJECT)
                .is_some_and(|found| found.as_str() == SUBJECT)
        })
        .and_then(PropertyRow::message_id)
}

/// The sweep the capture ended with: both folders looked at, and whatever is in them deleted.
async fn sweep(
    logon: &mut mapi_client::Logon,
    drafts: mapi_client::FolderId,
    deleted: mapi_client::FolderId,
) {
    for folder in [deleted, drafts] {
        if let Some(found) = find(logon, folder).await {
            assert!(
                logon
                    .folder(folder)
                    .delete_messages(&[found])
                    .await
                    .expect("RopDeleteMessages"),
                "the captured delete reported partial completion"
            );
        }
    }
}

impl Acted {
    /// Everything both mailboxes' captures say, which for this scenario is everything: nothing it
    /// sends is localised, because everything it sends this crate chose.
    fn assert_shape_is_an_acted_on_message(&self) {
        // Both identifiers came back zeroed, because that is what the corpus holds — and the replay
        // then *sent* them, in the replace, the marks, the submit, the move and the delete, which
        // `assert_requests_match` has already checked byte for byte.
        assert_eq!(self.saved, ZEROED_ID);
        assert_eq!(self.found, Some(ZEROED_ID));

        assert_eq!(
            self.recipients, 1,
            "RopRemoveAllRecipients ran before the RopModifyRecipients, so one address survives"
        );
        assert!(self.marked_read, "PartialCompletion on the read flag");
        assert!(self.marked_unread, "PartialCompletion on the unread flag");
        assert!(self.moved, "PartialCompletion on the move");

        // The one refusal in the corpus that is a *send*. `ecInvalidRecips` is what Exchange
        // answers a submit on a message with no recipients, which its name does not lead a reader
        // to expect and which [MS-OXOMSG] §3.3.5.1.1 does not list.
        assert_eq!(self.submit, Some(ErrorCode::INVALID_RECIPIENTS));
    }
}

/// The en-US mailbox.
#[tokio::test]
async fn an_en_us_acting_session_replays_byte_for_byte() {
    replay("acts-en-us", Lcid::EN_US)
        .await
        .assert_shape_is_an_acted_on_message();
}

/// The nl-NL mailbox.
///
/// What the second mailbox proves here is what it proves for the write corpus: the Drafts folder is
/// found through the entry-id chain, and the two mailboxes' are different ids behind an
/// identical-looking call. It proves one thing more — Deleted Items comes from the *logon*, which
/// names all thirteen, so the move's destination is reached by a different route from its source.
#[tokio::test]
async fn an_nl_nl_acting_session_replays_against_its_own_folders() {
    replay("acts-nl-nl", Lcid::new(0x0413))
        .await
        .assert_shape_is_an_acted_on_message();
}
