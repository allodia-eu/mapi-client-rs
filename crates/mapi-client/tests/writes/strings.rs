//! A subject written as UTF-16 and read back as `PtypString8` by sessions connected with different
//! code pages: what proves an 8-bit string is decoded in the code page the session asked for.
//!
//! Exchange stores the subject as Unicode and converts it to the session's code page on the way
//! out, so each session reads back what that code page can hold of it — a `?` or the nearest
//! letter for the rest. The expectations are those conversions, as Exchange Server SE
//! `15.02.2562.056` made them.
//!
//! [MS-OXCDATA] §2.11.1.2 — string property values
//! [MS-OXCMAPIHTTP] §2.2.4.1.1 — `DefaultCodePage`

use mapi_client::{
    CodePage, FolderId, MessageClass, MessageId, PropertyTag, PropertyValue, SpecialFolder,
    TaggedValue,
};

use super::{MARKER, string};
use crate::{builder, client};

/// The subject, as `PtypString8`.
const SUBJECT_8: PropertyTag = PropertyTag::new(0x0037_001E);

/// What each session reads back, after the marker: Western European, Cyrillic, and Japanese, the
/// last two the non-Latin code pages, and 932 a multibyte one.
const READINGS: [(u16, &str); 3] = [
    (1252, ": Caf\u{E9} \u{20AC} \u{17E} ?????? ??"),
    (
        1251,
        ": Cafe \u{20AC} z \u{41F}\u{440}\u{438}\u{432}\u{435}\u{442} ??",
    ),
    (
        932,
        ": Cafe ? ? \u{41F}\u{440}\u{438}\u{432}\u{435}\u{442} \u{65E5}\u{672C}",
    ),
];

/// What the subject says after the marker, written as UTF-16: `Café € ž Привет 日本`.
const WRITTEN: &str =
    ": Caf\u{E9} \u{20AC} \u{17E} \u{41F}\u{440}\u{438}\u{432}\u{435}\u{442} \u{65E5}\u{672C}";

/// The written subject.
fn written() -> String {
    format!("{MARKER}{WRITTEN}")
}

#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn an_eight_bit_string_reads_back_in_the_sessions_code_page() {
    let mut logon = client()
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
    let id = logon
        .folder(drafts)
        .create_message(MessageClass::Note)
        .set([TaggedValue::new(PropertyTag::SUBJECT, string(&written())).expect("a string tag")])
        .save()
        .await
        .expect("the draft saves")
        .id();

    // Reported before the cleanup runs, so that a failed read cannot leave the draft behind.
    let mut outcome = Ok(());
    for (code_page, expected) in READINGS {
        if let Err(reason) = read_back(drafts, id, code_page, expected).await {
            println!("  {reason}");
            outcome = outcome.and(Err(reason));
        }
    }

    let deleted = logon.folder(drafts).delete_messages(&[id]).await;
    outcome.expect("every code page reads the subject back as Exchange converted it");
    assert!(
        deleted.expect("the draft deletes"),
        "the draft is still in Drafts"
    );
    logon.disconnect().await.expect("Disconnect");
}

/// Reads the subject as `PtypString8` in a session connected with `code_page`.
async fn read_back(
    folder: FolderId,
    id: MessageId,
    code_page: u16,
    expected: &str,
) -> Result<(), String> {
    let page = CodePage::new(code_page).map_err(|error| error.to_string())?;
    let mut logon = builder()
        .code_page(page)
        .build()
        .map_err(|error| error.to_string())?
        .connect()
        .await
        .map_err(|error| format!("Connect with {page}: {error}"))?
        .logon()
        .await
        .map_err(|error| format!("RopLogon with {page}: {error}"))?;
    let read = logon
        .message(folder, id)
        .properties()
        .read([SUBJECT_8])
        .await
        .map_err(|error| format!("reading the subject with {page}: {error}"));
    let _ = logon.disconnect().await;

    let read = read?;
    let subject = read.get(SUBJECT_8).and_then(PropertyValue::as_string);
    println!("  {page}: {subject:?}");
    let wanted = format!("{MARKER}{expected}");
    match subject {
        Some(text) if text.as_str() == wanted => Ok(()),
        other => Err(format!("{page} read {other:?}, not {wanted:?}")),
    }
}
