//! A response read as it arrives, against the server that streams it.

use std::sync::{Arc, Mutex};

use mapi_client::{Exchange, MetaTag, Observer, RequestType, WellKnownFolder};

/// Every meta-tag the client was told of, in order.
#[derive(Debug, Default)]
struct Tags(Mutex<Vec<(RequestType, MetaTag)>>);

impl Observer for Tags {
    fn observe(&self, _: &Exchange<'_>) {}

    fn meta_tag(&self, request: RequestType, tag: MetaTag) {
        if let Ok(mut tags) = self.0.lock() {
            tags.push((request, tag));
        }
    }
}

/// Exchange streams every answer behind a meta-tag preamble, and the client tells each tag as it
/// arrives: `PROCESSING` first and `DONE` last, for every request that has a Session Context.
/// [MS-OXCMAPIHTTP] §3.2.5.2 has the server "respond immediately" with `PROCESSING`, which is what
/// lets a bound on silence start counting from the first byte rather than from the last.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn every_response_is_told_as_it_arrives() {
    let tags = Arc::new(Tags::default());
    let client = crate::builder()
        .observer(Arc::clone(&tags))
        .build()
        .expect("a client");
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let _ = logon
        .well_known(WellKnownFolder::Inbox)
        .expect("the Inbox")
        .contents()
        .collect()
        .await
        .expect("the Inbox");
    logon.keep_alive().await.expect("a PING");
    logon.disconnect().await.expect("Disconnect");

    let tags = tags.0.lock().expect("the tags").clone();
    println!("{} meta-tags: {tags:?}", tags.len());
    for request in [
        RequestType::Connect,
        RequestType::Execute,
        RequestType::Ping,
        RequestType::Disconnect,
    ] {
        let mine: Vec<MetaTag> = tags
            .iter()
            .filter(|(kind, _)| *kind == request)
            .map(|(_, tag)| *tag)
            .collect();
        assert_eq!(
            mine.first(),
            Some(&MetaTag::Processing),
            "{request}: {mine:?}"
        );
        assert_eq!(mine.last(), Some(&MetaTag::Done), "{request}: {mine:?}");
    }
}
