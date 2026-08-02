//! The parts of the API a caller touches that are not a table read.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "a test that indexes a known layout is asserting something true about it"
)]

mod support;

use mapi_client::{Credentials, FolderId, PropertyTag, WellKnownFolder};
use support::{
    BOOKMARK_END, LOGON_HANDLE, MapiServer, OPEN_FOLDER_SLOT, TABLE_HANDLE, connect_ok,
    contents_row, disconnect_body, execute_body, get_table_response, hierarchy_row, logon_response,
    open_folder_response, query_rows_response, set_columns_response, well_known_folder_id,
};
use wiremock::ResponseTemplate;

/// The handle table an opened table read leaves behind.
const OPENED: [u32; 3] = [LOGON_HANDLE, 0x0000_0001, TABLE_HANDLE];

/// A client reports what it was configured with, which is what a diagnostic is written from.
#[tokio::test]
async fn a_client_reports_its_endpoint_and_distinguished_name() {
    let server = MapiServer::start().await;
    let client = server.client();

    assert!(client.endpoint().starts_with("http://127.0.0.1:"));
    assert!(client.endpoint().contains("MailboxId="));
    assert!(client.user_dn().as_str().ends_with("cn=alice"));

    // Clones share one connection pool and one client identity, and each can open its own session.
    let clone = client.clone();
    assert_eq!(clone.endpoint(), client.endpoint());
}

/// A logon hands over everything the server said about the mailbox, not just the folder ids.
#[tokio::test]
async fn a_logon_reports_what_the_server_said_about_the_mailbox() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));

    let connection = server.client().connect().await.unwrap();
    assert_eq!(connection.server().display_name(), "Alice Example");
    assert!(connection.server().dn_prefix().starts_with("/o=Example"));
    assert_eq!(connection.server().retry_delay(), 18_409);

    let logon = connection.logon().await.unwrap();
    assert_eq!(logon.mailbox().folder_ids().len(), 13);
    assert_eq!(logon.mailbox().logon_flags(), 0x01);
    assert_eq!(logon.server().display_name(), "Alice Example");
    assert_eq!(
        logon.folder_id(WellKnownFolder::Inbox).unwrap().as_u64(),
        well_known_folder_id(u64::try_from(WellKnownFolder::Inbox.index()).unwrap())
    );
}

/// Not every folder worth reading is one of the thirteen a logon names — a subfolder found by
/// walking the hierarchy is addressed by its own id.
#[tokio::test]
async fn a_folder_can_be_read_by_id_rather_than_by_name() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));

    let mut opened = open_folder_response(OPEN_FOLDER_SLOT);
    opened.extend(get_table_response(0x04, 2, 1));
    opened.extend(set_columns_response(2));
    opened.extend(query_rows_response(
        2,
        BOOKMARK_END,
        &[hierarchy_row(0x0D00_0000_0000_00FF, "Project", 4, false)],
    ));
    server.reply_ok(execute_body(&opened, &OPENED));
    server.reply_ok(execute_body(&[], &[TABLE_HANDLE]));

    let client = server.client();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();

    let arbitrary = FolderId::new(0x0D00_0000_0000_0042);
    let folder = logon.folder(arbitrary);
    assert_eq!(folder.id(), arbitrary);

    let rows = folder.subfolders().collect().await.unwrap();
    assert_eq!(
        rows[0].string(PropertyTag::DISPLAY_NAME).unwrap().as_str(),
        "Project"
    );

    // The id the caller gave is the one that went out, little-endian, in the RopOpenFolder body.
    let sent = server.rops(2).await;
    assert_eq!(&sent[4..12], &arbitrary.as_u64().to_le_bytes());
}

/// A Session Context can be torn down without ever logging on.
#[tokio::test]
async fn a_connection_can_be_disconnected_without_a_logon() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(disconnect_body());

    let connection = server.client().connect().await.unwrap();
    connection.disconnect().await.unwrap();

    let requests = server.requests().await;
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[1].headers.get("X-RequestType").unwrap(),
        &"Disconnect".to_owned()
    );
}

/// A bearer token goes out as the scheme says, and nothing else changes.
#[tokio::test]
async fn a_bearer_token_is_sent_as_an_authorization_header() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));

    let client = server
        .builder()
        .credentials(Credentials::bearer("eyJhbGciOiJub25lIn0"))
        .build()
        .unwrap();
    client.connect().await.unwrap();

    let requests = server.requests().await;
    assert_eq!(
        requests[0].headers.get("Authorization").unwrap(),
        &"Bearer eyJhbGciOiJub25lIn0".to_owned()
    );
}

/// An endpoint that has already authenticated the caller — a reverse proxy, say — wants no
/// `Authorization` header at all.
#[tokio::test]
async fn no_credentials_means_no_authorization_header() {
    let server = MapiServer::start().await;
    server.reply_ok(Vec::new());

    let client = server
        .builder()
        .credentials(Credentials::None)
        .build()
        .unwrap();
    client.ping().await.unwrap();

    let requests = server.requests().await;
    assert!(requests[0].headers.get("Authorization").is_none());
}

/// A 401 that names no scheme at all still has to read as a sentence rather than trailing off.
#[tokio::test]
async fn a_401_with_no_www_authenticate_still_reads_as_a_sentence() {
    let server = MapiServer::start().await;
    server.reply(ResponseTemplate::new(401));

    let client = server
        .builder()
        .credentials(Credentials::None)
        .build()
        .unwrap();
    let error = client.ping().await.unwrap_err();

    assert!(
        error
            .to_string()
            .contains("sent no credentials, server accepts nothing"),
        "{error}"
    );
}

/// Reading a table that has no rows is not an error, and it still costs exactly one round trip.
#[tokio::test]
async fn an_empty_folder_reads_as_no_rows() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));

    let mut opened = open_folder_response(OPEN_FOLDER_SLOT);
    opened.extend(get_table_response(0x05, 2, 0));
    opened.extend(set_columns_response(2));
    opened.extend(query_rows_response(2, BOOKMARK_END, &[]));
    server.reply_ok(execute_body(&opened, &OPENED));
    server.reply_ok(execute_body(&[], &[TABLE_HANDLE]));

    let client = server.client();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let mut rows = logon
        .well_known(WellKnownFolder::DeletedItems)
        .unwrap()
        .contents()
        .rows();

    assert!(rows.try_next().await.unwrap().is_none());
    assert!(
        rows.try_next().await.unwrap().is_none(),
        "an exhausted read stays exhausted"
    );
    assert_eq!(rows.row_count(), Some(0));
    rows.close().await.unwrap();

    // A read that never started has no handle to release, and closing it is still not an error.
    let rows = logon
        .well_known(WellKnownFolder::DeletedItems)
        .unwrap()
        .contents()
        .rows();
    rows.close().await.unwrap();
    assert_eq!(
        server.requests().await.len(),
        4,
        "a read that never started releases nothing"
    );
}

/// A page size of zero would ask the server for no rows and read that as the end of the table, so
/// it is clamped rather than sent.
#[tokio::test]
async fn a_page_size_of_zero_is_clamped_to_one() {
    let server = MapiServer::start().await;
    server.reply(connect_ok("Alice Example"));
    server.reply_ok(execute_body(&logon_response(0), &[LOGON_HANDLE]));

    let mut opened = open_folder_response(OPEN_FOLDER_SLOT);
    opened.extend(get_table_response(0x05, 2, 1));
    opened.extend(set_columns_response(2));
    opened.extend(query_rows_response(
        2,
        BOOKMARK_END,
        &[contents_row(0x1000, "Only", 0, 0)],
    ));
    server.reply_ok(execute_body(&opened, &OPENED));
    server.reply_ok(execute_body(&[], &[TABLE_HANDLE]));

    let client = server.client();
    let mut logon = client.connect().await.unwrap().logon().await.unwrap();
    let rows = logon
        .well_known(WellKnownFolder::Inbox)
        .unwrap()
        .contents()
        .page_size(0)
        .collect()
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);

    // RopQueryRows: RopId, LogonId, InputHandleIndex, Flags, ForwardRead, then RowCount.
    let sent = server.rops(2).await;
    let query_rows = &sent[sent.len() - 10..];
    assert_eq!(&query_rows[5..7], &1_u16.to_le_bytes());
}
