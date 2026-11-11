//! Handles given back when the object holding them is dropped, against the server that counts them.

use mapi_client::WellKnownFolder;

/// More tables than one Session Context may hold open at once.
///
/// Exchange Server SE `15.02.2562.056` refused the 501st object one context held with
/// `ecMaxObjsExceeded`; a session reading this many tables and dropping each part way would have
/// stopped being able to open anything long before the end, if the dropped tables stayed open.
const TABLES: usize = 600;

/// Every table is read a page into and dropped — never closed — and each one's release rides along
/// with the request that opens the next, so the context never holds more than one.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn dropping_tables_part_way_never_runs_a_session_out_of_objects() {
    let mut logon = crate::client()
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");

    for read in 0..TABLES {
        let mut rows = logon
            .well_known(WellKnownFolder::Inbox)
            .expect("the Inbox")
            .contents()
            .page_size(1)
            .rows();
        rows.try_next()
            .await
            .unwrap_or_else(|error| panic!("table {read}, opened after {read} dropped: {error}"));
    }
    println!("{TABLES} tables opened and dropped part way in one Session Context");

    logon.disconnect().await.expect("Disconnect");
}
