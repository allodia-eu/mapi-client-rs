//! A request given up on part way, against a server that may still be running it.
//!
//! Part of `tests/live.rs`, ignored for the same reason: CI never sees an Exchange Server. The fake
//! server in `tests/errors.rs` proves the client side — that a dropped future leaves the connection
//! poisoned rather than wedged. What only a real server can say is what it makes of the
//! `Disconnect` that follows, because [MS-OXCMAPIHTTP] §3.2.5.1 has it "fail every subsequent
//! request" in a Session Context once it sees two at a time, and the request the client gave up on
//! may still be running there.

use core::time::Duration;

use mapi_client::{Error, WellKnownFolder};

/// Deadlines from "before the request leaves" to "while the server is answering", so that between
/// them every point at which a caller can give up is hit at least once.
const DEADLINES_MS: [u64; 9] = [0, 1, 2, 3, 5, 8, 13, 21, 34];

/// Every deadline leaves a connection that disconnects. When the deadline fired, the connection
/// first refuses further work, naming the abandonment.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_request_given_up_on_still_lets_the_connection_disconnect() {
    let client = super::client();
    let mut abandoned = 0_usize;

    for deadline in DEADLINES_MS {
        let mut logon = client
            .connect()
            .await
            .expect("Connect")
            .logon()
            .await
            .expect("RopLogon");

        let gave_up = {
            let mut rows = logon
                .well_known(WellKnownFolder::Inbox)
                .expect("the Inbox")
                .contents()
                .rows();
            let read = tokio::time::timeout(Duration::from_millis(deadline), rows.try_next()).await;
            if read.is_err() {
                let refused = rows.try_next().await.expect_err("a poisoned connection");
                assert!(
                    matches!(&refused, Error::Poisoned { cause } if cause.contains("abandoned")),
                    "{refused:?}"
                );
            }
            read.is_err()
        };

        logon.disconnect().await.unwrap_or_else(|error| {
            panic!("the disconnect after a {deadline} ms deadline failed: {error}")
        });
        println!(
            "{deadline:>2} ms: {}, then disconnected",
            if gave_up { "abandoned" } else { "completed" }
        );
        abandoned += usize::from(gave_up);
    }

    assert!(
        abandoned > 0,
        "no deadline was short enough to abandon a request, so nothing was tested"
    );
}
