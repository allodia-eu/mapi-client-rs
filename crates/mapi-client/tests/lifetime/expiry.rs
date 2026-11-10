//! How long a Session Context lasts, as the server reports it, and keeping one alive.

use core::time::Duration;
use std::time::Instant;

/// The lifetime moves once the logon has run — measured on Exchange Server SE `15.02.2562.056` as
/// five minutes after `Connect` and fifteen after `RopLogon` — and a `PING` carrying the session's
/// cookies restarts it, which only a response carrying `X-ExpirationInfo` shows.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_ping_with_the_sessions_cookies_restarts_its_lifetime() {
    let before = Instant::now();
    let connection = crate::client().connect().await.expect("Connect");
    let connected = connection.expires_at().expect("the Connect response says");
    println!("after Connect: {:?} left", connected.duration_since(before));

    let mut logon = connection.logon().await.expect("RopLogon");
    let logged_on = logon.expires_at().expect("the logon response says");
    let lifetime = logged_on.duration_since(before);
    println!("after RopLogon: {lifetime:?} left");
    assert!(
        logged_on >= connected,
        "a later response never shortens what is left: {connected:?} then {logged_on:?}"
    );
    assert!(
        lifetime >= Duration::from_mins(1),
        "an idle lifetime under a minute would leave no room to keep it alive: {lifetime:?}"
    );

    tokio::time::sleep(Duration::from_secs(2)).await;
    let refreshed = logon.keep_alive().await.expect("a PING that refreshed");
    assert!(
        refreshed > logged_on,
        "the PING moved the deadline: {logged_on:?} then {refreshed:?}"
    );
    assert_eq!(logon.expires_at(), Some(refreshed));
    println!(
        "a PING two seconds later moved the deadline by {:?}",
        refreshed.duration_since(logged_on)
    );

    logon.disconnect().await.expect("Disconnect");
}
