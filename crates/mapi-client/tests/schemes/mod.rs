//! Every authentication scheme this client speaks, against the mailbox all of them should reach.
//!
//! Part of `tests/live.rs`, ignored for the same reason: CI never sees an Exchange Server. Its own
//! file because that one is at the workspace's 500-line limit, and because this is the only suite
//! that builds its own clients rather than using `builder()` — which it has to, since the whole
//! question is what happens when the credentials differ.

use mapi_client::{Credentials, LegacyDn, MapiClient};

use super::{LIVE_TIMEOUT, required};

/// A client for one set of credentials, with everything else exactly as the rest of the suite has
/// it.
fn for_credentials(credentials: Credentials) -> MapiClient {
    MapiClient::builder()
        .endpoint(required("MAPI_LIVE_ENDPOINT"))
        .user_dn(LegacyDn::new(required("MAPI_LIVE_USER_DN")).expect("a usable legacyExchangeDN"))
        .credentials(credentials)
        .timeout(LIVE_TIMEOUT)
        .build()
        .expect("a client")
}

/// Credentials the server will not accept must be reported as a refusal naming the schemes it
/// does accept — the diagnosis that distinguishes a wrong password from an unsupported scheme.
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn a_wrong_password_is_reported_as_a_refusal_not_a_mystery() {
    let error = for_credentials(Credentials::basic(
        required("MAPI_LIVE_USERNAME"),
        "definitely-not-the-password",
    ))
    .ping()
    .await
    .expect_err("a wrong password is refused");

    println!("{error}");
    assert!(
        matches!(error, mapi_client::Error::Unauthorized { .. }),
        "{error:?}"
    );
}

/// Every scheme the server offers reaches the same mailbox, and refuses the same wrong password.
///
/// This is the test that says NTLM and Negotiate work, rather than that they compile. Both are
/// multi-leg handshakes bound to a connection, so what it proves is not one header but the whole
/// arrangement: the pinned pool, the serialised requests, the channel binding computed from the
/// server's own certificate, and the `Persistent-Auth` reuse that follows.
///
/// Measured against Exchange Server SE `15.02.2562.045`, whose MAPI virtual directory reports
/// `IISAuthenticationMethods {Basic, Ntlm, OAuth, Negotiate}` and
/// `ExtendedProtectionTokenChecking Require`. That last setting is why the channel binding is not
/// optional: the same `AUTHENTICATE_MESSAGE` without an `MsvAvChannelBindings` pair is answered
/// with a 401 restarting the handshake, which is byte for byte what a wrong password looks like.
///
/// Setting `MAPI_LIVE_AUTH` runs the *whole* live suite over one scheme, which is the other half of
/// this: here three schemes are compared against each other, there each one is put through
/// everything the client can do.
#[cfg(feature = "ntlm")]
#[tokio::test]
#[ignore = "needs a live Exchange Server; run scripts\\Test-Live.ps1"]
async fn ntlm_and_negotiate_reach_the_same_mailbox_as_basic() {
    let username = required("MAPI_LIVE_USERNAME");
    let password = required("MAPI_LIVE_PASSWORD");

    let mut owners = Vec::new();
    for (scheme, credentials) in [
        ("Basic", Credentials::basic(&username, &password)),
        ("NTLM", Credentials::ntlm(&username, &password)),
        ("Negotiate", Credentials::negotiate(&username, &password)),
    ] {
        let client = for_credentials(credentials);

        // `ping` is one request; `connect` then `logon` are two more over the same connection,
        // which is what exercises the reuse rather than only the handshake.
        client.ping().await.expect("PING");
        let logon = client
            .connect()
            .await
            .expect("Connect")
            .logon()
            .await
            .expect("RopLogon");
        let owner = logon.mailbox().mailbox_guid().to_string();
        println!("{scheme}: logged on to {owner}");
        logon.disconnect().await.expect("Disconnect");
        owners.push((scheme, owner));
    }

    let (_, first) = owners.first().expect("three schemes were tried");
    for (scheme, owner) in &owners {
        assert_eq!(owner, first, "{scheme} reached a different mailbox");
    }

    // And each refuses a wrong password rather than succeeding differently. For the two handshake
    // schemes the refusal arrives as the server restarting the handshake, which this crate has to
    // report as a refused credential and not as a malformed challenge.
    for (scheme, credentials) in [
        ("Basic", Credentials::basic(&username, "not-the-password")),
        ("NTLM", Credentials::ntlm(&username, "not-the-password")),
        (
            "Negotiate",
            Credentials::negotiate(&username, "not-the-password"),
        ),
    ] {
        let error = for_credentials(credentials)
            .ping()
            .await
            .expect_err("a wrong password is refused");
        println!("{scheme}: {error}");
        assert!(
            matches!(error, mapi_client::Error::Unauthorized { .. }),
            "{scheme}: {error:?}"
        );
    }
}
