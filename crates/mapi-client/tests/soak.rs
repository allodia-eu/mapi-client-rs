//! One logon kept for hours against a real Exchange Server: busy, idle and kept alive, idle past
//! its lifetime and recovered.
//!
//! **Ignored, and not part of `tests/live.rs`**, because it takes as long as it is told to and the
//! live suite is meant to be run whole. `scripts\Test-Soak.ps1` runs it, pointed at a mailbox no
//! other suite counts the contents of, and compares the server's own count of Session Contexts
//! before and after. Everything it does is a read.
//!
//! What it proves, cycle after cycle until its time is up:
//!
//! * **Nothing leaks within a Session Context.** Each busy stretch runs enough iterations in one
//!   context that leaking a single server object per iteration would have the server refuse the
//!   501st — Exchange Server SE `15.02.2562.056` holds 500 per context — and every iteration takes
//!   each path that holds a handle across round trips, dropping and closing in turn.
//! * **A context kept alive survives idling past most of its lifetime** — twice, by `PING`, with no
//!   reconnect.
//! * **A context idled past its lifetime is re-established on the next request**, with nothing lost
//!   but the time a reconnect takes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    reason = "a soak is meant to be read by the person running it"
)]

use core::time::Duration;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use mapi_client::mapi_proto::fasttransfer::SyncEvent;
use mapi_client::{
    ContentsDownload, Credentials, Exchange, LegacyDn, Logon, MapiClient, Observer, PropertyTag,
    WellKnownFolder,
};

/// What the server said in the last few exchanges, for the report when something goes wrong:
/// request type, `X-ResponseCode` and `X-ExpirationInfo`.
#[derive(Debug, Default)]
struct Recent(Mutex<Vec<String>>);

impl Observer for Recent {
    fn observe(&self, exchange: &Exchange<'_>) {
        let headers = exchange.response_headers();
        let line = format!(
            "{} -> {} (expiration {})",
            exchange.request_type(),
            headers.get("X-ResponseCode").unwrap_or("none"),
            headers.get("X-ExpirationInfo").unwrap_or("none"),
        );
        if let Ok(mut recent) = self.0.lock() {
            recent.push(line);
            let excess = recent.len().saturating_sub(6);
            recent.drain(..excess);
        }
    }
}

impl Recent {
    fn take(&self) -> String {
        self.0
            .lock()
            .map(|mut recent| recent.drain(..).collect::<Vec<_>>().join("; "))
            .unwrap_or_default()
    }
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set. Run scripts\\Test-Soak.ps1."))
}

fn setting(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |value| value.parse().expect(name))
}

/// Idles for `length`, and refuses to go on if the machine was suspended meanwhile.
///
/// The server times a Session Context out on wall-clock time, and this sleeps on the monotonic
/// clock, which stops while the machine is suspended. The first overnight run was voided that way:
/// the lab was paused twice, its clock jumped nine hours, and a context kept alive by a PING every
/// twelve monotonic minutes was found gone — rightly, by the server's clock. A run across a
/// suspend says nothing about either kind of idle, so it stops and says why.
async fn idle(length: Duration) {
    let wall = SystemTime::now();
    tokio::time::sleep(length).await;
    let passed = wall.elapsed().unwrap_or_default();
    assert!(
        passed < length + Duration::from_mins(1),
        "the clock moved {passed:?} during a {length:?} idle: the machine was suspended, so this \
         run cannot judge a Session Context's lifetime. Run it again on a machine that stays up."
    );
}

/// The credentials `MAPI_LIVE_AUTH` asks for — basic, ntlm or negotiate, defaulting to Basic — as
/// the live suite reads them.
///
/// The scheme is the soak's question as much as the session is. Basic has nothing in it that
/// expires inside a day; `Negotiate` authenticates every new connection with a Kerberos service
/// ticket that does, and a session that lasts past the ticket's lifetime has to be seen to fetch a
/// new one rather than fall back to NTLM or fail.
fn credentials() -> Credentials {
    let (username, password) = (
        required("MAPI_LIVE_USERNAME"),
        required("MAPI_LIVE_PASSWORD"),
    );
    match std::env::var("MAPI_LIVE_AUTH").unwrap_or_default().as_str() {
        #[cfg(feature = "ntlm")]
        "ntlm" => Credentials::ntlm(&username, password),
        #[cfg(feature = "ntlm")]
        "negotiate" => Credentials::negotiate(&username, password),
        "" | "basic" => Credentials::basic(username, password),
        other => panic!("MAPI_LIVE_AUTH={other} is not basic, ntlm or negotiate"),
    }
}

/// How the client last authenticated, for the trace — and a refusal to go on if `Negotiate` was
/// asked for and Kerberos was not what it got, because then nothing about tickets is being tested.
fn authenticated(client: &MapiClient) -> String {
    #[cfg(feature = "ntlm")]
    if let Some(how) = client.authentication() {
        let negotiating = std::env::var("MAPI_LIVE_AUTH").is_ok_and(|auth| auth == "negotiate");
        assert!(
            !negotiating || how.kerberos_unavailable.is_none(),
            "Negotiate fell back from Kerberos: {:?}",
            how.kerberos_unavailable
        );
        return format!("authenticated by {:?}", how.mechanism);
    }
    let _ = client;
    "authenticated by Basic".to_owned()
}

/// Says what happened, and when, relative to the start.
fn note(started: Instant, what: &str) {
    println!(
        "[{:>7.1} min] {what}",
        started.elapsed().as_secs_f64() / 60.0
    );
}

/// One iteration: every path that holds a handle across round trips, dropped part way and closed.
async fn iterate(logon: &mut Logon) -> mapi_client::Result<()> {
    let inbox = logon.folder_id(WellKnownFolder::Inbox)?;
    let subtree = logon.folder_id(WellKnownFolder::IpmSubtree)?;

    // A table read a page into and dropped, one read to its end and dropped, and one closed.
    {
        let mut rows = logon.folder(inbox).contents().page_size(1).rows();
        let _ = rows.try_next().await?;
    }
    {
        let mut rows = logon.folder(subtree).subfolders().rows();
        while rows.try_next().await?.is_some() {}
    }
    let messages = logon.folder(inbox).contents().collect().await?;

    // A download dropped after its first event, and one run to its end and closed.
    {
        let mut download = logon.download(inbox, ContentsDownload::new(), None)?;
        let _ = download.try_next().await?;
    }
    let mut download = logon.download(inbox, ContentsDownload::new(), None)?;
    while let Some(event) = download.try_next().await? {
        if matches!(event, SyncEvent::State(_)) {
            break;
        }
    }
    download.close().await?;

    // A stream, where there is a message to read one from.
    if let Some(id) = messages
        .first()
        .and_then(mapi_client::PropertyRow::message_id)
    {
        let _ = logon
            .message(inbox, id)
            .stream(PropertyTag::BODY)
            .read()
            .await;
    }
    let _ = logon.folder_stamps().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "takes as long as it is told to; run scripts\\Test-Soak.ps1"]
async fn one_logon_lasts_and_leaks_nothing() {
    let minutes = setting("MAPI_SOAK_MINUTES", 60);
    let iterations = setting("MAPI_SOAK_ITERATIONS", 600);
    let kept_idle = Duration::from_secs(setting("MAPI_SOAK_KEPT_IDLE_SECS", 720));
    let expired_idle = Duration::from_secs(setting("MAPI_SOAK_EXPIRED_IDLE_SECS", 960));
    let deadline = Duration::from_secs(minutes * 60);

    let recent = Arc::new(Recent::default());
    let client = MapiClient::builder()
        .observer(Arc::clone(&recent))
        .endpoint(required("MAPI_LIVE_ENDPOINT"))
        .user_dn(LegacyDn::new(required("MAPI_LIVE_USER_DN")).unwrap())
        .credentials(credentials())
        .build()
        .unwrap();
    let started = Instant::now();
    let mut logon = client
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    note(started, "logged on");

    let (mut cycles, mut total) = (0_u64, 0_u64);
    while cycles == 0 || started.elapsed() < deadline {
        cycles += 1;
        let context = logon.reconnects();
        for iteration in 0..iterations {
            iterate(&mut logon).await.unwrap_or_else(|error| {
                panic!("cycle {cycles}, iteration {iteration} of one Session Context: {error}")
            });
        }
        total += iterations;
        assert_eq!(
            logon.reconnects(),
            context,
            "the busy stretch kept its context"
        );
        note(
            started,
            &format!(
                "cycle {cycles}: {iterations} iterations in one Session Context; {}",
                authenticated(&client)
            ),
        );
        let _ = recent.take();

        // Idle for most of the lifetime, twice, kept alive by a PING each time.
        for _ in 0..2 {
            idle(kept_idle).await;
            let left = logon
                .keep_alive()
                .await
                .expect("a PING that refreshed")
                .duration_since(Instant::now());
            note(
                started,
                &format!(
                    "kept alive after {kept_idle:?} idle; {left:?} left; {} reconnects; {}; {}",
                    logon.reconnects(),
                    recent.take(),
                    authenticated(&client)
                ),
            );
        }
        assert_eq!(logon.reconnects(), context, "kept alive, not replaced");

        // Idle past the lifetime: the next request finds the context gone and replaces it.
        idle(expired_idle).await;
        iterate(&mut logon)
            .await
            .expect("the first request after the context expired");
        assert_eq!(
            logon.reconnects(),
            context + 1,
            "the expired context was re-established once"
        );
        note(
            started,
            &format!(
                "idle {expired_idle:?}: the context expired and was re-established; {}; {}",
                recent.take(),
                authenticated(&client)
            ),
        );
    }

    let reconnects = logon.reconnects();
    logon.disconnect().await.expect("Disconnect");
    note(
        started,
        &format!("done: {cycles} cycles, {total} iterations, {reconnects} reconnects, no error"),
    );
}
