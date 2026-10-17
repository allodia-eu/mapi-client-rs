//! Which lane a request is lent, and whose turn a handshake is.

use core::time::Duration;

use super::*;

fn pool(size: usize) -> Pool {
    let settings = HttpSettings {
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        root_certificates: Arc::from([]),
        accept_invalid_certificates: false,
        connection_oriented: true,
        connections: NonZeroUsize::new(size).unwrap(),
    };
    Pool::new(settings.client().unwrap(), settings)
}

const MAIL: &str = "https://mail.example.test";
const ARCHIVE: &str = "https://archive.example.test";

/// A moment to show that something is waiting rather than done.
const MOMENT: Duration = Duration::from_millis(50);

/// The URL of a request to `origin`.
fn url(origin: &str) -> String {
    format!("{origin}/mapi/emsmdb/")
}

fn refusal() -> Result<()> {
    Err(Error::Unauthorized {
        url: url(MAIL),
        offered: vec!["NTLM".to_owned()],
        sent: "NTLM credentials",
    })
}

#[tokio::test]
async fn a_lane_authenticated_to_the_origin_is_lent_before_any_other() {
    let pool = pool(2);
    let mut first = pool.lease(MAIL.to_owned()).await.unwrap();
    assert!(!first.is_authenticated(), "a fresh lane is not");
    first.set_authenticated(true);
    drop(first);

    // The one idle lane is lent to another origin, to which it is not authenticated; a second
    // request to the first origin then gets a lane of its own.
    let archive = pool.lease(ARCHIVE.to_owned()).await.unwrap();
    assert!(!archive.is_authenticated());
    let mail = pool.lease(MAIL.to_owned()).await.unwrap();
    assert!(!mail.is_authenticated());
    drop(archive);
    drop(mail);

    // Two idle, the authenticated one returned first: it is still the one lent.
    let mut mail = pool.lease(MAIL.to_owned()).await.unwrap();
    assert!(mail.is_authenticated());
    mail.set_authenticated(false);
    assert!(!mail.is_authenticated());
}

#[tokio::test]
async fn a_request_waits_rather_than_open_a_lane_past_the_limit() {
    let pool = pool(1);
    let held = pool.lease(MAIL.to_owned()).await.unwrap();
    let mut waiting = core::pin::pin!(pool.lease(MAIL.to_owned()));
    assert!(tokio::time::timeout(MOMENT, &mut waiting).await.is_err());
    drop(held);
    assert!(waiting.await.is_ok());
}

#[tokio::test]
async fn a_lane_is_traded_for_an_idle_one_already_authenticated() {
    let pool = pool(2);
    let mut warm = pool.lease(MAIL.to_owned()).await.unwrap();
    let mut cold = pool.lease(MAIL.to_owned()).await.unwrap();
    warm.set_authenticated(true);
    cold.trade_for_warm();
    assert!(!cold.is_authenticated(), "nothing warm is idle yet");
    drop(warm);
    cold.trade_for_warm();
    assert!(cold.is_authenticated());

    // A lane authenticated to another origin is not warm for this one.
    let mut archive = pool.lease(ARCHIVE.to_owned()).await.unwrap();
    drop(cold);
    archive.trade_for_warm();
    assert!(!archive.is_authenticated());
}

#[tokio::test]
async fn handshakes_take_turns_until_one_has_worked() {
    let pool = pool(4);
    let lease = pool.lease(MAIL.to_owned()).await.unwrap();
    let mail = url(MAIL);
    let first = pool.turn(&lease, &mail).await.unwrap();
    let mut second = core::pin::pin!(pool.turn(&lease, &mail));
    assert!(tokio::time::timeout(MOMENT, &mut second).await.is_err());

    // A failure that is not a refusal proves nothing: the next in line tries for itself.
    first.settle(
        false,
        &Err::<(), _>(Error::Timeout {
            url: mail.clone(),
            after: MOMENT,
        }),
    );
    let second = second.await.unwrap();
    let mut third = core::pin::pin!(pool.turn(&lease, &mail));
    assert!(tokio::time::timeout(MOMENT, &mut third).await.is_err());

    second.settle(true, &Ok(()));
    let third = third.await.unwrap();
    // Once one has worked, nobody waits for anybody.
    let fourth = tokio::time::timeout(MOMENT, pool.turn(&lease, &mail)).await;
    assert!(fourth.unwrap().is_ok());
    drop(third);
}

/// A waiter is refused with the first, in an error naming its own request's URL — for a mailbox on
/// the same server, that is another endpoint than the one the refusal came from.
#[tokio::test]
async fn a_refusal_refuses_whoever_was_waiting_for_it() {
    let pool = pool(4);
    let lease = pool.lease(MAIL.to_owned()).await.unwrap();
    let mail = url(MAIL);
    let first = pool.turn(&lease, &mail).await.unwrap();
    let theirs = format!("{MAIL}/mapi/emsmdb/?MailboxId=archive");
    let mut waiting = core::pin::pin!(pool.turn(&lease, &theirs));
    assert!(tokio::time::timeout(MOMENT, &mut waiting).await.is_err());

    first.settle(false, &refusal());
    let Err(Error::Unauthorized {
        url: named,
        offered,
        sent,
    }) = waiting.await
    else {
        panic!("refused with the first");
    };
    assert_eq!(
        (named, offered, sent),
        (theirs.clone(), vec!["NTLM".to_owned()], "NTLM credentials")
    );

    // A request that arrives afterwards tries again, on its own.
    let again = pool.turn(&lease, &mail).await.unwrap();
    let mut behind = core::pin::pin!(pool.turn(&lease, &mail));
    assert!(tokio::time::timeout(MOMENT, &mut behind).await.is_err());
    again.settle(true, &Ok(()));
    assert!(behind.await.is_ok(), "the handshake worked after all");
}

/// What one server refused says nothing certain about another: its waiters take their own turns.
#[tokio::test]
async fn each_origin_takes_its_own_turns() {
    let pool = pool(4);
    let mail = pool.lease(MAIL.to_owned()).await.unwrap();
    let archive = pool.lease(ARCHIVE.to_owned()).await.unwrap();
    let (mail_url, archive_url) = (url(MAIL), url(ARCHIVE));
    let first = pool.turn(&mail, &mail_url).await.unwrap();
    let elsewhere = tokio::time::timeout(MOMENT, pool.turn(&archive, &archive_url)).await;
    let elsewhere = elsewhere
        .expect("not waiting on another server's turn")
        .unwrap();

    let mut waiting = core::pin::pin!(pool.turn(&archive, &archive_url));
    assert!(tokio::time::timeout(MOMENT, &mut waiting).await.is_err());
    first.settle(false, &refusal());
    assert!(
        tokio::time::timeout(MOMENT, &mut waiting).await.is_err(),
        "still waiting on its own server's turn, not refused with the other's"
    );
    elsewhere.settle(true, &Ok(()));
    assert!(waiting.await.is_ok());
}

#[tokio::test]
async fn a_refusal_after_one_has_worked_makes_them_take_turns_again() {
    let pool = pool(4);
    let lease = pool.lease(MAIL.to_owned()).await.unwrap();
    pool.turn(&lease, &url(MAIL))
        .await
        .unwrap()
        .settle(true, &Ok(()));
    pool.turn(&lease, &url(MAIL))
        .await
        .unwrap()
        .settle(false, &refusal());
    let _held = pool.turn(&lease, &url(MAIL)).await.unwrap();
    assert!(
        tokio::time::timeout(MOMENT, pool.turn(&lease, &url(MAIL)))
            .await
            .is_err()
    );
}

/// So does a connection believed authenticated being refused: the password may have changed, and
/// every lane sending the old one at once would cost a lockout count each.
#[tokio::test]
async fn a_doubted_connection_makes_them_take_turns_again() {
    let pool = pool(4);
    let lease = pool.lease(MAIL.to_owned()).await.unwrap();
    pool.turn(&lease, &url(MAIL))
        .await
        .unwrap()
        .settle(true, &Ok(()));
    lease.doubt();
    let _held = pool.turn(&lease, &url(MAIL)).await.unwrap();
    assert!(
        tokio::time::timeout(MOMENT, pool.turn(&lease, &url(MAIL)))
            .await
            .is_err()
    );
}
