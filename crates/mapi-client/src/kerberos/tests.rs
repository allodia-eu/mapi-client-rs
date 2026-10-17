//! What a ticket request comes to, against a KDC that answers with errors written by hand. The
//! request that ends in a ticket is the live suite's: it needs a KDC that holds the keys.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::*;

/// A minimal DER element.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else {
        out.extend_from_slice(&[
            0x82,
            u8::try_from(len >> 8).unwrap(),
            u8::try_from(len & 0xFF).unwrap(),
        ]);
    }
    out.extend_from_slice(value);
    out
}

fn int(value: u8) -> Vec<u8> {
    tlv(0x02, &[value])
}

/// A `KRB-ERROR` — [RFC 4120] §5.9.1 — with the fields a reader requires.
fn krb_error(code: u8) -> Vec<u8> {
    let name = tlv(
        0x30,
        &[
            tlv(0xA0, &int(2)),
            tlv(
                0xA1,
                &tlv(
                    0x30,
                    &[tlv(0x1B, b"krbtgt"), tlv(0x1B, b"EXAMPLE.TEST")].concat(),
                ),
            ),
        ]
        .concat(),
    );
    let fields = [
        tlv(0xA0, &int(5)),
        tlv(0xA1, &int(30)),
        tlv(0xA4, &tlv(0x18, b"20270115080000Z")),
        tlv(0xA5, &int(0)),
        tlv(0xA6, &int(code)),
        tlv(0xA9, &tlv(0x1B, b"EXAMPLE.TEST")),
        tlv(0xAA, &name),
    ]
    .concat();
    tlv(0x7E, &tlv(0x30, &fields))
}

/// A KDC that answers every request with `reply`, framed.
async fn kdc(reply: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let reply = reply.clone();
            tokio::spawn(async move {
                let mut prefix = [0u8; 4];
                stream.read_exact(&mut prefix).await.unwrap();
                let mut request = vec![0u8; usize::try_from(u32::from_be_bytes(prefix)).unwrap()];
                stream.read_exact(&mut request).await.unwrap();
                let mut framed = u32::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
                framed.extend_from_slice(&reply);
                stream.write_all(&framed).await.unwrap();
            });
        }
    });
    address
}

async fn ask(identity: &Identity, locator: KdcLocator) -> Acquired {
    Kerberos::new(locator)
        .ticket(identity, "HTTP/mail.example.test", Duration::from_secs(5))
        .await
        .unwrap()
}

fn alice() -> Identity {
    Identity::new("alice@example.test", "hunter2")
}

/// A wrong password, a disabled or locked account and an expired password are reported: NTLM
/// would fail them too, and say less.
#[tokio::test]
async fn a_refusal_of_the_credential_is_reported_rather_than_fallen_back_from() {
    for code in [24, 18, 23] {
        let locator = KdcLocator::new().kdc("EXAMPLE.TEST", kdc(krb_error(code)).await);
        match ask(&alice(), locator).await {
            Acquired::Refused(negotiate_auth::Error::KdcRefused { code: refused, .. }) => {
                assert_eq!(refused, i32::from(code));
            }
            other => panic!("{code}: {other:?}"),
        }
    }
}

/// Anything else that keeps a ticket out of reach leaves NTLM to try, with the reason kept.
#[tokio::test]
async fn anything_else_leaves_ntlm_to_try_with_the_reason() {
    let unknown = KdcLocator::new().kdc("EXAMPLE.TEST", kdc(krb_error(6)).await);
    let Acquired::Unavailable(reason) = ask(&alice(), unknown).await else {
        panic!("unavailable")
    };
    assert!(reason.contains("C_PRINCIPAL_UNKNOWN"), "{reason}");

    let garbage = KdcLocator::new().kdc("EXAMPLE.TEST", kdc(b"not DER".to_vec()).await);
    assert!(matches!(
        ask(&alice(), garbage).await,
        Acquired::Unavailable(_)
    ));

    let nowhere = KdcLocator::new().kdc("ELSEWHERE.TEST", "127.0.0.1:1");
    let Acquired::Unavailable(reason) = ask(&alice(), nowhere).await else {
        panic!("unavailable")
    };
    #[cfg(not(feature = "hickory-dns"))]
    assert!(
        reason.contains("no KDC is known for EXAMPLE.TEST"),
        "{reason}"
    );
    let _ = reason;

    // `DOMAIN\user` names no realm, which is the rule rather than a fault.
    let netbios = Identity::new("EXAMPLE\\alice", "hunter2");
    let Acquired::Unavailable(reason) = ask(&netbios, KdcLocator::new()).await else {
        panic!("unavailable")
    };
    assert!(reason.contains("names no realm"), "{reason}");
}

#[test]
fn a_ticket_is_reused_until_five_minutes_before_it_ends() {
    let now = Duration::new(1_800_000_000, 0);
    assert!(fresh(now + Duration::new(301, 0), now));
    assert!(!fresh(now + Duration::new(300, 0), now));
    assert!(!fresh(now, now));
}

#[test]
fn entropy_is_fresh_every_time() {
    assert_ne!(entropy().unwrap(), entropy().unwrap());
}

#[test]
fn a_record_and_a_locator_are_built_from_their_parts() {
    let record = SrvRecord::new(1, 2, 88, "kdc.example.test");
    assert_eq!((record.priority, record.weight, record.port), (1, 2, 88));
    assert_eq!(record.target, "kdc.example.test");
    let locator = KdcLocator::new().kdc("EXAMPLE.TEST", "kdc.example.test");
    assert!(format!("{locator:?}").contains("kdc.example.test"));
}

/// A ticket-granting ticket already held buys the next service's ticket with one TGS exchange and
/// no password — and a service the KDC does not hold leaves NTLM to try.
#[tokio::test]
async fn a_cached_tgt_buys_the_next_ticket_without_the_password() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let kdc = Arc::new(
        negotiate_auth::testing::TestKdc::new(
            "EXAMPLE.TEST",
            "alice@example.test",
            "hunter2",
            "HTTP/mail.example.test",
            now,
        )
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let answered = Arc::new(AtomicUsize::new(0));
    let (count, server) = (Arc::clone(&answered), Arc::clone(&kdc));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut prefix = [0u8; 4];
            stream.read_exact(&mut prefix).await.unwrap();
            let mut request = vec![0u8; usize::try_from(u32::from_be_bytes(prefix)).unwrap()];
            stream.read_exact(&mut request).await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let reply = server.answer(&request);
            let mut framed = u32::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&reply);
            stream.write_all(&framed).await.unwrap();
        }
    });

    let kerberos = Kerberos::new(KdcLocator::new().kdc("EXAMPLE.TEST", address));
    let timeout = Duration::new(5, 0);
    let first = kerberos
        .ticket(&alice(), "HTTP/mail.example.test", timeout)
        .await
        .unwrap();
    assert!(matches!(first, Acquired::Ticket(_)));
    assert_eq!(answered.load(Ordering::SeqCst), 3);

    // A ticket the server refused is forgotten, and the TGT buys its replacement.
    kerberos.forget("HTTP/mail.example.test");
    let again = kerberos
        .ticket(&alice(), "HTTP/mail.example.test", timeout)
        .await
        .unwrap();
    assert!(matches!(again, Acquired::Ticket(_)));
    assert_eq!(answered.load(Ordering::SeqCst), 4, "one TGS-REQ");

    // And a client that authenticates as someone else starts with none of it.
    let other = kerberos.without_tickets();
    assert!(other.lock().services.is_empty() && other.lock().tgt.is_none());
    assert!(
        Arc::ptr_eq(&other.realms, &kerberos.realms),
        "but the realms"
    );

    let second = kerberos
        .ticket(&alice(), "HTTP/other.example.test", timeout)
        .await
        .unwrap();
    let Acquired::Unavailable(reason) = second else {
        panic!("this KDC holds one service")
    };
    assert!(reason.contains("S_PRINCIPAL_UNKNOWN"), "{reason}");
    assert_eq!(
        answered.load(Ordering::SeqCst),
        5,
        "one TGS-REQ, no AS exchange"
    );
}

/// What is known without asking a KDC: an account that names no realm, and a service whose last
/// request came to nothing a moment ago — for which `Negotiate` goes straight to NTLM.
#[tokio::test]
async fn what_came_to_nothing_is_not_asked_about_again_at_once() {
    let kerberos = Kerberos::new(KdcLocator::new().kdc("EXAMPLE.TEST", kdc(krb_error(6)).await));
    let netbios = Identity::new("EXAMPLE\\alice", "hunter2");
    let reason = kerberos.unavailable(&netbios, "HTTP/mail.example.test");
    assert!(reason.unwrap().contains("names no realm"));
    assert_eq!(
        kerberos.unavailable(&alice(), "HTTP/mail.example.test"),
        None
    );

    let Acquired::Unavailable(reason) = kerberos
        .ticket(&alice(), "HTTP/mail.example.test", Duration::from_secs(5))
        .await
        .unwrap()
    else {
        panic!("unavailable")
    };
    assert_eq!(
        kerberos.unavailable(&alice(), "HTTP/mail.example.test"),
        Some(reason)
    );
    assert_eq!(
        kerberos.unavailable(&alice(), "HTTP/other.example.test"),
        None,
        "another service is still worth asking about"
    );
}

/// A TGT the KDC no longer honours is dropped and the password asked instead, once — rather than
/// kept to its end time while every handshake falls back to NTLM.
#[tokio::test]
async fn a_refused_tgt_is_replaced_from_the_password() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let kdc = Arc::new(
        negotiate_auth::testing::TestKdc::new(
            "EXAMPLE.TEST",
            "alice@example.test",
            "hunter2",
            "HTTP/mail.example.test",
            now,
        )
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let answered = Arc::new(AtomicUsize::new(0));
    let (count, server) = (Arc::clone(&answered), Arc::clone(&kdc));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut prefix = [0u8; 4];
            stream.read_exact(&mut prefix).await.unwrap();
            let mut request = vec![0u8; usize::try_from(u32::from_be_bytes(prefix)).unwrap()];
            stream.read_exact(&mut request).await.unwrap();
            // The fourth request is the TGS-REQ made with the cached TGT: `KRB_AP_ERR_TKT_EXPIRED`.
            let reply = if count.fetch_add(1, Ordering::SeqCst) == 3 {
                krb_error(32)
            } else {
                server.answer(&request)
            };
            let mut framed = u32::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&reply);
            stream.write_all(&framed).await.unwrap();
        }
    });

    let kerberos = Kerberos::new(KdcLocator::new().kdc("EXAMPLE.TEST", address));
    let timeout = Duration::new(5, 0);
    for _ in 0..2 {
        let acquired = kerberos
            .ticket(&alice(), "HTTP/mail.example.test", timeout)
            .await
            .unwrap();
        assert!(matches!(acquired, Acquired::Ticket(_)), "{acquired:?}");
        kerberos.forget("HTTP/mail.example.test");
    }
    assert_eq!(
        answered.load(Ordering::SeqCst),
        7,
        "AS, AS, TGS; the refused TGS; AS, AS, TGS"
    );
}

/// Connections authenticating at once ask the KDCs once: the rest wait for that answer, and find
/// the ticket in the cache.
#[tokio::test]
async fn connections_that_want_a_ticket_at_once_ask_for_it_once() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let kdc = Arc::new(
        negotiate_auth::testing::TestKdc::new(
            "EXAMPLE.TEST",
            "alice@example.test",
            "hunter2",
            "HTTP/mail.example.test",
            now,
        )
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let answered = Arc::new(AtomicUsize::new(0));
    let (count, server) = (Arc::clone(&answered), Arc::clone(&kdc));
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (count, server) = (Arc::clone(&count), Arc::clone(&server));
            tokio::spawn(async move {
                let mut prefix = [0u8; 4];
                stream.read_exact(&mut prefix).await.unwrap();
                let mut request = vec![0u8; usize::try_from(u32::from_be_bytes(prefix)).unwrap()];
                stream.read_exact(&mut request).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let reply = server.answer(&request);
                let mut framed = u32::try_from(reply.len()).unwrap().to_be_bytes().to_vec();
                framed.extend_from_slice(&reply);
                stream.write_all(&framed).await.unwrap();
            });
        }
    });

    let kerberos = Kerberos::new(KdcLocator::new().kdc("EXAMPLE.TEST", address));
    let alice = alice();
    let ask = || kerberos.ticket(&alice, "HTTP/mail.example.test", Duration::new(5, 0));
    let (first, second, third) = tokio::join!(ask(), ask(), ask());
    for acquired in [first, second, third] {
        assert!(matches!(acquired, Ok(Acquired::Ticket(_))), "{acquired:?}");
    }
    assert_eq!(answered.load(Ordering::SeqCst), 3, "AS, AS, TGS: once");
}

/// No two messages carry the same time, however close together they are built — on one thread or
/// on several.
#[test]
fn no_two_messages_carry_the_same_time() {
    let mut stamps: Vec<Duration> = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| (0..1000).map(|_| stamp()).collect::<Vec<_>>()))
            .collect();
        threads
            .into_iter()
            .flat_map(|thread| {
                let stamps = thread.join().unwrap();
                assert!(stamps.windows(2).all(|pair| pair[0] < pair[1]));
                stamps
            })
            .collect()
    });
    stamps.sort_unstable();
    stamps.dedup();
    assert_eq!(stamps.len(), 4000);
    let drift = stamps.last().unwrap().saturating_sub(now());
    assert!(
        drift < Duration::from_secs(1),
        "ahead of the clock by {drift:?}"
    );
}

/// A refusal of the TGT itself is told apart from one of the credential, and from the rest: it is
/// the one the password may yet get past.
#[test]
fn a_refused_tgt_is_told_apart() {
    let refused = |code| negotiate_auth::Error::KdcRefused {
        realm: "EXAMPLE.TEST".to_owned(),
        code,
        status: None,
    };
    for code in [20, 32, 41] {
        assert!(about_the_tgt(&refused(code)), "{code}");
        assert!(!about_the_credential(&refused(code)), "{code}");
    }
    assert!(!about_the_tgt(&refused(24)));
    assert!(!about_the_tgt(&refused(7)));
}
