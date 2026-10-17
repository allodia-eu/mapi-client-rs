//! Finding KDCs and talking to one, against resolvers and listeners made up for the purpose.

use std::sync::Arc;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::*;
use crate::kerberos::{SrvLookup, SrvResolver};

/// A resolver that answers every name with the same records, or the same failure.
#[derive(Debug)]
struct Fixed(Result<Vec<SrvRecord>, &'static str>);

impl SrvResolver for Fixed {
    fn resolve<'a>(&'a self, name: &'a str) -> SrvLookup<'a> {
        assert!(name.starts_with("_kerberos._tcp."), "{name}");
        let answer = self.0.clone().map_err(std::io::Error::other);
        Box::pin(async move { answer })
    }
}

fn record(priority: u16, weight: u16, target: &str) -> SrvRecord {
    SrvRecord::new(priority, weight, 88, target)
}

/// A listener that answers one request with `reply` as written — prefix and all — and hands back
/// what it was sent.
async fn kdc(reply: Vec<u8>) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).await.unwrap();
        let mut request = vec![0u8; usize::try_from(u32::from_be_bytes(prefix)).unwrap()];
        stream.read_exact(&mut request).await.unwrap();
        stream.write_all(&reply).await.unwrap();
        request
    });
    (address, task)
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// [RFC 2782]: priority first, zero weights first within one, then by the weighted draw — here
/// with the draw made by hand, so that each branch is the one under test.
#[test]
fn records_are_ordered_by_priority_then_weight() {
    let records = vec![
        record(10, 0, "c"),
        record(0, 60, "a"),
        record(0, 40, "b"),
        record(0, 0, "zero"),
    ];
    // Sum 100 at priority 0: a draw of 0 takes the zero-weight record; 50 lands in the 60 of `a`
    // — which sorts first after the zero — and 100 in what is left.
    let mut draws = [0u32, 50, 100, 7].into_iter();
    let ordered: Vec<String> = order(records.clone(), || draws.next().unwrap())
        .into_iter()
        .map(|record| record.target)
        .collect();
    assert_eq!(ordered, ["zero", "a", "b", "c"]);

    // A draw past the sum still picks something; nothing is ever lost.
    assert_eq!(order(records, || u32::MAX).len(), 4);
    assert!(order(Vec::new(), || 0).is_empty());
}

#[test]
fn a_named_kdc_gets_port_88_unless_it_has_one() {
    assert_eq!(with_port("kdc.example.test"), "kdc.example.test:88");
    assert_eq!(with_port("kdc.example.test:750"), "kdc.example.test:750");
    assert_eq!(with_port("10.0.0.1"), "10.0.0.1:88");
    assert_eq!(with_port("[2001:db8::1]:88"), "[2001:db8::1]:88");
    assert_eq!(with_port("[2001:db8::1]"), "[2001:db8::1]:88");
    assert_eq!(with_port("2001:db8::1"), "[2001:db8::1]:88");
    assert_eq!(with_port("::1"), "[::1]:88");
    assert_eq!(with_port("kdc:notaport"), "kdc:notaport:88");
}

#[tokio::test]
async fn named_kdcs_come_first_and_a_resolver_serves_the_rest() {
    let locator = KdcLocator::new()
        .kdc("example.test", "kdc1.example.test")
        .kdc("EXAMPLE.TEST", "kdc2.example.test:750")
        .resolver(Arc::new(Fixed(Ok(vec![
            record(0, 0, "dc.child.example.test."),
            record(1, 0, "."),
        ]))));
    assert_eq!(
        addresses(&locator, "EXAMPLE.TEST").await.unwrap(),
        ["kdc1.example.test:88", "kdc2.example.test:750"]
    );
    assert_eq!(
        addresses(&locator, "CHILD.EXAMPLE.TEST").await.unwrap(),
        ["dc.child.example.test:88"],
        "the trailing dot is dropped, and `.` is no KDC at all"
    );
}

#[tokio::test]
async fn a_realm_with_no_kdc_says_why() {
    let nothing = KdcLocator::new().resolver(Arc::new(Fixed(Ok(vec![record(0, 0, ".")]))));
    assert!(
        addresses(&nothing, "EXAMPLE.TEST")
            .await
            .unwrap_err()
            .contains("names no KDC")
    );

    let failing = KdcLocator::new().resolver(Arc::new(Fixed(Err("SERVFAIL"))));
    let error = addresses(&failing, "EXAMPLE.TEST").await.unwrap_err();
    assert!(
        error.contains("_kerberos._tcp.EXAMPLE.TEST") && error.contains("SERVFAIL"),
        "{error}"
    );

    #[cfg(not(feature = "hickory-dns"))]
    assert!(
        addresses(&KdcLocator::new(), "EXAMPLE.TEST")
            .await
            .unwrap_err()
            .contains("KdcLocator::kdc")
    );
}

/// [RFC 4120] §7.2.2's framing in both directions, and the replies that are no reply.
#[tokio::test]
async fn a_message_is_framed_and_its_reply_unframed() {
    let (address, sent) = kdc(framed(b"the reply")).await;
    let reply = exchange(&address, b"the request", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(reply, b"the reply");
    assert_eq!(sent.await.unwrap(), b"the request");

    for bad in [vec![0, 0, 0, 0], 0x0020_0000u32.to_be_bytes().to_vec()] {
        let (address, _) = kdc(bad).await;
        let error = exchange(&address, b"x", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("which is no reply"), "{error}");
    }

    // A KDC that never answers is given up on.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent = listener.local_addr().unwrap().to_string();
    let error = exchange(&silent, b"x", Duration::from_millis(200))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    drop(listener);
}

/// [MS-KILE] §3.2.6: a KDC that does not answer is passed over for the next — and next time the
/// one that answered is tried first, so the dead one is not waited for again.
#[tokio::test]
async fn the_next_kdc_is_tried_when_one_does_not_answer() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap().to_string();
    drop(closed);
    let (alive, _) = kdc(framed(b"answered")).await;

    let locator = KdcLocator::new()
        .kdc("EXAMPLE.TEST", dead.clone())
        .kdc("EXAMPLE.TEST", alive.clone());
    let message = message_for("EXAMPLE.TEST");
    let realms = Realms::default();
    let reply = send(&locator, &realms, &message, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(reply, b"answered");
    assert_eq!(
        realms.known("EXAMPLE.TEST", Instant::now()),
        Some(Ok(vec![alive, dead]))
    );
}

/// A realm none of whose KDCs answered is left alone for [`RETRY_AFTER`], with the reason kept,
/// rather than waited for again by every connection.
#[tokio::test]
async fn a_realm_whose_kdcs_did_not_answer_is_left_alone_for_a_while() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap().to_string();
    drop(closed);

    let locator = KdcLocator::new().kdc("EXAMPLE.TEST", dead.clone());
    let message = message_for("EXAMPLE.TEST");
    let realms = Realms::default();
    let error = send(&locator, &realms, &message, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        error.starts_with("no KDC for EXAMPLE.TEST answered") && error.contains(&dead),
        "{error}"
    );

    let now = Instant::now();
    assert_eq!(realms.unreachable("example.test", now), Some(error.clone()));
    assert_eq!(realms.unreachable("OTHER.TEST", now), None);
    assert_eq!(
        realms.unreachable("EXAMPLE.TEST", now + RETRY_AFTER),
        None,
        "and tried again after"
    );

    // A KDC that has since come up on that address is not asked until then.
    let listener = TcpListener::bind(&dead).await.unwrap();
    let again = send(&locator, &realms, &message, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(again, error);
    drop(listener);
}

/// The resolver is asked once per realm, not once per message.
#[tokio::test]
async fn a_realms_kdcs_are_looked_up_once() {
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct Counting(AtomicUsize, u16);
    impl SrvResolver for Counting {
        fn resolve<'a>(&'a self, _: &'a str) -> SrvLookup<'a> {
            self.0.fetch_add(1, Ordering::SeqCst);
            let record = SrvRecord::new(0, 0, self.1, "127.0.0.1.");
            Box::pin(async move { Ok(vec![record]) })
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut prefix = [0u8; 4];
            stream.read_exact(&mut prefix).await.unwrap();
            let mut request = vec![0u8; usize::try_from(u32::from_be_bytes(prefix)).unwrap()];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&framed(b"answered")).await.unwrap();
        }
    });

    let resolver = Arc::new(Counting(AtomicUsize::new(0), port));
    let shared: Arc<dyn SrvResolver> = resolver.clone();
    let locator = KdcLocator::new().resolver(shared);
    let realms = Realms::default();
    let message = message_for("EXAMPLE.TEST");
    for _ in 0..2 {
        let reply = send(&locator, &realms, &message, Duration::from_secs(5)).await;
        assert_eq!(reply.unwrap(), b"answered");
    }
    assert_eq!(resolver.0.load(Ordering::SeqCst), 1);

    // A realm whose lookup failed is left alone too.
    let failing = KdcLocator::new().resolver(Arc::new(Fixed(Err("SERVFAIL"))));
    let realms = Realms::default();
    let error = send(&failing, &realms, &message, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(error.contains("SERVFAIL"), "{error}");
    assert_eq!(
        realms.unreachable("EXAMPLE.TEST", Instant::now()),
        Some(error)
    );
}

/// A real first message for `realm`, from `negotiate-auth`, so that what goes over the wire is an
/// AS-REQ.
fn message_for(realm: &str) -> KdcMessage {
    let identity = negotiate_auth::Identity::new("alice", "hunter2").realm(realm);
    let entropy = negotiate_auth::KerberosEntropy::new([7; 64], Duration::new(1_800_000_000, 0));
    negotiate_auth::TicketRequest::new(&identity, "HTTP/mail.example.test", &entropy)
        .unwrap()
        .1
}
