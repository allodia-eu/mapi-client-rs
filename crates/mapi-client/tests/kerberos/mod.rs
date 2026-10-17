//! Kerberos inside `Negotiate`, against a lab whose Exchange server is in an Active Directory
//! realm.
//!
//! Part of `tests/live.rs`, ignored for the same reason. `scripts\Test-Live.ps1` runs it with the
//! `hickory-dns` feature, so that the client finds the KDCs the way a caller with no resolver of
//! its own would: through the system's DNS and the realm's `_kerberos._tcp` SRV records.

use core::time::Duration;
use std::io::{Read as _, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

use mapi_client::{Credentials, LegacyDn, MapiClient};
use negotiate_auth::{
    ChannelBinding, Entropy, Handshake, Identity, KerberosEntropy, Mechanism, TicketRequest,
    TicketStep,
};

use super::{LIVE_TIMEOUT, required};

fn client(credentials: Credentials) -> MapiClient {
    MapiClient::builder()
        .endpoint(required("MAPI_LIVE_ENDPOINT"))
        .user_dn(LegacyDn::new(required("MAPI_LIVE_USER_DN")).expect("a usable legacyExchangeDN"))
        .credentials(credentials)
        .timeout(LIVE_TIMEOUT)
        .build()
        .expect("a client")
}

/// The point of the whole branch, stated as an assertion: `Negotiate` authenticates with Kerberos,
/// and the client reports that it did — while `NTLM` credentials report NTLM, with no reason to
/// give, because they never offer Kerberos.
#[tokio::test]
#[ignore = "needs a live Exchange Server in a Kerberos realm; run scripts\\Test-Live.ps1"]
async fn negotiate_authenticates_with_kerberos_and_says_so() {
    let username = required("MAPI_LIVE_USERNAME");
    let password = required("MAPI_LIVE_PASSWORD");

    let negotiate = client(Credentials::negotiate(&username, &password));
    let logon = negotiate
        .connect()
        .await
        .expect("Connect")
        .logon()
        .await
        .expect("RopLogon");
    let authentication = negotiate.authentication().expect("a handshake ran");
    println!("Negotiate: {authentication:?}");
    assert_eq!(
        authentication.mechanism,
        Mechanism::Kerberos,
        "fell back to NTLM: {:?}",
        authentication.kerberos_unavailable
    );
    assert_eq!(authentication.kerberos_unavailable, None);
    logon.disconnect().await.expect("Disconnect");

    let ntlm = client(Credentials::ntlm(&username, &password));
    ntlm.ping().await.expect("PING");
    let authentication = ntlm.authentication().expect("a handshake ran");
    assert_eq!(authentication.mechanism, Mechanism::Ntlm);
    assert_eq!(authentication.kerberos_unavailable, None);
}

/// [MS-KILE] §3.1.5.10's MUST, end to end: a user of a child realm, named by UPN, reaches the
/// parent realm's Exchange through a server referral from the child's KDC.
///
/// The account needs no mailbox — this is authentication, and `PING` is answered for any account
/// the server has authenticated. `MAPI_LIVE_REFERRAL_USERNAME` names it, and its password is
/// `MAPI_LIVE_REFERRAL_PASSWORD`, or the lab's own when that is unset.
#[tokio::test]
#[ignore = "needs a live Exchange Server and a child realm; run scripts\\Test-Live.ps1"]
async fn a_child_realm_user_reaches_exchange_through_a_referral() {
    let Ok(username) = std::env::var("MAPI_LIVE_REFERRAL_USERNAME") else {
        panic!(
            "MAPI_LIVE_REFERRAL_USERNAME is not set. This test needs a user of a child domain of \
             the Exchange server's own, named by UPN; scripts\\Test-Live.ps1 -ReferralUser sets it."
        );
    };
    let password = std::env::var("MAPI_LIVE_REFERRAL_PASSWORD")
        .unwrap_or_else(|_| required("MAPI_LIVE_PASSWORD"));

    let child = client(Credentials::negotiate(&username, password));
    child.ping().await.expect("PING, as the child-realm user");
    let authentication = child.authentication().expect("a handshake ran");
    println!("{username}: {authentication:?}");
    assert_eq!(
        authentication.mechanism,
        Mechanism::Kerberos,
        "fell back to NTLM: {:?}",
        authentication.kerberos_unavailable
    );
}

/// [MS-KILE] §3.2.5.8's clock-skew recovery, on **one** connection — the case a fresh connection
/// per request could not show, because SPNEGO's continuation token only means something to the
/// server context that saw the first one.
///
/// Driven through `negotiate-auth` directly, because a client's clock cannot be moved from outside
/// it: the first AP-REQ is built an hour slow, the server's `KRB_AP_ERR_SKEW` comes back, and the
/// retry it makes possible goes on the same connection.
#[tokio::test]
#[ignore = "needs a live Exchange Server in a Kerberos realm; run scripts\\Test-Live.ps1"]
async fn a_skewed_clock_is_recovered_on_one_connection() {
    let endpoint = required("MAPI_LIVE_ENDPOINT");
    let host = reqwest::Url::parse(&endpoint)
        .expect("an endpoint URL")
        .host_str()
        .expect("a host")
        .to_owned();
    let identity = Identity::new(
        &required("MAPI_LIVE_USERNAME"),
        required("MAPI_LIVE_PASSWORD"),
    );
    let ticket = service_ticket(&identity, &format!("HTTP/{host}"));

    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(1)
        .tls_info(true)
        .http1_only()
        .build()
        .expect("an HTTP client");
    let post = |authorization: Option<String>| {
        let mut request = http
            .post(&endpoint)
            .header("Content-Length", "0")
            .header("X-RequestType", "PING");
        if let Some(value) = authorization {
            request = request.header("Authorization", value);
        }
        request.send()
    };

    // The first leg brings the certificate the AP-REQ binds to.
    let probe = post(None).await.expect("the first request");
    assert_eq!(probe.status(), 401);
    let certificate = probe
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate().map(<[u8]>::to_vec))
        .expect("the server's certificate");
    let _ = probe.bytes().await;

    let mut handshake = Handshake::kerberos(
        ticket,
        identity,
        Entropy::from_unix_time([0x11; 8], now()),
        [entropy(-3_600), entropy(0)],
    )
    .channel_binding(ChannelBinding::tls_server_end_point(&certificate));

    let skewed = post(Some(handshake.initial().expect("the AP-REQ")))
        .await
        .expect("the AP-REQ");
    assert_eq!(skewed.status(), 401, "an hour of skew is refused");
    let challenge = negotiate_header(&skewed);
    let _ = skewed.bytes().await;

    // The retry is accepted with the AP-REP — on a 401, with `accept-incomplete` and the server's
    // mechListMIC, because [RFC 4178] §5 requires the MIC exchange once the accepted token was not
    // the optimistic one — and the client's MIC completes it. Measured: three legs after the first.
    let mut answer = handshake
        .advance(&challenge)
        .expect("the retry, on the server's clock");
    let mut answered = post(Some(answer)).await.expect("the retry");
    let mut legs = 2;
    while answered.status() == 401 && handshake.state() != negotiate_auth::State::Complete {
        let challenge = negotiate_header(&answered);
        let _ = answered.bytes().await;
        answer = handshake.advance(&challenge).expect("the next leg");
        answered = post(Some(answer)).await.expect("the next leg");
        legs += 1;
    }
    println!(
        "answered {} after {legs} authenticated legs",
        answered.status()
    );
    assert_ne!(answered.status(), 401, "the retry was refused");
    // After the MIC exchange the success carries no token: the AP-REP came on the 401 before it.
    let last = answered
        .headers()
        .get_all("WWW-Authenticate")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("Negotiate"))
        .map(str::to_owned);
    handshake
        .finish(last.as_deref())
        .expect("the AP-REP proved the server");
    assert_eq!(handshake.mechanism(), Some(Mechanism::Kerberos));
}

/// A service ticket, asked for over TCP from the KDC `MAPI_LIVE_KDC` names, for every realm the
/// request passes through — which, for this account, is its own.
fn service_ticket(identity: &Identity, service: &str) -> negotiate_auth::ServiceTicket {
    let kdc = required("MAPI_LIVE_KDC");
    let (mut request, mut message) =
        TicketRequest::new(identity, service, &entropy(0)).expect("a ticket request");
    loop {
        let mut stream = std::net::TcpStream::connect(&kdc).expect("the KDC");
        let length = u32::try_from(message.bytes().len()).expect("a message to frame");
        stream.write_all(&length.to_be_bytes()).expect("a length");
        stream.write_all(message.bytes()).expect("a message");
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).expect("a reply length");
        let mut reply = vec![0u8; usize::try_from(u32::from_be_bytes(prefix)).expect("a length")];
        stream.read_exact(&mut reply).expect("a reply");
        match request
            .receive(&reply, &entropy(0))
            .expect("the KDC's answer")
        {
            TicketStep::Send(next) => message = next,
            TicketStep::Done(tickets) => return tickets.service().clone(),
            _ => panic!("a step this test was written before"),
        }
    }
}

fn negotiate_header(response: &reqwest::Response) -> String {
    response
        .headers()
        .get_all("WWW-Authenticate")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("Negotiate"))
        .expect("a Negotiate token")
        .to_owned()
}

fn now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
}

/// Fresh Kerberos entropy, with the clock moved by `skew` seconds. Random enough for a test: the
/// bytes come from the hasher's per-process random keys.
fn entropy(skew: i64) -> KerberosEntropy {
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut random = [0u8; 64];
    for chunk in random.chunks_mut(8) {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u8(0);
        for (slot, byte) in chunk.iter_mut().zip(hasher.finish().to_le_bytes()) {
            *slot = byte;
        }
    }
    let now = now();
    let moved = if skew < 0 {
        now.saturating_sub(Duration::from_secs(skew.unsigned_abs()))
    } else {
        now.saturating_add(Duration::from_secs(skew.unsigned_abs()))
    };
    KerberosEntropy::new(random, moved)
}
