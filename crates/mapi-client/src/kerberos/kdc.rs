//! Finding a realm's KDCs, carrying one message to one of them, and remembering which answered.

use core::time::Duration;
use std::sync::Mutex;
use std::time::Instant;

use mapi_auth::KdcMessage;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use super::{KdcLocator, SrvRecord};

/// The port a KDC listens on when nothing says otherwise — [RFC 4120] §7.2.2: "SHOULD listen for
/// them on port 88".
const PORT: u16 = 88;

/// The largest reply this client will read. A KDC reply carries a ticket and its encrypted part;
/// with a large PAC that is tens of kilobytes, never a megabyte. The cap is what stops a length
/// prefix from a hostile peer becoming an allocation of four gigabytes.
const MAX_REPLY: usize = 1 << 20;

/// How long a realm's KDCs, once found, are used without asking the resolver again. An
/// [`SrvRecord`] carries no TTL — a platform resolver need not report one — so this is a fixed
/// window: long enough that a burst of connections, or an Autodiscover search across its
/// candidates, looks the realm up once, and short enough that a KDC added to DNS is used soon.
const KEEP_FOR: Duration = Duration::from_mins(10);

/// How long a realm none of whose KDCs answered — or whose lookup failed — is left alone before it
/// is tried again. Without it, every new connection would wait out every KDC's timeout again
/// before falling back to NTLM; [MS-KILE] §3.2.6 leaves what to do about a KDC that does not
/// answer to the implementation.
pub(super) const RETRY_AFTER: Duration = Duration::from_mins(1);

/// What is known of each realm's KDCs.
#[derive(Debug, Default)]
pub(super) struct Realms(Mutex<Vec<(String, Known)>>);

/// What is known of one realm's KDCs, and until when.
#[derive(Clone, Debug)]
struct Known {
    until: Instant,
    /// The KDCs, in the order to try them — the one that last answered first — or why there are
    /// none to try.
    kdcs: Result<Vec<String>, String>,
}

impl Realms {
    /// Why `realm`'s KDCs are not worth asking at `now`, when that is known.
    pub(super) fn unreachable(&self, realm: &str, now: Instant) -> Option<String> {
        self.known(realm, now).and_then(Result::err)
    }

    fn known(&self, realm: &str, now: Instant) -> Option<Result<Vec<String>, String>> {
        self.lock()
            .iter()
            .find(|(name, known)| name.eq_ignore_ascii_case(realm) && known.until > now)
            .map(|(_, known)| known.kdcs.clone())
    }

    fn remember(&self, realm: &str, kdcs: Result<Vec<String>, String>, now: Instant) {
        let keep = if kdcs.is_ok() { KEEP_FOR } else { RETRY_AFTER };
        let mut realms = self.lock();
        realms.retain(|(name, known)| !name.eq_ignore_ascii_case(realm) && known.until > now);
        realms.push((
            realm.to_owned(),
            Known {
                until: now.checked_add(keep).unwrap_or(now),
                kdcs,
            },
        ));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<(String, Known)>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Sends `message` to a KDC for its realm and returns the reply, trying each KDC in turn and
/// waiting at most `timeout` for each.
///
/// [MS-KILE] §3.2.6 leaves what to do about a KDC that does not answer to the implementation;
/// this one moves on to the next, tries the one that answered first next time, and leaves a realm
/// none of whose KDCs answered alone for [`RETRY_AFTER`].
///
/// # Errors
///
/// Why no KDC answered, in words, for
/// [`MapiClient::authentication`](crate::MapiClient::authentication) to report when `Negotiate`
/// falls back to NTLM.
pub(super) async fn send(
    locator: &KdcLocator,
    realms: &Realms,
    message: &KdcMessage,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let realm = message.realm();
    let addresses = if let Some(known) = realms.known(realm, Instant::now()) {
        known?
    } else {
        let found = addresses(locator, realm).await;
        realms.remember(realm, found.clone(), Instant::now());
        found?
    };
    let mut failures = Vec::new();
    for (at, address) in addresses.iter().enumerate() {
        match exchange(address, message.bytes(), timeout).await {
            Ok(reply) => {
                if at > 0 {
                    let mut preferred = addresses.clone();
                    preferred.rotate_left(at);
                    realms.remember(realm, Ok(preferred), Instant::now());
                }
                return Ok(reply);
            }
            Err(error) => failures.push(format!("{address}: {error}")),
        }
    }
    let reason = format!("no KDC for {realm} answered ({})", failures.join("; "));
    realms.remember(realm, Err(reason.clone()), Instant::now());
    Err(reason)
}

/// The KDCs for `realm`, in the order to try them.
async fn addresses(locator: &KdcLocator, realm: &str) -> Result<Vec<String>, String> {
    let named: Vec<String> = locator
        .kdcs
        .iter()
        .filter(|(named, _)| named.eq_ignore_ascii_case(realm))
        .map(|(_, address)| with_port(address))
        .collect();
    if !named.is_empty() {
        return Ok(named);
    }

    let resolver = match &locator.resolver {
        Some(resolver) => resolver.clone(),
        None => system_resolver().ok_or_else(|| no_kdc_known(realm))?,
    };
    // [RFC 4120] §7.2.3.2: "_Service._Proto.Realm", the service being "kerberos"; TCP, because
    // that is the transport this client speaks (§7.2.2: "Clients MUST support the sending of TCP
    // requests").
    let name = format!("_kerberos._tcp.{realm}");
    let records = resolver
        .resolve(&name)
        .await
        .map_err(|error| format!("looking up {name} failed: {error}"))?;
    let ordered: Vec<String> = order(records, random)
        .into_iter()
        .filter(|record| record.target != ".")
        .map(|record| format!("{}:{}", record.target.trim_end_matches('.'), record.port))
        .collect();
    if ordered.is_empty() {
        return Err(format!("{name} names no KDC"));
    }
    Ok(ordered)
}

/// Why `realm` has no KDC to ask whatever DNS would say, when that is so: none is named for it and
/// there is no resolver to look one up with — which is known without any I/O.
pub(super) fn unlocatable(locator: &KdcLocator, realm: &str) -> Option<String> {
    let named = locator
        .kdcs
        .iter()
        .any(|(named, _)| named.eq_ignore_ascii_case(realm));
    let resolver = locator.resolver.is_some() || cfg!(feature = "hickory-dns");
    (!named && !resolver).then(|| no_kdc_known(realm))
}

fn no_kdc_known(realm: &str) -> String {
    format!(
        "no KDC is known for {realm}: name one with KdcLocator::kdc, or give a resolver with \
         KdcLocator::resolver"
    )
}

#[cfg(feature = "hickory-dns")]
fn system_resolver() -> Option<std::sync::Arc<dyn super::SrvResolver>> {
    super::hickory::system()
}

#[cfg(not(feature = "hickory-dns"))]
const fn system_resolver() -> Option<std::sync::Arc<dyn super::SrvResolver>> {
    None
}

/// `host` with port 88 added when it names none. A bracketed IPv6 literal keeps its brackets, and
/// a bare one gains them, since `::1:88` would read as an address rather than a port.
fn with_port(address: &str) -> String {
    if address.parse::<std::net::Ipv6Addr>().is_ok() {
        return format!("[{address}]:{PORT}");
    }
    let has_port = match address.rsplit_once(':') {
        Some((host, port)) => {
            port.parse::<u16>().is_ok() && (!host.contains(':') || host.ends_with(']'))
        }
        None => false,
    };
    if has_port {
        address.to_owned()
    } else {
        format!("{address}:{PORT}")
    }
}

/// [RFC 2782]'s order: lowest priority first, and within one priority a weighted random choice —
/// "the following algorithm SHOULD be used to order the SRV RRs of the same priority": zero
/// weights first, then pick by a uniform random number up to the sum of the weights, the first
/// record whose running sum reaches it, and repeat with what is left.
fn order(mut records: Vec<SrvRecord>, mut random: impl FnMut() -> u32) -> Vec<SrvRecord> {
    records.sort_by_key(|record| (record.priority, record.weight != 0));
    let mut ordered = Vec::with_capacity(records.len());
    while let Some(first) = records.first() {
        let priority = first.priority;
        let end = records
            .iter()
            .position(|record| record.priority != priority)
            .unwrap_or(records.len());
        let mut group: Vec<SrvRecord> = records.drain(..end).collect();
        while !group.is_empty() {
            let sum: u32 = group.iter().map(|record| u32::from(record.weight)).sum();
            let target = random().checked_rem(sum.saturating_add(1)).unwrap_or(0);
            let mut running = 0u32;
            let at = group
                .iter()
                .position(|record| {
                    running = running.saturating_add(u32::from(record.weight));
                    running >= target
                })
                .unwrap_or(0);
            ordered.push(group.remove(at));
        }
    }
    ordered
}

/// A uniform random number from the operating system, for [`order`]. A failure costs only the
/// spread of load across a realm's KDCs, never correctness, so it falls back to zero.
fn random() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).map_or(0, |()| u32::from_le_bytes(bytes))
}

/// One request and its reply over TCP — [RFC 4120] §7.2.2: each "preceded by the length … as 4
/// octets in network byte order", whose high bit "MUST currently be set to zero".
async fn exchange(address: &str, message: &[u8], timeout: Duration) -> std::io::Result<Vec<u8>> {
    let work = async {
        let length = u32::try_from(message.len())
            .ok()
            .filter(|length| length & 0x8000_0000 == 0)
            .ok_or_else(|| std::io::Error::other("a message too long to frame"))?;
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(message).await?;

        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).await?;
        let length = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
        if length == 0 || length > MAX_REPLY {
            // A Windows Server 2025 KDC answers a request it cannot read — a nonce with the top
            // bit set, measured — with a length of zero and nothing after it.
            return Err(std::io::Error::other(format!(
                "a reply of {length} bytes, which is no reply"
            )));
        }
        let mut reply = vec![0u8; length];
        stream.read_exact(&mut reply).await?;
        Ok(reply)
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "no reply in time"))?
}

#[cfg(test)]
mod tests;
