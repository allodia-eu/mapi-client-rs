//! The public face of the Kerberos client: getting a service ticket, one KDC message at a time.

use core::time::Duration;

use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::kerberos::asn1::PrincipalName;
use crate::kerberos::exchange::{self, Acquisition, Credential, Step};
use crate::kerberos::fresh::Fresh;

/// The clock and randomness one Kerberos message needs — the Kerberos counterpart of
/// [`Entropy`](crate::Entropy), for the same reason: this crate has neither.
///
/// Build a new one for every call that takes one. The sixty-four bytes must come from a
/// cryptographically secure source: they become nonces, confounders, session subkeys and sequence
/// numbers, and a predictable subkey is a predictable session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KerberosEntropy {
    fresh: Fresh,
}

impl KerberosEntropy {
    /// Sixty-four random bytes and the current time as a duration since the Unix epoch.
    #[must_use]
    pub const fn new(random: [u8; 64], since_epoch: Duration) -> Self {
        Self {
            fresh: Fresh {
                now: since_epoch,
                random,
            },
        }
    }

    pub(crate) const fn fresh(&self) -> &Fresh {
        &self.fresh
    }
}

/// One message for a KDC: what to send, and to which realm's KDC.
///
/// Finding that KDC is the caller's — [MS-KILE] §3.2.3 has a client look up the DNS SRV record
/// `_kerberos._tcp.<realm>` ([RFC 4120] §7.2.3.2) — and so is the transport: TCP, with the message
/// preceded by its length as four big-endian bytes ([RFC 4120] §7.2.2), and the reply read the
/// same way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcMessage {
    realm: String,
    message: Vec<u8>,
}

impl KdcMessage {
    /// The realm whose KDC this is for. It changes as referrals are followed.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The message, without the TCP length prefix.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.message
    }
}

/// What to do after a KDC has answered.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TicketStep {
    /// Send this to a KDC and hand its reply to [`TicketRequest::receive`].
    Send(KdcMessage),
    /// Finished: the service ticket, and the ticket-granting ticket that can buy more.
    Done(Tickets),
}

/// Getting a ticket for one service: the AS exchange (unless a ticket-granting ticket is already
/// held), then the TGS exchange, following referrals across realms.
///
/// ```no_run
/// use core::time::Duration;
/// use negotiate_auth::{Identity, KerberosEntropy, TicketRequest, TicketStep};
///
/// # fn kdc(realm: &str, message: &[u8]) -> Vec<u8> { unimplemented!() }
/// # fn entropy() -> KerberosEntropy { KerberosEntropy::new([0; 64], Duration::ZERO) }
/// let identity = Identity::new("alice@example.test", "hunter2");
/// let (mut request, mut message) =
///     TicketRequest::new(&identity, "HTTP/mail.example.test", &entropy())?;
/// let tickets = loop {
///     let reply = kdc(message.realm(), message.bytes());
///     match request.receive(&reply, &entropy())? {
///         TicketStep::Send(next) => message = next,
///         TicketStep::Done(tickets) => break tickets,
///         _ => unreachable!(),
///     }
/// };
/// # let _ = tickets;
/// # Ok::<(), negotiate_auth::Error>(())
/// ```
pub struct TicketRequest {
    acquisition: Acquisition,
}

impl core::fmt::Debug for TicketRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TicketRequest").finish_non_exhaustive()
    }
}

impl TicketRequest {
    /// Starts from a password: an AS exchange for `identity`, then a ticket for `service`, written
    /// `HTTP/mail.example.test`.
    ///
    /// # Errors
    ///
    /// [`Error::KerberosName`] if the identity names no realm — a NetBIOS domain is not one — or
    /// the service name is not `service/host`.
    pub fn new(
        identity: &Identity,
        service: &str,
        entropy: &KerberosEntropy,
    ) -> Result<(Self, KdcMessage)> {
        let (client, realm) = identity
            .kerberos_name()
            .ok_or_else(|| Error::KerberosName {
                name: identity.username().to_owned(),
                reason: "it names no realm; use user@realm or give one with Identity::realm",
            })?;
        let (acquisition, request) = Acquisition::with_password(
            client,
            &realm,
            identity.password().to_owned(),
            service_name(service)?,
            entropy.fresh(),
        )?;
        Ok((Self { acquisition }, message(request)))
    }

    /// Starts from a ticket-granting ticket already held, so that a second service, or a second
    /// connection, costs one TGS exchange and no password.
    ///
    /// # Errors
    ///
    /// [`Error::KerberosName`] if the service name is not `service/host`.
    pub fn with_tgt(
        tgt: &TicketGrantingTicket,
        service: &str,
        entropy: &KerberosEntropy,
    ) -> Result<(Self, KdcMessage)> {
        let (acquisition, request) = Acquisition::with_tgt(
            tgt.credential.clone(),
            service_name(service)?,
            tgt.clock_offset,
            entropy.fresh(),
        )?;
        Ok((Self { acquisition }, message(request)))
    }

    /// Takes a KDC's reply to the last message.
    ///
    /// # Errors
    ///
    /// [`Error::KdcRefused`] when a KDC said no — a wrong password is `KDC_ERR_PREAUTH_FAILED` —
    /// [`Error::KdcReply`] when a reply failed a check, [`Error::Crypto`] when one did not
    /// decrypt, and [`Error::Malformed`] when one did not parse. Each ends the request.
    pub fn receive(&mut self, reply: &[u8], entropy: &KerberosEntropy) -> Result<TicketStep> {
        Ok(match self.acquisition.receive(reply, entropy.fresh())? {
            Step::Send(request) => TicketStep::Send(message(request)),
            Step::Done(tickets) => TicketStep::Done(Tickets {
                parts: Box::new((
                    ServiceTicket {
                        credential: tickets.service,
                        clock_offset: tickets.clock_offset,
                    },
                    TicketGrantingTicket {
                        credential: tickets.tgt,
                        clock_offset: tickets.clock_offset,
                    },
                )),
            }),
        })
    }
}

/// What a finished [`TicketRequest`] yields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tickets {
    /// Boxed, because two credentials beside a [`KdcMessage`] in [`TicketStep`] would make every
    /// step the size of the rare last one.
    parts: Box<(ServiceTicket, TicketGrantingTicket)>,
}

impl Tickets {
    /// The ticket for the service, for [`Handshake::kerberos`](crate::Handshake::kerberos).
    #[must_use]
    pub fn service(&self) -> &ServiceTicket {
        &self.parts.0
    }

    /// The ticket-granting ticket, for [`TicketRequest::with_tgt`].
    #[must_use]
    pub fn tgt(&self) -> &TicketGrantingTicket {
        &self.parts.1
    }

    /// Both, by value.
    #[must_use]
    pub fn into_parts(self) -> (ServiceTicket, TicketGrantingTicket) {
        *self.parts
    }
}

/// A ticket for one service, with its session key. Opaque; its key never prints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceTicket {
    pub(crate) credential: Credential,
    pub(crate) clock_offset: i64,
}

impl ServiceTicket {
    /// When it stops working, as a duration since the Unix epoch by the local clock.
    #[must_use]
    pub fn expires(&self) -> Duration {
        local_time(&self.credential, self.clock_offset)
    }

    /// The client it was issued to, as `name@REALM` in the KDC's canonical form.
    #[must_use]
    pub fn client(&self) -> String {
        principal(&self.credential)
    }
}

/// A ticket-granting ticket: what lets a client get more service tickets without its password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketGrantingTicket {
    credential: Credential,
    clock_offset: i64,
}

impl TicketGrantingTicket {
    /// When it stops working, as a duration since the Unix epoch by the local clock.
    #[must_use]
    pub fn expires(&self) -> Duration {
        local_time(&self.credential, self.clock_offset)
    }

    /// The client it was issued to, as `name@REALM` in the KDC's canonical form.
    #[must_use]
    pub fn client(&self) -> String {
        principal(&self.credential)
    }
}

fn message(request: exchange::KdcRequest) -> KdcMessage {
    KdcMessage {
        realm: request.realm,
        message: request.message,
    }
}

/// `service/host` as an `NT-SRV-INST` name — [MS-KILE] §3.1.5.11's SPN, without a port or a
/// service name, which an HTTP SPN has neither of.
fn service_name(service: &str) -> Result<PrincipalName> {
    match service.split_once('/') {
        Some((class, host)) if !class.is_empty() && !host.is_empty() && !host.contains('/') => Ok(
            PrincipalName::new(PrincipalName::NT_SRV_INST, &[class, host]),
        ),
        _ => Err(Error::KerberosName {
            name: service.to_owned(),
            reason: "a service principal name is written service/host",
        }),
    }
}

/// A KDC end time on the local clock: the KDC's time less however far its clock leads ours.
fn local_time(credential: &Credential, clock_offset: i64) -> Duration {
    Duration::from_secs(
        credential
            .endtime
            .unix()
            .saturating_add_signed(clock_offset.saturating_neg()),
    )
}

fn principal(credential: &Credential) -> String {
    format!(
        "{}@{}",
        credential.cname.components.join("/"),
        credential.crealm
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kerberos::asn1::KerberosTime;
    use crate::kerberos::crypto::{Enctype, Key};
    use crate::kerberos::kdc::Ticket;

    /// A Unix time, written in seconds whatever unit clippy would rather it in.
    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    /// The public face end to end, against the same synthetic KDC the exchange's own tests use:
    /// a password to tickets, then a second service ticket from the ticket-granting ticket.
    #[test]
    fn a_request_runs_to_tickets_and_the_tgt_buys_more() {
        use crate::kerberos::exchange::double::{Forest, KDC_TIME, Realm, User};
        let mut forest = Forest::new(vec![Realm {
            name: "EXAMPLE.TEST",
            users: vec![User {
                name: "alice",
                upn: "alice@example.test",
                password: "hunter2",
                preauth: true,
            }],
            services: vec!["HTTP/mail.example.test"],
            referral: None,
        }]);
        let entropy = |seed| KerberosEntropy::new([seed; 64], secs(KDC_TIME));
        let identity = Identity::new("alice@example.test", "hunter2");
        let (mut request, mut message) =
            TicketRequest::new(&identity, "HTTP/mail.example.test", &entropy(1)).unwrap();
        let tickets = loop {
            let reply = forest.answer(message.realm(), message.bytes());
            match request.receive(&reply, &entropy(2)).unwrap() {
                TicketStep::Send(next) => message = next,
                TicketStep::Done(tickets) => break tickets,
            }
        };
        assert_eq!(tickets.service().client(), "alice@EXAMPLE.TEST");
        assert_eq!(tickets.tgt().expires(), secs(KDC_TIME + 36_000));

        let (mut again, message) =
            TicketRequest::with_tgt(tickets.tgt(), "HTTP/mail.example.test", &entropy(3)).unwrap();
        let reply = forest.answer(message.realm(), message.bytes());
        assert!(matches!(
            again.receive(&reply, &entropy(4)).unwrap(),
            TicketStep::Done(_)
        ));
    }

    #[test]
    fn a_service_name_is_service_slash_host() {
        let name = service_name("HTTP/mail.example.test").unwrap();
        assert_eq!(name.components, ["HTTP", "mail.example.test"]);
        assert_eq!(name.name_type, PrincipalName::NT_SRV_INST);
        for bad in ["mail.example.test", "/host", "HTTP/", "HTTP/host/extra"] {
            assert!(
                matches!(service_name(bad), Err(Error::KerberosName { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn an_identity_without_a_realm_is_not_asked_about() {
        let entropy = KerberosEntropy::new([1; 64], secs(1_800_000_000));
        let refused = TicketRequest::new(
            &Identity::new("EXAMPLE\\alice", "hunter2"),
            "HTTP/mail.example.test",
            &entropy,
        );
        assert!(matches!(
            refused,
            Err(Error::KerberosName { ref name, .. }) if name == "alice"
        ));

        let (request, message) = TicketRequest::new(
            &Identity::new("alice@example.test", "hunter2"),
            "HTTP/mail.example.test",
            &entropy,
        )
        .unwrap();
        assert_eq!(message.realm(), "EXAMPLE.TEST");
        assert_eq!(message.bytes()[0], 0x6A, "an AS-REQ");
        assert!(format!("{request:?}").starts_with("TicketRequest"));
    }

    #[test]
    fn a_ticket_reports_its_client_and_its_expiry_on_the_local_clock() {
        let credential = Credential {
            crealm: "EXAMPLE.TEST".to_owned(),
            cname: PrincipalName::new(1, &["alice"]),
            ticket: Ticket {
                raw: vec![0x61, 0x00],
                realm: "EXAMPLE.TEST".to_owned(),
                sname: PrincipalName::new(2, &["krbtgt", "EXAMPLE.TEST"]),
            },
            key: Key::new(Enctype::Aes256Sha1, vec![0; 32]).unwrap(),
            flags: 0,
            endtime: KerberosTime::from_unix(1_800_036_000),
        };
        // The KDC's clock leads ours by 600 seconds, so its end time is earlier on ours.
        let tgt = TicketGrantingTicket {
            credential: credential.clone(),
            clock_offset: 600,
        };
        assert_eq!(tgt.expires(), secs(1_800_035_400));
        assert_eq!(tgt.client(), "alice@EXAMPLE.TEST");
        let service = ServiceTicket {
            credential,
            clock_offset: -60,
        };
        assert_eq!(service.expires(), secs(1_800_036_060));
        assert_eq!(service.client(), "alice@EXAMPLE.TEST");

        let entropy = KerberosEntropy::new([1; 64], secs(1_800_000_000));
        let (_, message) =
            TicketRequest::with_tgt(&tgt, "HTTP/mail.example.test", &entropy).unwrap();
        assert_eq!(message.bytes()[0], 0x6C, "a TGS-REQ");
        assert!(TicketRequest::with_tgt(&tgt, "nonsense", &entropy).is_err());

        let tickets = Tickets {
            parts: Box::new((service, tgt)),
        };
        assert_eq!(tickets.service().client(), tickets.tgt().client());
        let (service, tgt) = tickets.into_parts();
        assert_ne!(service.expires(), tgt.expires());
    }
}
