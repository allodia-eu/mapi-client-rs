//! The test KDC, driven by this crate's own client — which is the only judge of it that matters.

use super::*;
use crate::{
    Entropy, Error, Handshake, Identity, KerberosEntropy, Mechanism, TicketRequest, TicketStep,
};

const NOW: Duration = Duration::new(1_800_000_000, 0);

fn kdc() -> TestKdc {
    TestKdc::new(
        "EXAMPLE.TEST",
        "alice@example.test",
        "hunter2",
        "HTTP/mail.example.test",
        NOW,
    )
    .unwrap()
}

fn entropy(seed: u8) -> KerberosEntropy {
    KerberosEntropy::new([seed; 64], NOW)
}

/// Runs a ticket request against `kdc` to its end.
fn tickets(kdc: &TestKdc, identity: &Identity, service: &str) -> crate::Result<crate::Tickets> {
    let (mut request, mut message) = TicketRequest::new(identity, service, &entropy(1))?;
    loop {
        assert_eq!(message.realm(), "EXAMPLE.TEST");
        match request.receive(&kdc.answer(message.bytes()), &entropy(2))? {
            TicketStep::Send(next) => message = next,
            TicketStep::Done(tickets) => return Ok(tickets),
        }
    }
}

#[test]
fn a_client_gets_a_ticket_and_the_service_accepts_it() {
    let kdc = kdc();
    let identity = Identity::new("alice@example.test", "hunter2");
    let tickets = tickets(&kdc, &identity, "HTTP/mail.example.test").unwrap();
    assert_eq!(tickets.service().client(), "alice@EXAMPLE.TEST");
    assert_eq!(tickets.tgt().expires(), NOW + Duration::new(36_000, 0));

    let mut handshake = Handshake::kerberos(
        tickets.service().clone(),
        identity,
        Entropy::new([1; 8], 0),
        [entropy(3), entropy(4)],
    );
    let first = handshake.initial().unwrap();
    let success = kdc
        .accept(&first)
        .expect("the service accepts its own ticket");
    handshake.finish(Some(&success)).unwrap();
    assert_eq!(handshake.mechanism(), Some(Mechanism::Kerberos));

    // And the TGT buys a second ticket without the password.
    let (mut again, message) =
        TicketRequest::with_tgt(tickets.tgt(), "HTTP/mail.example.test", &entropy(5)).unwrap();
    assert!(matches!(
        again
            .receive(&kdc.answer(message.bytes()), &entropy(6))
            .unwrap(),
        TicketStep::Done(_)
    ));
}

#[test]
fn a_wrong_password_and_an_unknown_service_are_refused() {
    let kdc = kdc();
    let wrong = tickets(
        &kdc,
        &Identity::new("alice@example.test", "hunter3"),
        "HTTP/mail.example.test",
    );
    assert!(matches!(wrong, Err(Error::KdcRefused { code: 24, .. })));

    let identity = Identity::new("alice@example.test", "hunter2");
    let unknown = tickets(&kdc, &identity, "HTTP/elsewhere.example.test");
    assert!(matches!(unknown, Err(Error::KdcRefused { code: 7, .. })));
}

#[test]
fn what_the_kdc_cannot_read_is_a_generic_error() {
    let kdc = kdc();
    for request in [&b""[..], b"not DER", &der::tlv(der::application(5), &[])] {
        let reply = kdc.answer(request);
        assert_eq!(reply.first(), Some(&0x7E), "a KRB-ERROR");
    }
    // A TGS-REQ presenting a ticket this KDC never issued.
    let other = TestKdc::new(
        "EXAMPLE.TEST",
        "alice",
        "hunter2",
        "HTTP/mail.example.test",
        NOW,
    )
    .unwrap();
    let identity = Identity::new("alice@example.test", "hunter2");
    let tgt = tickets(&other, &identity, "HTTP/mail.example.test").unwrap();
    let (_, message) =
        TicketRequest::with_tgt(tgt.tgt(), "HTTP/mail.example.test", &entropy(7)).unwrap();
    assert_eq!(kdc.answer(message.bytes()).first(), Some(&0x7E));
}

#[test]
fn the_service_accepts_nothing_but_its_own_tickets() {
    let kdc = kdc();
    let identity = Identity::new("alice@example.test", "hunter2");
    for value in [
        "NTLM TlRMTVNTUAABAAAA",
        "Negotiate !!!",
        "Negotiate oQcwBaADCgEA",
    ] {
        assert_eq!(kdc.accept(value), None, "{value}");
    }

    // A ticket from another KDC is not one this service can read.
    let other = TestKdc::new(
        "EXAMPLE.TEST",
        "alice",
        "hunter2",
        "HTTP/mail.example.test",
        NOW,
    )
    .unwrap();
    let foreign = tickets(&other, &identity, "HTTP/mail.example.test").unwrap();
    let mut handshake = Handshake::kerberos(
        foreign.service().clone(),
        identity,
        Entropy::new([1; 8], 0),
        [entropy(3), entropy(4)],
    );
    assert_eq!(kdc.accept(&handshake.initial().unwrap()), None);

    // Nor is anything but an AP-REQ inside the SPNEGO wrapper.
    let not_ap_req = spnego::init_token(&[gss::OID], &gss::frame([0x02, 0x00], &[0x30, 0x00]));
    assert_eq!(
        kdc.accept(&format!("Negotiate {}", BASE64.encode(not_ap_req))),
        None
    );
    assert!(format!("{kdc:?}").contains("EXAMPLE.TEST"));
}
