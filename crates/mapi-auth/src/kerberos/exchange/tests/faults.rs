//! Replies that do not answer the request, and KDCs that cannot answer it: every check
//! [`super::super::Acquisition`] makes, each made to fail once.

use super::super::double::Fault;
use super::super::{Acquisition, Error, Step};
use super::{drive, forest, fresh, logon, reason, service, upn};

#[test]
fn a_kdc_without_aes_keys_for_the_account_is_reported() {
    for (fault, expected) in [
        (Fault::Rc4Only, "the KDC holds no AES key for this account"),
        (
            Fault::NoEtypeInfo,
            "no PA-ETYPE-INFO2 to make the password's key from",
        ),
    ] {
        let mut forest = forest();
        forest.fault = Some(fault);
        let result = logon(
            &mut forest,
            upn("alice@example.test"),
            "EXAMPLE.TEST",
            "hunter2",
        );
        assert_eq!(reason(result), expected);
    }
}

/// [RFC 6806] §11, which a Windows Server 2025 KDC was measured to honour: the checksum of the
/// request must be there and must verify, or the reply is refused.
#[test]
fn an_altered_request_is_caught_by_the_kdcs_checksum() {
    for (fault, expected) in [
        (
            Fault::ChecksumOverOtherBytes,
            "a request checksum that does not match the request sent",
        ),
        (
            Fault::ChecksumMissing,
            "the enc-pa-rep flag without the request's checksum",
        ),
        (
            Fault::ChecksumOfAnotherType,
            "a request checksum of a type the reply key does not use",
        ),
    ] {
        let mut forest = forest();
        forest.fault = Some(fault);
        let result = logon(
            &mut forest,
            upn("alice@example.test"),
            "EXAMPLE.TEST",
            "hunter2",
        );
        assert_eq!(reason(result), expected);
    }

    // A KDC that does not implement it sets no flag, and is not held to it.
    let mut forest = forest();
    forest.enc_pa_rep = false;
    logon(
        &mut forest,
        upn("alice@example.test"),
        "EXAMPLE.TEST",
        "hunter2",
    )
    .unwrap();
}

/// [RFC 4120] §3.1.5's checks on an AS-REP.
#[test]
fn an_as_rep_that_does_not_answer_the_request_is_refused() {
    for (fault, expected) in [
        (Fault::WrongNonce, "a nonce that is not the request's"),
        (
            Fault::TicketNotKrbtgt,
            "a ticket that is not this realm's krbtgt",
        ),
        (
            Fault::TicketFromAnotherRealm,
            "a ticket that is not this realm's krbtgt",
        ),
        (
            Fault::InnerNameDiffers,
            "an encrypted part that names another ticket",
        ),
        (
            Fault::EncPartEtype(17),
            "a reply encrypted under a key of another type",
        ),
        (
            Fault::SessionKeyType(23),
            "a session key of a type the request did not offer",
        ),
    ] {
        let mut forest = forest();
        forest.fault = Some(fault);
        let result = logon(
            &mut forest,
            upn("alice@example.test"),
            "EXAMPLE.TEST",
            "hunter2",
        );
        assert_eq!(reason(result), expected, "{fault:?}");
    }
}

/// [RFC 4120] §3.3.4 and [RFC 6806] §6's checks on a TGS-REP.
#[test]
fn a_tgs_rep_that_does_not_answer_the_request_is_refused() {
    for (fault, expected) in [
        (Fault::WrongNonce, "a nonce that is not the request's"),
        (
            Fault::TicketFromAnotherRealm,
            "a ticket from a realm other than the one asked",
        ),
        (Fault::ClientRenamed, "a reply naming a different client"),
        (
            Fault::InnerNameDiffers,
            "an encrypted part that names another ticket",
        ),
        (
            Fault::TicketNotKrbtgt,
            "a ticket for a service other than the one asked",
        ),
        (
            Fault::EncPartEtype(17),
            "a reply encrypted under a key of another type",
        ),
    ] {
        let mut forest = forest();
        let tgt = logon(
            &mut forest,
            upn("alice@example.test"),
            "EXAMPLE.TEST",
            "hunter2",
        )
        .unwrap()
        .tgt;
        forest.fault = Some(fault);
        let result = drive(
            &mut forest,
            Acquisition::with_tgt(tgt, service(), 0, &fresh(9)),
        );
        assert_eq!(reason(result), expected, "{fault:?}");
    }
}

#[test]
fn a_reply_that_is_not_der_is_malformed() {
    let mut forest = forest();
    forest.fault = Some(Fault::Unparsable);
    let result = logon(
        &mut forest,
        upn("alice@example.test"),
        "EXAMPLE.TEST",
        "hunter2",
    );
    assert!(matches!(result, Err(Error::Malformed { .. })));
}

#[test]
fn a_finished_acquisition_reads_nothing_more() {
    let (mut acquisition, mut request) = Acquisition::with_password(
        upn("alice@example.test"),
        "EXAMPLE.TEST",
        "hunter2".to_owned(),
        service(),
        &fresh(0),
    )
    .unwrap();
    let mut forest = forest();
    loop {
        let reply = forest.answer(&request.realm, &request.message);
        match acquisition.receive(&reply, &fresh(1)).unwrap() {
            Step::Send(next) => request = next,
            Step::Done(_) => break,
        }
    }
    assert_eq!(
        acquisition.receive(&[], &fresh(2)),
        Err(Error::OutOfOrder {
            state: "finished",
            attempted: "read another KDC reply",
        })
    );
}
