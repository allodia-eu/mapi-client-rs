//! The `hickory-dns` feature: an [`SrvResolver`] for a caller with no resolver of its own, reading
//! the operating system's resolver configuration.
//!
//! A host with a native resolver should prefer it — see the [module](super) for why — but a
//! command-line tool or a service on a server has nothing better to hand.

use std::sync::Arc;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, Record, RecordType};

use super::{SrvLookup, SrvRecord, SrvResolver};

/// The system's resolver, as `hickory-resolver` reads its configuration.
#[derive(Debug)]
struct System(TokioResolver);

impl SrvResolver for System {
    fn resolve<'a>(&'a self, name: &'a str) -> SrvLookup<'a> {
        Box::pin(async move {
            // Fully qualified, so that no search domain is tried in front of a name that is
            // already complete.
            let absolute = if name.ends_with('.') {
                name.to_owned()
            } else {
                format!("{name}.")
            };
            match self.0.lookup(absolute, RecordType::SRV).await {
                Ok(lookup) => Ok(records(lookup.answers())),
                Err(error) if error.is_no_records_found() => Ok(Vec::new()),
                Err(error) => Err(std::io::Error::other(error)),
            }
        })
    }
}

/// The SRV records among a lookup's answers, which can also carry the CNAMEs that led to them.
fn records(answers: &[Record]) -> Vec<SrvRecord> {
    answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::SRV(srv) => Some(SrvRecord::new(
                srv.priority,
                srv.weight,
                srv.port,
                srv.target.to_utf8(),
            )),
            _ => None,
        })
        .collect()
}

/// The system's resolver, or `None` if its configuration cannot be read.
pub(super) fn system() -> Option<Arc<dyn SrvResolver>> {
    let resolver = TokioResolver::builder_tokio().ok()?.build().ok()?;
    Some(Arc::new(System(resolver)))
}

#[cfg(test)]
mod tests {
    use hickory_resolver::proto::rr::Name;
    use hickory_resolver::proto::rr::rdata::{CNAME, SRV};

    use super::*;

    #[test]
    fn srv_answers_become_records_and_the_rest_is_dropped() {
        let name = Name::from_ascii("_kerberos._tcp.example.test.").unwrap();
        let target = Name::from_ascii("kdc.example.test.").unwrap();
        let answers = [
            Record::from_rdata(name.clone(), 60, RData::CNAME(CNAME(target.clone()))),
            Record::from_rdata(name, 60, RData::SRV(SRV::new(0, 100, 88, target))),
        ];
        assert_eq!(
            records(&answers),
            [SrvRecord::new(0, 100, 88, "kdc.example.test.")]
        );
    }

    /// The system's resolver can be built here and asked, and a name that cannot exist is no
    /// records rather than a failure — or a failure, where this machine has no working DNS, which
    /// costs nothing but the Kerberos attempt.
    #[tokio::test]
    async fn the_system_resolver_answers_a_name_that_cannot_exist() {
        let Some(resolver) = system() else {
            return;
        };
        match resolver.resolve("_kerberos._tcp.example.invalid").await {
            Ok(records) => assert!(records.is_empty()),
            Err(error) => assert!(!error.to_string().is_empty()),
        }
        assert!(format!("{resolver:?}").contains("System"));
        let _ = resolver.resolve("_kerberos._tcp.example.invalid.").await;
    }
}
