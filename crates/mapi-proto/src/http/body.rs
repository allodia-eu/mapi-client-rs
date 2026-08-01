//! Response bodies for the request types this crate sends.
//!
//! Every one of them has the same trap: **a failure body is not a success body with zeros in it.**
//! It stops right after `StatusCode`, so parsing it with the success layout turns a clear server
//! verdict into a confusing truncation error.
//!
//! [MS-OXCMAPIHTTP] §2.2.4.1.2 — `Connect` success response body
//! [MS-OXCMAPIHTTP] §2.2.4.1.3 — `Connect` failure response body
//! [MS-OXCMAPIHTTP] §2.2.4.2.2 — `Execute` success response body
//! [MS-OXCMAPIHTTP] §2.2.4.2.3 — `Execute` failure response body

use crate::error::{ErrorCode, Result};
use crate::wire::Reader;

/// A parsed `Connect` response body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ConnectResponse {
    pub(crate) status_code: u32,
    pub(crate) error_code: ErrorCode,
    pub(crate) polls_max: u32,
    pub(crate) retry_count: u32,
    pub(crate) retry_delay: u32,
    pub(crate) dn_prefix: String,
    pub(crate) display_name: String,
}

impl ConnectResponse {
    pub(crate) fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let status_code = r.u32()?;
        if status_code != 0 {
            return Ok(Self {
                status_code,
                ..Self::default()
            });
        }

        Ok(Self {
            status_code,
            error_code: ErrorCode::new(r.u32()?),
            polls_max: r.u32()?,
            retry_count: r.u32()?,
            retry_delay: r.u32()?,
            dn_prefix: r.ascii_z()?,
            display_name: r.utf16_z()?,
        })
    }

    pub(crate) const fn is_success(&self) -> bool {
        self.status_code == 0 && self.error_code.is_success()
    }
}

/// A parsed `Execute` response body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExecuteResponse {
    pub(crate) status_code: u32,
    pub(crate) error_code: ErrorCode,
    pub(crate) rop_buffer: Vec<u8>,
}

impl ExecuteResponse {
    pub(crate) fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let status_code = r.u32()?;
        if status_code != 0 {
            return Ok(Self {
                status_code,
                ..Self::default()
            });
        }

        let error_code = ErrorCode::new(r.u32()?);
        let _flags = r.u32()?;
        let size = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
        Ok(Self {
            status_code,
            error_code,
            rop_buffer: r.bytes(size)?.to_vec(),
        })
    }

    pub(crate) const fn is_success(&self) -> bool {
        self.status_code == 0 && self.error_code.is_success()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Writer;

    #[test]
    fn a_connect_success_body_round_trips() {
        let mut w = Writer::new();
        w.u32(0).u32(0).u32(60_000).u32(3).u32(1_000);
        w.ascii_z("/o=First Organization/ou=Exchange Administrative Group");
        for unit in "Spike Test Usr".encode_utf16() {
            w.u16(unit);
        }
        w.u16(0).u32(0);

        let response = ConnectResponse::parse(&w.finish()).unwrap();
        assert!(response.is_success());
        assert_eq!(response.polls_max, 60_000);
        assert_eq!(response.retry_count, 3);
        assert_eq!(response.retry_delay, 1_000);
        assert!(response.dn_prefix.starts_with("/o="));
        assert_eq!(response.display_name, "Spike Test Usr");
    }

    /// §2.2.4.1.3: the failure body stops after `StatusCode`. Everything the success layout
    /// promises is simply absent.
    #[test]
    fn a_connect_failure_body_parses_as_a_verdict_not_a_truncation() {
        let mut w = Writer::new();
        w.u32(0x0000_000A).u32(0);

        let response = ConnectResponse::parse(&w.finish()).unwrap();
        assert!(!response.is_success());
        assert_eq!(response.status_code, 0x0000_000A);
        assert!(response.display_name.is_empty());
    }

    #[test]
    fn a_connect_body_reports_the_servers_error_code() {
        let mut w = Writer::new();
        w.u32(0)
            .u32(ErrorCode::UNKNOWN_USER.as_u32())
            .u32(0)
            .u32(0)
            .u32(0);
        w.ascii_z("").u16(0);

        let response = ConnectResponse::parse(&w.finish()).unwrap();
        assert!(!response.is_success());
        assert_eq!(response.error_code, ErrorCode::UNKNOWN_USER);
    }

    #[test]
    fn an_execute_success_body_carries_the_rop_buffer() {
        let mut w = Writer::new();
        w.u32(0)
            .u32(0)
            .u32(0)
            .u32(3)
            .bytes(&[0xAA, 0xBB, 0xCC])
            .u32(0);

        let response = ExecuteResponse::parse(&w.finish()).unwrap();
        assert!(response.is_success());
        assert_eq!(response.rop_buffer, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn an_execute_failure_body_is_truncated_after_status() {
        let mut w = Writer::new();
        w.u32(0x0000_000A);

        let response = ExecuteResponse::parse(&w.finish()).unwrap();
        assert!(!response.is_success());
        assert_eq!(response.status_code, 0x0000_000A);
        assert!(response.rop_buffer.is_empty());
    }

    #[test]
    fn a_lying_rop_buffer_size_is_an_error_not_a_panic() {
        let mut w = Writer::new();
        w.u32(0).u32(0).u32(0).u32(0xFFFF_FFFF).bytes(&[0xAA]);
        assert!(ExecuteResponse::parse(&w.finish()).is_err());
    }

    #[test]
    fn hostile_response_bodies_never_panic() {
        for body in [
            &b""[..],
            &[0x00][..],
            &[0x00, 0x00, 0x00, 0x00][..],
            &[0xFF; 7][..],
            &[0x00; 24][..],
        ] {
            let _ = ConnectResponse::parse(body);
            let _ = ExecuteResponse::parse(body);
        }
    }
}
