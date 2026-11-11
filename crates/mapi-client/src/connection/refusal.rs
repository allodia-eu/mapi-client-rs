//! What a refused ROP means, as an error.

use mapi_proto::RopResponse;

use crate::error::Error;

/// Turns a refused ROP response into the error that says what to do about it.
///
/// `None` for every response that is not a refusal, including the successful ones and the
/// `RopRelease` that produces no response at all.
pub(crate) fn refusal(response: &RopResponse, during: &'static str) -> Option<Error> {
    match response {
        RopResponse::LogonRedirect { server_name } => Some(Error::WrongServer {
            server_name: server_name.clone(),
        }),
        RopResponse::Failed { code, .. } => Some(Error::Rop {
            during,
            code: *code,
        }),
        RopResponse::BufferTooSmall { size_needed } => Some(Error::ResponseTooLarge {
            size_needed: *size_needed,
        }),
        RopResponse::Backoff { duration_ms } => Some(Error::Backoff {
            duration_ms: *duration_ms,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use mapi_proto::{ErrorCode, RopId};

    use super::*;

    #[test]
    fn every_kind_of_refusal_becomes_an_actionable_error() {
        let refused = RopResponse::Failed {
            rop: RopId::LOGON,
            code: ErrorCode::LOGIN_PERMISSION,
        };
        assert!(matches!(
            refusal(&refused, "the logon"),
            Some(Error::Rop {
                during: "the logon",
                code: ErrorCode::LOGIN_PERMISSION
            })
        ));

        let moved = RopResponse::LogonRedirect {
            server_name: "/o=Example/cn=other".to_owned(),
        };
        assert!(matches!(
            refusal(&moved, "x"),
            Some(Error::WrongServer { .. })
        ));

        let too_big = RopResponse::BufferTooSmall { size_needed: 4096 };
        assert!(matches!(
            refusal(&too_big, "x"),
            Some(Error::ResponseTooLarge { size_needed: 4096 })
        ));

        let busy = RopResponse::Backoff { duration_ms: 5000 };
        assert!(matches!(
            refusal(&busy, "x"),
            Some(Error::Backoff { duration_ms: 5000 })
        ));
    }
}
