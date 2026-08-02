//! A live Session Context, and the round trip that drives it.
//!
//! MAPI/HTTP allows exactly one request in flight per Session Context, and a server reports the
//! violation as `X-ResponseCode` 15 (Invalid Sequence) — a diagnostic that points nowhere near the
//! cause. That rule is not documented here and hoped for: every method that sends anything takes
//! `&mut self`, so the borrow checker refuses a second request while the first is outstanding.
//!
//! [MS-OXCMAPIHTTP] §2.2.3.3.3 — `X-ResponseCode` 15

use mapi_proto::{
    Connected, Execution, LegacyDn, Outcome, Request, RopBatch, RopResponse, Session,
};

use crate::describe;
use crate::error::{Error, Result};
use crate::logon::Logon;
use crate::transport::Transport;

/// One established Session Context.
///
/// Dropping this leaves the context for the server to time out. [`disconnect`](Self::disconnect)
/// tears it down at once, which is the polite thing to do and the only way to free the server's
/// handles before the timeout.
#[derive(Debug)]
pub struct Connection {
    transport: Transport,
    session: Session,
    connected: Connected,
    user_dn: LegacyDn,
    /// Why this connection stopped being usable, if it did. See [`Error::Poisoned`].
    poison: Option<String>,
}

impl Connection {
    pub(crate) const fn new(
        transport: Transport,
        session: Session,
        connected: Connected,
        user_dn: LegacyDn,
    ) -> Self {
        Self {
            transport,
            session,
            connected,
            user_dn,
            poison: None,
        }
    }

    /// What the server reported when the Session Context was established: the mailbox owner's
    /// display name, and the retry advice.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.1.2 — `Connect` success response body
    #[must_use]
    pub const fn server(&self) -> &Connected {
        &self.connected
    }

    /// Logs on to the mailbox, which is what every later ROP hangs off.
    ///
    /// One round trip. The [`Logon`] takes ownership of this connection: there is one logon per
    /// Session Context, so nothing is lost, and it means the logon handle cannot outlive the
    /// session it belongs to.
    ///
    /// # Errors
    ///
    /// [`Error::Rop`] if the server refused the logon — `LoginPermission` for an account without
    /// rights to the mailbox, `UnknownUser` for a distinguished name it cannot map — or
    /// [`Error::WrongServer`] if the mailbox has moved. Whatever the reason, this connection's
    /// Session Context is torn down on the way out rather than left for the server to time out.
    ///
    /// [MS-OXCROPS] §2.2.3.1 — `RopLogon`
    pub async fn logon(mut self) -> Result<Logon> {
        let mut batch = RopBatch::new();
        let slot = batch.logon(&self.user_dn.clone());

        let execution = match self.execute(batch, "the logon").await {
            Ok(execution) => execution,
            Err(error) => {
                self.close_quietly().await;
                return Err(error);
            }
        };

        let (Some(response), Some(handle)) = (execution.logon(), execution.handle(slot)) else {
            self.close_quietly().await;
            return Err(Error::Unexpected {
                expected: "a RopLogon response",
                found: "no logon in the batch's responses",
            });
        };

        Ok(Logon::new(self, handle, response.clone()))
    }

    /// Tears the Session Context down.
    ///
    /// # Errors
    ///
    /// Whatever the round trip failed with. A failure here has already cost nothing: the server
    /// times an abandoned Session Context out on its own.
    ///
    /// [MS-OXCMAPIHTTP] §2.2.4.3 — `Disconnect`
    pub async fn disconnect(mut self) -> Result<()> {
        self.usable()?;
        let request = self.session.begin_disconnect()?;
        match self.round_trip(request).await? {
            Outcome::Disconnected => Ok(()),
            other => Err(Error::Unexpected {
                expected: "a Disconnect response",
                found: describe(&other),
            }),
        }
    }

    /// Tears the Session Context down without reporting whether it worked.
    ///
    /// For the error paths, where the caller already has a more informative failure in hand and a
    /// second one would only bury it. Skipped entirely when the connection is poisoned, because
    /// then the round trip is known to be pointless.
    async fn close_quietly(&mut self) {
        if self.poison.is_some() {
            return;
        }
        if let Ok(request) = self.session.begin_disconnect() {
            let _ = self.round_trip(request).await;
        }
    }

    /// Runs a batch of ROPs and reports the first refusal in it as an error.
    ///
    /// A failing ROP does not fail the `Execute` — the server runs what it can and reports each
    /// result — so a caller that only checked the transport would read a plausible-looking empty
    /// answer instead of a refusal.
    pub(crate) async fn execute(
        &mut self,
        batch: RopBatch,
        during: &'static str,
    ) -> Result<Execution> {
        self.usable()?;
        let request = self.session.execute(batch)?;
        let outcome = self.round_trip(request).await?;

        let Outcome::Executed(execution) = outcome else {
            return Err(Error::Unexpected {
                expected: "an Execute response",
                found: describe(&outcome),
            });
        };

        for response in execution.responses() {
            if let Some(error) = refusal(response, during) {
                return Err(error);
            }
        }
        Ok(execution)
    }

    /// Sends one request and interprets the answer, poisoning the connection if it never arrived.
    async fn round_trip(&mut self, request: Request) -> Result<Outcome> {
        match self.transport.send(&request).await {
            Ok((headers, body)) => Ok(self.session.on_response(&headers, &body)?),
            Err(error) => {
                // The request went out and no answer came back, so whether the server acted on it
                // is unknowable. Sending the next request regardless is how a client ends up
                // reading the answer to the previous one.
                self.poison = Some(error.to_string());
                Err(error)
            }
        }
    }

    fn usable(&self) -> Result<()> {
        match &self.poison {
            Some(cause) => Err(Error::Poisoned {
                cause: cause.clone(),
            }),
            None => Ok(()),
        }
    }
}

/// Turns a refused ROP response into the error that says what to do about it.
///
/// `None` for every response that is not a refusal, including the successful ones and the
/// `RopRelease` that produces no response at all.
fn refusal(response: &RopResponse, during: &'static str) -> Option<Error> {
    match response {
        RopResponse::LogonRedirect { server_name } => Some(Error::WrongServer {
            server_name: server_name.clone(),
        }),
        RopResponse::Failed { code, .. } => Some(Error::Rop {
            during,
            code: *code,
        }),
        RopResponse::BufferTooSmall { size_needed } => Some(Error::PageTooLarge {
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
            Some(Error::PageTooLarge { size_needed: 4096 })
        ));

        let busy = RopResponse::Backoff { duration_ms: 5000 };
        assert!(matches!(
            refusal(&busy, "x"),
            Some(Error::Backoff { duration_ms: 5000 })
        ));
    }
}
