//! The Kerberos legs of a `Negotiate` handshake that offers it first.
//!
//! One round trip when the server picks Kerberos, which is what Exchange does: the AP-REQ goes as
//! SPNEGO's optimistic token, and the success that answers it carries the AP-REP. More legs only
//! when the server asks for them — a clock-skew error to retry ([MS-KILE] §3.2.5.8), and then the
//! `mechListMIC` exchange [RFC 4178] §5 requires once the accepted token was not the optimistic
//! one, or `request-mic`.

use super::{Handshake, Mechanism, State};
use crate::binding::ChannelBinding;
use crate::error::{Error, Result};
use crate::kerberos::client::{KerberosEntropy, ServiceTicket};
use crate::kerberos::gss::{Initiator, Reply};
use crate::spnego::{self, KERBEROS_OID, NTLM_OID, NegState, ServerToken};

/// What is offered, most preferred first: Kerberos under the standard OID [MS-SPNG] §3.1.5.2 says
/// to use, then NTLM.
pub(super) const OFFERED: [&[u8]; 2] = [KERBEROS_OID, NTLM_OID];

/// The Kerberos half of a handshake.
#[derive(Clone, Debug)]
pub(super) struct Side {
    ticket: ServiceTicket,
    /// The first AP-REQ's entropy, and the retry's.
    entropy: [KerberosEntropy; 2],
    initiator: Option<Initiator>,
    /// Whether an AP-REP has been checked: the server has proved it holds the service key.
    proven: bool,
}

impl Side {
    pub(super) const fn new(ticket: ServiceTicket, entropy: [KerberosEntropy; 2]) -> Self {
        Self {
            ticket,
            entropy,
            initiator: None,
            proven: false,
        }
    }

    /// The first AP-REQ, bound to the channel the handshake runs over.
    pub(super) fn start(&mut self, binding: ChannelBinding) -> Result<Vec<u8>> {
        let [first, _] = &self.entropy;
        let (initiator, token) = Initiator::start(
            self.ticket.credential.clone(),
            binding,
            self.ticket.clock_offset,
            first.fresh(),
        )?;
        self.initiator = Some(initiator);
        Ok(token)
    }

    fn initiator(&mut self) -> Result<&mut Initiator> {
        self.initiator.as_mut().ok_or(Error::OutOfOrder {
            state: "not started",
            attempted: "read a Kerberos reply",
        })
    }

    /// Reads the server's Kerberos token.
    fn read(&mut self, token: &[u8]) -> Result<Reply> {
        let [_, retry] = self.entropy;
        let reply = self.initiator()?.read(token, retry.fresh())?;
        self.proven |= reply == Reply::Accepted;
        Ok(reply)
    }

    /// Checks the server's `mechListMIC` over the list this side offered.
    fn verify_mic(&mut self, mic: &[u8]) -> Result<()> {
        let list = spnego::mech_type_list(&OFFERED);
        self.initiator()?
            .verify_mic(&list, mic)
            .map_err(|_| Error::MechListMicMismatch {
                received: mic.to_vec(),
            })
    }
}

impl Handshake {
    /// Answers a 401 to the Kerberos token: a skew error to retry, or an AP-REP with
    /// `request-mic`. Anything else on a 401 is a refusal.
    pub(super) fn kerberos_answer(&mut self, server: &ServerToken) -> Result<String> {
        let refused = Error::Refused {
            scheme: self.scheme.name(),
        };
        let side = self.side()?;
        let Some(token) = server.response_token.as_deref() else {
            return Err(refused);
        };
        let reply = match side.read(token)? {
            Reply::Retry(ap_req) => spnego::response_token(Some(&ap_req), None),
            // [RFC 4178] §5 (b): an acceptor that requires the MIC exchange sends its last
            // mechanism token "and includes a mechlistMIC token and an accept-incomplete state",
            // and the initiator (I) verifies it and answers with its own "and an accept_complete
            // state". Measured: IIS does exactly this for a retry after `KRB_AP_ERR_SKEW`, where
            // the optimistic token was not the one accepted. `request-mic` asks for the same
            // answer without the acceptor's MIC.
            Reply::Accepted
                if server.mech_list_mic.is_some() || server.state == Some(NegState::RequestMic) =>
            {
                if let Some(theirs) = server.mech_list_mic.as_deref() {
                    side.verify_mic(theirs)?;
                }
                let list = spnego::mech_type_list(&OFFERED);
                let mic = side.initiator()?.mic(&list)?;
                self.state = State::Complete;
                spnego::completing_token(&mic)
            }
            Reply::Accepted => return Err(refused),
        };
        Ok(self.header(&reply))
    }

    /// Checks the success that ended a Kerberos handshake: the AP-REP, unless a 401 already
    /// carried it, and the server's `mechListMIC` if it sent one.
    pub(super) fn kerberos_finish(&mut self, www_authenticate: Option<&str>) -> Result<()> {
        if self.state == State::Ready {
            return Err(Error::OutOfOrder {
                state: "not started",
                attempted: "check the server's last token",
            });
        }
        let server = match www_authenticate.map(|value| self.decode(value)) {
            // The bare scheme name carries no token, which leaves nothing to prove the server.
            None | Some(Err(Error::Refused { .. })) => None,
            Some(token) => Some(spnego::parse(&token?)?),
        };
        if let Some(server) = &server {
            if server.state == Some(NegState::Reject) {
                return Err(Error::Refused {
                    scheme: self.scheme.name(),
                });
            }
            if self.select(server)? == Mechanism::Ntlm {
                return Err(Error::ServiceReply {
                    reason: "a success naming NTLM, which was never run",
                });
            }
        }

        let side = self.side()?;
        if !side.proven {
            let token = server
                .as_ref()
                .and_then(|server| server.response_token.as_deref())
                .ok_or(Error::ServiceReply {
                    reason: "a success without the AP-REP that proves the server",
                })?;
            if let Reply::Retry(_) = side.read(token)? {
                return Err(Error::ServiceReply {
                    reason: "a clock-skew error on a response that succeeded",
                });
            }
        }
        if let Some(mic) = server
            .as_ref()
            .and_then(|server| server.mech_list_mic.as_deref())
        {
            side.verify_mic(mic)?;
        }
        self.mechanism = Some(Mechanism::Kerberos);
        self.state = State::Complete;
        Ok(())
    }

    fn side(&mut self) -> Result<&mut Side> {
        self.kerberos.as_deref_mut().ok_or(Error::OutOfOrder {
            state: "without a Kerberos ticket",
            attempted: "read a Kerberos reply",
        })
    }
}
