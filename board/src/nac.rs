//! Network access: every service a node exposes asks for a NAC.
//!
//! A wallet's access credential, from its class's issuer, is its network
//! access credential, as in Briolette. Every connection starts with one:
//!
//! - The server sends a fresh challenge and the epoch it is in.
//! - The client signs the challenge with a fresh randomization of its access
//!   credential, with (service, epoch) as basename. The service is the name
//!   the client dialed, chosen by the client, so a server can't make a
//!   client sign under another service's basename and link it across
//!   services.
//! - The server learns the client's class and a pseudonym for this service
//!   in this epoch, nothing else. It counts connections per pseudonym and
//!   refuses past a limit, refuses classes it doesn't know, and can bar a
//!   pseudonym for the rest of the epoch.
//!
//! The pseudonym changes every epoch and differs between services, so the
//! gate rate-limits without tracking anyone.

use crate::node::Node;
use pave_kernel::hash::encode;
use pave_kernel::{Credential, Scheme, Sig};
use pave_scheme_briolette::BrioletteV1;
use serde::{Deserialize, Serialize};

/// Connections one pseudonym may open to one service in one epoch.
pub const NAC_LIMIT: u32 = 4096;

/// The server's opening: a challenge to sign, and its epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub nonce: [u8; 32],
    pub epoch: u32,
}

/// The client's answer: a signature by a fresh randomization of its access
/// credential, with (service, epoch) as basename.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NacProof {
    pub access: Credential,
    pub sig: Sig,
}

pub fn basename(service: &str, epoch: u32) -> Vec<u8> {
    encode(&("pave/nac/v0", service, epoch))
}

fn signed(service: &str, c: &Challenge) -> Vec<u8> {
    encode(&("pave/nac/v0", service, c.nonce, c.epoch))
}

/// What a server knows about a client after the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub class: String,
    pub nym: Vec<u8>,
}

impl Node {
    /// Server: a challenge for a new connection.
    pub fn nac_challenge(&self) -> Challenge {
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        Challenge {
            nonce,
            epoch: self.epoch(),
        }
    }

    /// Client: answer a challenge from `service`, the name it dialed.
    ///
    /// Refuses a challenge more than an epoch behind its own: a server that
    /// kept an old epoch would keep the client's pseudonym from changing. A
    /// challenge ahead is fine; the client has been away and is catching up.
    pub fn nac_prove(&self, service: &str, c: &Challenge) -> Result<NacProof, String> {
        if c.epoch + 1 < self.epoch() {
            return Err(format!(
                "the service is at epoch {}, this node at {}",
                c.epoch,
                self.epoch()
            ));
        }
        let a = BrioletteV1 {
            group_public_key: self.town.classes[&self.class].group_public_key.clone(),
        };
        let access = a.credential(&self.access);
        let sig = a.sign(
            &self.access,
            &access,
            &signed(service, c),
            Some(&basename(service, c.epoch)),
        );
        Ok(NacProof { access, sig })
    }

    /// Server: check a client's answer for this node's `service` name, and
    /// count the connection against its pseudonym.
    pub fn nac_admit(
        &mut self,
        service: &str,
        c: &Challenge,
        p: &NacProof,
    ) -> Result<Admitted, String> {
        let msg = signed(service, c);
        let bsn = basename(service, c.epoch);
        let admitted = self.town.classes.iter().find_map(|(name, class)| {
            let a = BrioletteV1 {
                group_public_key: class.group_public_key.clone(),
            };
            (a.verify(&p.access, &msg, Some(&bsn), &p.sig))
                .then(|| a.nym(&p.sig))
                .flatten()
                .map(|nym| Admitted {
                    class: name.clone(),
                    nym,
                })
        });
        let admitted = admitted.ok_or("no network access credential of this town")?;
        if self.nac_barred.contains(&(c.epoch, admitted.nym.clone())) {
            return Err("barred from this service for this epoch".into());
        }
        // Forget earlier epochs' counts and bars.
        self.nac_seen.retain(|(e, _), _| *e + 1 >= c.epoch);
        self.nac_barred.retain(|(e, _)| *e + 1 >= c.epoch);
        let n = self
            .nac_seen
            .entry((c.epoch, admitted.nym.clone()))
            .or_insert(0);
        *n += 1;
        if *n > self.nac_limit {
            return Err("too many connections this epoch".into());
        }
        Ok(admitted)
    }

    /// Server: bar a pseudonym from this service for the rest of the epoch.
    pub fn nac_bar(&mut self, epoch: u32, nym: Vec<u8>) {
        self.nac_barred.insert((epoch, nym));
    }
}
