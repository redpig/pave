//! One request type for every mint: refills, post tokens, votes, check-ins
//! and shift keys are all the same thing with a different spec and body.
//!
//! A request is signed by a fresh randomization of a group credential (an
//! access class, a voter roll, a co-op's members) over the spec, the period,
//! the slot, the request time, a profile-specific body and the signer's
//! standing. What the basename links is the spec's [`Linkage`]:
//!
//! - [`Linkage::Slots`]: (domain, scope, period, slot), a budget of requests
//!   per period that can't be linked to each other, then linked ones (see
//!   [`crate::slots`]). Refills, post tokens, shift keys.
//! - [`Linkage::Period`]: (domain, scope, period), one pseudonym per holder
//!   per period: counting. Check-ins.
//! - [`Linkage::Scope`]: (domain, scope), one pseudonym per holder for the
//!   whole scope: one live coin per voter. Votes.
//!
//! A request may also carry more signatures over the same bytes: by the same
//! credential under another basename (a pseudonym for a purpose), or by a
//! credential of another group with no basename (showing membership, linking
//! nothing). The spec is data, so an app can build any mint's requests from
//! a profile's description alone.

use crate::bulletin::Cheat;
use pave_kernel::hash::{encode, Hash};
use pave_kernel::{Credential, Scheme, Sig};
use pave_protocol::Standing;
use pave_scheme_briolette::{BrioletteV1, HolderKey};
use serde::{Deserialize, Serialize};

/// What a request's basename links.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Linkage {
    /// A budget of this many unlinkable requests per period.
    Slots(u32),
    /// One pseudonym per holder per period.
    Period,
    /// One pseudonym per holder for the scope.
    Scope,
}

/// How a mint's requests are formed and checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestSpec {
    /// A domain string with a version, such as `pave/ticket-request/v2`.
    pub domain: String,
    /// The mint, sequence, election or dispatch the requests go to.
    pub scope: Hash,
    pub linkage: Linkage,
    /// How far a request's time may be from the mint's, in milliseconds, or
    /// None to take any.
    pub max_skew_ms: Option<u64>,
}

/// A request: the spec's fields, a profile's body, and the signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request<B> {
    pub period: u64,
    pub slot: u32,
    /// When it was made, in milliseconds since 1970.
    pub at: u64,
    pub body: B,
    pub signer: Credential,
    /// The signer's standing against the mint's ruled list.
    pub standing: Standing,
    pub sig: Sig,
    pub also: Vec<Also>,
}

/// Another signature over a request's bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Also {
    /// By the same credential under another basename: a pseudonym for that.
    Basename { basename: Vec<u8>, sig: Sig },
    /// By a credential of another group, with no basename: shows membership.
    Shown { credential: Credential, sig: Sig },
}

/// What a mint expects in a request's [`Also`], in order.
pub enum Expect<'a> {
    Basename(Vec<u8>),
    Shown(&'a [u8]),
}

/// A checked request: the group that signed it, its pseudonym, and the
/// pseudonym of each [`Also::Basename`] (None for [`Also::Shown`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub group: String,
    pub nym: Vec<u8>,
    pub also: Vec<Option<Vec<u8>>>,
}

/// Milliseconds since 1970.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

impl RequestSpec {
    /// The basename for a period and slot, as the linkage says.
    pub fn basename(&self, period: u64, slot: u32) -> Vec<u8> {
        match self.linkage {
            Linkage::Slots(_) => crate::slots::basename(&self.domain, &self.scope, period, slot),
            Linkage::Period => encode(&(&self.domain, self.scope, period)),
            Linkage::Scope => encode(&(&self.domain, self.scope)),
        }
    }

    fn bytes<B: Serialize>(&self, period: u64, slot: u32, at: u64, body: &B, standing: &Standing) -> Vec<u8> {
        encode(&("pave/request/v1", &self.domain, self.scope, period, slot, at, body, standing))
    }

    /// Sign a request with `key`, a member of the group `group`, proving
    /// standing against `ruled`. `basenames` adds signatures by the same
    /// credential under other basenames; `shown` adds signatures by
    /// credentials of other groups, each a (key, group key).
    #[allow(clippy::too_many_arguments)]
    pub fn sign<B: Serialize>(&self, key: &HolderKey, group: &[u8], period: u64, slot: u32, body: B, ruled: &[Cheat], basenames: &[Vec<u8>], shown: &[(&HolderKey, &[u8])]) -> Result<Request<B>, String> {
        self.sign_at(now_ms(), key, group, period, slot, body, ruled, basenames, shown)
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_at<B: Serialize>(&self, at: u64, key: &HolderKey, group: &[u8], period: u64, slot: u32, body: B, ruled: &[Cheat], basenames: &[Vec<u8>], shown: &[(&HolderKey, &[u8])]) -> Result<Request<B>, String> {
        let a = BrioletteV1 { group_public_key: group.to_vec() };
        let signer = a.credential(key);
        let standing = Standing::prove(&a, key, &signer, ruled).ok_or("ruled out: no standing against the mint's list")?;
        let msg = self.bytes(period, slot, at, &body, &standing);
        let sig = a.sign(key, &signer, &msg, Some(&self.basename(period, slot)));
        let mut also: Vec<Also> = basenames.iter().map(|b| Also::Basename { basename: b.clone(), sig: a.sign(key, &signer, &msg, Some(b)) }).collect();
        for (k, g) in shown {
            let s = BrioletteV1 { group_public_key: g.to_vec() };
            let credential = s.credential(k);
            let sig = s.sign(k, &credential, &msg, None);
            also.push(Also::Shown { credential, sig });
        }
        Ok(Request { period, slot, at, body, signer, standing, sig, also })
    }

    /// Check a request at the mint: the slot within the budget, fresh if the
    /// spec asks, signed by a member of one of `groups` (name, group key),
    /// standing against `ruled`, and each extra signature as `expect` says.
    pub fn verify<'a, B: Serialize>(&self, req: &Request<B>, groups: impl IntoIterator<Item = (&'a String, &'a Vec<u8>)>, ruled: &[Cheat], expect: &[Expect]) -> Result<Verified, String> {
        match self.linkage {
            Linkage::Slots(n) if req.slot >= n => return Err(format!("slots are 0 to {}", n - 1)),
            Linkage::Period | Linkage::Scope if req.slot != 0 => return Err("this request has no slots".into()),
            _ => {}
        }
        if let Some(skew) = self.max_skew_ms {
            if req.at.abs_diff(now_ms()) > skew {
                return Err("a stale request".into());
            }
        }
        let msg = self.bytes(req.period, req.slot, req.at, &req.body, &req.standing);
        let bsn = self.basename(req.period, req.slot);
        let (group, a) = groups
            .into_iter()
            .map(|(name, g)| (name.clone(), BrioletteV1 { group_public_key: g.clone() }))
            .find(|(_, a)| a.verify(&req.signer, &msg, Some(&bsn), &req.sig))
            .ok_or("not signed by a member")?;
        let nym = a.nym(&req.sig).ok_or("no pseudonym")?;
        let st = &req.standing;
        if st.credential != req.signer || !st.covers(ruled) || !st.verify(&a) {
            return Err("ruled out: no standing against the mint's list".into());
        }
        if req.also.len() != expect.len() {
            return Err("missing or extra signatures".into());
        }
        let mut also = vec![];
        for (x, e) in req.also.iter().zip(expect) {
            match (x, e) {
                (Also::Basename { basename, sig }, Expect::Basename(want)) if basename == want && a.verify(&req.signer, &msg, Some(basename), sig) => also.push(Some(a.nym(sig).ok_or("no pseudonym")?)),
                (Also::Shown { credential, sig }, Expect::Shown(g)) if (BrioletteV1 { group_public_key: g.to_vec() }).verify(credential, &msg, None, sig) => also.push(None),
                _ => return Err("an extra signature doesn't check out".into()),
            }
        }
        Ok(Verified { group, nym, also })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pave_scheme_briolette::{Issuer, PendingKey};

    fn member(i: &Issuer) -> HolderKey {
        let (p, req) = PendingKey::generate(&pave_scheme_briolette::join_nonce());
        p.finish(&BrioletteV1 { group_public_key: i.group_public_key.clone() }, &i.issue(&req).unwrap()).unwrap()
    }

    fn spec(linkage: Linkage, skew: Option<u64>) -> RequestSpec {
        RequestSpec { domain: "test/v1".into(), scope: Hash([7; 32]), linkage, max_skew_ms: skew }
    }

    #[test]
    fn checks() {
        let (roll, other) = (Issuer::new(), Issuer::new());
        let (k, o) = (member(&roll), member(&other));
        let groups = [("roll".to_string(), roll.group_public_key.clone())];
        let g = || groups.iter().map(|(n, g)| (n, g));

        // Slots: within the budget, the same holder's slots give unrelated
        // pseudonyms; one slot twice gives the same one.
        let s = spec(Linkage::Slots(2), None);
        let a = s.verify(&s.sign(&k, &roll.group_public_key, 1, 0, 1u8, &[], &[], &[]).unwrap(), g(), &[], &[]).unwrap();
        let b = s.verify(&s.sign(&k, &roll.group_public_key, 1, 1, 1u8, &[], &[], &[]).unwrap(), g(), &[], &[]).unwrap();
        let c = s.verify(&s.sign(&k, &roll.group_public_key, 1, 0, 2u8, &[], &[], &[]).unwrap(), g(), &[], &[]).unwrap();
        assert_ne!(a.nym, b.nym);
        assert_eq!(a.nym, c.nym);
        assert!(s.verify(&s.sign(&k, &roll.group_public_key, 1, 2, 1u8, &[], &[], &[]).unwrap(), g(), &[], &[]).is_err());

        // A request without slots takes only slot 0.
        let p = spec(Linkage::Period, None);
        assert!(p.verify(&p.sign(&k, &roll.group_public_key, 1, 3, 1u8, &[], &[], &[]).unwrap(), g(), &[], &[]).unwrap_err().contains("no slots"));

        // Freshness, when the spec asks for it.
        let f = spec(Linkage::Scope, Some(1000));
        let old = f.sign_at(now_ms() - 5000, &k, &roll.group_public_key, 0, 0, 1u8, &[], &[], &[]).unwrap();
        assert!(f.verify(&old, g(), &[], &[]).unwrap_err().contains("stale"));
        assert!(f.verify(&f.sign(&k, &roll.group_public_key, 0, 0, 1u8, &[], &[], &[]).unwrap(), g(), &[], &[]).is_ok());

        // Extra signatures: exactly what the mint expects, under the basename
        // it expects, or by a member of the group it names.
        let want = b"purpose one".to_vec();
        let r = s.sign(&k, &roll.group_public_key, 1, 0, 1u8, &[], std::slice::from_ref(&want), &[]).unwrap();
        assert!(s.verify(&r, g(), &[], &[Expect::Basename(want.clone())]).unwrap().also[0].is_some());
        assert!(s.verify(&r, g(), &[], &[]).unwrap_err().contains("missing or extra"));
        let wrong = s.sign(&k, &roll.group_public_key, 1, 0, 1u8, &[], &[b"purpose two".to_vec()], &[]).unwrap();
        assert!(s.verify(&wrong, g(), &[], &[Expect::Basename(want)]).is_err());
        let shown = s.sign(&k, &roll.group_public_key, 1, 0, 1u8, &[], &[], &[(&o, &other.group_public_key)]).unwrap();
        assert!(s.verify(&shown, g(), &[], &[Expect::Shown(&other.group_public_key)]).is_ok());
        assert!(s.verify(&shown, g(), &[], &[Expect::Shown(&roll.group_public_key)]).is_err());

        // Not a member: another group's key.
        assert!(s.verify(&s.sign(&o, &other.group_public_key, 1, 0, 1u8, &[], &[], &[]).unwrap(), g(), &[], &[]).is_err());
    }
}
