//! Food delivery's outcomes: what the description in `profiles/food.json`
//! can't say on its own, because it reads more than one record.
//!
//! - **The time witness is the board.** The kernel has no clock, so the
//!   customer's confirmation also goes out as a `delivered` note on the job
//!   board, in the order's thread. The board server stamps every post with
//!   its own clock (see [`crate::bulletin`]), so the note's clock is when it
//!   was delivered, as far as anyone can show.
//! - **The seal.** The bag's tamper seal carries the manifest's label code.
//!   At the door the customer reads it; the note says whether it matched.
//! - **The outcome** compares the note with the order's deadline: on time,
//!   late by so many seconds, or delivered with a broken seal. It is what a
//!   dispute over the order starts from.
//! - **Vouching for the courier.** The customer can vouch for the courier
//!   that handed the bag over, in the thread of that courier's key (best its
//!   badge on its trade key, so jobs and deliveries make one reputation; see
//!   [`crate::board`]). A vouch carries the parcel's custody records, so any
//!   reader checks it from the records alone: the bag was minted from a
//!   shipper's budget, the courier's key handed it to the addressee, the
//!   addressee confirmed it, and the vouch is signed by the addressee. Each
//!   parcel counts once, and each person once.
//! - **Offering the delivery.** The co-op named as the parcel's provider
//!   offers it as a job about the parcel, posted under that provider key,
//!   whose worker must show the dispatch's badge. Couriers reply
//!   anonymously; the co-op accepts one on its badge; the restaurant hands
//!   the bag only to the key that accept shows. Once custody shows that key
//!   handed it to the customer and the courier marks the job done, the
//!   co-op pays the job with a vouch: a coin the courier holds.

use crate::board::{contractor, Known};
use pave_kernel::Credential;
use crate::bulletin::purpose;
use crate::parcel::{label_hash, Manifest, Step};
use pave_kernel::hash::Hash;
use pave_kernel::Record;
use std::collections::BTreeSet;
use serde::{Deserialize, Serialize};

/// The customer's note on delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivered {
    pub order: Hash,
    pub seal_ok: bool,
}

/// The customer's vouch for the courier who delivered: the manifest, and
/// the records from the parcel's mint to its retirement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryVouch {
    pub manifest: Manifest,
    pub records: Vec<Record>,
    pub note: String,
}

/// One delivery vouch that counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryVouched {
    pub parcel: Hash,
    pub note: String,
}

/// How a food order went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// No delivered note from the customer's key yet.
    Pending,
    OnTime { at: u64 },
    Late { at: u64, by: u64 },
    /// Delivered, but the seal's code didn't match the label.
    SealBroken { at: u64 },
}

impl crate::node::Node {
    /// Customer: post that the order arrived, with whether the seal matched,
    /// signed by the key the order was delivered to. Confirm the parcel
    /// first; the note waits for the next sync with the board.
    pub fn note_delivered(&mut self, m: &Manifest, order: Hash, seal: &str) -> Result<Hash, String> {
        let seal_ok = m.label == Some(label_hash(&m.parcel, seal));
        let note = Delivered { order, seal_ok };
        let scope = self.town.jobs.scope;
        self.compose(&scope, &m.addressee, "delivered", Some(order), pave_kernel::hash::encode(&note), None)
    }

    /// Customer: vouch for the courier who handed this wallet the parcel,
    /// in that courier key's thread, counted once per person. The parcel
    /// must be delivered and confirmed.
    pub fn vouch_delivery(&mut self, m: &Manifest, note: &str) -> Result<Hash, String> {
        if !self.mine.contains(&m.addressee) {
            return Err("only the addressee vouches for its delivery".into());
        }
        let c = self.custody(m);
        if !c.delivered {
            return Err("not delivered".into());
        }
        let courier = c.steps.iter().rev().find_map(|s| match s {
            Step::Handoff { from, to } if *to == m.addressee => Some(from.clone()),
            _ => None,
        });
        let courier = courier.ok_or("no courier handed it over")?;
        let mut records: Vec<Record> = self.view.creator(&m.parcel).into_iter().cloned().collect();
        let mut state = m.parcel;
        while let Some(r) = self.view.spender(&state) {
            records.push(r.clone());
            state = r.output(0);
        }
        let who = contractor(&courier);
        let scope = self.town.jobs.scope;
        let v = DeliveryVouch { manifest: m.clone(), records, note: note.into() };
        self.compose(&scope, &m.addressee, "delivery vouch", Some(who), pave_kernel::hash::encode(&v), Some(purpose(&scope, "vouch", &who)))
    }

    /// Anyone: the delivery vouches for the courier key whose contractor id
    /// is `who`, and how many distinct people made them. Each vouch's
    /// records are learned first, as from any meet.
    pub fn delivery_vouches(&mut self, who: &Hash) -> (usize, Vec<DeliveryVouched>) {
        let scope = self.town.jobs.scope;
        let Ok(copy) = self.copy(&scope) else { return (0, vec![]) };
        let mut found = vec![];
        for i in copy.items() {
            if i.post.kind != "delivery vouch" || i.post.thread != Some(*who) {
                continue;
            }
            let Ok(v) = ciborium::from_reader::<DeliveryVouch, _>(i.content) else { continue };
            if *i.signer != v.manifest.addressee {
                continue;
            }
            let Some((_, nym)) = i.counted(&purpose(&scope, "vouch", who)) else { continue };
            found.push((v, nym));
        }
        let (mut parcels, mut people, mut out) = (BTreeSet::new(), BTreeSet::new(), vec![]);
        for (v, nym) in found {
            for r in &v.records {
                let _ = self.view.apply(r);
            }
            let m = &v.manifest;
            let c = self.custody(m);
            let by_courier = c.steps.iter().any(|s| matches!(s, Step::Handoff { from, to } if *to == m.addressee && contractor(from) == *who));
            if c.delivered && by_courier && parcels.insert(m.parcel) {
                people.insert(nym);
                out.push(DeliveryVouched { parcel: m.parcel, note: v.note });
            }
        }
        (people.len(), out)
    }

    /// Provider: offer the delivery of `m` as a job paying `pay`, under the
    /// provider key the manifest names, for couriers with its dispatch's
    /// badge.
    pub fn offer_delivery(&mut self, m: &Manifest, pay: u64) -> Result<Hash, String> {
        let provider = m.provider.clone().filter(|p| self.mine.contains(p)).ok_or("only the parcel's provider offers it")?;
        let d = m.dispatch.as_deref().ok_or("this parcel names no dispatch")?;
        self.post_as(provider, "Deliver a parcel", pay, Some(Known::Badge(d.clone())), Some(m.parcel))
    }

    /// The delivery job for `m`: the one job about it posted under the
    /// provider key, and the key of the courier accepted for it. None if
    /// the provider posted more than one: nobody is assigned until that's
    /// settled. (The profile's own gate still takes only badged keys.)
    pub fn delivery_job(&self, m: &Manifest) -> Option<(Hash, Option<Credential>)> {
        let provider = m.provider.as_ref()?;
        let mut offers = self.jobs().into_values().filter(|j| j.about == Some(m.parcel) && j.poster == *provider);
        let j = offers.next()?;
        offers.next().is_none().then_some((j.id, j.known_key))
    }

    /// Restaurant: the courier the provider assigned to `m`, if any.
    pub fn assigned_courier(&self, m: &Manifest) -> Option<Credential> {
        self.delivery_job(m)?.1
    }

    /// Provider: pay the delivery job for `m` and vouch for the courier,
    /// once custody shows the assigned courier's key handed it to the
    /// addressee and the addressee confirmed it.
    pub fn pay_delivery(&mut self, m: &Manifest, note: &str) -> Result<Hash, String> {
        let (job, key) = self.delivery_job(m).ok_or("no delivery job for this parcel")?;
        let key = key.ok_or("no courier accepted")?;
        let c = self.custody(m);
        let handed = c.steps.iter().any(|s| matches!(s, Step::Handoff { from, to } if *from == key && *to == m.addressee));
        if !c.delivered || !handed {
            return Err("custody doesn't show the assigned courier delivering it".into());
        }
        self.pay_and_vouch(job, "delivery", note, None)
    }

    /// Anyone: how the order went, from the board, against its deadline.
    pub fn food_outcome(&self, m: &Manifest, order: Hash, due: u64) -> Outcome {
        let Ok(copy) = self.copy(&self.town.jobs.scope) else { return Outcome::Pending };
        let note = copy.items().into_iter().find_map(|i| {
            let ok = i.post.kind == "delivered" && i.post.thread == Some(order) && *i.signer == m.addressee;
            let d: Delivered = ciborium::from_reader(i.content).ok()?;
            (ok && d.order == order).then_some((i.post.clock, d.seal_ok))
        });
        match note {
            None => Outcome::Pending,
            Some((at, false)) => Outcome::SealBroken { at },
            Some((at, true)) if at > due => Outcome::Late { at, by: at - due },
            Some((at, true)) => Outcome::OnTime { at },
        }
    }
}
