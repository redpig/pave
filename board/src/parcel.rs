//! Packages: custody as a coin.
//!
//! A package is a parcel coin: one, not divisible, never expiring, with a
//! limit on handoffs. Everything here is ordinary kernel operations.
//!
//! - **Shipping.** The town gives a shipper a parcel budget. Shipping mints
//!   one parcel to the shipper. The parcel's id is its origin state.
//! - **Manifest.** What it is, where from and to, who it is for (the
//!   addressee's credential) and the pay per hop. It travels with the
//!   parcel, hand to hand, and every handoff's receipt commits to its hash.
//! - **Handoff.** The holder transfers the parcel to the next courier's
//!   credential. The courier wants it: holding it is what gets them paid.
//! - **Take.** The courier acknowledges by moving the parcel to a fresh
//!   credential of its own. That record only the courier can sign, so the
//!   giver can show the handoff happened.
//! - **Delivery.** The addressee retires the parcel. Only the addressee's
//!   credential can sign that, so "delivered" can't be claimed by a courier.
//! - **Double handoff.** Handing one parcel to two people is using one
//!   state twice: the kernel's evidence, as for a double spend.
//! - **Delivery modes.** The shipper picks one in the manifest. *Signed*:
//!   the addressee retires the parcel. *Code*: the recipient has no wallet
//!   and tells the courier a code at the door; the courier's closing record
//!   commits to it, and only the shipper, who knows it, can check. *Drop*:
//!   unattended; the closing record commits to the cell and a salted photo
//!   hash, the courier posts a matching note on the job board, and it
//!   counts as delivered once a window of epochs passes without a dispute.
//! - **Disputes.** A party (the addressee, the shipper, a courier) can
//!   dispute delivery on the job board (see [`crate::dispute`]). The final
//!   ruling decides, unless the addressee signed; a referral holds it.
//! - **Provider.** A shipper may name a shipping provider, such as a co-op,
//!   before the first handoff. Then the shipper pays the provider once it
//!   is delivered, and the provider pays its couriers.
//! - **A dispatch.** A provider's co-op may run a dispatch (see
//!   [`crate::dispatch`]), named in the manifest before the first handoff.
//!   Then the parcel is handed only to keys with that dispatch's shift
//!   ticket, taken under one, checked with the dispatch's clerk trusted, and
//!   its couriers are paid only at such keys. A courier the dispatch ruled
//!   out has its keys revoked, so nobody takes a parcel from it.
//! - **A lost phone.** The parcel's token was on the phone; the package
//!   wasn't. Its label carries a code the shipper keeps. Whoever has the
//!   package and the code can ask the shipper to remint it to a new key.
//! - **Remints are layered on a lineage coin.** Shipping mints two parcel
//!   coins: the token that travels, and a lineage coin the shipper keeps.
//!   The manifest names the lineage and the token's generation. A remint
//!   moves the lineage coin to the shipper's own fresh key, its receipt
//!   committing to the old and new parcel, and mints a token for the next
//!   generation. So reminting twice is one lineage state used twice: kernel
//!   evidence against the shipper. A token whose generation is behind its
//!   lineage is void, and takers refuse it as they refuse a stale epoch.
//!   The shipper posts the lineage record on the job board so takers hear
//!   of it, and pays the old token's couriers up to the remint, never after.
//! - **Who holds it.** A courier may post a note on the job board when it
//!   takes a parcel, signed with one of its identities: whoever was given
//!   that identity (the co-op's dispatch) sees which member holds it.
//! - **Pay.** Once it is delivered, the shipper pays the signer of every
//!   handoff after its own, each payment's receipt naming the parcel, and
//!   never a courier caught handing one parcel to two people.

use crate::node::{apply_ok, Node};
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{Credential, Kind, Op, Schema};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Most transfers a parcel may make, takes included.
pub const MAX_HOPS: u32 = 32;

pub fn parcel_schema() -> Schema {
    Schema {
        label: "parcel".into(),
        divisible: false,
        soft_expiry: None,
        hard_expiry: None,
        offline_transfers: Some(MAX_HOPS),
        max_per_holder: None,
        sequence: None,
    }
}

/// How delivery is shown.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// The addressee retires the parcel.
    #[default]
    Signed,
    /// The courier commits to a code the recipient gives at the door.
    Code,
    /// Left unattended; settles after `window` epochs without a dispute.
    Drop { window: u32 },
}

/// What travels with a parcel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub parcel: Hash,
    pub what: String,
    pub from_cell: String,
    pub to_cell: String,
    /// The credential that may confirm delivery.
    pub addressee: Credential,
    pub pay_per_hop: u64,
    #[serde(default)]
    pub mode: Mode,
    /// The shipping provider (a co-op), if the shipper pays one rather than
    /// the couriers: the credential it is paid at.
    #[serde(default)]
    pub provider: Option<Credential>,
    /// The hash of the code on the parcel's label.
    #[serde(default)]
    pub label: Option<Hash>,
    /// The dispatch whose couriers carry it, if any.
    #[serde(default)]
    pub dispatch: Option<crate::dispatch::Roster>,
    /// The parcel this one replaces, after a remint.
    #[serde(default)]
    pub replaces: Option<Hash>,
    /// The lineage coin the shipper keeps, and this token's generation in it.
    #[serde(default)]
    pub lineage: Option<Hash>,
    #[serde(default)]
    pub generation: u32,
    /// What the parcel is for, such as the hash of an order's binding.
    #[serde(default)]
    pub about: Option<Hash>,
}

impl Manifest {
    pub fn hash(&self) -> Hash {
        hash_of("pave/parcel/manifest", self)
    }
}

/// The receipt of the transfer that makes `hop`: a handoff to someone else,
/// or a take by the one who received it.
pub fn handoff_receipt(manifest: &Hash, hop: u32) -> Hash {
    hash_of("pave/parcel/handoff", &(manifest, hop))
}

pub fn take_receipt(manifest: &Hash, hop: u32) -> Hash {
    hash_of("pave/parcel/take", &(manifest, hop))
}

pub fn code_receipt(manifest: &Hash, hop: u32, code: &str) -> Hash {
    hash_of("pave/parcel/code", &(manifest, hop, code))
}

pub fn drop_receipt(manifest: &Hash, hop: u32, cell: &str, photo: &Hash) -> Hash {
    hash_of("pave/parcel/drop", &(manifest, hop, cell, photo))
}

pub fn remint_receipt(old: &Hash, new: &Hash) -> Hash {
    hash_of("pave/parcel/remint", &(old, new))
}

pub fn label_hash(parcel: &Hash, code: &str) -> Hash {
    hash_of("pave/parcel/label", &(parcel, code))
}

pub fn shipping_receipt(parcel: &Hash) -> Hash {
    hash_of("pave/parcel/shipping", parcel)
}

pub fn pay_receipt(parcel: &Hash, courier: &Credential) -> Hash {
    hash_of("pave/parcel/pay", &(parcel, courier))
}

/// One step in a parcel's custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Step {
    /// `from` handed it to `to`.
    Handoff { from: Credential, to: Credential },
    /// `by` acknowledged taking it.
    Take { by: Credential },
    /// The holder retired it: delivered, if it was the addressee.
    Retired { by: Credential },
    /// The holder closed it by code or drop: a transfer to itself whose
    /// receipt is neither a handoff nor a take.
    Closed {
        by: Credential,
        receipt: Hash,
        hop: u32,
    },
}

/// Where delivery stands, as this wallet sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Delivery {
    InTransit,
    /// Delivered, and how it is shown: "signed", "code", "drop" or "ruled".
    Delivered(&'static str),
    /// A drop waiting out its window, until this epoch.
    Pending(u32),
    /// Closed by code, and this wallet can't check the code.
    Unverified,
    /// A party's dispute is open.
    Disputed,
    /// Ruled not delivered.
    NotDelivered,
    /// Referred to an outside authority.
    Referred(String),
    /// Reminted: this token is void, and the parcel goes on as this one,
    /// if this wallet knows it.
    Replaced(Option<Hash>),
}

#[derive(Clone, Debug, Serialize)]
pub struct Custody {
    pub steps: Vec<Step>,
    /// Who holds it now, if it isn't retired.
    pub holder: Option<Credential>,
    /// Whether the addressee retired it.
    pub delivered: bool,
}

impl Node {
    /// Operator: give a shipper a budget of `count` parcels, held by `to`.
    pub fn issue_parcel_budget(&mut self, to: Credential, count: u64) -> Result<Hash, String> {
        let op = self
            .operator
            .as_ref()
            .ok_or("only the town issues parcel budgets")?;
        let rec = pave_kernel::sign(
            self.view.scheme(),
            &op.root,
            &op.root_cred,
            Op::IssueBudget {
                authority: self.town.genesis.rooting_capability(),
                schema: parcel_schema(),
                amount: count,
                to,
            },
        );
        apply_ok(&mut self.view, &rec)?;
        self.save()?;
        Ok(rec.output(0))
    }

    fn parcel_budget(&self) -> Option<pave_kernel::Coin> {
        self.view
            .unspent()
            .find(|c| {
                c.kind == Kind::MintBudget
                    && c.schema == self.town.parcels
                    && c.amount > 0
                    && self.mine.contains(&c.holder)
            })
            .cloned()
    }

    /// Shipper: mint a parcel and keep its manifest. Returns the manifest,
    /// to hand to the first courier with the parcel.
    pub fn ship(
        &mut self,
        what: &str,
        from_cell: &str,
        to_cell: &str,
        addressee: Credential,
        pay_per_hop: u64,
    ) -> Result<Manifest, String> {
        self.ship_with(
            what,
            from_cell,
            to_cell,
            addressee,
            pay_per_hop,
            Mode::Signed,
        )
        .map(|(m, _)| m)
    }

    /// Ship with a delivery mode. For [`Mode::Code`], returns the code to
    /// give the recipient; the shipper keeps it to check the courier's.
    pub fn ship_with(
        &mut self,
        what: &str,
        from_cell: &str,
        to_cell: &str,
        addressee: Credential,
        pay_per_hop: u64,
        mode: Mode,
    ) -> Result<(Manifest, Option<String>), String> {
        let (parcel, lineage) = (self.mint_parcel()?, self.mint_parcel()?);
        let label = random_code(8);
        let m = Manifest {
            parcel,
            what: what.into(),
            from_cell: from_cell.into(),
            to_cell: to_cell.into(),
            addressee,
            pay_per_hop,
            mode,
            provider: None,
            label: Some(label_hash(&parcel, &label)),
            dispatch: None,
            replaces: None,
            lineage: Some(lineage),
            generation: 0,
            about: None,
        };
        self.labels.insert(parcel, label);
        let code = (m.mode == Mode::Code).then(|| random_code(6));
        if let Some(c) = &code {
            self.codes.insert(m.parcel, c.clone());
        }
        self.parcels.insert(m.parcel, m.clone());
        self.save()?;
        Ok((m, code))
    }

    /// Mint one parcel coin to a fresh key from this wallet's budget.
    fn mint_parcel(&mut self) -> Result<Hash, String> {
        let budget = self
            .parcel_budget()
            .ok_or("no parcel budget: ask the town for one")?;
        // The change stays with the budget's key: it links nothing new.
        let me = self.fresh()?;
        let rec = self.signed(
            &budget.holder,
            Op::Mint {
                budget: budget.state,
                amount: 1,
                to: me,
                change_to: budget.holder.clone(),
            },
        )?;
        apply_ok(&mut self.view, &rec)?;
        Ok(rec.output(0))
    }

    fn close(
        &mut self,
        m: &Manifest,
        receipt: impl FnOnce(u32) -> Hash,
    ) -> Result<(Credential, Hash), String> {
        let coin = self.held(&m.parcel)?;
        let me = self.fresh()?;
        let rec = self.signed(
            &coin.holder,
            Op::Transfer {
                state: coin.state,
                to: me,
                receipt: receipt(coin.hops + 1),
            },
        )?;
        apply_ok(&mut self.view, &rec)?;
        self.save()?;
        Ok((coin.holder, rec.output(0)))
    }

    /// Courier: close a code delivery with the code the recipient gave.
    pub fn deliver_by_code(&mut self, m: &Manifest, code: &str) -> Result<Hash, String> {
        if m.mode != Mode::Code {
            return Err("this parcel isn't a code delivery".into());
        }
        let h = m.hash();
        self.close(m, |hop| code_receipt(&h, hop, code))
            .map(|(_, s)| s)
    }

    /// Courier: close an unattended drop, committing to where and to a
    /// salted photo hash, and post the matching note to the job board.
    pub fn drop_off(&mut self, m: &Manifest, cell: &str, photo: Hash) -> Result<Hash, String> {
        if !matches!(m.mode, Mode::Drop { .. }) {
            return Err("this parcel isn't a drop delivery".into());
        }
        let h = m.hash();
        let (holder, state) = self.close(m, |hop| drop_receipt(&h, hop, cell, &photo))?;
        let msg = crate::board::BoardMsg::Dropped {
            parcel: m.parcel,
            cell: cell.into(),
            photo,
        };
        let scope = self.town.jobs.scope;
        self.compose(&scope, &holder, msg.kind(), msg.job(), msg.encode(), None)?;
        Ok(state)
    }

    /// The parties to a parcel: its addressee and everyone in its custody.
    pub fn parties(&self, m: &Manifest) -> std::collections::BTreeSet<Credential> {
        let mut out: std::collections::BTreeSet<Credential> =
            [m.addressee.clone()].into_iter().collect();
        for s in self.custody(m).steps {
            match s {
                Step::Handoff { from, to } => {
                    out.insert(from);
                    out.insert(to);
                }
                Step::Take { by } | Step::Retired { by } | Step::Closed { by, .. } => {
                    out.insert(by);
                }
            }
        }
        out
    }

    /// Where a parcel's delivery stands.
    pub fn delivery(&self, m: &Manifest) -> Delivery {
        use crate::dispute::{final_outcome, open_dispute, Answer};
        if let Some(n) = self.replaced_by(m) {
            return Delivery::Replaced(n);
        }
        let c = self.custody(m);
        if c.delivered {
            return Delivery::Delivered("signed");
        }
        let (ds, _) = self.disputes();
        let parties = self.parties(m);
        // Only disputes a party opened count, with their appeals, whoever filed those.
        let root = |d: &crate::dispute::Dispute| {
            let mut d = d.clone();
            while let Some(p) = d.appeal_of.and_then(|a| ds.get(&a)) {
                d = p.clone();
            }
            d.opener
        };
        let party_disputes: BTreeMap<Hash, crate::dispute::Dispute> = ds
            .iter()
            .filter(|(_, d)| parties.contains(&root(d)))
            .map(|(k, d)| (*k, d.clone()))
            .collect();
        match final_outcome(&party_disputes, &m.parcel) {
            Some(Answer::Yes) => return Delivery::Delivered("ruled"),
            Some(Answer::No) => return Delivery::NotDelivered,
            Some(Answer::Refer(to)) => return Delivery::Referred(to),
            None => {}
        }
        if open_dispute(&party_disputes, &m.parcel) {
            return Delivery::Disputed;
        }
        let has_closing = c.steps.iter().any(|s| matches!(s, Step::Closed { .. }));
        match (&m.mode, self.closer(m)) {
            (Mode::Signed, _) => Delivery::InTransit,
            (Mode::Code, Some(_)) => Delivery::Delivered("code"),
            (Mode::Code, None) if !has_closing => Delivery::InTransit,
            (Mode::Code, None) if self.codes.contains_key(&m.parcel) => Delivery::NotDelivered,
            (Mode::Code, None) => Delivery::Unverified,
            (Mode::Drop { window }, Some((_, at))) if self.epoch() >= at + window => {
                Delivery::Delivered("drop")
            }
            (Mode::Drop { window }, Some((_, at))) => Delivery::Pending(at + window),
            (Mode::Drop { .. }, None) => Delivery::InTransit,
        }
    }

    /// The closing that delivered a code or drop parcel, as far as this
    /// wallet can check: its signer, and for a drop the epoch of its note.
    fn closer(&self, m: &Manifest) -> Option<(Credential, u32)> {
        let h = m.hash();
        let closings: Vec<(Credential, Hash, u32)> = self
            .custody(m)
            .steps
            .into_iter()
            .filter_map(|s| {
                if let Step::Closed { by, receipt, hop } = s {
                    Some((by, receipt, hop))
                } else {
                    None
                }
            })
            .collect();
        match &m.mode {
            Mode::Signed => None,
            Mode::Code => {
                let code = self.codes.get(&m.parcel)?;
                closings
                    .into_iter()
                    .find(|(_, r, hop)| *r == code_receipt(&h, *hop, code))
                    .map(|(by, _, _)| (by, 0))
            }
            Mode::Drop { .. } => {
                let copy = self.copy(&self.town.jobs.scope).ok()?;
                copy.items().into_iter().find_map(|i| {
                    match crate::board::BoardMsg::decode(i.content) {
                        Some(crate::board::BoardMsg::Dropped {
                            parcel,
                            cell,
                            photo,
                        }) if parcel == m.parcel && i.post.thread == Some(parcel) => closings
                            .iter()
                            .find(|(by, r, hop)| {
                                by == i.signer && *r == drop_receipt(&h, *hop, &cell, &photo)
                            })
                            .map(|(by, _, _)| (by.clone(), i.post.epoch)),
                        _ => None,
                    }
                })
            }
        }
    }

    /// The parcel's current state, if this wallet holds it.
    fn held(&self, parcel: &Hash) -> Result<pave_kernel::Coin, String> {
        self.view
            .unspent()
            .find(|c| {
                c.origin == *parcel
                    && c.schema == self.town.parcels
                    && self.mine.contains(&c.holder)
            })
            .cloned()
            .ok_or_else(|| "this wallet doesn't hold that parcel".into())
    }

    /// Hand a parcel this wallet holds to `to`, a credential the next
    /// courier (or the addressee) gave. They meet to carry the record.
    pub fn hand_off(&mut self, parcel: &Hash, to: Credential) -> Result<Hash, String> {
        let m = self
            .parcels
            .get(parcel)
            .ok_or("no manifest for that parcel")?
            .clone();
        let coin = self.held(parcel)?;
        if to != m.addressee && !self.dispatched(&m, &to) {
            return Err("the next courier has no shift ticket from this parcel's dispatch".into());
        }
        let rec = self.signed(
            &coin.holder,
            Op::Transfer {
                state: coin.state,
                to,
                receipt: handoff_receipt(&m.hash(), coin.hops + 1),
            },
        )?;
        apply_ok(&mut self.view, &rec)?;
        self.save()?;
        Ok(rec.output(0))
    }

    /// Courier: take a parcel handed to this wallet. Checks that it is held
    /// here, that the handoff commits to this manifest, and that the coin
    /// passes this wallet's usual checks; then acknowledges by moving it to
    /// a fresh credential of its own.
    pub fn take_parcel(&mut self, m: &Manifest) -> Result<Hash, String> {
        self.take_parcel_as(m, None)
    }

    /// Take a parcel, and with `identity`, post a note signed with that
    /// identity so whoever holds it (the co-op's dispatch) knows who has it.
    pub fn take_parcel_as(&mut self, m: &Manifest, identity: Option<&str>) -> Result<Hash, String> {
        let coin = self.held(&m.parcel)?;
        let creator = self
            .view
            .creator(&coin.state)
            .ok_or("unknown parcel state")?
            .clone();
        match &creator.op {
            Op::Transfer { receipt, .. } if *receipt == handoff_receipt(&m.hash(), coin.hops) => {}
            _ => return Err("that handoff doesn't match the manifest".into()),
        }
        if self.replaced_by(m).is_some() {
            return Err("this token is void: its shipper reminted the parcel".into());
        }
        if self.reminted_twice(m) {
            return Err("its shipper reminted it twice".into());
        }
        let trusted: Vec<(Credential, Hash)> = m
            .dispatch
            .iter()
            .map(|d| (d.clerk.clone(), d.sequence()))
            .collect();
        self.check_trusting(&coin.state, &trusted)
            .map_err(|r| format!("{r:?}"))?;
        let me = match &m.dispatch {
            Some(d) => self
                .shift_key(d)
                .ok_or("no shift key: ask dispatch for one")?,
            None => self.fresh()?,
        };
        let rec = self.signed(
            &coin.holder,
            Op::Transfer {
                state: coin.state,
                to: me,
                receipt: take_receipt(&m.hash(), coin.hops + 1),
            },
        )?;
        apply_ok(&mut self.view, &rec)?;
        self.parcels.insert(m.parcel, m.clone());
        if identity.is_some() {
            let msg = crate::board::BoardMsg::Took {
                parcel: m.parcel,
                hop: coin.hops + 1,
            };
            let scope = self.town.jobs.scope;
            self.compose_as(
                &scope,
                &coin.holder,
                msg.kind(),
                msg.job(),
                msg.encode(),
                None,
                identity,
            )?;
        }
        self.save()?;
        Ok(rec.output(0))
    }

    /// Shipper: the code printed on a parcel's label.
    pub fn label_code(&self, parcel: &Hash) -> Option<&String> {
        self.labels.get(parcel)
    }

    /// Shipper: name the dispatch whose couriers carry it, before the first
    /// handoff.
    pub fn name_dispatch(
        &mut self,
        parcel: &Hash,
        d: crate::dispatch::Dispatch,
    ) -> Result<Manifest, String> {
        let coin = self.held(parcel)?;
        if coin.hops > 0 {
            return Err("the dispatch is named before the first handoff".into());
        }
        for r in &d.records {
            apply_ok(&mut self.view, r)?;
        }
        let m = self
            .parcels
            .get_mut(parcel)
            .ok_or("no manifest for that parcel")?;
        m.dispatch = Some(d.roster);
        let m = m.clone();
        self.save()?;
        Ok(m)
    }

    /// Whether `key` holds a shift ticket or a courier badge from the
    /// parcel's dispatch, if it names one.
    fn dispatched(&self, m: &Manifest, key: &Credential) -> bool {
        match &m.dispatch {
            None => true,
            Some(d) => self.know.tickets.get(key).is_some_and(|t| {
                d.shift_of(self.view.scheme(), t).is_some()
                    || d.badge_of(self.view.scheme(), t).is_some()
            }),
        }
    }

    /// Whether this token is void: its lineage has moved past its
    /// generation, as this wallet's view has it. Returns the next
    /// generation's parcel, if the lineage record names one this wallet knows.
    pub fn replaced_by(&self, m: &Manifest) -> Option<Option<Hash>> {
        let lineage = m.lineage?;
        let h = pave_protocol::head(&self.view, &lineage)?;
        if h.number <= m.generation {
            return None;
        }
        // The record that moved the lineage past this generation.
        let mut state = lineage;
        for _ in 0..m.generation {
            state = self.view.spender(&state)?.output(0);
        }
        let rec = self.view.spender(&state)?;
        Some(self.parcels.values().find(|n| n.replaces == Some(m.parcel) && matches!(&rec.op, Op::Transfer { receipt, .. } if *receipt == remint_receipt(&m.parcel, &n.parcel))).map(|n| n.parcel))
    }

    /// Whether one of the parcel's lineage states was used twice: its shipper
    /// reminted one generation twice.
    pub fn reminted_twice(&self, m: &Manifest) -> bool {
        let Some(mut state) = m.lineage else {
            return false;
        };
        let used: std::collections::BTreeSet<Hash> =
            self.view.evidence().map(|e| e.basename).collect();
        for _ in 0..=MAX_HOPS {
            if used.contains(&state) {
                return true;
            }
            match self.view.spender(&state) {
                Some(r) => state = r.output(0),
                None => return false,
            }
        }
        false
    }

    /// Take the lineage records the shipper posted on the job board into
    /// this wallet's view. Returns how many were new.
    pub fn hear_remints(&mut self) -> usize {
        let Ok(copy) = self.copy(&self.town.jobs.scope) else {
            return 0;
        };
        let recs: Vec<pave_kernel::Record> = copy
            .items()
            .into_iter()
            .filter_map(|i| match crate::board::BoardMsg::decode(i.content) {
                Some(crate::board::BoardMsg::Replaced { roll, .. }) => Some(roll),
                _ => None,
            })
            .collect();
        recs.iter()
            .filter(|r| matches!(self.view.apply(r), Ok(pave_kernel::Applied::Accepted)))
            .count()
    }

    /// Shipper: remint a parcel to `to`, for whoever has the package and
    /// shows its label code. The replacement keeps the manifest's terms,
    /// names the old parcel, and is handed to `to`; the old token is void.
    pub fn remint_parcel(
        &mut self,
        old: &Manifest,
        code: &str,
        to: Credential,
    ) -> Result<Manifest, String> {
        if old.label != Some(label_hash(&old.parcel, code)) {
            return Err("that isn't the code on the parcel's label".into());
        }
        let shipper = self
            .custody(old)
            .steps
            .iter()
            .find_map(|s| {
                if let Step::Handoff { from, .. } = s {
                    Some(from.clone())
                } else {
                    None
                }
            })
            .ok_or("this parcel hasn't left its shipper")?;
        let lineage = self
            .view
            .unspent()
            .find(|c| Some(c.origin) == old.lineage && self.mine.contains(&c.holder))
            .cloned()
            .ok_or("only the shipper, holding the lineage, remints")?;
        if lineage.hops != old.generation {
            return Err("already reminted".into());
        }
        let parcel = self.mint_parcel()?;
        let label = random_code(8);
        let m = Manifest {
            parcel,
            label: Some(label_hash(&parcel, &label)),
            replaces: Some(old.parcel),
            generation: old.generation + 1,
            ..old.clone()
        };
        self.labels.insert(parcel, label);
        if let Some(c) = self.codes.get(&old.parcel).cloned() {
            self.codes.insert(parcel, c);
        }
        // The layer underneath: moving the lineage is what voids the old
        // token, and it can be done once per generation.
        let next = self.fresh()?;
        let roll = self.signed(
            &lineage.holder,
            Op::Transfer {
                state: lineage.state,
                to: next,
                receipt: remint_receipt(&old.parcel, &parcel),
            },
        )?;
        apply_ok(&mut self.view, &roll)?;
        self.parcels.insert(parcel, m.clone());
        self.hand_off(&parcel, to)?;
        let msg = crate::board::BoardMsg::Replaced {
            parcel: old.parcel,
            with: parcel,
            roll,
        };
        let scope = self.town.jobs.scope;
        self.compose(&scope, &shipper, msg.kind(), msg.job(), msg.encode(), None)?;
        self.save()?;
        Ok(m)
    }

    /// Shipper: say what the parcel is for, before the first handoff.
    pub fn name_about(&mut self, parcel: &Hash, about: Hash) -> Result<Manifest, String> {
        if self.held(parcel)?.hops > 0 {
            return Err("what it's for is named before the first handoff".into());
        }
        let m = self
            .parcels
            .get_mut(parcel)
            .ok_or("no manifest for that parcel")?;
        m.about = Some(about);
        let m = m.clone();
        self.save()?;
        Ok(m)
    }

    /// Shipper: name the provider, before the first handoff.
    pub fn name_provider(
        &mut self,
        parcel: &Hash,
        provider: Credential,
    ) -> Result<Manifest, String> {
        let coin = self.held(parcel)?;
        if coin.hops > 0 {
            return Err("the provider is named before the first handoff".into());
        }
        let m = self
            .parcels
            .get_mut(parcel)
            .ok_or("no manifest for that parcel")?;
        m.provider = Some(provider);
        let m = m.clone();
        self.save()?;
        Ok(m)
    }

    /// Shipper: pay the provider `price` once the parcel is delivered, once.
    pub fn pay_provider(&mut self, m: &Manifest, price: u64) -> Result<Hash, String> {
        let provider = m.provider.clone().ok_or("this parcel has no provider")?;
        if !matches!(self.delivery(m), Delivery::Delivered(_)) {
            return Err("not delivered".into());
        }
        let receipt = shipping_receipt(&m.parcel);
        if self.view.records().iter().any(|r| matches!(&r.op, Op::Transfer { receipt: x, .. } | Op::Split { receipt: x, .. } if *x == receipt)) {
            return Err("already paid".into());
        }
        self.pay_to(provider, price, receipt)
    }

    /// Who has taken a parcel, as this wallet can tell: for each take
    /// whose courier posted a note, the identity it signed with and this
    /// wallet's name for it, if it was given that identity.
    pub fn who_took(&self, m: &Manifest) -> Vec<(u32, Credential, Option<String>)> {
        let takes: Vec<Credential> = self
            .custody(m)
            .steps
            .into_iter()
            .filter_map(|s| {
                if let Step::Take { by } = s {
                    Some(by)
                } else {
                    None
                }
            })
            .collect();
        let Ok(copy) = self.copy(&self.town.jobs.scope) else {
            return vec![];
        };
        copy.items()
            .into_iter()
            .filter_map(|i| match crate::board::BoardMsg::decode(i.content) {
                Some(crate::board::BoardMsg::Took { parcel, hop })
                    if parcel == m.parcel
                        && i.post.thread == Some(parcel)
                        && takes.contains(i.signer) =>
                {
                    let id = i.by.clone()?;
                    let name = self
                        .contacts
                        .iter()
                        .find(|(_, c)| **c == id)
                        .map(|(n, _)| n.clone());
                    Some((hop, id, name))
                }
                _ => None,
            })
            .collect()
    }

    /// Addressee: confirm delivery by retiring the parcel.
    pub fn confirm_delivery(&mut self, m: &Manifest) -> Result<Hash, String> {
        let coin = self.held(&m.parcel)?;
        if coin.holder != m.addressee {
            return Err("only the manifest's addressee confirms delivery".into());
        }
        let rec = self.signed(&coin.holder, Op::Retire { state: coin.state })?;
        apply_ok(&mut self.view, &rec)?;
        self.parcels.insert(m.parcel, m.clone());
        self.save()?;
        Ok(rec.id())
    }

    /// A parcel's custody as this wallet's view has it.
    pub fn custody(&self, m: &Manifest) -> Custody {
        let (mut steps, mut state, mut holder, mut delivered) = (vec![], m.parcel, None, false);
        let mut hop = 0;
        loop {
            if let Some(c) = self.view.coin(&state) {
                holder = Some(c.holder.clone());
                break;
            }
            let Some(rec) = self.view.spender(&state) else {
                break;
            };
            hop += 1;
            match &rec.op {
                Op::Transfer { receipt, .. } if *receipt == take_receipt(&m.hash(), hop) => steps
                    .push(Step::Take {
                        by: rec.signer.clone(),
                    }),
                Op::Transfer { to, receipt, .. } if *receipt == handoff_receipt(&m.hash(), hop) => {
                    steps.push(Step::Handoff {
                        from: rec.signer.clone(),
                        to: to.clone(),
                    })
                }
                Op::Transfer { receipt, .. } => steps.push(Step::Closed {
                    by: rec.signer.clone(),
                    receipt: *receipt,
                    hop,
                }),
                Op::Retire { .. } => {
                    delivered = rec.signer == m.addressee;
                    steps.push(Step::Retired {
                        by: rec.signer.clone(),
                    });
                    break;
                }
                _ => break,
            }
            state = rec.output(0);
        }
        Custody {
            steps,
            holder,
            delivered,
        }
    }

    /// Shipper: pay the signer of every handoff after this wallet's own,
    /// once the addressee has confirmed delivery. Returns the payments.
    pub fn pay_couriers(&mut self, m: &Manifest) -> Result<Vec<Hash>, String> {
        if m.provider.as_ref().is_some_and(|p| !self.mine.contains(p)) {
            return Err("this parcel's provider pays its couriers".into());
        }
        if self.delivery_job(m).is_some_and(|(_, k)| k.is_some()) {
            return Err("this parcel's courier is paid through its delivery job".into());
        }
        let c = self.custody(m);
        if !matches!(self.delivery(m), Delivery::Delivered(_)) {
            return Err("not delivered".into());
        }
        // Each handoff's signer, and whoever closed it validly (by code or
        // drop; for a ruled delivery, the last closing). Never a courier
        // caught handing one parcel to two people.
        let last_closing = c.steps.iter().rev().find_map(|s| {
            if let Step::Closed { by, .. } = s {
                Some(by.clone())
            } else {
                None
            }
        });
        let closer = self.closer(m).map(|(by, _)| by).or(last_closing);
        let handoffs = |c: &Custody| -> Vec<Credential> {
            // The first handoff is the shipper's own.
            c.steps
                .iter()
                .filter_map(|s| {
                    if let Step::Handoff { from, .. } = s {
                        Some(from.clone())
                    } else {
                        None
                    }
                })
                .skip(1)
                .collect()
        };
        // After a remint, the old token's couriers up to the remint too, at
        // the old parcel's receipts.
        let before: Vec<(Hash, Credential)> = match m.replaces.and_then(|p| self.parcels.get(&p)) {
            Some(old) => handoffs(&self.custody(old))
                .into_iter()
                .map(|c| (old.parcel, c))
                .collect(),
            None => vec![],
        };
        let couriers: Vec<(Hash, Credential)> = before
            .into_iter()
            .chain(
                handoffs(&c)
                    .into_iter()
                    .chain(closer)
                    .map(|c| (m.parcel, c)),
            )
            .filter(|(_, from)| {
                !self.mine.contains(from)
                    && !self.view.flagged().contains(from)
                    && self.dispatched(m, from)
            })
            .collect();
        let mut out = vec![];
        for (parcel, courier) in couriers {
            let receipt = pay_receipt(&parcel, &courier);
            let paid = self.view.records().iter().any(|r| matches!(&r.op, Op::Transfer { receipt: x, .. } | Op::Split { receipt: x, .. } if *x == receipt));
            if paid {
                continue;
            }
            out.push(self.pay_to(courier, m.pay_per_hop, receipt)?);
        }
        Ok(out)
    }

    /// Pay `amount` to `to` from one coin, with change to a fresh credential.
    pub fn pay_to(&mut self, to: Credential, amount: u64, receipt: Hash) -> Result<Hash, String> {
        let coin = self
            .my_coins()
            .into_iter()
            .find(|c| c.amount >= amount)
            .ok_or("no single coin covers the pay")?;
        let rec = if coin.amount == amount {
            self.signed(
                &coin.holder,
                Op::Transfer {
                    state: coin.state,
                    to,
                    receipt,
                },
            )?
        } else {
            let change = self.fresh()?;
            self.signed(
                &coin.holder,
                Op::Split {
                    state: coin.state,
                    parts: vec![(amount, to), (coin.amount - amount, change)],
                    receipt,
                },
            )?
        };
        apply_ok(&mut self.view, &rec)?;
        Ok(rec.output(0))
    }
}

fn random_code(digits: u32) -> String {
    let mut b = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    format!(
        "{:0width$}",
        u64::from_le_bytes(b) % 10u64.pow(digits),
        width = digits as usize
    )
}
