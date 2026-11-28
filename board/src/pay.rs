//! Paying another wallet directly: a handshake that sends only what the
//! payment needs.
//!
//! 1. **Invoice.** The payee names the amount's receiving credential, with
//!    its ticket. The payer checks that ticket first: from a trusted clerk,
//!    in date, not in a revoked group, and allowed to receive the amount.
//! 2. **Offer.** The payer names the coin it would pay with and the ids of
//!    the coin's provenance (8-byte prefixes). Nothing else about the
//!    payer's wallet is revealed, and no coin is revealed before the invoice.
//! 3. **Lacks.** The payee answers with the ids it doesn't already have.
//! 4. **Proposal.** The payer sends just those records, the tickets they
//!    name, and its standing. The payee judges the coin as it stands.
//! 5. **Payment.** Only on an accept does the payer sign: a transfer, or a
//!    split with change, committing to the invoice's memo.
//! 6. **Ack.** The payee checks the payment and signs its record id with the
//!    invoice's credential. Until then the payer keeps the payment pending,
//!    and resending the very same record later completes it.
//!
//! Provenance travels only with the coin, so a payment never shows the
//! payee anything about the payer's other coins or its other payments.

use crate::node::{apply_ok, Node};
use pave_kernel::{Credential, Hash, Op, Record, Scheme, Sig};
use pave_protocol::accept::ancestry;
use pave_protocol::{check, cheat_list, head, SignedTicket, Standing};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub type Prefix = [u8; 8];

pub fn prefix(h: &Hash) -> Prefix {
    h.0[..8].try_into().unwrap()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invoice {
    pub amount: u64,
    pub memo: Hash,
    pub to: Credential,
    pub ticket: SignedTicket,
    /// The credit to pay in, by schema; none for the town's cash.
    #[serde(default)]
    pub credit: Option<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Offer {
    pub to: Credential,
    pub state: Hash,
    pub ids: Vec<Prefix>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub to: Credential,
    pub state: Hash,
    pub records: Vec<Record>,
    pub tickets: Vec<SignedTicket>,
    pub standing: Standing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayVerdict {
    Accept,
    NeedStanding(Vec<(Vec<u8>, Vec<u8>)>),
    Refuse(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ack {
    pub record: Hash,
    pub sig: Sig,
}

fn ack_bytes(record: &Hash) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/pay-ack/v0", record))
}

/// The memo hash an invoice commits a payment to.
pub fn memo_hash(memo: &str) -> Hash {
    pave_kernel::hash::hash_of("pave/pay-memo/v0", &memo)
}

impl Node {
    /// Payee: an invoice for `amount`, to a fresh credential.
    pub fn invoice(&mut self, amount: u64, memo: &str) -> Result<Invoice, String> {
        self.invoice_for(amount, memo_hash(memo))
    }

    /// Payee: an invoice whose payment commits to `memo`, such as the hash
    /// of an order's binding.
    pub fn invoice_for(&mut self, amount: u64, memo: Hash) -> Result<Invoice, String> {
        let to = self.fresh()?;
        let ticket = self.know.tickets.get(&to).cloned().ok_or("no ticket for a fresh credential")?;
        self.invoices.insert(to.clone(), (amount, memo));
        self.save()?;
        Ok(Invoice { amount, memo, to, ticket, credit: None })
    }

    /// Payee: an invoice to be paid in another credit than the town's cash,
    /// such as a ramp's.
    pub fn invoice_in(&mut self, credit: Hash, amount: u64, memo: Hash) -> Result<Invoice, String> {
        let mut inv = self.invoice_for(amount, memo)?;
        if credit != self.town.cash {
            self.invoice_credit.insert(inv.to.clone(), credit);
            inv.credit = Some(credit);
            self.save()?;
        }
        Ok(inv)
    }

    /// Payee: the credit an open invoice to `to` is in.
    fn invoiced_credit(&self, to: &Credential) -> Hash {
        self.invoice_credit.get(to).copied().unwrap_or(self.town.cash)
    }

    /// Payer: is the payee's ticket one this wallet would pay to?
    pub fn check_invoice(&mut self, inv: &Invoice) -> Result<(), String> {
        let s = self.view.scheme().clone();
        if inv.ticket.ticket.credential != inv.to || !inv.ticket.verify(&s) {
            return Err("the invoice's ticket isn't for its credential, or isn't signed".into());
        }
        let policy = self.policy();
        let seq = policy.trusted_clerks.get(&inv.ticket.clerk).ok_or("the invoice's ticket is from a clerk this wallet doesn't trust")?;
        if *seq != inv.ticket.ticket.sequence {
            return Err("the invoice's ticket counts by another sequence".into());
        }
        let h = head(&self.view, seq).ok_or("no epoch for the clerk's sequence")?;
        let schema = self.view.schema(&self.town.cash).ok_or("unknown cash schema")?;
        if let Some(soft) = schema.soft_expiry {
            if h.number >= inv.ticket.ticket.epoch.saturating_add(soft) {
                return Err("the invoice's ticket has expired".into());
            }
        }
        if let Some(d) = h.data.and_then(|d| self.know.epoch_data.get(&d)) {
            if d.revoked.contains_key(&inv.ticket.ticket.group) {
                return Err("the invoice's ticket is in a revoked group".into());
            }
        }
        if inv.ticket.ticket.max_spend.is_some_and(|m| m < inv.amount) {
            return Err("the invoice's ticket can't receive that much".into());
        }
        self.know.add_ticket(&s, inv.ticket.clone());
        Ok(())
    }

    /// Every record in a coin's provenance.
    pub(crate) fn provenance(&self, state: &Hash) -> Vec<Record> {
        // In the view's order, so a receiver can apply them one by one.
        let ids: BTreeSet<Hash> = ancestry(&self.view, state).iter().filter_map(|s| self.view.creator(s)).map(|r| r.id()).collect();
        self.view.records().iter().filter(|r| ids.contains(&r.id())).cloned().collect()
    }

    /// Payer: offer a coin that covers the invoice.
    pub fn offer(&self, inv: &Invoice) -> Result<Offer, String> {
        let coin = self.my_coins_in(&inv.credit.unwrap_or(self.town.cash)).into_iter().find(|c| c.amount >= inv.amount).ok_or("no single coin covers it")?;
        let ids = self.provenance(&coin.state).iter().map(|r| prefix(&r.id())).collect();
        Ok(Offer { to: inv.to.clone(), state: coin.state, ids })
    }

    /// Payee: the offered ids this wallet lacks.
    pub fn lacks(&self, offer: &Offer) -> Vec<Prefix> {
        let have: BTreeSet<Prefix> = self.view.records().iter().map(|r| prefix(&r.id())).collect();
        offer.ids.iter().filter(|p| !have.contains(*p)).copied().collect()
    }

    /// Payer: the records the payee lacks, the tickets they name, and standing
    /// against `cheats`.
    pub fn propose(&self, offer: &Offer, lacks: &[Prefix], cheats: &[(Vec<u8>, Vec<u8>)]) -> Result<Proposal, String> {
        let want: BTreeSet<&Prefix> = lacks.iter().collect();
        let records: Vec<Record> = self.provenance(&offer.state).into_iter().filter(|r| want.contains(&prefix(&r.id()))).collect();
        let coin = self.view.coin(&offer.state).ok_or("the coin is gone")?;
        let named: BTreeSet<&Credential> = records.iter().flat_map(|r| std::iter::once(&r.signer).chain(crate::node::op_recipients(&r.op))).chain(coin.history.iter()).collect();
        let tickets = self.know.tickets.values().filter(|t| named.contains(&t.ticket.credential)).cloned().collect();
        let standing = Standing::prove(self.view.scheme(), &self.key, &coin.holder, cheats).ok_or("this wallet is a known cheat")?;
        Ok(Proposal { to: offer.to.clone(), state: offer.state, records, tickets, standing })
    }

    /// Payee: judge the coin as it stands.
    pub fn judge(&mut self, p: &Proposal) -> PayVerdict {
        let Some(&(amount, _)) = self.invoices.get(&p.to) else { return PayVerdict::Refuse("no such invoice".into()) };
        let s = self.view.scheme().clone();
        for r in &p.records {
            let _ = self.view.apply(r);
        }
        for t in &p.tickets {
            self.know.add_ticket(&s, t.clone());
        }
        if p.standing.verify(&s) {
            self.know.add_standing(&s, p.standing.clone());
        }
        let Some(coin) = self.view.coin(&p.state).cloned() else { return PayVerdict::Refuse("unknown coin, or already spent".into()) };
        if coin.amount < amount {
            return PayVerdict::Refuse("the coin doesn't cover the invoice".into());
        }
        if coin.schema != self.invoiced_credit(&p.to) {
            return PayVerdict::Refuse("the coin is in another credit than the invoice".into());
        }
        let cheats = cheat_list(&self.view);
        if !self.know.standing.get(&coin.holder).is_some_and(|st| st.covers(&cheats)) {
            return PayVerdict::NeedStanding(cheats);
        }
        match check(&self.view, &self.know, &p.state, &coin.holder, &self.policy()) {
            Ok(()) => PayVerdict::Accept,
            Err(e) => PayVerdict::Refuse(format!("{e:?}")),
        }
    }

    /// Payer: sign the payment, keeping it pending until acknowledged.
    pub fn pay_invoice(&mut self, inv: &Invoice, state: Hash) -> Result<Record, String> {
        let coin = self.view.coin(&state).filter(|c| self.mine.contains(&c.holder)).cloned().ok_or("not a coin this wallet holds")?;
        let op = if coin.amount == inv.amount {
            Op::Transfer { state, to: inv.to.clone(), receipt: inv.memo }
        } else {
            let change = self.fresh()?;
            Op::Split { state, parts: vec![(inv.amount, inv.to.clone()), (coin.amount - inv.amount, change)], receipt: inv.memo }
        };
        let rec = pave_kernel::sign(self.view.scheme(), &self.key, &coin.holder, op);
        let rec = self.guard(rec)?;
        apply_ok(&mut self.view, &rec)?;
        if !self.pending.contains(&rec) {
            self.pending.push(rec.clone());
        }
        self.save()?;
        Ok(rec)
    }

    /// Payee: take a payment against an invoice and acknowledge it.
    pub fn take_payment(&mut self, rec: &Record) -> Result<Ack, String> {
        let (to, out) = match &rec.op {
            Op::Transfer { to, receipt, .. } => (to.clone(), (0u32, *receipt)),
            Op::Split { parts, receipt, .. } => (parts.first().ok_or("empty split")?.1.clone(), (0u32, *receipt)),
            _ => return Err("not a payment".into()),
        };
        let &(amount, memo) = self.invoices.get(&to).ok_or("no such invoice")?;
        if out.1 != memo {
            return Err("the payment doesn't commit to the invoice's memo".into());
        }
        apply_ok(&mut self.view, rec)?;
        let state = rec.output(out.0);
        let coin = self.view.coin(&state).cloned().ok_or("the payment's coin is missing")?;
        if coin.amount != amount {
            return Err(format!("paid {}, invoiced {amount}", coin.amount));
        }
        if coin.schema != self.invoiced_credit(&to) {
            return Err("paid in another credit than the invoice".into());
        }
        check(&self.view, &self.know, &state, &rec.signer, &self.policy()).map_err(|e| format!("{e:?}"))?;
        self.invoices.remove(&to);
        self.invoice_credit.remove(&to);
        self.paid.insert(rec.id(), to.clone());
        let sig = self.view.scheme().sign(&self.key, &to, &ack_bytes(&rec.id()), None);
        self.save()?;
        Ok(Ack { record: rec.id(), sig })
    }

    /// Payee: acknowledge a payment taken before (a resend after a dropped
    /// connection).
    pub fn re_ack(&self, rec: &Record) -> Option<Ack> {
        let to = self.paid.get(&rec.id())?;
        Some(Ack { record: rec.id(), sig: self.view.scheme().sign(&self.key, to, &ack_bytes(&rec.id()), None) })
    }

    /// Payer: check the payee's acknowledgment and settle the payment.
    pub fn confirm(&mut self, rec: &Record, ack: &Ack) -> Result<(), String> {
        let to = match &rec.op {
            Op::Transfer { to, .. } => to,
            Op::Split { parts, .. } => &parts[0].1,
            _ => return Err("not a payment".into()),
        };
        if ack.record != rec.id() || !self.view.scheme().verify(to, &ack_bytes(&ack.record), None, &ack.sig) {
            return Err("the acknowledgment isn't the payee's".into());
        }
        self.pending.retain(|r| r != rec);
        self.save()
    }
}
