//! Swapping: an old coin in, a fresh coin of the same value out.
//!
//! The swapper is a holder, not a kernel operation. It never pays out
//! without taking something in: the holder transfers the old coin to a
//! credential of the swapper's, the swapper retires it, and the mint pays
//! the same amount to a fresh ticketed credential of the holder's. All three
//! records are public, so anyone can check each payout against a retirement.
//!
//! It is the online path back for coins that recipients refuse offline:
//!
//! - **Expired coins** (soft or hard) are swapped at once. Expiry exists to
//!   force a coin back online, and this is where it comes back.
//! - **Coins tainted by a revoked group**, inside the window, are held for
//!   [`SWAP_HOLD`] epochs and paid only if no evidence against their sender
//!   has surfaced by then. An honest holder waits a little; a class
//!   breaker's clones have time to be caught.
//! - **Known cheats and double spends** are refused: the sender needs
//!   standing against every cheat the swapper knows, and the transfer must
//!   be the only use of the old coin the swapper has seen.
//!
//! Two steps, so a holder never signs its coin away before it knows the
//! answer: a quote on the coin as it stands, then the transfer. The quote is
//! signed by the swapper, so a swapper that takes the coin and then breaks
//! its quote leaves evidence against itself.

use crate::node::{apply_ok, Bundle, Node, S};
use pave_kernel::{Credential, Hash, Op, Record, Scheme, Sig};
use pave_protocol::{check, cheat_list, head, Policy, Refusal, Standing};
use serde::{Deserialize, Serialize};

/// Epochs a coin tainted by a revoked group waits before it is paid.
pub const SWAP_HOLD: u32 = 2;

/// Step 1, from the holder: the coin as it stands, and the holder's standing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuoteRequest {
    pub state: Hash,
    pub standing: Standing,
    /// The coin's provenance.
    pub bundle: Bundle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pay,
    Hold { until: u32 },
    /// Prove standing against these cheats and ask again.
    NeedStanding(Vec<(Vec<u8>, Vec<u8>)>),
    Refuse(String),
}

/// The swapper's signed quote.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Quote {
    pub state: Hash,
    pub verdict: Verdict,
    /// Transfer the coin here.
    pub swapper: Credential,
    pub sig: Sig,
}

/// Step 2, from the holder: the old coin transferred to the swapper,
/// committing to the credential the fresh coin goes to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapRequest {
    pub transfer: Record,
    pub to: Credential,
    /// The ticket for `to`.
    pub bundle: Bundle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SwapOutcome {
    /// The retirement of the old coin and the mint of the new one, with the
    /// mint's provenance.
    Paid { retire: Box<Record>, mint: Box<Record>, bundle: Box<Bundle> },
    /// Held until this epoch; collect then.
    Held { until: u32 },
}

/// A swap waiting out its hold.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Held {
    pub state: Hash,
    pub to: Credential,
    pub sender: Credential,
    pub until: u32,
}

/// The receipt a swap transfer commits to: where the fresh coin goes.
pub fn swap_receipt(to: &Credential) -> Hash {
    pave_kernel::hash::hash_of("pave/swap/v0", to)
}

fn quote_bytes(state: &Hash, verdict: &Verdict, swapper: &Credential) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/swap-quote/v0", state, verdict, swapper))
}

impl Quote {
    pub fn verify(&self, scheme: &S) -> bool {
        scheme.verify(&self.swapper, &quote_bytes(&self.state, &self.verdict, &self.swapper), None, &self.sig)
    }
}

impl Node {
    fn epoch_now(&self) -> Result<u32, String> {
        Ok(head(&self.view, &self.town.sequence).ok_or("no epoch")?.number)
    }

    /// Holder: ask for a quote on the coin at `state`, with standing against
    /// `cheats` (start with the cheats this wallet knows of).
    pub fn quote_request(&self, state: Hash, cheats: &[(Vec<u8>, Vec<u8>)]) -> Result<QuoteRequest, String> {
        let holder = self.view.coin(&state).filter(|c| self.mine.contains(&c.holder)).ok_or("not a coin this wallet holds")?.holder.clone();
        let standing = Standing::prove(self.view.scheme(), &self.key, &holder, cheats).ok_or("this wallet is a known cheat")?;
        Ok(QuoteRequest { state, standing, bundle: self.bundle() })
    }

    fn verdict(&mut self, state: &Hash, sender: &Credential) -> Verdict {
        let Ok(now) = self.epoch_now() else { return Verdict::Refuse("no epoch".into()) };
        let cheats = cheat_list(&self.view);
        if self.view.flagged().contains(sender) {
            return Verdict::Refuse("a known cheat".into());
        }
        if !self.know.standing.get(sender).is_some_and(|st| st.covers(&cheats)) {
            return Verdict::NeedStanding(cheats);
        }
        // The usual acceptance, except expiry: bringing expired coins back
        // is what a swapper is for.
        let policy = Policy { honor_expiry: false, ..self.policy() };
        match check(&self.view, &self.know, state, sender, &policy) {
            Ok(()) => Verdict::Pay,
            Err(Refusal::Revoked { .. }) => Verdict::Hold { until: now + SWAP_HOLD },
            Err(e) => Verdict::Refuse(format!("{e:?}")),
        }
    }

    /// Swapper: quote on a coin as it stands.
    pub fn quote(&mut self, req: &QuoteRequest) -> Result<Quote, String> {
        if self.operator.is_none() {
            return Err("only the town swaps".into());
        }
        self.absorb_bundle(&req.bundle);
        let s = self.view.scheme().clone();
        if req.standing.verify(&s) {
            self.know.add_standing(&s, req.standing.clone());
        }
        let sender = self.view.coin(&req.state).ok_or("unknown coin, or already spent")?.holder.clone();
        let verdict = self.verdict(&req.state, &sender);
        let swapper = s.credential(&self.key);
        self.issue_tickets(std::slice::from_ref(&swapper), "hardware")?;
        let sig = s.sign(&self.key, &swapper, &quote_bytes(&req.state, &verdict, &swapper), None);
        Ok(Quote { state: req.state, verdict, swapper, sig })
    }

    /// Holder: having a quote to pay or hold, transfer the coin.
    pub fn swap_request(&mut self, quote: &Quote) -> Result<SwapRequest, String> {
        if !quote.verify(self.view.scheme()) {
            return Err("the quote isn't signed".into());
        }
        if !matches!(quote.verdict, Verdict::Pay | Verdict::Hold { .. }) {
            return Err(format!("the swapper won't take it: {:?}", quote.verdict));
        }
        let holder = self.view.coin(&quote.state).filter(|c| self.mine.contains(&c.holder)).ok_or("not a coin this wallet holds")?.holder.clone();
        let to = self.fresh()?;
        let s = self.view.scheme().clone();
        let transfer = pave_kernel::sign(&s, &self.key, &holder, Op::Transfer { state: quote.state, to: quote.swapper.clone(), receipt: swap_receipt(&to) });
        let transfer = self.guard(transfer)?;
        apply_ok(&mut self.view, &transfer)?;
        let mut bundle = self.bundle();
        bundle.records.clear();
        bundle.conflicts.clear();
        bundle.tickets = self.know.tickets.get(&to).cloned().into_iter().collect();
        Ok(SwapRequest { transfer, to, bundle })
    }

    /// Swapper: take the old coin and pay or hold, as quoted.
    pub fn answer_swap(&mut self, req: &SwapRequest) -> Result<SwapOutcome, String> {
        let Op::Transfer { state, receipt, .. } = req.transfer.op else { return Err("not a transfer".into()) };
        if receipt != swap_receipt(&req.to) {
            return Err("the transfer doesn't commit to this credential".into());
        }
        let sender = req.transfer.signer.clone();
        self.absorb_bundle(&req.bundle);
        if !self.know.tickets.contains_key(&req.to) {
            return Err("no ticket for the credential to pay".into());
        }
        // Judge the coin as it stood, then take it.
        let verdict = self.verdict(&state, &sender);
        apply_ok(&mut self.view, &req.transfer).map_err(|e| format!("the old coin was used elsewhere: {e}"))?;
        let new_state = req.transfer.output(0);
        match verdict {
            Verdict::Pay => self.pay_swap(new_state, &req.to),
            Verdict::Hold { until } => {
                let op = self.operator.as_mut().ok_or("only the town swaps")?;
                op.held.push(Held { state: new_state, to: req.to.clone(), sender, until });
                Ok(SwapOutcome::Held { until })
            }
            v => Err(format!("refused: {v:?}")),
        }
    }

    /// Swapper: pay a held swap whose hold is over, unless evidence against
    /// its sender has surfaced meanwhile.
    pub fn collect_swap(&mut self, to: &Credential) -> Result<SwapOutcome, String> {
        let now = self.epoch_now()?;
        let op = self.operator.as_ref().ok_or("only the town swaps")?;
        let h = op.held.iter().find(|h| &h.to == to).cloned().ok_or("no swap held for that credential")?;
        if now < h.until {
            return Ok(SwapOutcome::Held { until: h.until });
        }
        let cheats = cheat_list(&self.view);
        let stood = self.know.standing.get(&h.sender).is_some_and(|st| st.covers(&cheats));
        if self.view.flagged().contains(&h.sender) || !stood {
            return Err("refused: evidence against the sender surfaced during the hold".into());
        }
        self.operator.as_mut().unwrap().held.retain(|x| x.state != h.state);
        self.pay_swap(h.state, &h.to)
    }

    fn pay_swap(&mut self, state: Hash, to: &Credential) -> Result<SwapOutcome, String> {
        let s = self.view.scheme().clone();
        let coin = self.view.coin(&state).ok_or("the old coin isn't held here")?.clone();
        let retire = pave_kernel::sign(&s, &self.key, &coin.holder, Op::Retire { state });
        let retire = self.guard(retire)?;
        apply_ok(&mut self.view, &retire)?;
        let op = self.operator.as_ref().ok_or("only the town swaps")?;
        let mint = pave_kernel::sign(&s, &op.minter, &op.minter_cred, Op::Mint { budget: op.cash_budget, amount: coin.amount, to: to.clone(), change_to: op.minter_cred.clone() });
        let mint = self.guard(mint)?;
        self.operator.as_mut().unwrap().cash_budget = mint.output(1);
        apply_ok(&mut self.view, &mint)?;
        Ok(SwapOutcome::Paid { retire: Box::new(retire), mint: Box::new(mint), bundle: Box::new(self.bundle()) })
    }

    /// Holder: take the swapper's answer. Returns the fresh coin, if paid.
    pub fn take_swap(&mut self, outcome: &SwapOutcome) -> Result<Option<Hash>, String> {
        match outcome {
            SwapOutcome::Paid { retire, mint, bundle } => {
                self.absorb_bundle(bundle);
                apply_ok(&mut self.view, retire)?;
                apply_ok(&mut self.view, mint)?;
                Ok(Some(mint.output(0)))
            }
            SwapOutcome::Held { .. } => Ok(None),
        }
    }
}
