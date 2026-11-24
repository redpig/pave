//! A node: one wallet's view, knowledge and keys, saved as a record log and
//! rebuilt by replay. A town operator node also holds the root, clerk and
//! minter keys (one operator, each role under its own key).

use crate::board::{self, BoardMsg};
use ed25519_dalek::SigningKey;
use pave_kernel::receipt::Receipt;
use pave_kernel::scheme::DevScheme;
use pave_kernel::*;
use pave_protocol::gossip::Hint;
use pave_protocol::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// What every member of a town knows about it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Town {
    pub genesis: Genesis,
    pub board: Hash,
    pub sequence: Hash,
    pub clerk: Credential,
    pub cash: Hash,
}

/// The operator's role keys.
#[derive(Clone, Serialize, Deserialize)]
pub struct Operator {
    pub root: [u8; 32],
    pub clerk: [u8; 32],
    pub minter: [u8; 32],
    pub cash_budget: Hash,
    pub next_group: u32,
}

/// Everything a node keeps on disk.
#[derive(Serialize, Deserialize)]
pub struct Saved {
    pub name: String,
    pub key: [u8; 32],
    pub town: Town,
    pub records: Vec<Record>,
    pub conflicts: Vec<Record>,
    pub evidence: Vec<Evidence>,
    pub tickets: Vec<SignedTicket>,
    pub epoch_data: Vec<EpochData>,
    pub hints: Vec<Hint>,
    pub operator: Option<Operator>,
    /// Records signed but deliberately not applied locally (the `cheat`
    /// command), handed to the next peer met.
    pub outbox: Vec<Record>,
    /// States this wallet double-spent; it hides its other spends of them.
    pub cheat_states: Vec<Hash>,
}

/// What two nodes swap when they meet: their records and what travels with
/// a coin's provenance (tickets, epoch data, evidence).
#[derive(Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub genesis: Hash,
    pub records: Vec<Record>,
    pub conflicts: Vec<Record>,
    pub evidence: Vec<Evidence>,
    pub tickets: Vec<SignedTicket>,
    pub epoch_data: Vec<EpochData>,
}

pub struct Node {
    pub path: PathBuf,
    pub name: String,
    pub key: SigningKey,
    pub me: Credential,
    pub town: Town,
    pub view: View<DevScheme>,
    pub know: Knowledge,
    pub operator: Option<Operator>,
    pub outbox: Vec<Record>,
    pub cheat_states: BTreeSet<Hash>,
}

fn cash_schema() -> Schema {
    Schema {
        label: "test credit (no cash value)".into(),
        divisible: true,
        soft_expiry: Some(4),
        hard_expiry: Some(8),
        offline_transfers: Some(5),
        max_per_holder: None,
        sequence: None,
    }
}

fn keygen() -> SigningKey {
    DevScheme::keygen()
}

fn apply_ok(view: &mut View<DevScheme>, rec: &Record) -> Result<(), String> {
    match view.apply(rec) {
        Ok(Applied::Accepted) | Ok(Applied::Duplicate) => Ok(()),
        other => Err(format!("{other:?}")),
    }
}

impl Node {
    /// Create a town: genesis, the clerk's epoch sequence, a test-credit
    /// budget and an open board scope. The operator holds every role.
    pub fn init_town(path: &Path, label: &str) -> Result<Node, String> {
        let (root, clerk, minter) = (keygen(), keygen(), keygen());
        let s = DevScheme;
        let (rc, cc, mc) = (s.credential(&root), s.credential(&clerk), s.credential(&minter));
        let genesis = Genesis { label: label.into(), root_rules: ScopeRules::default(), rooting: rc.clone() };
        let mut view = View::new(DevScheme, genesis.clone());
        let auth = genesis.rooting_capability();

        let seq_budget = sign(&s, &root, &rc, Op::IssueBudget { authority: auth, schema: epoch_schema(label), amount: 1, to: cc.clone() });
        apply_ok(&mut view, &seq_budget)?;
        let seq = sign(&s, &clerk, &cc, Op::Mint { budget: seq_budget.output(0), amount: 1, to: cc.clone(), change_to: cc.clone() });
        apply_ok(&mut view, &seq)?;
        let cash = sign(&s, &root, &rc, Op::IssueBudget { authority: auth, schema: cash_schema(), amount: 1_000_000, to: mc.clone() });
        apply_ok(&mut view, &cash)?;
        let board = sign(&s, &root, &rc, Op::CreateScope { parent: genesis.root_scope(), rules: ScopeRules::default(), authority: auth });
        apply_ok(&mut view, &board)?;

        let town = Town { genesis, board: board.output(0), sequence: seq.output(0), clerk: cc, cash: cash_schema().id() };
        let operator = Operator { root: root.to_bytes(), clerk: clerk.to_bytes(), minter: minter.to_bytes(), cash_budget: cash.output(0), next_group: 1 };
        let key = keygen();
        let me = s.credential(&key);
        let node = Node { path: path.into(), name: "town".into(), key, me, town, view, know: Knowledge::default(), operator: Some(operator), outbox: vec![], cheat_states: BTreeSet::new() };
        node.save()?;
        Ok(node)
    }

    /// Enroll a person (done online, before going out): the clerk issues a
    /// ticket at the current epoch and the minter grants test credit.
    pub fn enroll(&mut self, name: &str, out: &Path, credit: u64) -> Result<Node, String> {
        let op = self.operator.as_mut().ok_or("only the town operator can enroll")?;
        let (clerk, minter) = (SigningKey::from_bytes(&op.clerk), SigningKey::from_bytes(&op.minter));
        let s = DevScheme;
        let key = keygen();
        let me = s.credential(&key);
        let epoch = head(&self.view, &self.town.sequence).ok_or("no epoch")?.number;
        let ticket = SignedTicket::issue(&s, &clerk, &self.town.clerk, Ticket { credential: me.clone(), sequence: self.town.sequence, epoch, group: op.next_group, max_spend: None });
        op.next_group += 1;
        self.know.add_ticket(&s, ticket);
        if credit > 0 {
            let mc = s.credential(&minter);
            let mint = sign(&s, &minter, &mc, Op::Mint { budget: op.cash_budget, amount: credit, to: me.clone(), change_to: mc.clone() });
            apply_ok(&mut self.view, &mint)?;
            op.cash_budget = mint.output(1);
        }
        self.save()?;
        let mut person = Node {
            path: out.into(),
            name: name.into(),
            key,
            me,
            town: self.town.clone(),
            view: View::new(DevScheme, self.town.genesis.clone()),
            know: Knowledge::default(),
            operator: None,
            outbox: vec![],
            cheat_states: BTreeSet::new(),
        };
        person.absorb_bundle(&self.bundle());
        person.save()?;
        Ok(person)
    }

    pub fn load(path: &Path) -> Result<Node, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let saved: Saved = ciborium::from_reader(bytes.as_slice()).map_err(|e| e.to_string())?;
        let key = SigningKey::from_bytes(&saved.key);
        let me = DevScheme.credential(&key);
        let mut node = Node {
            path: path.into(),
            name: saved.name,
            key,
            me,
            town: saved.town.clone(),
            view: View::new(DevScheme, saved.town.genesis.clone()),
            know: Knowledge::default(),
            operator: saved.operator,
            outbox: saved.outbox,
            cheat_states: saved.cheat_states.into_iter().collect(),
        };
        node.absorb_bundle(&Bundle {
            genesis: saved.town.genesis.root_scope(),
            records: saved.records,
            conflicts: saved.conflicts,
            evidence: saved.evidence,
            tickets: saved.tickets,
            epoch_data: saved.epoch_data,
        });
        pave_protocol::gossip::absorb_hints(&mut node.know, &saved.hints);
        Ok(node)
    }

    pub fn save(&self) -> Result<(), String> {
        let saved = Saved {
            name: self.name.clone(),
            key: self.key.to_bytes(),
            town: self.town.clone(),
            records: self.view.records().to_vec(),
            conflicts: self.view.conflicts().to_vec(),
            evidence: self.view.evidence().cloned().collect(),
            tickets: self.know.tickets.values().cloned().collect(),
            epoch_data: self.know.epoch_data.values().cloned().collect(),
            hints: self.know.hints.iter().copied().collect(),
            operator: self.operator.clone(),
            outbox: self.outbox.clone(),
            cheat_states: self.cheat_states.iter().copied().collect(),
        };
        let bytes = pave_kernel::hash::encode(&saved);
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }

    pub fn bundle(&self) -> Bundle {
        // An honest wallet shares everything. A cheating one hides its other
        // spends of the states it double-spent, as a real cheater would.
        let hidden = |r: &Record| r.op.consumes().iter().any(|s| self.cheat_states.contains(s));
        let mut records: Vec<Record> = self.view.records().iter().filter(|r| !hidden(r)).cloned().collect();
        records.extend(self.outbox.iter().cloned());
        Bundle {
            genesis: self.town.genesis.root_scope(),
            records,
            conflicts: self.view.conflicts().iter().filter(|r| !hidden(r)).cloned().collect(),
            evidence: self.view.evidence().filter(|e| !self.cheat_states.contains(&e.basename)).cloned().collect(),
            tickets: self.know.tickets.values().cloned().collect(),
            epoch_data: self.know.epoch_data.values().cloned().collect(),
        }
    }

    /// Merge what a peer sent. Returns the states with new evidence.
    pub fn absorb_bundle(&mut self, b: &Bundle) -> Vec<Hash> {
        let before: BTreeSet<Hash> = self.view.evidence().map(|e| e.basename).collect();
        for r in b.records.iter().chain(b.conflicts.iter()) {
            let _ = self.view.apply(r);
        }
        for e in &b.evidence {
            self.view.import_evidence(e);
        }
        for t in &b.tickets {
            self.know.add_ticket(&DevScheme, t.clone());
        }
        for d in &b.epoch_data {
            self.know.add_epoch_data(&self.view, d.clone());
        }
        self.view.evidence().map(|e| e.basename).filter(|h| !before.contains(h)).collect()
    }

    pub fn policy(&self) -> Policy {
        Policy::wallet([(self.town.clerk.clone(), self.town.sequence)].into_iter().collect())
    }

    pub fn carries(&self) -> BTreeSet<Hash> {
        [self.town.sequence].into_iter().collect()
    }

    /// States in the history of coins this node holds: what fork hints matter to.
    pub fn watch(&self) -> BTreeSet<Hash> {
        let mut w = BTreeSet::new();
        for c in self.view.coins_held_by(&self.me) {
            w.extend(pave_protocol::accept::ancestry(&self.view, &c.state));
        }
        w
    }

    /// The revocation group of this wallet's ticket, if it has one.
    pub fn group(&self) -> Option<u32> {
        self.know.tickets.get(&self.me).map(|t| t.ticket.group)
    }

    pub fn my_coins(&self) -> Vec<Coin> {
        let mut v: Vec<Coin> = self
            .view
            .coins_held_by(&self.me)
            .filter(|c| c.kind == Kind::Value && c.schema == self.town.cash && c.amount > 0)
            .cloned()
            .collect();
        v.sort_by_key(|c| std::cmp::Reverse(c.amount));
        v
    }

    fn signed(&self, op: Op) -> Record {
        sign(&DevScheme, &self.key, &self.me, op)
    }

    fn apply_own(&mut self, rec: &Record) -> Result<(), String> {
        apply_ok(&mut self.view, rec)
    }

    fn send(&mut self, msg: BoardMsg, receipt: Hash) -> Result<Hash, String> {
        let rec = self.signed(Op::Send { scope: self.town.board, presenting: None, body: msg.encode(), receipt });
        self.apply_own(&rec)?;
        Ok(rec.id())
    }

    /// Post a job, with a zero-value split of a coin covering the pay as
    /// proof of means, committing to the terms.
    pub fn post(&mut self, title: &str, pay: u64) -> Result<Hash, String> {
        let coin = self.my_coins().into_iter().find(|c| c.amount >= pay).ok_or("no single coin covers the pay")?;
        let terms = Receipt::Node(vec![
            ("public".into(), Receipt::leaf(format!("{title} | pay {pay}").into_bytes())),
            ("parties".into(), Receipt::leaf(b"terms: done when the poster signs off".to_vec())),
        ]);
        let me = self.me.clone();
        let proof = self.signed(Op::Split { state: coin.state, parts: vec![(coin.amount, me.clone()), (0, me)], receipt: terms.root() });
        self.apply_own(&proof)?;
        self.send(BoardMsg::Post { title: title.into(), pay, means: proof.id() }, terms.root())
    }

    pub fn reply(&mut self, job: Hash, note: &str) -> Result<Hash, String> {
        self.send(BoardMsg::Reply { job, note: note.into() }, Hash([0; 32]))
    }
    pub fn accept(&mut self, job: Hash, worker: Credential) -> Result<Hash, String> {
        self.send(BoardMsg::Accept { job, worker }, Hash([0; 32]))
    }
    pub fn done(&mut self, job: Hash) -> Result<Hash, String> {
        self.send(BoardMsg::Done { job }, Hash([0; 32]))
    }

    /// Pay the accepted worker: a transfer (or a split, if the coin is larger)
    /// whose receipt commits to the job.
    pub fn pay(&mut self, job_id: Hash) -> Result<Hash, String> {
        let jobs = board::jobs(&self.view, &self.town.board);
        let job = jobs.get(&job_id).ok_or("unknown job")?;
        if job.poster != self.me {
            return Err("only the poster pays".into());
        }
        let worker = job.worker.clone().ok_or("no worker accepted")?;
        if job.status != board::Status::Done {
            return Err(format!("job is {:?}, not Done", job.status));
        }
        let pay = job.pay;
        let coin = self.my_coins().into_iter().find(|c| c.amount >= pay).ok_or("no single coin covers the pay")?;
        let receipt = board::pay_receipt(&job_id);
        let rec = if coin.amount == pay {
            self.signed(Op::Transfer { state: coin.state, to: worker, receipt })
        } else {
            let me = self.me.clone();
            self.signed(Op::Split { state: coin.state, parts: vec![(pay, worker), (coin.amount - pay, me)], receipt })
        };
        self.apply_own(&rec)?;
        let payment = rec.output(0);
        self.send(BoardMsg::Paid { job: job_id, payment }, receipt)?;
        Ok(payment)
    }

    /// A dishonest wallet: sign a transfer of `state` without applying it
    /// locally, and hand it to the next peer met. Used to show detection.
    pub fn cheat(&mut self, state: Hash, to: Credential) -> Result<Hash, String> {
        let held = self.view.coin(&state).map(|c| c.holder == self.me);
        let spent_here = self.view.spender(&state).is_some_and(|r| r.signer == self.me);
        if held != Some(true) && !spent_here {
            return Err("not a state this wallet held".into());
        }
        let rec = self.signed(Op::Transfer { state, to, receipt: Hash([0; 32]) });
        self.outbox.push(rec.clone());
        self.cheat_states.insert(state);
        Ok(rec.output(0))
    }

    /// Plain transfer of a whole coin.
    pub fn spend(&mut self, state: Hash, to: Credential) -> Result<Hash, String> {
        let rec = self.signed(Op::Transfer { state, to, receipt: Hash([0; 32]) });
        self.apply_own(&rec)?;
        Ok(rec.output(0))
    }

    /// Operator: roll the clerk's epoch, optionally revoking ticket groups.
    pub fn roll_epoch(&mut self, revoked: BTreeSet<u32>) -> Result<u32, String> {
        let op = self.operator.as_ref().ok_or("only the town operator rolls epochs")?;
        let clerk = SigningKey::from_bytes(&op.clerk);
        let h = head(&self.view, &self.town.sequence).ok_or("no epoch")?;
        let coin = self.view.coin(&h.state).ok_or("epoch state missing")?.clone();
        let data = EpochData { sequence: self.town.sequence, number: h.number + 1, revoked_groups: revoked };
        let rec = roll(&DevScheme, &clerk, &self.town.clerk, &coin, &self.town.clerk, &data);
        apply_ok(&mut self.view, &rec)?;
        self.know.add_epoch_data(&self.view, data);
        Ok(h.number + 1)
    }

    /// Would this wallet accept the coin at `state`?
    pub fn check(&self, state: &Hash) -> Result<(), Refusal> {
        let coin = self.view.coin(state).ok_or(Refusal::UnknownState)?;
        let n = coin.history.len();
        let sender = if n >= 2 { coin.history[n - 2].clone() } else { coin.holder.clone() };
        check(&self.view, &self.know, state, &sender, &self.policy())
    }
}
