//! A node: one wallet's view, knowledge and keys, saved as a record log and
//! rebuilt by replay, on Briolette v1 credentials (ECDAA over BLS12-381).
//!
//! A wallet enrolls once with the registrar and gets a supply of prefetched
//! tickets, each certifying a fresh randomized credential. Every holding and
//! every role in a job (poster, replier) uses a fresh one, so a wallet's
//! actions are unlinkable unless it uses something twice. A town operator
//! node also holds the registrar key and the root, clerk and minter roles,
//! each under its own enrolled key.

use crate::board::{self, BoardMsg};
use pave_kernel::receipt::Receipt;
use pave_kernel::*;
use pave_protocol::gossip::Hint;
use pave_protocol::*;
use pave_scheme_briolette::{randomize, BrioletteV1, HolderKey, Issuer, JoinReply, JoinRequest, PendingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub type S = BrioletteV1;

/// Tickets a wallet gets at enrollment, beyond the ones its credit uses.
pub const PREFETCH: usize = 8;

/// What every member of a town knows about it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Town {
    pub genesis: Genesis,
    pub group_public_key: Vec<u8>,
    pub board: Hash,
    pub sequence: Hash,
    pub clerk: Credential,
    pub cash: Hash,
}

/// The operator: registrar plus the root, clerk and minter roles, each its
/// own enrolled key with a fixed credential.
#[derive(Clone, Serialize, Deserialize)]
pub struct Operator {
    pub registrar: Issuer,
    pub root: HolderKey,
    pub root_cred: Credential,
    pub clerk: HolderKey,
    pub minter: HolderKey,
    pub minter_cred: Credential,
    pub cash_budget: Hash,
    pub next_group: u32,
}

/// The town's answer to a join request.
#[derive(Clone, Serialize, Deserialize)]
pub struct Enrollment {
    pub town: Town,
    pub join: JoinReply,
    pub group: u32,
    /// The first `credited` credentials hold the test credit.
    pub credited: usize,
    pub creds: Vec<Credential>,
    pub bundle: Bundle,
}

#[derive(Serialize, Deserialize)]
pub struct Saved {
    pub name: String,
    pub key: HolderKey,
    pub group: u32,
    pub pool: Vec<Credential>,
    pub mine: Vec<Credential>,
    pub town: Town,
    pub records: Vec<Record>,
    pub conflicts: Vec<Record>,
    pub evidence: Vec<Evidence>,
    pub tickets: Vec<SignedTicket>,
    pub epoch_data: Vec<EpochData>,
    pub hints: Vec<Hint>,
    pub standing: Vec<Standing>,
    pub operator: Option<Operator>,
    pub outbox: Vec<Record>,
    pub cheat_states: Vec<Hash>,
}

/// What two nodes swap when they meet: records, and what travels with a
/// coin's provenance (tickets for the credentials in those records, epoch
/// data, evidence). Tickets for unused credentials are never shared.
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
    pub key: HolderKey,
    pub group: u32,
    /// Credentials with tickets, not yet used.
    pub pool: Vec<Credential>,
    /// Every credential this wallet has a ticket for.
    pub mine: BTreeSet<Credential>,
    pub town: Town,
    pub view: View<S>,
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

fn apply_ok(view: &mut View<S>, rec: &Record) -> Result<(), String> {
    match view.apply(rec) {
        Ok(Applied::Accepted) | Ok(Applied::Duplicate) => Ok(()),
        other => Err(format!("{other:?}")),
    }
}

/// Every credential an operation names as a recipient.
fn op_recipients(op: &Op) -> Vec<&Credential> {
    match op {
        Op::Derive { to, .. } | Op::IssueBudget { to, .. } | Op::Transfer { to, .. } | Op::Merge { to, .. } => vec![to],
        Op::Mint { to, change_to, .. } => vec![to, change_to],
        Op::Split { parts, .. } => parts.iter().map(|(_, c)| c).collect(),
        _ => vec![],
    }
}

/// The bytes a ticket refill request signs.
pub fn refill_bytes(creds: &[Credential]) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/ticket-request/v0", creds))
}

impl Node {
    fn scheme(&self) -> &S {
        self.view.scheme()
    }

    /// Create a town: a registrar, enrolled role keys, genesis, the clerk's
    /// epoch sequence, a test-credit budget and an open board scope.
    pub fn init_town(path: &Path, label: &str) -> Result<Node, String> {
        let registrar = Issuer::new();
        let s = registrar.scheme();
        let (root, clerk, minter, me) = (registrar.join_locally(), registrar.join_locally(), registrar.join_locally(), registrar.join_locally());
        let (rc, cc, mc) = (s.credential(&root), s.credential(&clerk), s.credential(&minter));
        let genesis = Genesis { label: label.into(), root_rules: ScopeRules::default(), rooting: rc.clone() };
        let mut view = View::new(s.clone(), genesis.clone());
        let auth = genesis.rooting_capability();

        let seq_budget = sign(&s, &root, &rc, Op::IssueBudget { authority: auth, schema: epoch_schema(label), amount: 1, to: cc.clone() });
        apply_ok(&mut view, &seq_budget)?;
        let seq = sign(&s, &clerk, &cc, Op::Mint { budget: seq_budget.output(0), amount: 1, to: cc.clone(), change_to: cc.clone() });
        apply_ok(&mut view, &seq)?;
        let cash = sign(&s, &root, &rc, Op::IssueBudget { authority: auth, schema: cash_schema(), amount: 1_000_000, to: mc.clone() });
        apply_ok(&mut view, &cash)?;
        let board = sign(&s, &root, &rc, Op::CreateScope { parent: genesis.root_scope(), rules: ScopeRules::default(), authority: auth });
        apply_ok(&mut view, &board)?;

        let town = Town {
            genesis,
            group_public_key: registrar.group_public_key.clone(),
            board: board.output(0),
            sequence: seq.output(0),
            clerk: cc,
            cash: cash_schema().id(),
        };
        let operator = Operator { registrar, root, root_cred: rc, clerk, minter, minter_cred: mc, cash_budget: cash.output(0), next_group: 1 };
        let node = Node {
            path: path.into(),
            name: "town".into(),
            key: me,
            group: 0,
            pool: vec![],
            mine: BTreeSet::new(),
            town,
            view,
            know: Knowledge::default(),
            operator: Some(operator),
            outbox: vec![],
            cheat_states: BTreeSet::new(),
        };
        node.save()?;
        Ok(node)
    }

    /// Operator: the clerk certifies credentials into `group` at the current epoch.
    pub fn issue_tickets(&mut self, creds: &[Credential], group: u32) -> Result<Vec<SignedTicket>, String> {
        let op = self.operator.as_ref().ok_or("only the town operator issues tickets")?;
        let epoch = head(&self.view, &self.town.sequence).ok_or("no epoch")?.number;
        let s = self.view.scheme().clone();
        let out: Vec<SignedTicket> = creds
            .iter()
            .map(|c| SignedTicket::issue(&s, &op.clerk, &self.town.clerk, Ticket { credential: c.clone(), sequence: self.town.sequence, epoch, group, max_spend: None }))
            .collect();
        for t in &out {
            self.know.add_ticket(&s, t.clone());
        }
        Ok(out)
    }

    /// Operator: enroll a person (online, once). The wallet generated its own
    /// key and sends only a join request, so the registrar never holds a
    /// member's secret key. The town answers with the credential, a group, a
    /// batch of ticketed credentials and test credit minted to some of them.
    pub fn enroll(&mut self, req: &JoinRequest, credits: &[u64]) -> Result<Enrollment, String> {
        let op = self.operator.as_mut().ok_or("only the town operator can enroll")?;
        let join = op.registrar.issue(req)?;
        let group = op.next_group;
        op.next_group += 1;
        let s = self.view.scheme().clone();
        let creds: Vec<Credential> = (0..PREFETCH + credits.len()).map(|_| randomize(&join.credential)).collect();
        self.issue_tickets(&creds, group)?;
        for (i, amount) in credits.iter().enumerate() {
            let op = self.operator.as_mut().unwrap();
            let mint = sign(&s, &op.minter, &op.minter_cred, Op::Mint { budget: op.cash_budget, amount: *amount, to: creds[i].clone(), change_to: op.minter_cred.clone() });
            op.cash_budget = mint.output(1);
            apply_ok(&mut self.view, &mint)?;
        }
        self.save()?;
        let mut bundle = self.bundle();
        bundle.tickets = self.know.tickets.values().filter(|t| creds.contains(&t.ticket.credential)).cloned().collect();
        Ok(Enrollment { town: self.town.clone(), join, group, credited: credits.len(), creds, bundle })
    }

    /// Wallet: finish enrolling with the town's answer to this wallet's join
    /// request, checking that the credential is bound to its own key.
    pub fn finish_enrollment(pending: PendingKey, e: &Enrollment, name: &str, out: &Path) -> Result<Node, String> {
        let s = BrioletteV1 { group_public_key: e.town.group_public_key.clone() };
        let key = pending.finish(&s, &e.join)?;
        let mut person = Node {
            path: out.into(),
            name: name.into(),
            key,
            group: e.group,
            pool: e.creds[e.credited..].to_vec(),
            mine: e.creds.iter().cloned().collect(),
            town: e.town.clone(),
            view: View::new(s.clone(), e.town.genesis.clone()),
            know: Knowledge::default(),
            operator: None,
            outbox: vec![],
            cheat_states: BTreeSet::new(),
        };
        // The pool must be signable: each credential randomizes our own.
        for c in &e.creds {
            let sig = s.sign(&person.key, c, b"pave/enroll-check", None);
            if !s.verify(c, b"pave/enroll-check", None, &sig) {
                return Err("enrollment credential is not ours".into());
            }
        }
        person.absorb_bundle(&e.bundle);
        person.save()?;
        Ok(person)
    }

    pub fn load(path: &Path) -> Result<Node, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let saved: Saved = ciborium::from_reader(bytes.as_slice()).map_err(|e| e.to_string())?;
        let scheme = BrioletteV1 { group_public_key: saved.town.group_public_key.clone() };
        let mut node = Node {
            path: path.into(),
            name: saved.name,
            key: saved.key,
            group: saved.group,
            pool: saved.pool,
            mine: saved.mine.into_iter().collect(),
            town: saved.town.clone(),
            view: View::new(scheme, saved.town.genesis.clone()),
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
        node.absorb_standings(saved.standing);
        Ok(node)
    }

    pub fn save(&self) -> Result<(), String> {
        let saved = Saved {
            name: self.name.clone(),
            key: self.key.clone(),
            group: self.group,
            pool: self.pool.clone(),
            mine: self.mine.iter().cloned().collect(),
            town: self.town.clone(),
            records: self.view.records().to_vec(),
            conflicts: self.view.conflicts().to_vec(),
            evidence: self.view.evidence().cloned().collect(),
            tickets: self.know.tickets.values().cloned().collect(),
            epoch_data: self.know.epoch_data.values().cloned().collect(),
            hints: self.know.hints.iter().copied().collect(),
            standing: self.know.standing.values().cloned().collect(),
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
        // An honest wallet shares everything it has seen. A cheating one
        // hides its other spends of the states it double-spent.
        let hidden = |r: &Record| r.op.consumes().iter().any(|s| self.cheat_states.contains(s));
        let mut records: Vec<Record> = self.view.records().iter().filter(|r| !hidden(r)).cloned().collect();
        records.extend(self.outbox.iter().cloned());
        let conflicts: Vec<Record> = self.view.conflicts().iter().filter(|r| !hidden(r)).cloned().collect();
        // Tickets only for credentials those records name: never the pool.
        let named: BTreeSet<&Credential> = records
            .iter()
            .chain(conflicts.iter())
            .flat_map(|r| std::iter::once(&r.signer).chain(op_recipients(&r.op)))
            .collect();
        Bundle {
            genesis: self.town.genesis.root_scope(),
            tickets: self.know.tickets.values().filter(|t| named.contains(&t.ticket.credential)).cloned().collect(),
            records,
            conflicts,
            evidence: self.view.evidence().filter(|e| !self.cheat_states.contains(&e.basename)).cloned().collect(),
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
            if !before.contains(&e.basename) {
                self.view.import_evidence(e);
            }
        }
        let s = self.view.scheme().clone();
        for t in &b.tickets {
            if self.know.tickets.get(&t.ticket.credential) != Some(t) {
                self.know.add_ticket(&s, t.clone());
            }
        }
        for d in &b.epoch_data {
            if !self.know.epoch_data.contains_key(&d.hash()) {
                self.know.add_epoch_data(&self.view, d.clone());
            }
        }
        self.view.evidence().map(|e| e.basename).filter(|h| !before.contains(h)).collect()
    }

    /// Standing for every credential this wallet has paid others from,
    /// against every cheat it knows of. A cheat gets none: its key is on the
    /// list, whichever credential it asks about.
    pub fn standings(&self) -> Vec<Standing> {
        let list = cheat_list(&self.view);
        if list.is_empty() {
            return vec![];
        }
        let paid_from: BTreeSet<&Credential> = self
            .view
            .records()
            .iter()
            .chain(self.outbox.iter())
            .filter(|r| self.mine.contains(&r.signer) && op_recipients(&r.op).iter().any(|c| !self.mine.contains(*c)))
            .map(|r| &r.signer)
            .collect();
        paid_from.into_iter().filter_map(|c| Standing::prove(self.scheme(), &self.key, c, &list)).collect()
    }

    pub fn absorb_standings(&mut self, v: Vec<Standing>) -> usize {
        let s = self.view.scheme().clone();
        v.into_iter().filter(|st| self.know.add_standing(&s, st.clone())).count()
    }

    pub fn policy(&self) -> Policy {
        Policy::wallet([(self.town.clerk.clone(), self.town.sequence)].into_iter().collect())
    }

    pub fn carries(&self) -> BTreeSet<Hash> {
        [self.town.sequence].into_iter().collect()
    }

    /// States in the history of coins this wallet holds: what fork hints matter to.
    pub fn watch(&self) -> BTreeSet<Hash> {
        let mut w = BTreeSet::new();
        for c in self.my_coins() {
            w.extend(pave_protocol::accept::ancestry(&self.view, &c.state));
        }
        w
    }

    pub fn my_coins(&self) -> Vec<Coin> {
        let mut v: Vec<Coin> = self
            .view
            .unspent()
            .filter(|c| self.mine.contains(&c.holder) && c.kind == Kind::Value && c.schema == self.town.cash && c.amount > 0)
            .cloned()
            .collect();
        v.sort_by_key(|c| std::cmp::Reverse(c.amount));
        v
    }

    /// A fresh credential with a ticket, from the prefetched pool.
    pub fn fresh(&mut self) -> Result<Credential, String> {
        self.pool.pop().ok_or_else(|| "out of tickets: refill when you next meet the town".into())
    }

    /// Ask the town for `count` more tickets, authenticated by one of this
    /// wallet's ticketed credentials so the clerk knows its group.
    pub fn refill_request(&mut self, count: usize) -> Result<(Vec<Credential>, Credential, Sig), String> {
        let by = self.mine.iter().next().cloned().ok_or("no credential to ask with")?;
        let creds: Vec<Credential> = (0..count).map(|_| self.scheme().credential(&self.key)).collect();
        let sig = self.scheme().sign(&self.key, &by, &refill_bytes(&creds), None);
        Ok((creds, by, sig))
    }

    /// Operator: answer a refill request with tickets in the asker's group.
    pub fn answer_refill(&mut self, creds: &[Credential], by: &Credential, sig: &Sig) -> Result<Vec<SignedTicket>, String> {
        if !self.view.scheme().verify(by, &refill_bytes(creds), None, sig) {
            return Err("bad refill request".into());
        }
        let group = self.know.tickets.get(by).ok_or("unknown credential")?.ticket.group;
        self.issue_tickets(creds, group)
    }

    pub fn take_tickets(&mut self, tickets: Vec<SignedTicket>) -> usize {
        let s = self.view.scheme().clone();
        let mut n = 0;
        for t in tickets {
            let c = t.ticket.credential.clone();
            if self.know.add_ticket(&s, t) && self.mine.insert(c.clone()) {
                self.pool.push(c);
                n += 1;
            }
        }
        n
    }

    fn signed(&self, signer: &Credential, op: Op) -> Record {
        sign(self.scheme(), &self.key, signer, op)
    }

    fn send_as(&mut self, signer: &Credential, msg: BoardMsg, receipt: Hash) -> Result<Hash, String> {
        let rec = self.signed(signer, Op::Send { scope: self.town.board, presenting: None, body: msg.encode(), receipt });
        apply_ok(&mut self.view, &rec)?;
        Ok(rec.id())
    }

    fn job(&self, id: &Hash) -> Result<board::Job, String> {
        board::jobs(&self.view, &self.town.board).remove(id).ok_or_else(|| "unknown job".into())
    }

    /// Post a job under a fresh credential, with a zero-value split of a coin
    /// covering the pay as proof of means, committing to the terms.
    pub fn post(&mut self, title: &str, pay: u64) -> Result<Hash, String> {
        let coin = self.my_coins().into_iter().find(|c| c.amount >= pay).ok_or("no single coin covers the pay")?;
        let poster = self.fresh()?;
        let terms = Receipt::Node(vec![
            ("public".into(), Receipt::leaf(format!("{title} | pay {pay}").into_bytes())),
            ("parties".into(), Receipt::leaf(b"terms: done when the poster signs off".to_vec())),
        ]);
        let proof = self.signed(&coin.holder, Op::Split { state: coin.state, parts: vec![(coin.amount, poster.clone()), (0, poster.clone())], receipt: terms.root() });
        apply_ok(&mut self.view, &proof)?;
        self.send_as(&poster, BoardMsg::Post { title: title.into(), pay, means: proof.id() }, terms.root())
    }

    /// Reply under a fresh credential; that credential is who gets accepted and paid.
    pub fn reply(&mut self, job: Hash, note: &str) -> Result<Hash, String> {
        let me = self.fresh()?;
        self.send_as(&me, BoardMsg::Reply { job, note: note.into() }, Hash([0; 32]))
    }

    pub fn accept(&mut self, job: Hash, worker: Credential) -> Result<Hash, String> {
        let poster = self.job(&job)?.poster;
        if !self.mine.contains(&poster) {
            return Err("only the poster accepts".into());
        }
        self.send_as(&poster, BoardMsg::Accept { job, worker }, Hash([0; 32]))
    }

    pub fn done(&mut self, job: Hash) -> Result<Hash, String> {
        let worker = self.job(&job)?.worker.ok_or("no worker accepted")?;
        if !self.mine.contains(&worker) {
            return Err("only the accepted worker marks done".into());
        }
        self.send_as(&worker, BoardMsg::Done { job }, Hash([0; 32]))
    }

    /// Pay the accepted worker: a transfer, or a split with change to a fresh
    /// credential, whose receipt commits to the job.
    pub fn pay(&mut self, job_id: Hash) -> Result<Hash, String> {
        let job = self.job(&job_id)?;
        if !self.mine.contains(&job.poster) {
            return Err("only the poster pays".into());
        }
        let worker = job.worker.clone().ok_or("no worker accepted")?;
        if job.status != board::Status::Done {
            return Err(format!("job is {:?}, not Done", job.status));
        }
        let coin = self.my_coins().into_iter().find(|c| c.amount >= job.pay).ok_or("no single coin covers the pay")?;
        let receipt = board::pay_receipt(&job_id);
        let rec = if coin.amount == job.pay {
            self.signed(&coin.holder, Op::Transfer { state: coin.state, to: worker, receipt })
        } else {
            let change = self.fresh()?;
            self.signed(&coin.holder, Op::Split { state: coin.state, parts: vec![(job.pay, worker), (coin.amount - job.pay, change)], receipt })
        };
        apply_ok(&mut self.view, &rec)?;
        let payment = rec.output(0);
        self.send_as(&job.poster, BoardMsg::Paid { job: job_id, payment }, receipt)?;
        Ok(payment)
    }

    /// A fresh credential to be paid at.
    pub fn receive(&mut self) -> Result<Credential, String> {
        self.fresh()
    }

    /// Plain transfer of a whole coin.
    pub fn spend(&mut self, state: Hash, to: Credential) -> Result<Hash, String> {
        let holder = self.view.coin(&state).filter(|c| self.mine.contains(&c.holder)).ok_or("not a coin this wallet holds")?.holder.clone();
        let rec = self.signed(&holder, Op::Transfer { state, to, receipt: Hash([0; 32]) });
        apply_ok(&mut self.view, &rec)?;
        Ok(rec.output(0))
    }

    /// A dishonest wallet: sign another transfer of `state` without applying
    /// it locally, hide the earlier spend, and hand it to the next peer met.
    pub fn cheat(&mut self, state: Hash, to: Credential) -> Result<Hash, String> {
        let holder = match (self.view.coin(&state), self.view.spender(&state)) {
            (Some(c), _) if self.mine.contains(&c.holder) => c.holder.clone(),
            (_, Some(r)) if self.mine.contains(&r.signer) => r.signer.clone(),
            _ => return Err("not a state this wallet held".into()),
        };
        let rec = self.signed(&holder, Op::Transfer { state, to, receipt: Hash([0; 32]) });
        self.outbox.push(rec.clone());
        self.cheat_states.insert(state);
        Ok(rec.output(0))
    }

    /// Operator: roll the clerk's epoch, optionally revoking ticket groups.
    pub fn roll_epoch(&mut self, revoked: BTreeSet<u32>) -> Result<u32, String> {
        let op = self.operator.as_ref().ok_or("only the town operator rolls epochs")?;
        let h = head(&self.view, &self.town.sequence).ok_or("no epoch")?;
        let coin = self.view.coin(&h.state).ok_or("epoch state missing")?.clone();
        let data = EpochData { sequence: self.town.sequence, number: h.number + 1, revoked_groups: revoked };
        let rec = roll(self.view.scheme(), &op.clerk, &self.town.clerk, &coin, &self.town.clerk, &data);
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

    /// The ticket group behind a credential, if this wallet has its ticket.
    pub fn group_of(&self, c: &Credential) -> Option<u32> {
        self.know.tickets.get(c).map(|t| t.ticket.group)
    }
}
