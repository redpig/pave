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
use crate::bulletin::{BoardInfo, Copy, PostReceipt, Submission};
use pave_kernel::receipt::Receipt;
use pave_kernel::*;
use pave_protocol::gossip::Hint;
use pave_protocol::*;
use pave_scheme_briolette::{join_nonce, randomize, BrioletteV1, HolderKey, Issuer, JoinReply, JoinRequest, PendingKey};
use serde::{Deserialize, Serialize};
use crate::vault::{Keystore, SoftwareKeystore};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub type S = BrioletteV1;

/// The identities a wallet starts with, from least to most identifiable:
/// one shared with a few people, one with its contacts, one public. Posting
/// with none is the anonymous tier.
pub const IDENTITY_TIERS: [&str; 3] = ["close", "contacts", "public"];

/// Tickets a wallet asks for at a time.
pub const PREFETCH: usize = 8;
/// Ticket groups are drawn at random from this many, one per batch.
pub const GROUPS: u32 = 4096;
/// Most credentials one ticket request may name.
pub const MAX_BATCH: usize = 16;
/// Most ticket requests one wallet may make per epoch.
pub const BATCHES_PER_EPOCH: usize = 2;

/// A class of wallet: a kind of device or level of assurance. Each class has
/// its own network-access issuer, so a wallet's requests show its class and
/// nothing else, and its own ticket terms. Recipients see only the terms.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Class {
    pub group_public_key: Vec<u8>,
    /// Most one ticket may receive in one coin.
    pub max_spend: Option<u64>,
}

/// What every member of a town knows about it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Town {
    pub genesis: Genesis,
    pub group_public_key: Vec<u8>,
    pub sequence: Hash,
    pub clerk: Credential,
    pub cash: Hash,
    pub classes: BTreeMap<String, Class>,
    /// The town's job board. Its host is the town.
    pub jobs: BoardInfo,
    /// The town's reports board, with its mirror and moderator roles.
    pub reports: BoardInfo,
    /// The parcel schema: packages in custody. See [`crate::parcel`].
    pub parcels: Hash,
}

/// The operator: registrar plus the root, clerk and minter roles, each its
/// own enrolled key with a fixed credential.
#[derive(Clone, Serialize, Deserialize)]
pub struct Operator {
    /// Issues transfer credentials. One group for everyone, so coins don't
    /// show what kind of wallet holds them.
    pub registrar: Issuer,
    /// Issues network-access credentials, one issuer per class.
    pub access: BTreeMap<String, Issuer>,
    /// Classes no longer served, after a class break, until members re-attest.
    pub closed: BTreeSet<String>,
    /// The clerk's private map from ticket group to class. It names no one.
    pub groups: BTreeMap<u32, String>,
    /// Every group revoked so far, with the epoch it was revoked in;
    /// revocation is cumulative.
    pub revoked: BTreeMap<u32, u32>,
    /// Ticket requests this epoch, by request pseudonym, for the rate limit.
    pub asked: BTreeMap<Vec<u8>, usize>,
    pub asked_epoch: u32,
    /// Swaps waiting out their hold.
    pub held: Vec<crate::swap::Held>,
    pub root: HolderKey,
    pub root_cred: Credential,
    pub clerk: HolderKey,
    pub minter: HolderKey,
    pub minter_cred: Credential,
    pub cash_budget: Hash,
}

/// A wallet's join request: a transfer key and a network-access key, both
/// generated on the wallet.
#[derive(Clone, Serialize, Deserialize)]
pub struct Join {
    pub transfer: JoinRequest,
    pub access: JoinRequest,
}

/// The wallet's side of a join until the town answers. Keep it secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingJoin {
    pub transfer: PendingKey,
    pub access: PendingKey,
}

impl PendingJoin {
    pub fn generate() -> (PendingJoin, Join) {
        let (t, tr) = PendingKey::generate(&join_nonce());
        let (a, ar) = PendingKey::generate(&join_nonce());
        (PendingJoin { transfer: t, access: a }, Join { transfer: tr, access: ar })
    }
}

/// What the clerk asks of a ticket request this epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefillTerms {
    pub epoch: u32,
    /// Every cheat the clerk knows of: each requested credential needs standing against all of them.
    pub cheats: Vec<(Vec<u8>, Vec<u8>)>,
}

/// An anonymous ticket request. It is signed with a fresh randomization of
/// the wallet's access credential, with the epoch as basename: the clerk
/// learns the wallet's class and can count its requests this epoch, and
/// nothing links it to the wallet's tickets, its other requests or its name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefillRequest {
    pub epoch: u32,
    pub creds: Vec<Credential>,
    pub standing: Vec<Standing>,
    pub access: Credential,
    pub sig: Sig,
}

/// The town's answer to a join request.
#[derive(Clone, Serialize, Deserialize)]
pub struct Enrollment {
    pub town: Town,
    pub transfer: JoinReply,
    pub access: JoinReply,
    pub class: String,
    pub group: u32,
    /// Credentials holding the test credit. The wallet's other tickets come
    /// from anonymous refills, so the town can't tie them to this enrollment.
    pub creds: Vec<Credential>,
    pub bundle: Bundle,
}

#[derive(Serialize, Deserialize)]
pub struct Saved {
    pub name: String,
    pub key: HolderKey,
    pub access: HolderKey,
    pub class: String,
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
    pub swaps_held: Vec<Credential>,
    pub signed_log: Vec<(Hash, Record)>,
    pub invoices: Vec<(Credential, u64, Hash)>,
    pub paid: Vec<(Hash, Credential)>,
    pub pending: Vec<Record>,
    /// Each board copy: its posts, and receipts for this wallet's own.
    #[serde(default)]
    pub boards: Vec<(Hash, Vec<Submission>, Vec<PostReceipt>)>,
    #[serde(default)]
    pub outgoing: Vec<Submission>,
    #[serde(default)]
    pub trade: Option<Credential>,
    #[serde(default)]
    pub identities: Vec<(String, Credential)>,
    #[serde(default)]
    pub contacts: Vec<(String, Credential)>,
    #[serde(default)]
    pub parcels: Vec<crate::parcel::Manifest>,
    #[serde(default)]
    pub codes: Vec<(Hash, String)>,
}

/// A summary of what a wallet has: id prefixes of its records, evidence
/// and epoch data.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Have {
    pub records: BTreeSet<crate::pay::Prefix>,
    pub evidence: BTreeSet<crate::pay::Prefix>,
    pub epochs: BTreeSet<crate::pay::Prefix>,
}

/// What two nodes swap when they meet: records, and what travels with a
/// coin's provenance (tickets for the credentials in those records, epoch
/// data, evidence). Tickets for unused credentials are never shared.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// Network-access key, for anonymous requests to the town's services.
    pub access: HolderKey,
    pub class: String,
    /// The ticket group of this wallet's enrollment batch.
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
    /// Credentials a swapper owes a fresh coin to, after its hold.
    pub swaps_held: Vec<Credential>,
    /// Every state this wallet has signed away, and the record it released.
    pub signed_log: BTreeMap<Hash, Record>,
    /// Seals the saved state; see [`crate::vault`].
    pub vault: std::sync::Mutex<Box<dyn Keystore>>,
    /// Payee: open invoices, by receiving credential: (amount, memo).
    pub invoices: BTreeMap<Credential, (u64, Hash)>,
    /// Payee: payments taken, by record id, so a resend is acknowledged again.
    pub paid: BTreeMap<Hash, Credential>,
    /// Payer: payments signed and sent but not yet acknowledged.
    pub pending: Vec<Record>,
    /// Copies of the town's boards, by scope. See [`crate::bulletin`].
    pub boards: BTreeMap<Hash, Copy>,
    /// Posts signed and waiting for their host.
    pub outgoing: Vec<Submission>,
    /// This wallet's trade key, once it replies as a contractor.
    pub trade: Option<Credential>,
    /// Stable credentials this wallet signs with for chosen audiences, by label.
    pub identities: BTreeMap<String, Credential>,
    /// Stable credentials others shared with this wallet, by the name it knows them by.
    pub contacts: BTreeMap<String, Credential>,
    /// Manifests of parcels this wallet shipped, carried or received.
    pub parcels: BTreeMap<Hash, crate::parcel::Manifest>,
    /// Delivery codes for parcels this wallet shipped by code.
    pub codes: BTreeMap<Hash, String>,
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

pub(crate) fn apply_ok(view: &mut View<S>, rec: &Record) -> Result<(), String> {
    match view.apply(rec) {
        Ok(Applied::Accepted) | Ok(Applied::Duplicate) => Ok(()),
        other => Err(format!("{other:?}")),
    }
}

/// Every credential an operation names as a recipient.
pub(crate) fn op_recipients(op: &Op) -> Vec<&Credential> {
    match op {
        Op::Derive { to, .. } | Op::IssueBudget { to, .. } | Op::Transfer { to, .. } | Op::Merge { to, .. } => vec![to],
        Op::Mint { to, change_to, .. } => vec![to, change_to],
        Op::Split { parts, .. } => parts.iter().map(|(_, c)| c).collect(),
        _ => vec![],
    }
}

/// The basename a ticket request is signed with: one per clerk epoch.
pub fn refill_basename(sequence: &Hash, epoch: u32) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/ticket-request/v0", sequence, epoch))
}

/// The bytes a ticket request signs.
pub fn refill_bytes(epoch: u32, creds: &[Credential], standing: &[Standing]) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/ticket-request/v0", epoch, creds, standing))
}

/// The classes a test town starts with.
fn default_classes() -> Vec<(&'static str, Option<u64>)> {
    vec![("hardware", None), ("software", Some(50))]
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
        let jobs = sign(&s, &root, &rc, Op::CreateScope { parent: genesis.root_scope(), rules: ScopeRules::default(), authority: auth });
        apply_ok(&mut view, &jobs)?;
        let reports = sign(&s, &root, &rc, Op::CreateScope { parent: genesis.root_scope(), rules: ScopeRules::default(), authority: auth });
        apply_ok(&mut view, &reports)?;

        let access: BTreeMap<String, Issuer> = default_classes().iter().map(|(c, _)| (c.to_string(), Issuer::new())).collect();
        let classes = default_classes()
            .into_iter()
            .map(|(c, max_spend)| (c.to_string(), Class { group_public_key: access[c].group_public_key.clone(), max_spend }))
            .collect();
        let town = Town {
            genesis,
            group_public_key: registrar.group_public_key.clone(),
            sequence: seq.output(0),
            clerk: cc,
            cash: cash_schema().id(),
            classes,
            parcels: crate::parcel::parcel_schema().id(),
            jobs: BoardInfo { scope: jobs.output(0), host: s.credential(&me), roles: [("escrow".to_string(), s.credential(&me))].into_iter().collect() },
            reports: BoardInfo {
                scope: reports.output(0),
                host: s.credential(&me),
                roles: [("mirror".to_string(), s.credential(&me)), ("moderator".to_string(), s.credential(&me))].into_iter().collect(),
            },
        };
        let my_access = access["hardware"].join_locally();
        let operator = Operator {
            registrar,
            access,
            closed: BTreeSet::new(),
            groups: BTreeMap::new(),
            revoked: BTreeMap::new(),
            asked: BTreeMap::new(),
            asked_epoch: 0,
            held: vec![],
            root,
            root_cred: rc,
            clerk,
            minter,
            minter_cred: mc,
            cash_budget: cash.output(0),
        };
        let mut node = Node {
            path: path.into(),
            name: "town".into(),
            key: me,
            access: my_access,
            class: "hardware".into(),
            group: 0,
            pool: vec![],
            mine: BTreeSet::new(),
            town,
            view,
            know: Knowledge::default(),
            operator: Some(operator),
            outbox: vec![],
            cheat_states: BTreeSet::new(),
            swaps_held: vec![],
            signed_log: BTreeMap::new(),
            invoices: BTreeMap::new(),
            paid: BTreeMap::new(),
            pending: vec![],
            boards: BTreeMap::new(),
            outgoing: vec![],
            trade: None,
            identities: BTreeMap::new(),
            contacts: BTreeMap::new(),
            parcels: BTreeMap::new(),
            codes: BTreeMap::new(),
            vault: std::sync::Mutex::new(Box::new(SoftwareKeystore::for_state(path)?)),
        };
        node.open_boards()?;
        node.save()?;
        Ok(node)
    }

    /// Operator: a fresh random ticket group for a batch from `class`.
    fn new_group(&mut self, class: &str) -> Result<u32, String> {
        let op = self.operator.as_mut().ok_or("only the town operator assigns groups")?;
        loop {
            let g = rand::Rng::gen_range(&mut rand::rngs::OsRng, 1..GROUPS);
            if op.revoked.contains_key(&g) {
                continue;
            }
            match op.groups.get(&g) {
                Some(c) if c != class => continue,
                _ => {
                    op.groups.insert(g, class.to_string());
                    return Ok(g);
                }
            }
        }
    }

    /// Operator: the clerk certifies a batch of credentials from `class`, in
    /// a fresh random group, at the current epoch, on the class's terms.
    pub fn issue_tickets(&mut self, creds: &[Credential], class: &str) -> Result<(u32, Vec<SignedTicket>), String> {
        let group = self.new_group(class)?;
        let max_spend = self.town.classes.get(class).ok_or("unknown class")?.max_spend;
        let op = self.operator.as_ref().ok_or("only the town operator issues tickets")?;
        let epoch = head(&self.view, &self.town.sequence).ok_or("no epoch")?.number;
        let s = self.view.scheme().clone();
        let out: Vec<SignedTicket> = creds
            .iter()
            .map(|c| SignedTicket::issue(&s, &op.clerk, &self.town.clerk, Ticket { credential: c.clone(), sequence: self.town.sequence, epoch, group, max_spend }))
            .collect();
        for t in &out {
            self.know.add_ticket(&s, t.clone());
        }
        Ok((group, out))
    }

    /// Operator: enroll a person (online, once) into a class. The wallet
    /// generated its own keys and sends only public keys with proofs, so the
    /// registrar never holds a member's secret. The town answers with a
    /// transfer credential, an access credential for the class, and test
    /// credit minted to ticketed credentials. Everything else the wallet gets
    /// later through anonymous refills.
    pub fn enroll(&mut self, join: &Join, class: &str, credits: &[u64]) -> Result<Enrollment, String> {
        let op = self.operator.as_mut().ok_or("only the town operator can enroll")?;
        if op.closed.contains(class) {
            return Err(format!("class {class} is closed"));
        }
        let transfer = op.registrar.issue(&join.transfer)?;
        let access = op.access.get(class).ok_or("unknown class")?.issue(&join.access)?;
        let s = self.view.scheme().clone();
        let creds: Vec<Credential> = credits.iter().map(|_| randomize(&transfer.credential)).collect();
        let group = if creds.is_empty() { 0 } else { self.issue_tickets(&creds, class)?.0 };
        for (i, amount) in credits.iter().enumerate() {
            let op = self.operator.as_mut().unwrap();
            let mint = sign(&s, &op.minter, &op.minter_cred, Op::Mint { budget: op.cash_budget, amount: *amount, to: creds[i].clone(), change_to: op.minter_cred.clone() });
            let mint = self.guard(mint)?;
            self.operator.as_mut().unwrap().cash_budget = mint.output(1);
            apply_ok(&mut self.view, &mint)?;
        }
        self.save()?;
        // Only what the new member needs: its coins' provenance, the epoch
        // sequence and the board scope. Never the rest of the town's view.
        let mut keep: std::collections::BTreeMap<Hash, Record> = BTreeMap::new();
        let mut roots: Vec<Hash> = (0..credits.len()).filter_map(|i| self.view.coins_held_by(&creds[i]).next().map(|c| c.state)).collect();
        if let Some(h) = head(&self.view, &self.town.sequence) {
            roots.push(h.state);
        }
        for st in roots {
            for r in self.provenance(&st) {
                keep.insert(r.id(), r);
            }
        }
        for r in self.view.records().iter().filter(|r| matches!(r.op, Op::CreateScope { .. })) {
            keep.insert(r.id(), r.clone());
        }
        let mut bundle = self.bundle();
        bundle.records = self.view.records().iter().filter(|r| keep.contains_key(&r.id())).cloned().collect();
        bundle.conflicts.clear();
        bundle.tickets = self.know.tickets.values().filter(|t| creds.contains(&t.ticket.credential)).cloned().collect();
        Ok(Enrollment { town: self.town.clone(), transfer, access, class: class.into(), group, creds, bundle })
    }

    /// Wallet: finish enrolling with the town's answer to this wallet's join
    /// request, checking that both credentials are bound to its own keys.
    pub fn finish_enrollment(pending: PendingJoin, e: &Enrollment, name: &str, out: &Path) -> Result<Node, String> {
        let s = BrioletteV1 { group_public_key: e.town.group_public_key.clone() };
        let class = e.town.classes.get(&e.class).ok_or("unknown class")?;
        let key = pending.transfer.finish(&s, &e.transfer)?;
        let access = pending.access.finish(&BrioletteV1 { group_public_key: class.group_public_key.clone() }, &e.access)?;
        let mut person = Node {
            path: out.into(),
            name: name.into(),
            key,
            access,
            class: e.class.clone(),
            group: e.group,
            pool: vec![],
            mine: e.creds.iter().cloned().collect(),
            town: e.town.clone(),
            view: View::new(s.clone(), e.town.genesis.clone()),
            know: Knowledge::default(),
            operator: None,
            outbox: vec![],
            cheat_states: BTreeSet::new(),
            swaps_held: vec![],
            signed_log: BTreeMap::new(),
            invoices: BTreeMap::new(),
            paid: BTreeMap::new(),
            pending: vec![],
            boards: BTreeMap::new(),
            outgoing: vec![],
            trade: None,
            identities: BTreeMap::new(),
            contacts: BTreeMap::new(),
            parcels: BTreeMap::new(),
            codes: BTreeMap::new(),
            vault: std::sync::Mutex::new(Box::new(SoftwareKeystore::for_state(out)?)),
        };
        for c in &e.creds {
            let sig = s.sign(&person.key, c, b"pave/enroll-check", None);
            if !s.verify(c, b"pave/enroll-check", None, &sig) {
                return Err("enrollment credential is not ours".into());
            }
        }
        person.absorb_bundle(&e.bundle);
        person.open_boards()?;
        // One identity per privacy tier, ready before the first post.
        for tier in IDENTITY_TIERS {
            let c = s.credential(&person.key);
            person.identities.insert(tier.to_string(), c);
        }
        person.save()?;
        Ok(person)
    }

    /// Load a wallet sealed by the software keystore beside it.
    pub fn load(path: &Path) -> Result<Node, String> {
        Self::load_with(path, Box::new(SoftwareKeystore::for_state(path)?))
    }

    /// Load a wallet sealed by `vault`.
    pub fn load_with(path: &Path, vault: Box<dyn Keystore>) -> Result<Node, String> {
        let sealed = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let bytes = vault.open(&sealed)?;
        let saved: Saved = ciborium::from_reader(bytes.as_slice()).map_err(|e| e.to_string())?;
        let scheme = BrioletteV1 { group_public_key: saved.town.group_public_key.clone() };
        let mut node = Node {
            path: path.into(),
            name: saved.name,
            key: saved.key,
            access: saved.access,
            class: saved.class,
            group: saved.group,
            pool: saved.pool,
            mine: saved.mine.into_iter().collect(),
            town: saved.town.clone(),
            view: View::new(scheme, saved.town.genesis.clone()),
            know: Knowledge::default(),
            operator: saved.operator,
            outbox: saved.outbox,
            cheat_states: saved.cheat_states.into_iter().collect(),
            swaps_held: saved.swaps_held,
            signed_log: saved.signed_log.into_iter().collect(),
            invoices: saved.invoices.into_iter().map(|(c, a, m)| (c, (a, m))).collect(),
            paid: saved.paid.into_iter().collect(),
            pending: saved.pending,
            boards: BTreeMap::new(),
            outgoing: saved.outgoing,
            trade: saved.trade,
            identities: saved.identities.into_iter().collect(),
            contacts: saved.contacts.into_iter().collect(),
            parcels: saved.parcels.into_iter().map(|m| (m.parcel, m)).collect(),
            codes: saved.codes.into_iter().collect(),
            vault: std::sync::Mutex::new(vault),
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
        node.open_boards()?;
        for (scope, posts, receipts) in saved.boards {
            node.absorb_posts(&scope, &posts);
            if let Some(c) = node.boards.get_mut(&scope) {
                c.receipts.extend(receipts.into_iter().map(|r| (r.post, r)));
            }
        }
        Ok(node)
    }

    pub fn save(&self) -> Result<(), String> {
        let saved = Saved {
            name: self.name.clone(),
            key: self.key.clone(),
            access: self.access.clone(),
            class: self.class.clone(),
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
            swaps_held: self.swaps_held.clone(),
            signed_log: self.signed_log.iter().map(|(h, r)| (*h, r.clone())).collect(),
            invoices: self.invoices.iter().map(|(c, (a, m))| (c.clone(), *a, *m)).collect(),
            paid: self.paid.iter().map(|(h, c)| (*h, c.clone())).collect(),
            pending: self.pending.clone(),
            boards: self.boards.iter().map(|(s, c)| (*s, c.submissions(), c.receipts.values().cloned().collect())).collect(),
            outgoing: self.outgoing.clone(),
            trade: self.trade.clone(),
            identities: self.identities.iter().map(|(l, c)| (l.clone(), c.clone())).collect(),
            contacts: self.contacts.iter().map(|(n, c)| (n.clone(), c.clone())).collect(),
            parcels: self.parcels.values().cloned().collect(),
            codes: self.codes.iter().map(|(p, c)| (*p, c.clone())).collect(),
        };
        let bytes = pave_kernel::hash::encode(&saved);
        let mut vault = self.vault.lock().unwrap();
        let sealed = vault.seal(&bytes)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, sealed).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())?;
        vault.commit()
    }

    /// Move this wallet's state to another keystore, such as a device's.
    pub fn use_keystore(&mut self, vault: Box<dyn Keystore>) -> Result<(), String> {
        self.vault = std::sync::Mutex::new(vault);
        self.save()
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

    /// What this wallet already has, as 8-byte id prefixes, so a peer can
    /// send only the rest.
    pub fn have(&self) -> Have {
        use crate::pay::prefix;
        Have {
            records: self.view.records().iter().chain(self.view.conflicts().iter()).map(|r| prefix(&r.id())).collect(),
            evidence: self.view.evidence().map(|e| prefix(&e.basename)).collect(),
            epochs: self.know.epoch_data.keys().map(prefix).collect(),
        }
    }

    /// The bundle, less what the peer already has. A prefix collision only
    /// means a record isn't sent; the peer asks again next time.
    pub fn bundle_for(&self, have: &Have) -> Bundle {
        use crate::pay::prefix;
        let mut b = self.bundle();
        b.records.retain(|r| !have.records.contains(&prefix(&r.id())));
        b.conflicts.retain(|r| !have.records.contains(&prefix(&r.id())));
        b.evidence.retain(|e| !have.evidence.contains(&prefix(&e.basename)));
        b.epoch_data.retain(|d| !have.epochs.contains(&prefix(&d.hash())));
        let named: BTreeSet<&Credential> = b.records.iter().chain(b.conflicts.iter()).flat_map(|r| std::iter::once(&r.signer).chain(op_recipients(&r.op))).collect();
        b.tickets.retain(|t| named.contains(&t.ticket.credential));
        b
    }

    /// Merge what a peer sent. Returns the states with new evidence.
    pub fn absorb_bundle(&mut self, b: &Bundle) -> Vec<Hash> {
        let before: BTreeSet<Hash> = self.view.evidence().map(|e| e.basename).collect();
        // Board posts don't travel between wallets; they go to their host.
        let boards: BTreeSet<Hash> = [self.town.jobs.scope, self.town.reports.scope].into_iter().collect();
        for r in b.records.iter().chain(b.conflicts.iter()) {
            if matches!(&r.op, Op::Send { scope, .. } if boards.contains(scope)) {
                continue;
            }
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

    /// Operator: what a ticket request must meet this epoch.
    pub fn refill_terms(&self) -> Result<RefillTerms, String> {
        let epoch = head(&self.view, &self.town.sequence).ok_or("no epoch")?.number;
        Ok(RefillTerms { epoch, cheats: cheat_list(&self.view) })
    }

    /// Ask for `count` more tickets, anonymously: fresh credentials, each
    /// with standing against every cheat the clerk knows of, signed with a
    /// fresh randomization of this wallet's access credential.
    pub fn refill_request(&self, terms: &RefillTerms, count: usize) -> Result<RefillRequest, String> {
        let s = self.scheme();
        let creds: Vec<Credential> = (0..count).map(|_| s.credential(&self.key)).collect();
        let standing = creds
            .iter()
            .map(|c| Standing::prove(s, &self.key, c, &terms.cheats).ok_or_else(|| "this wallet is a known cheat".to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let a = BrioletteV1 { group_public_key: self.town.classes[&self.class].group_public_key.clone() };
        let access = a.credential(&self.access);
        let bsn = refill_basename(&self.town.sequence, terms.epoch);
        let sig = a.sign(&self.access, &access, &refill_bytes(terms.epoch, &creds, &standing), Some(&bsn));
        Ok(RefillRequest { epoch: terms.epoch, creds, standing, access, sig })
    }

    /// Operator: answer an anonymous ticket request. The access signature
    /// shows the class; its pseudonym, fixed per epoch, counts requests;
    /// standing keeps known cheats out; each batch gets a fresh random group.
    pub fn answer_refill(&mut self, req: &RefillRequest) -> Result<Vec<SignedTicket>, String> {
        let terms = self.refill_terms()?;
        if req.epoch != terms.epoch {
            return Err(format!("stale request: the clerk is at epoch {}", terms.epoch));
        }
        if req.creds.is_empty() || req.creds.len() > MAX_BATCH || req.standing.len() != req.creds.len() {
            return Err(format!("ask for 1 to {MAX_BATCH} tickets, each with standing"));
        }
        let msg = refill_bytes(req.epoch, &req.creds, &req.standing);
        let bsn = refill_basename(&self.town.sequence, req.epoch);
        let class = self
            .town
            .classes
            .iter()
            .find(|(_, c)| BrioletteV1 { group_public_key: c.group_public_key.clone() }.verify(&req.access, &msg, Some(&bsn), &req.sig))
            .map(|(name, _)| name.clone())
            .ok_or("not signed by a member of any class")?;
        let nym = self.scheme().nym(&req.sig).ok_or("no request pseudonym")?;
        let s = self.view.scheme().clone();
        for (c, st) in req.creds.iter().zip(&req.standing) {
            if st.credential != *c || !st.covers(&terms.cheats) || !st.verify(&s) {
                return Err("a credential lacks standing".into());
            }
        }
        let op = self.operator.as_mut().ok_or("only the town operator issues tickets")?;
        if op.closed.contains(&class) {
            return Err(format!("class {class} is closed: update the wallet and enroll again"));
        }
        if op.asked_epoch != req.epoch {
            op.asked.clear();
            op.asked_epoch = req.epoch;
        }
        let n = op.asked.entry(nym).or_default();
        if *n >= BATCHES_PER_EPOCH {
            return Err(format!("at most {BATCHES_PER_EPOCH} ticket requests per epoch"));
        }
        *n += 1;
        Ok(self.issue_tickets(&req.creds, &class)?.1)
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

    pub(crate) fn signed(&mut self, signer: &Credential, op: Op) -> Result<Record, String> {
        let rec = sign(self.scheme(), &self.key, signer, op);
        self.guard(rec)
    }

    /// The signing log: refuse to release a signature that uses a state this
    /// wallet already signed away, unless it is the very same operation, in
    /// which case hand back the record released before (a retry after a
    /// crash). The log is saved before the signature leaves, so a crash
    /// can't forget it. Every role key the town holds goes through here too:
    /// an issuer that signs one epoch twice is caught like any cheat.
    pub(crate) fn guard(&mut self, rec: Record) -> Result<Record, String> {
        for b in rec.op.consumes() {
            if let Some(prior) = self.signed_log.get(&b) {
                return if prior.op == rec.op && prior.signer == rec.signer {
                    Ok(prior.clone())
                } else {
                    Err(format!("refusing to sign state {} a second time", hex::encode(&b.0[..6])))
                };
            }
        }
        for b in rec.op.consumes() {
            self.signed_log.insert(b, rec.clone());
        }
        self.save()?;
        Ok(rec)
    }

    /// Post to the job board as `signer`, queued for the town.
    fn send_as(&mut self, signer: &Credential, msg: BoardMsg) -> Result<Hash, String> {
        let thread = msg.job();
        let scope = self.town.jobs.scope;
        self.compose(&scope, signer, msg.kind(), thread, msg.encode(), None)
    }

    /// The job board as this wallet's copy has it.
    pub fn jobs(&self) -> BTreeMap<Hash, board::Job> {
        self.copy(&self.town.jobs.scope).map(board::jobs).unwrap_or_default()
    }

    /// A contractor's reputation on the job board: distinct people per job
    /// type, and the vouches that count.
    pub fn reputation(&self, who: &Hash) -> (BTreeMap<String, usize>, Vec<board::Vouched>) {
        self.copy(&self.town.jobs.scope).map(|c| board::reputation(c, &self.town.classes, &self.contacts, who)).unwrap_or_default()
    }

    /// The vouch coins this wallet holds, by state.
    pub fn vouch_coins(&self) -> Vec<Hash> {
        let Some(who) = self.contractor() else { return vec![] };
        self.reputation(&who).1.into_iter().map(|v| v.coin).filter(|c| self.view.coin(c).is_some_and(|c| self.mine.contains(&c.holder))).collect()
    }

    fn job(&self, id: &Hash) -> Result<board::Job, String> {
        self.jobs().remove(id).ok_or_else(|| "unknown job".into())
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
        let proof = self.signed(&coin.holder, Op::Split { state: coin.state, parts: vec![(coin.amount, poster.clone()), (0, poster.clone())], receipt: terms.root() })?;
        apply_ok(&mut self.view, &proof)?;
        self.send_as(&poster, BoardMsg::Post { title: title.into(), pay, means: proof.id(), terms: terms.root() })
    }

    /// Reply under a fresh credential; that credential is who gets accepted and paid.
    pub fn reply(&mut self, job: Hash, note: &str) -> Result<Hash, String> {
        let me = self.fresh()?;
        self.send_as(&me, BoardMsg::Reply { job, note: note.into(), trade: None })
    }

    /// This wallet's identity for `label`: a stable credential it can sign
    /// posts with, made on first use. A wallet starts with one per privacy
    /// tier ([`IDENTITY_TIERS`]). Share each with the people who should
    /// recognize what it signs. Everything signed with one links to
    /// everything else signed with it.
    pub fn identity(&mut self, label: &str) -> Result<Credential, String> {
        if !self.identities.contains_key(label) {
            let c = self.scheme().credential(&self.key);
            self.identities.insert(label.into(), c);
            self.save()?;
        }
        Ok(self.identities[label].clone())
    }

    /// Recognize what `name`'s stable credential signs from now on.
    pub fn add_contact(&mut self, name: &str, cred: Credential) -> Result<(), String> {
        self.contacts.insert(name.into(), cred);
        self.save()
    }

    /// This wallet's trade key: the stable identity its vouches name. It is
    /// made on first use, and links every job replied to under it.
    pub fn trade_key(&mut self) -> Result<Credential, String> {
        if self.trade.is_none() {
            self.trade = Some(self.scheme().credential(&self.key));
            self.save()?;
        }
        Ok(self.trade.clone().unwrap())
    }

    /// The contractor this wallet is known as, if it has a trade key.
    pub fn contractor(&self) -> Option<Hash> {
        self.trade.as_ref().map(board::contractor)
    }

    /// Reply as a contractor, opting into a vouch: the fresh credential
    /// that will be paid, signed over by this wallet's trade key.
    pub fn reply_as_contractor(&mut self, job: Hash, note: &str) -> Result<Hash, String> {
        let me = self.fresh()?;
        let key = self.trade_key()?;
        let sig = self.scheme().sign(&self.key, &key, &board::trade_bytes(&job, &me), None);
        self.send_as(&me, BoardMsg::Reply { job, note: note.into(), trade: Some(board::Trade { key, sig }) })
    }

    pub fn accept(&mut self, job: Hash, worker: Credential) -> Result<Hash, String> {
        let poster = self.job(&job)?.poster;
        if !self.mine.contains(&poster) {
            return Err("only the poster accepts".into());
        }
        self.send_as(&poster, BoardMsg::Accept { job, worker })
    }

    pub fn done(&mut self, job: Hash) -> Result<Hash, String> {
        let worker = self.job(&job)?.worker.ok_or("no worker accepted")?;
        if !self.mine.contains(&worker) {
            return Err("only the accepted worker marks done".into());
        }
        self.send_as(&worker, BoardMsg::Done { job })
    }

    /// Pay the accepted worker: a transfer, or a split with change to a fresh
    /// credential, whose receipt commits to the job.
    pub fn pay(&mut self, job_id: Hash) -> Result<Hash, String> {
        self.pay_with(job_id, None)
    }

    /// Pay the accepted worker and vouch for them for `category`: the
    /// payment's second output is a zero-value vouch coin to the worker,
    /// and the vouch is posted, endorsed, in the contractor's thread. The
    /// worker must have replied as a contractor.
    /// With `as_stable`, the vouch is also signed with that stable
    /// credential, so whoever was given it knows the vouch is this wallet's.
    pub fn pay_and_vouch(&mut self, job_id: Hash, category: &str, note: &str, identity: Option<&str>) -> Result<Hash, String> {
        self.pay_with(job_id, Some((category, note, identity)))
    }

    fn pay_with(&mut self, job_id: Hash, vouch: Option<(&str, &str, Option<&str>)>) -> Result<Hash, String> {
        let job = self.job(&job_id)?;
        if !self.mine.contains(&job.poster) {
            return Err("only the poster pays".into());
        }
        let worker = job.worker.clone().ok_or("no worker accepted")?;
        if job.status != board::Status::Done {
            return Err(format!("job is {:?}, not Done", job.status));
        }
        let coin = self.my_coins().into_iter().find(|c| c.amount >= job.pay).ok_or("no single coin covers the pay")?;
        let who = match vouch {
            Some(_) => Some(*job.contractors.get(&worker).ok_or("the worker didn't reply as a contractor")?),
            None => None,
        };
        let rec = match (vouch, who) {
            (Some((category, _, _)), Some(who)) => {
                let mut parts = vec![(job.pay, worker.clone()), (0, worker)];
                if coin.amount > job.pay {
                    parts.push((coin.amount - job.pay, self.fresh()?));
                }
                self.signed(&coin.holder, Op::Split { state: coin.state, parts, receipt: board::vouch_receipt(&job_id, &who, category) })?
            }
            _ if coin.amount == job.pay => self.signed(&coin.holder, Op::Transfer { state: coin.state, to: worker, receipt: board::pay_receipt(&job_id) })?,
            _ => {
                let change = self.fresh()?;
                self.signed(&coin.holder, Op::Split { state: coin.state, parts: vec![(job.pay, worker), (coin.amount - job.pay, change)], receipt: board::pay_receipt(&job_id) })?
            }
        };
        apply_ok(&mut self.view, &rec)?;
        let payment = rec.output(0);
        self.send_as(&job.poster, BoardMsg::Paid { job: job_id, payment })?;
        if let (Some((category, note, identity)), Some(who)) = (vouch, who) {
            let msg = BoardMsg::Vouch { job: job_id, category: category.into(), note: note.into(), payment: Box::new(rec) };
            let scope = self.town.jobs.scope;
            self.compose_as(&scope, &job.poster, msg.kind(), Some(who), msg.encode(), Some(&[]), identity)?;
        }
        Ok(payment)
    }

    /// A fresh credential to be paid at.
    pub fn receive(&mut self) -> Result<Credential, String> {
        self.fresh()
    }

    /// Plain transfer of a whole coin.
    pub fn spend(&mut self, state: Hash, to: Credential) -> Result<Hash, String> {
        let holder = self.view.coin(&state).filter(|c| self.mine.contains(&c.holder)).ok_or("not a coin this wallet holds")?.holder.clone();
        let rec = self.signed(&holder, Op::Transfer { state, to, receipt: Hash([0; 32]) })?;
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
        // A tampered wallet: it skips its own signing log.
        let rec = sign(self.scheme(), &self.key, &holder, Op::Transfer { state, to, receipt: Hash([0; 32]) });
        self.outbox.push(rec.clone());
        self.cheat_states.insert(state);
        Ok(rec.output(0))
    }

    /// Operator: roll the clerk's epoch, revoking ticket groups and whole
    /// classes. Revocation is cumulative. A revoked class is closed: its
    /// wallets get no tickets until they update and enroll again.
    pub fn roll_epoch(&mut self, groups: BTreeSet<u32>, classes: BTreeSet<String>) -> Result<u32, String> {
        let at = head(&self.view, &self.town.sequence).ok_or("no epoch")?.number + 1;
        let op = self.operator.as_mut().ok_or("only the town operator rolls epochs")?;
        for c in &classes {
            if !op.access.contains_key(c) {
                return Err(format!("unknown class {c}"));
            }
        }
        let class_groups: Vec<u32> = op.groups.iter().filter(|(_, c)| classes.contains(*c)).map(|(g, _)| *g).collect();
        for g in groups.into_iter().chain(class_groups) {
            op.revoked.entry(g).or_insert(at);
        }
        op.closed.extend(classes);
        let revoked = op.revoked.clone();
        let op = self.operator.as_ref().unwrap();
        let h = head(&self.view, &self.town.sequence).ok_or("no epoch")?;
        let coin = self.view.coin(&h.state).ok_or("epoch state missing")?.clone();
        let data = EpochData { sequence: self.town.sequence, number: h.number + 1, revoked };
        let rec = roll(self.view.scheme(), &op.clerk, &self.town.clerk, &coin, &self.town.clerk, &data);
        let rec = self.guard(rec)?;
        apply_ok(&mut self.view, &rec)?;
        self.know.add_epoch_data(&self.view, data);
        Ok(h.number + 1)
    }

    /// Would this wallet accept the coin at `state`?
    pub fn check(&self, state: &Hash) -> Result<(), Refusal> {
        let coin = self.view.coin(state).ok_or(Refusal::UnknownState)?;
        let n = coin.history.len();
        let sender = if n >= 2 { coin.history[n - 2].clone() } else { coin.holder.clone() };
        // This wallet can always prove its own standing.
        let policy = Policy { require_standing: !self.mine.contains(&sender), ..self.policy() };
        check(&self.view, &self.know, state, &sender, &policy)
    }

    /// The ticket group behind a credential, if this wallet has its ticket.
    pub fn group_of(&self, c: &Credential) -> Option<u32> {
        self.know.tickets.get(c).map(|t| t.ticket.group)
    }
}
