//! A municipal election: an example of a mint whose basename isn't the
//! epoch and whose clock is its own.
//!
//! Everything here is a part the town already has:
//!
//! - **Voter rolls are issuer groups**, one per district, as classes are.
//!   Registering is a join: the voter's wallet generates the key, and the
//!   registrar issues a credential on its public key. The registrar never
//!   holds the voter's secret.
//! - **The basename is the election, not the epoch.** A vote request is
//!   signed by a fresh randomization of the voter's roll credential with the
//!   election as basename. Its pseudonym is the same for one voter for the
//!   whole election, however long the legal window, and unrelated across
//!   elections. The mint learns the district and that pseudonym, never who.
//! - **One live vote coin per pseudonym.** The election's mint (a capability
//!   derived from the town's root) tickets the credential the voter names,
//!   in a fresh random group, with a tag for (election, pseudonym, district),
//!   and mints it a vote coin. A voter who comes back during the window, say
//!   with a lost phone, is recognized by the pseudonym and gets a new coin;
//!   the old coin's group is revoked.
//! - **The election keeps its own clock.** Revocations go out on the
//!   election's own tick sequence, which ticks at every remint and at no
//!   other time. Nothing depends on the town's epochs.
//! - **Time limits are legal, not the system's.** The vote coin's schema has
//!   no expiry. The window is wall-clock dates set by law; the mint and the
//!   booths check them, and the authority can move them when a court does.
//! - **Voting is spending.** A vote is the coin's transfer to the booth of
//!   the voter's district, its receipt the hash of the ballot, exactly like
//!   a board post (see [`crate::bulletin`]). The booth runs the ordinary
//!   acceptance check with the election's clerk and sequence trusted, which
//!   refuses a revoked coin, and takes the vote by retiring the coin. Using
//!   a coin twice is a double spend.
//! - **Whether a voter may vote again is the law's choice.** With `revote`
//!   off, a voter whose coin was cast is refused a new one. With it on, a
//!   new coin revokes the cast one and the later vote counts instead, which
//!   also lets a coerced voter vote again in private.
//! - **Anyone can tally.** The ballots are public records. A reader checks
//!   each one as it checks a board post, drops those whose ticket group was
//!   revoked, and counts each pseudonym once, from its newest ticket, so a
//!   booth that hadn't heard of a remint can't make one voter count twice.

use crate::bulletin::{content_hash, now, BoardInfo, Clock, Copy, Post, Submission, CLOCK_SLACK};
use crate::node::{apply_ok, Node};
use pave_kernel::hash::{encode, hash_of, Hash};
use pave_kernel::objects::rights;
use pave_kernel::{sign, Credential, Kind, Op, Record, Schema, Scheme, Sig};
use pave_protocol::{epoch_schema, head, roll, EpochData, Policy, SignedTicket, Tag, Ticket};
use pave_scheme_briolette::{BrioletteV1, HolderKey, Issuer, JoinReply, JoinRequest, PendingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The vote coin's schema: one each, spent once, no expiry.
pub fn vote_schema(label: &str) -> Schema {
    Schema { label: format!("vote: {label}"), divisible: false, soft_expiry: None, hard_expiry: None, offline_transfers: Some(1), max_per_holder: Some(1), sequence: None }
}

/// What everyone knows about an election.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Election {
    /// The election's id: its mint capability's id.
    pub id: Hash,
    pub label: String,
    /// Each district's voter roll: an issuer's group key.
    pub districts: BTreeMap<String, Vec<u8>>,
    /// Each district's booth.
    pub booths: BTreeMap<String, Credential>,
    pub choices: Vec<String>,
    /// The legal window, in seconds since 1970.
    pub opens: u64,
    pub closes: u64,
    /// Whether a voter may vote again during the window, replacing the vote.
    pub revote: bool,
    /// The election's own tick sequence, and the clerk that rolls it and
    /// signs its tickets.
    pub sequence: Hash,
    pub clerk: Credential,
    pub schema: Hash,
    /// The public setup: the mint's capability, the ticks' budget and the
    /// first tick.
    pub records: Vec<Record>,
}

impl Election {
    pub fn mint(&self) -> &Record {
        &self.records[0]
    }
    /// The basename a vote request is signed with: the election itself.
    pub fn basename(&self) -> Vec<u8> {
        encode(&("pave/election/v1", self.id))
    }
    /// A district's ballot box, as a board.
    pub fn board(&self, district: &str) -> Hash {
        hash_of("pave/election/booth", &(self.id, district))
    }
    pub fn info(&self, district: &str) -> Option<BoardInfo> {
        Some(BoardInfo { scope: self.board(district), host: self.booths.get(district)?.clone(), roles: BTreeMap::new() })
    }
    fn open_at(&self, t: u64) -> bool {
        self.opens <= t && t < self.closes
    }
}

/// A registered voter's card: its roll credential for one district.
#[derive(Clone, Serialize, Deserialize)]
pub struct VoterCard {
    pub election: Hash,
    pub district: String,
    pub key: HolderKey,
}

impl VoterCard {
    /// The voter's side of registering: a key generated on the voter's own
    /// device and a join request for it.
    pub fn start() -> (PendingKey, JoinRequest) {
        PendingKey::generate(&pave_scheme_briolette::join_nonce())
    }
    pub fn finish(e: &Election, district: &str, pending: PendingKey, reply: &JoinReply) -> Result<VoterCard, String> {
        let gpk = e.districts.get(district).ok_or("no such district")?;
        let key = pending.finish(&BrioletteV1 { group_public_key: gpk.clone() }, reply)?;
        Ok(VoterCard { election: e.id, district: district.into(), key })
    }
}

/// An anonymous request for a vote coin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteRequest {
    pub election: Hash,
    /// The credential the coin is to be held under.
    pub cred: Credential,
    /// When the voter asked, in milliseconds, so a captured request can't be
    /// replayed to revoke a voter's coin.
    pub at: u64,
    pub voter: Credential,
    pub sig: Sig,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn request_bytes(election: &Hash, cred: &Credential, at: u64) -> Vec<u8> {
    encode(&("pave/election/request/v1", election, cred, at))
}

/// The mint's answer: the ticket, the coin's records, and the tick that
/// revoked an earlier coin, if there was one.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteGrant {
    pub ticket: SignedTicket,
    pub records: Vec<Record>,
    pub tick: Option<(Record, EpochData)>,
}

/// What the authority keeps about one voter pseudonym.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Issued {
    pub group: u32,
    pub credential: Credential,
    /// The latest request time, so requests only move forward.
    pub at: u64,
    pub cast: bool,
}

/// The election authority's private state, held by the operator.
#[derive(Clone, Serialize, Deserialize)]
pub struct Authority {
    pub election: Election,
    pub rolls: BTreeMap<String, Issuer>,
    pub issued: BTreeMap<Vec<u8>, Issued>,
    /// Revoked groups, with the tick they were revoked at.
    pub revoked: BTreeMap<u32, u32>,
    /// Every ballot the booths took.
    pub ballots: Vec<Submission>,
}

/// One district's result.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Count {
    pub votes: BTreeMap<String, usize>,
    /// Ballots dropped: revoked coins, and earlier votes a voter replaced.
    pub revoked: usize,
    pub replaced: usize,
}

impl Node {
    fn authority(&self, id: &Hash) -> Result<&Authority, String> {
        self.operator.as_ref().and_then(|o| o.elections.get(id)).ok_or_else(|| "this node doesn't run that election".into())
    }
    fn authority_mut(&mut self, id: &Hash) -> Result<&mut Authority, String> {
        self.operator.as_mut().and_then(|o| o.elections.get_mut(id)).ok_or_else(|| "this node doesn't run that election".into())
    }

    /// Operator: set up an election: a roll per district, a booth per
    /// district, a mint capability derived from the root, and the election's
    /// own tick sequence.
    pub fn open_election(&mut self, label: &str, districts: &[&str], choices: &[&str], opens: u64, closes: u64, revote: bool) -> Result<Election, String> {
        let op = self.operator.as_ref().ok_or("only the operator runs elections")?;
        let s = self.view.scheme().clone();
        let auth = self.town.genesis.rooting_capability();
        let clerk = s.credential(&op.clerk);
        let derive = sign(&s, &op.root, &op.root_cred, Op::Derive { parent: auth, rights: [rights::ISSUE.to_string()].into_iter().collect(), to: op.minter_cred.clone() });
        let budget = sign(&s, &op.root, &op.root_cred, Op::IssueBudget { authority: auth, schema: epoch_schema(&format!("election {label}")), amount: 1, to: clerk.clone() });
        let first = sign(&s, &op.clerk, &clerk, Op::Mint { budget: budget.output(0), amount: 1, to: clerk.clone(), change_to: clerk.clone() });
        for r in [&derive, &budget, &first] {
            apply_ok(&mut self.view, r)?;
        }
        let rolls: BTreeMap<String, Issuer> = districts.iter().map(|d| (d.to_string(), Issuer::new())).collect();
        let e = Election {
            id: derive.output(0),
            label: label.into(),
            districts: rolls.iter().map(|(d, i)| (d.clone(), i.group_public_key.clone())).collect(),
            booths: districts.iter().map(|d| (d.to_string(), s.credential(&self.key))).collect(),
            choices: choices.iter().map(|c| c.to_string()).collect(),
            opens,
            closes,
            revote,
            sequence: first.output(0),
            clerk,
            schema: vote_schema(label).id(),
            records: vec![derive, budget, first],
        };
        let a = Authority { election: e.clone(), rolls, issued: BTreeMap::new(), revoked: BTreeMap::new(), ballots: vec![] };
        self.operator.as_mut().unwrap().elections.insert(e.id, a);
        self.save()?;
        Ok(e)
    }

    /// The election as its authority has it now.
    pub fn election(&self, id: &Hash) -> Result<Election, String> {
        Ok(self.authority(id)?.election.clone())
    }

    /// Authority: move the legal window, as a court or an ordinance does.
    pub fn set_window(&mut self, id: &Hash, opens: u64, closes: u64) -> Result<(), String> {
        let e = &mut self.authority_mut(id)?.election;
        (e.opens, e.closes) = (opens, closes);
        self.save()
    }

    /// Registrar: put a voter on a district's roll, from the voter's join
    /// request. Who may register is checked outside pave, as today.
    pub fn register_voter(&mut self, id: &Hash, district: &str, req: &JoinRequest) -> Result<JoinReply, String> {
        self.authority(id)?.rolls.get(district).ok_or("no such district")?.issue(req)
    }

    /// Voter: ask for a vote coin held under `cred`, anonymously.
    pub fn vote_request(&self, e: &Election, card: &VoterCard, cred: &Credential) -> VoteRequest {
        let a = BrioletteV1 { group_public_key: e.districts[&card.district].clone() };
        let voter = a.credential(&card.key);
        let at = now_ms();
        let sig = a.sign(&card.key, &voter, &request_bytes(&e.id, cred, at), Some(&e.basename()));
        VoteRequest { election: e.id, cred: cred.clone(), at, voter, sig }
    }

    /// Mint: answer a vote request inside the legal window. A pseudonym seen
    /// before gets a new coin and its old coin's group is revoked on a new
    /// tick, unless it already voted and the election doesn't allow voting
    /// again.
    pub fn answer_vote(&mut self, req: &VoteRequest) -> Result<VoteGrant, String> {
        let t = now();
        let a = self.authority(&req.election)?;
        let e = a.election.clone();
        if !e.open_at(t) {
            return Err("outside the legal window".into());
        }
        if req.at.abs_diff(now_ms()) > CLOCK_SLACK * 1000 {
            return Err("a stale request".into());
        }
        let msg = request_bytes(&e.id, &req.cred, req.at);
        let bsn = e.basename();
        let (district, s) = e
            .districts
            .iter()
            .map(|(d, gpk)| (d.clone(), BrioletteV1 { group_public_key: gpk.clone() }))
            .find(|(_, s)| s.verify(&req.voter, &msg, Some(&bsn), &req.sig))
            .ok_or("not on any district's roll")?;
        let nym = s.nym(&req.sig).ok_or("no pseudonym")?;
        let prior = a.issued.get(&nym).cloned();
        let mut tick = None;
        if let Some(p) = &prior {
            if req.at <= p.at {
                return Err("an old request".into());
            }
            if p.cast && !e.revote {
                return Err("already voted".into());
            }
            tick = Some(self.tick_election(&e.id, Some(p.group))?);
        }
        let used: BTreeSet<u32> = {
            let a = self.authority(&e.id)?;
            a.issued.values().map(|i| i.group).chain(a.revoked.keys().copied()).collect()
        };
        let group = loop {
            let g = rand::Rng::gen_range(&mut rand::rngs::OsRng, 1..u32::MAX);
            if !used.contains(&g) {
                break g;
            }
        };
        let number = head(&self.view, &e.sequence).ok_or("no election tick")?.number;
        let op = self.operator.as_ref().unwrap();
        let sch = self.view.scheme().clone();
        let tag = Tag { purpose: e.id, nym: nym.clone(), class: district };
        let ticket = SignedTicket::issue(&sch, &op.clerk, &e.clerk, Ticket { credential: req.cred.clone(), sequence: e.sequence, epoch: number, group, max_spend: None, tag: Some(tag) });
        let (minter, me) = (op.minter.clone(), op.minter_cred.clone());
        let budget = sign(&sch, &minter, &me, Op::IssueBudget { authority: e.id, schema: vote_schema(&e.label), amount: 1, to: me.clone() });
        apply_ok(&mut self.view, &budget)?;
        let coin = self.guard(sign(&sch, &minter, &me, Op::Mint { budget: budget.output(0), amount: 1, to: req.cred.clone(), change_to: me.clone() }))?;
        apply_ok(&mut self.view, &coin)?;
        self.know.add_ticket(&sch, ticket.clone());
        self.authority_mut(&e.id)?.issued.insert(nym, Issued { group, credential: req.cred.clone(), at: req.at, cast: false });
        self.save()?;
        Ok(VoteGrant { ticket, records: vec![budget, coin], tick })
    }

    /// Authority: roll the election's own clock, revoking `group` if given.
    fn tick_election(&mut self, id: &Hash, group: Option<u32>) -> Result<(Record, EpochData), String> {
        let e = self.authority(id)?.election.clone();
        let h = head(&self.view, &e.sequence).ok_or("no election tick")?;
        if let Some(g) = group {
            self.authority_mut(id)?.revoked.insert(g, h.number + 1);
        }
        let data = EpochData { sequence: e.sequence, number: h.number + 1, revoked: self.authority(id)?.revoked.clone() };
        let current = self.view.coin(&h.state).ok_or("election tick missing")?.clone();
        let op = self.operator.as_ref().unwrap();
        let rec = roll(self.view.scheme(), &op.clerk, &e.clerk, &current, &e.clerk, &data);
        let rec = self.guard(rec)?;
        apply_ok(&mut self.view, &rec)?;
        self.know.add_epoch_data(&self.view, data.clone());
        Ok((rec, data))
    }

    /// Voter: keep a grant.
    pub fn take_vote(&mut self, e: &Election, g: &VoteGrant) -> Result<(), String> {
        for r in e.records.iter().chain(&g.records) {
            apply_ok(&mut self.view, r)?;
        }
        let s = self.view.scheme().clone();
        self.mine.insert(g.ticket.ticket.credential.clone());
        self.know.add_ticket(&s, g.ticket.clone());
        Ok(())
    }

    /// Booth: the tick and clock a ballot sent now commits to, inside the
    /// legal window only, so a voter doesn't spend a coin on a ballot the
    /// booth would refuse.
    pub fn booth_clock(&self, id: &Hash) -> Result<Clock, String> {
        let e = &self.authority(id)?.election;
        if !e.open_at(now()) {
            return Err("outside the legal window".into());
        }
        Ok(Clock { epoch: head(&self.view, &e.sequence).ok_or("no election tick")?.number, clock: now() })
    }

    /// Voter: cast the vote coin held under `cred` at its district's booth,
    /// with the booth's clock.
    pub fn cast_vote(&mut self, e: &Election, district: &str, cred: &Credential, choice: &str, at: &Clock) -> Result<Submission, String> {
        let state = self.view.unspent().find(|c| c.schema == e.schema && c.kind == Kind::Value && &c.holder == cred && !self.signed_log.contains_key(&c.state)).map(|c| c.state).ok_or("no vote coin for that key")?;
        let booth = e.booths.get(district).ok_or("no such district")?.clone();
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let post = Post { board: e.board(district), kind: "ballot".into(), thread: Some(e.id), content: content_hash(choice.as_bytes()), nonce, prior: None, epoch: at.epoch, clock: at.clock, by: None };
        let record = self.signed(cred, Op::Transfer { state, to: booth, receipt: post.receipt() })?;
        let mint = self.view.creator(&state).cloned().ok_or("the coin's mint is missing")?;
        let budget = mint.op.consumes().first().and_then(|b| self.view.creator(b)).cloned().ok_or("the coin's budget is missing")?;
        let provenance = vec![budget, mint];
        Ok(Submission { record, post, content: choice.as_bytes().to_vec(), provenance, ticket: self.know.tickets.get(cred).cloned(), taken: None })
    }

    /// Booth: take a vote for its district, inside the legal window: a coin
    /// from this election's mint, tagged for this district, that passes the
    /// ordinary acceptance check with the election's clerk and ticks
    /// trusted. Answers with the retire of the coin.
    pub fn accept_vote(&mut self, id: &Hash, sub: &Submission) -> Result<Record, String> {
        let e = self.authority(id)?.election.clone();
        if !e.open_at(now()) {
            return Err("outside the legal window".into());
        }
        let district = e.booths.keys().find(|d| e.board(d) == sub.post.board).ok_or("not a ballot box of this election")?.clone();
        if sub.post.clock.abs_diff(now()) > CLOCK_SLACK || sub.post.kind != "ballot" || sub.post.thread != Some(e.id) {
            return Err("not a ballot for now".into());
        }
        let choice = std::str::from_utf8(&sub.content).ok().filter(|c| e.choices.iter().any(|x| x == c)).ok_or("not a choice on the ballot")?;
        if content_hash(choice.as_bytes()) != sub.post.content {
            return Err("content doesn't match its hash".into());
        }
        let Op::Transfer { state, to, receipt } = &sub.record.op else {
            return Err("a vote is a coin's transfer".into());
        };
        if to != &e.booths[&district] || *receipt != sub.post.receipt() {
            return Err("the coin isn't sent to this booth with this ballot".into());
        }
        for r in &sub.provenance {
            if matches!(&r.op, Op::IssueBudget { authority, .. } if *authority != e.id) {
                return Err("a coin from another mint".into());
            }
            apply_ok(&mut self.view, r)?;
        }
        if self.view.coin(state).map(|c| c.schema) != Some(e.schema) {
            return Err("not a vote coin, or one already spent".into());
        }
        let t = sub.ticket.as_ref().ok_or("no ticket")?;
        let tag = t.ticket.tag.as_ref().ok_or("an untagged ticket")?;
        if tag.purpose != e.id || tag.class != district {
            return Err("not this district's vote".into());
        }
        let s = self.view.scheme().clone();
        self.know.add_ticket(&s, t.clone());
        let policy = Policy { require_standing: false, honor_ticket_caps: false, ..Policy::wallet([(e.clerk.clone(), e.sequence)].into_iter().collect()) };
        pave_protocol::check(&self.view, &self.know, state, &sub.record.signer, &policy).map_err(|r| format!("vote refused: {r:?}"))?;
        match self.view.apply(&sub.record) {
            Ok(pave_kernel::Applied::Accepted) => {}
            other => return Err(format!("vote refused: {other:?}")),
        }
        let taken = self.guard(sign(&s, &self.key, &e.booths[&district], Op::Retire { state: sub.record.output(0) }))?;
        apply_ok(&mut self.view, &taken)?;
        let nym = tag.nym.clone();
        let a = self.authority_mut(id)?;
        if let Some(i) = a.issued.get_mut(&nym) {
            i.cast = true;
        }
        a.ballots.push(Submission { taken: Some(taken.clone()), ..sub.clone() });
        self.save()?;
        Ok(taken)
    }

    /// Every ballot the booths took, and the revoked groups, for anyone to
    /// tally.
    pub fn ballots(&self, id: &Hash) -> Result<(Vec<Submission>, BTreeMap<u32, u32>), String> {
        let a = self.authority(id)?;
        Ok((a.ballots.clone(), a.revoked.clone()))
    }

    /// Anyone: tally ballots. Each is checked as a board post is, against
    /// the district's booth and the election's mint; a ballot counts only if
    /// its ticket is tagged for this election and district and its group
    /// wasn't revoked, and each pseudonym counts once, from its newest
    /// ticket.
    pub fn tally(&self, e: &Election, ballots: &[Submission], revoked: &BTreeMap<u32, u32>) -> Result<BTreeMap<String, Count>, String> {
        let mut out = BTreeMap::new();
        for district in e.booths.keys() {
            let info = e.info(district).unwrap();
            let mut copy = Copy::new(info, self.view.scheme().clone(), self.town.genesis.clone(), e.mint(), e.schema, e.clerk.clone())?;
            for b in ballots.iter().filter(|b| b.post.board == e.board(district)) {
                let _ = copy.absorb(b);
            }
            let mut count = Count::default();
            let mut latest: BTreeMap<Vec<u8>, (u32, String)> = BTreeMap::new();
            for item in copy.items() {
                let Some(t) = copy.ticket(&item.id) else { continue };
                let Some(tag) = t.ticket.tag.as_ref().filter(|g| g.purpose == e.id && &g.class == district) else { continue };
                if revoked.contains_key(&t.ticket.group) {
                    count.revoked += 1;
                    continue;
                }
                let Some(choice) = std::str::from_utf8(item.content).ok().filter(|c| e.choices.iter().any(|x| x == c)) else { continue };
                match latest.get(&tag.nym) {
                    Some((at, _)) if *at >= t.ticket.epoch => count.replaced += 1,
                    Some(_) => {
                        count.replaced += 1;
                        latest.insert(tag.nym.clone(), (t.ticket.epoch, choice.into()));
                    }
                    None => {
                        latest.insert(tag.nym.clone(), (t.ticket.epoch, choice.into()));
                    }
                }
            }
            for (_, choice) in latest.into_values() {
                *count.votes.entry(choice).or_default() += 1;
            }
            out.insert(district.clone(), count);
        }
        Ok(out)
    }
}
