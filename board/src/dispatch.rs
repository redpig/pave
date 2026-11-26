//! A co-op's dispatch: who may carry its parcels, how many a day, and what
//! happens when a courier's phone is lost. Another mint whose basename is
//! chosen for the linkage it needs: here, one pseudonym per member per day.
//!
//! - **Members are an issuer group**, like a district's voter roll. Joining
//!   is a join on a key the member's device made.
//! - **Shift keys.** A courier asks for tickets for the keys it will take
//!   parcels under, signed by a fresh randomization of its member credential
//!   with (dispatch, day) as basename. The pseudonym is the same for one
//!   member all day and unrelated across days, so dispatch can cap keys per
//!   member per day (labor rules, fair dispatch) and count distinct couriers
//!   without learning who anyone is. Tickets are tagged with that pseudonym
//!   and the day, and signed by the dispatch's clerk on its own tick
//!   sequence.
//! - **Membership is enforced where custody moves.** A parcel whose manifest
//!   names a dispatch is handed only to a key with that dispatch's ticket,
//!   taken only by checking it with the dispatch trusted, and paid only to
//!   such keys (see [`crate::parcel`]).
//! - **Banning outlasts the day.** A day pseudonym can't carry a ban to the
//!   next day, so a ruling puts the courier's (basename, pseudonym) on the
//!   dispatch's ruled list: every later shift request needs standing of the
//!   member credential against it. The ruling also revokes that day's
//!   groups, which stops the keys already issued.
//! - **A lost phone** isn't dispatch's business: the parcel's token is
//!   reminted by its shipper to whoever has the package and its label code
//!   (see [`crate::parcel`]).

use crate::bulletin::{now, Cheat, CLOCK_SLACK};
use crate::node::{apply_ok, Node};
use pave_kernel::hash::{encode, hash_of, Hash};
use pave_kernel::{sign, Credential, Op, Record, Scheme, Sig};
use pave_protocol::{epoch_schema, head, roll, EpochData, SignedTicket, Standing, Tag, Ticket};
use pave_scheme_briolette::{BrioletteV1, HolderKey, Issuer, JoinReply, JoinRequest, PendingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What everyone knows about a dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dispatch {
    /// The dispatch's id: its tick sequence.
    pub id: Hash,
    pub label: String,
    /// The members' group key.
    pub roll: Vec<u8>,
    /// The clerk that signs shift tickets and rolls the ticks.
    pub clerk: Credential,
    /// Most shift keys one member gets a day.
    pub per_day: usize,
    /// The ticks' budget and first tick.
    pub records: Vec<Record>,
}

impl Dispatch {
    pub fn sequence(&self) -> Hash {
        self.id
    }
    /// The basename for a day: one pseudonym per member per day.
    pub fn basename(&self, day: u64) -> Vec<u8> {
        encode(&("pave/dispatch/v1", self.id, day))
    }
    /// What a day's shift tickets are tagged for.
    pub fn purpose(&self, day: u64) -> Hash {
        hash_of("pave/dispatch/shift", &(self.id, day))
    }
    /// Whether `t` is this dispatch's shift ticket, for any day.
    pub fn shift_of(&self, s: &impl Scheme, t: &SignedTicket) -> Option<u64> {
        if t.clerk != self.clerk || t.ticket.sequence != self.id || !t.verify(s) {
            return None;
        }
        let tag = t.ticket.tag.as_ref()?;
        let day: u64 = tag.class.strip_prefix("day ")?.parse().ok()?;
        (tag.purpose == self.purpose(day)).then_some(day)
    }
}

/// Today, as dispatch counts days: days since 1970, UTC.
pub fn today() -> u64 {
    now() / 86_400
}

/// A member's card.
#[derive(Clone, Serialize, Deserialize)]
pub struct MemberCard {
    pub dispatch: Hash,
    pub key: HolderKey,
}

impl MemberCard {
    pub fn start() -> (PendingKey, JoinRequest) {
        PendingKey::generate(&pave_scheme_briolette::join_nonce())
    }
    pub fn finish(d: &Dispatch, pending: PendingKey, reply: &JoinReply) -> Result<MemberCard, String> {
        let key = pending.finish(&BrioletteV1 { group_public_key: d.roll.clone() }, reply)?;
        Ok(MemberCard { dispatch: d.id, key })
    }
}

/// An anonymous request for shift tickets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShiftRequest {
    pub dispatch: Hash,
    pub day: u64,
    pub creds: Vec<Credential>,
    pub at: u64,
    pub member: Credential,
    pub standing: Standing,
    pub sig: Sig,
}

fn shift_bytes(id: &Hash, day: u64, creds: &[Credential], at: u64, standing: &Standing) -> Vec<u8> {
    encode(&("pave/dispatch/shift/v1", id, day, creds, at, standing))
}

/// A day pseudonym's shift keys, each with its ticket group, by (day, pseudonym).
pub type Shifts = BTreeMap<(u64, Vec<u8>), Vec<(u32, Credential)>>;

/// What dispatch keeps, held by the operator.
#[derive(Clone, Serialize, Deserialize)]
pub struct Book {
    pub dispatch: Dispatch,
    pub roll: Issuer,
    /// Each (day, pseudonym)'s groups and keys.
    pub shifts: Shifts,
    pub last_at: BTreeMap<(u64, Vec<u8>), u64>,
    pub ruled: Vec<Cheat>,
    pub revoked: BTreeMap<u32, u32>,
}

impl Node {
    fn book(&self, id: &Hash) -> Result<&Book, String> {
        self.operator.as_ref().and_then(|o| o.dispatches.get(id)).ok_or_else(|| "this node doesn't run that dispatch".into())
    }
    fn book_mut(&mut self, id: &Hash) -> Result<&mut Book, String> {
        self.operator.as_mut().and_then(|o| o.dispatches.get_mut(id)).ok_or_else(|| "this node doesn't run that dispatch".into())
    }

    /// Operator: set up a dispatch: a member roll and its own ticks.
    pub fn open_dispatch(&mut self, label: &str, per_day: usize) -> Result<Dispatch, String> {
        let op = self.operator.as_ref().ok_or("only the operator runs a dispatch")?;
        let s = self.view.scheme().clone();
        let clerk = s.credential(&op.clerk);
        let budget = sign(&s, &op.root, &op.root_cred, Op::IssueBudget { authority: self.town.genesis.rooting_capability(), schema: epoch_schema(&format!("dispatch {label}")), amount: 1, to: clerk.clone() });
        let first = sign(&s, &op.clerk, &clerk, Op::Mint { budget: budget.output(0), amount: 1, to: clerk.clone(), change_to: clerk.clone() });
        apply_ok(&mut self.view, &budget)?;
        apply_ok(&mut self.view, &first)?;
        let roll = Issuer::new();
        let d = Dispatch { id: first.output(0), label: label.into(), roll: roll.group_public_key.clone(), clerk, per_day, records: vec![budget, first] };
        let book = Book { dispatch: d.clone(), roll, shifts: BTreeMap::new(), last_at: BTreeMap::new(), ruled: vec![], revoked: BTreeMap::new() };
        self.operator.as_mut().unwrap().dispatches.insert(d.id, book);
        self.save()?;
        Ok(d)
    }

    /// Dispatch: add a member, from the member's join request.
    pub fn add_member(&mut self, id: &Hash, req: &JoinRequest) -> Result<JoinReply, String> {
        self.book(id)?.roll.issue(req)
    }

    /// Dispatch: today's day and ruled list, for a shift request.
    pub fn shift_terms(&self, id: &Hash) -> Result<(u64, Vec<Cheat>), String> {
        Ok((today(), self.book(id)?.ruled.clone()))
    }

    /// Courier: ask for shift tickets for `n` fresh keys.
    pub fn shift_request(&mut self, d: &Dispatch, card: &MemberCard, terms: &(u64, Vec<Cheat>), n: usize) -> Result<ShiftRequest, String> {
        let creds: Vec<Credential> = (0..n).map(|_| self.view.scheme().credential(&self.key)).collect();
        let a = BrioletteV1 { group_public_key: d.roll.clone() };
        let member = a.credential(&card.key);
        let standing = Standing::prove(&a, &card.key, &member, &terms.1).ok_or("this member was ruled out")?;
        let at = now_ms();
        let sig = a.sign(&card.key, &member, &shift_bytes(&d.id, terms.0, &creds, at, &standing), Some(&d.basename(terms.0)));
        Ok(ShiftRequest { dispatch: d.id, day: terms.0, creds, at, member, standing, sig })
    }

    /// Dispatch: answer a shift request: today only, within the day's cap
    /// for the member's pseudonym, and with standing against every ruling.
    pub fn answer_shift(&mut self, req: &ShiftRequest) -> Result<Vec<SignedTicket>, String> {
        let book = self.book(&req.dispatch)?;
        let d = book.dispatch.clone();
        if req.day != today() {
            return Err("shift tickets are for today".into());
        }
        if req.at.abs_diff(now_ms()) > CLOCK_SLACK * 1000 {
            return Err("a stale request".into());
        }
        let a = BrioletteV1 { group_public_key: d.roll.clone() };
        if !a.verify(&req.member, &shift_bytes(&d.id, req.day, &req.creds, req.at, &req.standing), Some(&d.basename(req.day)), &req.sig) {
            return Err("not a member".into());
        }
        let nym = a.nym(&req.sig).ok_or("no pseudonym")?;
        let st = &req.standing;
        if st.credential != req.member || !st.covers(&book.ruled) || !st.verify(&a) {
            return Err("ruled out by dispatch".into());
        }
        let key = (req.day, nym.clone());
        if book.last_at.get(&key).is_some_and(|t| *t >= req.at) {
            return Err("an old request".into());
        }
        let had = book.shifts.get(&key).map_or(0, Vec::len);
        if req.creds.is_empty() || had + req.creds.len() > d.per_day {
            return Err(format!("at most {} keys a day ({had} issued)", d.per_day));
        }
        let used: std::collections::BTreeSet<u32> = book.shifts.values().flatten().map(|(g, _)| *g).collect();
        let group = loop {
            let g = rand::Rng::gen_range(&mut rand::rngs::OsRng, 1..u32::MAX);
            if !used.contains(&g) {
                break g;
            }
        };
        let epoch = head(&self.view, &d.id).ok_or("no dispatch tick")?.number;
        let op = self.operator.as_ref().unwrap();
        let s = self.view.scheme().clone();
        let tag = Tag { purpose: d.purpose(req.day), nym, class: format!("day {}", req.day) };
        let tickets: Vec<SignedTicket> = req.creds.iter().map(|c| SignedTicket::issue(&s, &op.clerk, &d.clerk, Ticket { credential: c.clone(), sequence: d.id, epoch, group, max_spend: None, tag: Some(tag.clone()) })).collect();
        for t in &tickets {
            self.know.add_ticket(&s, t.clone());
        }
        let book = self.book_mut(&req.dispatch)?;
        book.shifts.entry(key.clone()).or_default().extend(req.creds.iter().map(|c| (group, c.clone())));
        book.last_at.insert(key, req.at);
        self.save()?;
        Ok(tickets)
    }

    /// Courier: keep shift tickets, and the dispatch's ticks.
    pub fn take_shift(&mut self, d: &Dispatch, tickets: Vec<SignedTicket>) -> Result<(), String> {
        for r in &d.records {
            apply_ok(&mut self.view, r)?;
        }
        let s = self.view.scheme().clone();
        for t in tickets {
            if d.shift_of(&s, &t).is_none() {
                return Err("not this dispatch's shift ticket".into());
            }
            let c = t.ticket.credential.clone();
            self.know.add_ticket(&s, t);
            self.mine.insert(c.clone());
            self.shift_keys.push(c);
        }
        self.save()
    }

    /// An unused shift key from `d`, if this wallet has one: to be handed a
    /// parcel at, or to take one under.
    pub fn shift_key(&mut self, d: &Dispatch) -> Option<Credential> {
        let s = self.view.scheme().clone();
        let i = self.shift_keys.iter().position(|c| self.know.tickets.get(c).is_some_and(|t| d.shift_of(&s, t).is_some()))?;
        Some(self.shift_keys.remove(i))
    }

    /// Courier: the ticket to show with a shift key it wants a parcel handed
    /// to. Meets carry tickets only for keys their records name, so the key
    /// to receive at comes with its ticket.
    pub fn present(&self, key: &Credential) -> Option<SignedTicket> {
        self.know.tickets.get(key).cloned()
    }

    /// Giver: keep a ticket a courier showed, if it checks out.
    pub fn learn_ticket(&mut self, t: SignedTicket) -> Result<(), String> {
        let s = self.view.scheme().clone();
        if !t.verify(&s) {
            return Err("a bad ticket".into());
        }
        self.know.add_ticket(&s, t);
        Ok(())
    }

    /// Dispatch: roll its ticks, revoking `groups`.
    fn tick_dispatch(&mut self, id: &Hash, groups: &[u32]) -> Result<(), String> {
        let d = self.book(id)?.dispatch.clone();
        let h = head(&self.view, &d.id).ok_or("no dispatch tick")?;
        let book = self.book_mut(id)?;
        for g in groups {
            book.revoked.entry(*g).or_insert(h.number + 1);
        }
        let data = EpochData { sequence: d.id, number: h.number + 1, revoked: book.revoked.clone() };
        let current = self.view.coin(&h.state).ok_or("dispatch tick missing")?.clone();
        let op = self.operator.as_ref().unwrap();
        let rec = roll(self.view.scheme(), &op.clerk, &d.clerk, &current, &d.clerk, &data);
        let rec = self.guard(rec)?;
        apply_ok(&mut self.view, &rec)?;
        self.know.add_epoch_data(&self.view, data);
        self.save()
    }

    /// Dispatch: rule a courier out, by a key it took a parcel under: its
    /// day pseudonym goes on the ruled list and that day's groups are revoked.
    pub fn rule_courier(&mut self, id: &Hash, key: &Credential) -> Result<(), String> {
        let book = self.book(id)?;
        let ((day, nym), groups) = book.shifts.iter().find(|(_, ks)| ks.iter().any(|(_, c)| c == key)).map(|(k, ks)| (k.clone(), ks.iter().map(|(g, _)| *g).collect::<Vec<_>>())).ok_or("not a key this dispatch issued")?;
        let cheat = (book.dispatch.basename(day), nym);
        self.book_mut(id)?.ruled.push(cheat);
        self.tick_dispatch(id, &groups)
    }

}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}
