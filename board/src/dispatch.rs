//! A co-op's dispatch: who may carry its parcels, counting couriers per
//! day, and banning one. It reuses the town's own layering one level down:
//!
//! - **Members are an issuer group**, like a district's voter roll. Joining
//!   is a join on a key the member's device made.
//! - **Checking in is the count.** Each day dispatch runs a fresh issuer
//!   group, as a town runs a class. A member checks in by joining it, with
//!   the join signed by a fresh randomization of its member credential under
//!   (dispatch, day) as basename. That pseudonym is the same for one member
//!   all day and unrelated across days: distinct check-ins are distinct
//!   couriers, and checking in again (a new phone) is linked, so the count
//!   doesn't change. The day credential is the courier's daily credential.
//! - **Shift keys are refills.** A courier asks for tickets for the keys it
//!   will take parcels under. The request is signed twice: by the member
//!   credential with (dispatch, day, slot) as basename (see
//!   [`crate::slots`]), so a courier's first few requests a day can't be
//!   linked to each other and later ones are linked, not refused; and by
//!   the day credential, with no basename, which shows the courier checked
//!   in today and links nothing. Tickets are tagged with the request's
//!   pseudonym and the day, signed by dispatch's clerk on its own ticks.
//! - **Membership is enforced where custody moves.** A parcel whose manifest
//!   names a dispatch is handed only to a key with that dispatch's ticket,
//!   taken only by checking it with the dispatch trusted, and paid only to
//!   such keys (see [`crate::parcel`]).
//! - **Banning outlasts the day.** A ruling puts the courier's (basename,
//!   pseudonym) on dispatch's ruled list. Both pseudonyms come from the
//!   member credential, so every later check-in and shift request needs
//!   its standing against the list, on any day, under any slot. The ruling
//!   also revokes that request's group, which stops its keys.
//! - **A lost phone** isn't dispatch's business beyond a second check-in:
//!   the parcel's token is reminted by its shipper to whoever has the
//!   package and its label code (see [`crate::parcel`]).

use crate::bulletin::{now, Cheat, CLOCK_SLACK};
use crate::node::{apply_ok, Node};
use crate::request::{Expect, Linkage, Request, RequestSpec};
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{sign, Credential, Op, Record, Scheme};
use pave_protocol::{epoch_schema, head, roll, EpochData, SignedTicket, Tag, Ticket};
use pave_scheme_briolette::{BrioletteV1, HolderKey, Issuer, JoinReply, JoinRequest, PendingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Shift requests a courier makes per day that can't be linked to each other.
pub const SHIFT_SLOTS: u32 = 4;

/// A dispatch's public face: what a manifest or a job names, enough to
/// check its tickets and badges. Its ticks travel as records, as any do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    /// The dispatch's id: its tick sequence.
    pub id: Hash,
    pub label: String,
    /// The clerk that signs shift tickets and badges and rolls the ticks.
    pub clerk: Credential,
}

/// What members and couriers know about a dispatch: its roster, the
/// members' group key, and the records that set up its ticks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dispatch {
    pub roster: Roster,
    /// The members' group key.
    pub roll: Vec<u8>,
    /// The ticks' budget and first tick.
    pub records: Vec<Record>,
}

impl std::ops::Deref for Dispatch {
    type Target = Roster;
    fn deref(&self) -> &Roster {
        &self.roster
    }
}

impl Dispatch {
    fn members(&self) -> [(String, Vec<u8>); 1] {
        [("member".to_string(), self.roll.clone())]
    }
}

impl Roster {
    pub fn sequence(&self) -> Hash {
        self.id
    }
    /// The check-in spec: one pseudonym per member per day, for counting.
    pub fn check_in_spec(&self) -> RequestSpec {
        RequestSpec {
            domain: "pave/dispatch/checkin/v2".into(),
            scope: self.id,
            linkage: Linkage::Period,
            max_skew_ms: Some(CLOCK_SLACK * 1000),
        }
    }
    /// The shift request spec: a budget of unlinkable requests per day.
    pub fn shift_spec(&self) -> RequestSpec {
        RequestSpec {
            domain: "pave/dispatch/shift/v3".into(),
            scope: self.id,
            linkage: Linkage::Slots(SHIFT_SLOTS),
            max_skew_ms: Some(CLOCK_SLACK * 1000),
        }
    }
    /// What a day's shift tickets are tagged for.
    pub fn purpose(&self, day: u64) -> Hash {
        hash_of("pave/dispatch/shift", &(self.id, day))
    }
    /// What a courier badge's ticket is tagged for.
    pub fn badge_purpose(&self) -> Hash {
        hash_of("pave/dispatch/badge", &self.id)
    }
    /// The courier id on `t`, if it is a badge from this dispatch.
    pub fn badge_of(&self, s: &impl Scheme, t: &SignedTicket) -> Option<String> {
        let tag = t
            .ticket
            .tag
            .as_ref()
            .filter(|g| g.purpose == self.badge_purpose())?;
        (t.clerk == self.clerk && t.ticket.sequence == self.id && t.verify(s))
            .then(|| String::from_utf8(tag.nym.clone()).ok())
            .flatten()
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
    pub fn finish(
        d: &Dispatch,
        pending: PendingKey,
        reply: &JoinReply,
    ) -> Result<MemberCard, String> {
        let key = pending.finish(
            &BrioletteV1 {
                group_public_key: d.roll.clone(),
            },
            reply,
        )?;
        Ok(MemberCard {
            dispatch: d.id,
            key,
        })
    }
}

/// A courier's daily credential: its membership in the day's group.
#[derive(Clone, Serialize, Deserialize)]
pub struct DayCard {
    pub dispatch: Hash,
    pub day: u64,
    pub group: Vec<u8>,
    pub key: HolderKey,
}

/// A check-in: a join to the day's group, signed by the member credential
/// under [`Dispatch::check_in_spec`].
pub type CheckIn = Request<CheckInBody>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckInBody {
    pub dispatch: Hash,
    pub join: JoinRequest,
}

/// Dispatch's answer to a check-in: the day credential, and the day's group key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckedIn {
    pub reply: JoinReply,
    pub group: Vec<u8>,
}

/// An anonymous request for shift tickets, signed by the member credential
/// under [`Dispatch::shift_spec`] and shown by the day credential.
pub type ShiftRequest = Request<ShiftBody>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShiftBody {
    pub dispatch: Hash,
    pub creds: Vec<Credential>,
}

/// Shift keys, each with its ticket group, by the request's (day, slot, pseudonym).
pub type Shifts = BTreeMap<(u64, u32, Vec<u8>), Vec<(u32, Credential)>>;

/// What dispatch keeps, held by the operator.
#[derive(Clone, Serialize, Deserialize)]
pub struct Book {
    pub dispatch: Dispatch,
    pub roll: Issuer,
    /// Each (day, pseudonym)'s groups and keys.
    pub shifts: Shifts,
    /// Each day's group, and the check-in pseudonyms seen: the count.
    pub days: BTreeMap<u64, Issuer>,
    pub checked_in: BTreeMap<u64, BTreeSet<Vec<u8>>>,
    /// Shift request pseudonyms today, to see which are linked.
    pub requests: crate::slots::Seen,
    pub ruled: Vec<Cheat>,
    pub revoked: BTreeMap<u32, u32>,
    /// Badges: each courier id's identity key and ticket group. Who the
    /// courier is stays with the co-op, outside pave.
    #[serde(default)]
    pub badges: BTreeMap<String, (Credential, u32)>,
}

impl Node {
    fn book(&self, id: &Hash) -> Result<&Book, String> {
        self.operator
            .as_ref()
            .and_then(|o| o.dispatches.get(id))
            .ok_or_else(|| "this node doesn't run that dispatch".into())
    }
    fn book_mut(&mut self, id: &Hash) -> Result<&mut Book, String> {
        self.operator
            .as_mut()
            .and_then(|o| o.dispatches.get_mut(id))
            .ok_or_else(|| "this node doesn't run that dispatch".into())
    }

    /// Operator: set up a dispatch: a member roll and its own ticks.
    pub fn open_dispatch(&mut self, label: &str) -> Result<Dispatch, String> {
        let op = self
            .operator
            .as_ref()
            .ok_or("only the operator runs a dispatch")?;
        let s = self.view.scheme().clone();
        let clerk = s.credential(&op.clerk);
        let budget = sign(
            &s,
            &op.root,
            &op.root_cred,
            Op::IssueBudget {
                authority: self.town.genesis.rooting_capability(),
                schema: epoch_schema(&format!("dispatch {label}")),
                amount: 1,
                to: clerk.clone(),
            },
        );
        let first = sign(
            &s,
            &op.clerk,
            &clerk,
            Op::Mint {
                budget: budget.output(0),
                amount: 1,
                to: clerk.clone(),
                change_to: clerk.clone(),
            },
        );
        apply_ok(&mut self.view, &budget)?;
        apply_ok(&mut self.view, &first)?;
        let roll = Issuer::new();
        let d = Dispatch {
            roster: Roster {
                id: first.output(0),
                label: label.into(),
                clerk,
            },
            roll: roll.group_public_key.clone(),
            records: vec![budget, first],
        };
        let book = Book {
            dispatch: d.clone(),
            roll,
            shifts: BTreeMap::new(),
            days: BTreeMap::new(),
            checked_in: BTreeMap::new(),
            requests: Default::default(),
            ruled: vec![],
            revoked: BTreeMap::new(),
            badges: BTreeMap::new(),
        };
        self.operator
            .as_mut()
            .unwrap()
            .dispatches
            .insert(d.id, book);
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

    /// Courier: check in for today: a join to the day's group, signed by
    /// the member credential under the day's check-in basename.
    pub fn check_in(
        &self,
        d: &Dispatch,
        card: &MemberCard,
        terms: &(u64, Vec<Cheat>),
    ) -> Result<(PendingKey, CheckIn), String> {
        let (pending, join) = PendingKey::generate(&pave_scheme_briolette::join_nonce());
        let req = d.check_in_spec().sign(
            &card.key,
            &d.roll,
            terms.0,
            0,
            CheckInBody {
                dispatch: d.id,
                join,
            },
            &terms.1,
            &[],
            &[],
        )?;
        Ok((pending, req))
    }

    /// Dispatch: answer a check-in: today, a member, with standing against
    /// every ruling. A member who checked in already today (a new phone) is
    /// linked to it and counted once.
    pub fn answer_check_in(&mut self, req: &CheckIn) -> Result<CheckedIn, String> {
        let book = self.book(&req.body.dispatch)?;
        let d = book.dispatch.clone();
        if req.period != today() {
            return Err("check in for today".into());
        }
        let members = d.members();
        let v =
            d.check_in_spec()
                .verify(req, members.iter().map(|(n, g)| (n, g)), &book.ruled, &[])?;
        let book = self.book_mut(&req.body.dispatch)?;
        let issuer = book.days.entry(req.period).or_insert_with(Issuer::new);
        let reply = issuer.issue(&req.body.join)?;
        let group = issuer.group_public_key.clone();
        book.checked_in.entry(req.period).or_default().insert(v.nym);
        self.save()?;
        Ok(CheckedIn { reply, group })
    }

    /// Dispatch: how many distinct couriers checked in on `day`.
    pub fn couriers(&self, id: &Hash, day: u64) -> Result<usize, String> {
        Ok(self.book(id)?.checked_in.get(&day).map_or(0, BTreeSet::len))
    }

    /// Courier: keep the day credential.
    pub fn day_card(
        d: &Dispatch,
        day: u64,
        pending: PendingKey,
        c: &CheckedIn,
    ) -> Result<DayCard, String> {
        let key = pending.finish(
            &BrioletteV1 {
                group_public_key: c.group.clone(),
            },
            &c.reply,
        )?;
        Ok(DayCard {
            dispatch: d.id,
            day,
            group: c.group.clone(),
            key,
        })
    }

    /// Courier: ask for shift tickets for `n` fresh keys, as a member who
    /// checked in today.
    pub fn shift_request(
        &mut self,
        d: &Dispatch,
        card: &MemberCard,
        day: &DayCard,
        terms: &(u64, Vec<Cheat>),
        n: usize,
    ) -> Result<ShiftRequest, String> {
        let creds: Vec<Credential> = (0..n)
            .map(|_| self.view.scheme().credential(&self.key))
            .collect();
        let slot = self.slots.take(&d.id, terms.0, SHIFT_SLOTS);
        d.shift_spec().sign(
            &card.key,
            &d.roll,
            terms.0,
            slot,
            ShiftBody {
                dispatch: d.id,
                creds,
            },
            &terms.1,
            &[],
            &[(&day.key, &day.group)],
        )
    }

    /// Dispatch: answer a shift request: today, a member with standing
    /// against every ruling, who checked in today. Requests past the slots
    /// are served and linked to an earlier one.
    pub fn answer_shift(&mut self, req: &ShiftRequest) -> Result<Vec<SignedTicket>, String> {
        let book = self.book(&req.body.dispatch)?;
        let d = book.dispatch.clone();
        if req.period != today() {
            return Err("shift tickets are for today".into());
        }
        let creds = &req.body.creds;
        if creds.is_empty() || creds.len() > crate::node::MAX_BATCH {
            return Err(format!("ask for 1 to {} keys", crate::node::MAX_BATCH));
        }
        let day = book
            .days
            .get(&req.period)
            .ok_or("nobody has checked in today")?;
        let members = d.members();
        let v = d
            .shift_spec()
            .verify(
                req,
                members.iter().map(|(n, g)| (n, g)),
                &book.ruled,
                &[Expect::Shown(&day.group_public_key)],
            )
            .map_err(|e| {
                if e.contains("extra signature") {
                    "check in first: no day credential".to_string()
                } else {
                    e
                }
            })?;
        let nym = v.nym;
        let used: BTreeSet<u32> = book.shifts.values().flatten().map(|(g, _)| *g).collect();
        let group = loop {
            let g = rand::Rng::gen_range(&mut rand::rngs::OsRng, 1..u32::MAX);
            if !used.contains(&g) {
                break g;
            }
        };
        let epoch = head(&self.view, &d.id).ok_or("no dispatch tick")?.number;
        let op = self.operator.as_ref().unwrap();
        let s = self.view.scheme().clone();
        let tag = Tag {
            purpose: d.purpose(req.period),
            nym: nym.clone(),
            class: format!("day {}", req.period),
        };
        let tickets: Vec<SignedTicket> = creds
            .iter()
            .map(|c| {
                SignedTicket::issue(
                    &s,
                    &op.clerk,
                    &d.clerk,
                    Ticket {
                        credential: c.clone(),
                        sequence: d.id,
                        epoch,
                        group,
                        max_spend: None,
                        tag: Some(tag.clone()),
                    },
                )
            })
            .collect();
        for t in &tickets {
            self.know.add_ticket(&s, t.clone());
        }
        let book = self.book_mut(&req.body.dispatch)?;
        book.requests.note(req.period, nym.clone());
        book.shifts
            .entry((req.period, req.slot, nym))
            .or_default()
            .extend(creds.iter().map(|c| (group, c.clone())));
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
    pub fn shift_key(&mut self, d: &Roster) -> Option<Credential> {
        let s = self.view.scheme().clone();
        let i = self.shift_keys.iter().position(|c| {
            self.know
                .tickets
                .get(c)
                .is_some_and(|t| d.shift_of(&s, t).is_some())
        })?;
        Some(self.shift_keys.remove(i))
    }

    /// Co-op: issue a courier badge: a ticket for the courier's stable
    /// identity key, tagged with the co-op's courier id, in a group of its
    /// own so it can be revoked alone. The co-op vets the courier and keeps
    /// who they are; pave sees the id.
    pub fn issue_badge(
        &mut self,
        id: &Hash,
        courier: &str,
        key: &Credential,
    ) -> Result<SignedTicket, String> {
        let d = self.book(id)?.dispatch.clone();
        let used: BTreeSet<u32> = {
            let b = self.book(id)?;
            b.shifts
                .values()
                .flatten()
                .map(|(g, _)| *g)
                .chain(b.badges.values().map(|(_, g)| *g))
                .collect()
        };
        let group = loop {
            let g = rand::Rng::gen_range(&mut rand::rngs::OsRng, 1..u32::MAX);
            if !used.contains(&g) {
                break g;
            }
        };
        let epoch = head(&self.view, &d.id).ok_or("no dispatch tick")?.number;
        let op = self.operator.as_ref().unwrap();
        let s = self.view.scheme().clone();
        let tag = Tag {
            purpose: d.badge_purpose(),
            nym: courier.as_bytes().to_vec(),
            class: "badge".into(),
        };
        let t = SignedTicket::issue(
            &s,
            &op.clerk,
            &d.clerk,
            Ticket {
                credential: key.clone(),
                sequence: d.id,
                epoch,
                group,
                max_spend: None,
                tag: Some(tag),
            },
        );
        self.know.add_ticket(&s, t.clone());
        self.book_mut(id)?
            .badges
            .insert(courier.into(), (key.clone(), group));
        self.save()?;
        Ok(t)
    }

    /// Co-op: revoke a courier's badge on a new tick.
    pub fn revoke_badge(&mut self, id: &Hash, courier: &str) -> Result<(), String> {
        let (_, group) = self
            .book(id)?
            .badges
            .get(courier)
            .cloned()
            .ok_or("no such badge")?;
        self.tick_dispatch(id, &[group])
    }

    /// Courier: keep a badge, and the dispatch's ticks.
    pub fn take_badge(&mut self, d: &Dispatch, t: SignedTicket) -> Result<(), String> {
        for r in &d.records {
            apply_ok(&mut self.view, r)?;
        }
        let s = self.view.scheme().clone();
        d.badge_of(&s, &t).ok_or("not a badge from this dispatch")?;
        self.mine.insert(t.ticket.credential.clone());
        self.know.add_ticket(&s, t);
        self.save()
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
        let data = EpochData {
            sequence: d.id,
            number: h.number + 1,
            revoked: book.revoked.clone(),
        };
        let current = self
            .view
            .coin(&h.state)
            .ok_or("dispatch tick missing")?
            .clone();
        let op = self.operator.as_ref().unwrap();
        let rec = roll(
            self.view.scheme(),
            &op.clerk,
            &d.clerk,
            &current,
            &d.clerk,
            &data,
        );
        let rec = self.guard(rec)?;
        apply_ok(&mut self.view, &rec)?;
        self.know.add_epoch_data(&self.view, data);
        self.save()
    }

    /// Dispatch: rule a courier out, by a key it took a parcel under: the
    /// pseudonym of the request that key came from goes on the ruled list,
    /// and that request's group is revoked.
    pub fn rule_courier(&mut self, id: &Hash, key: &Credential) -> Result<(), String> {
        let book = self.book(id)?;
        let ((day, slot, nym), groups) = book
            .shifts
            .iter()
            .find(|(_, ks)| ks.iter().any(|(_, c)| c == key))
            .map(|(k, ks)| (k.clone(), ks.iter().map(|(g, _)| *g).collect::<Vec<_>>()))
            .ok_or("not a key this dispatch issued")?;
        let cheat = (book.dispatch.shift_spec().basename(day, slot), nym);
        self.book_mut(id)?.ruled.push(cheat);
        self.tick_dispatch(id, &groups)
    }
}
