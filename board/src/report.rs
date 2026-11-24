//! The civic reports profile: public reports of problems in the street,
//! such as a sidewalk blocked without a permit.
//!
//! It is useful before any city adopts it. Reports are public posts in a
//! town's reports scope, and the city's own published permit data is
//! mirrored in, signed by a mirror role, so "no permit" is something anyone
//! can check rather than an accusation.
//!
//! - **Issues.** An issue is a category in a coarse location cell, opened on
//!   a day. Everyone who reports the same thing reports the same issue.
//! - **One person, one report per issue, unlinkably.** Each report carries
//!   an endorsement: a signature by a fresh randomization of the reporter's
//!   access credential, with the issue as basename. Its pseudonym is the
//!   same for one person on one issue and unrelated across issues, so ten
//!   neighbors count as ten and one person counts once, and nobody learns
//!   who they are. The access credential's issuer shows which class of
//!   wallet reported, nothing more.
//! - **Rulings without unmasking.** A report ruled malicious puts its
//!   (basename, pseudonym) on a public list. Later reports carry standing
//!   against every ruling made before their epoch: the ruled reporter can't
//!   produce it, and nobody else is affected or identified.
//! - **Facts, not verdicts.** A report states what was seen, where (a cell
//!   about 150 m across) and on what day, and commits to a photo by a salted
//!   hash that its reporter can reveal to whoever checks it. Whether a permit
//!   covers it comes from the mirrored data, and the subject can reply or
//!   point to a permit in the same thread.
//! - **Delayed publication.** A wallet holds its own reports back until the
//!   next epoch, so a post doesn't say "sent at 8:02 from that corner".
//! - **Forwarding and clearing.** Anyone can record that an issue was sent
//!   on through the city's existing channels (a 311 ticket number), and
//!   people can confirm it was cleared, each counted once like reports.

use crate::node::{apply_ok, Node};
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::{Credential, Op, Scheme, Sig, View};
use pave_protocol::{head, Standing};
use pave_scheme_briolette::BrioletteV1;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A (basename, pseudonym) pair, as on a ruled list.
type Cheat = (Vec<u8>, Vec<u8>);

/// Public cells are geohashes of this length: about 150 m by 150 m.
pub const CELL_PRECISION: usize = 7;

/// A geohash of `precision` characters.
pub fn cell(lat: f64, lon: f64, precision: usize) -> String {
    const BASE32: &[u8] = b"0123456789bcdefghjkmnpqrstuvwxyz";
    let (mut lat_r, mut lon_r) = ((-90.0, 90.0), (-180.0, 180.0));
    let (mut out, mut bits, mut ch, mut even) = (String::new(), 0, 0usize, true);
    while out.len() < precision {
        let (r, v): (&mut (f64, f64), f64) = if even { (&mut lon_r, lon) } else { (&mut lat_r, lat) };
        let mid = (r.0 + r.1) / 2.0;
        ch <<= 1;
        if v >= mid {
            ch |= 1;
            r.0 = mid;
        } else {
            r.1 = mid;
        }
        even = !even;
        bits += 1;
        if bits == 5 {
            out.push(BASE32[ch] as char);
            bits = 0;
            ch = 0;
        }
    }
    out
}

/// What makes two reports the same issue.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IssueKey {
    pub category: String,
    pub cell: String,
    /// The day it was first seen, as the first reporter saw it (YYYY-MM-DD).
    pub opened: String,
}

impl IssueKey {
    pub fn id(&self) -> Hash {
        hash_of("pave/report/issue", self)
    }
}

/// A reporter's anonymous endorsement of one message about one issue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endorsement {
    /// A fresh randomization of the reporter's access credential.
    pub access: Credential,
    pub sig: Sig,
    /// Standing against every ruled reporter the reporter knew of.
    pub standing: Standing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportMsg {
    /// A report of an issue. The first one opens it.
    Report { key: IssueKey, observed: String, note: String, photo: Option<Hash>, epoch: u32, endorsement: Endorsement },
    /// Someone confirms the issue is cleared.
    Cleared { issue: Hash, epoch: u32, endorsement: Endorsement },
    /// A reply, such as from whoever the issue is about, optionally pointing
    /// to a mirrored permit.
    Reply { issue: Hash, text: String, permit: Option<Hash> },
    /// The issue was sent on through another channel, with its receipt.
    Forwarded { issue: Hash, channel: String, receipt: String },
    /// From the mirror role: a permit from the city's published data.
    Permit { source: String, source_id: String, kind: String, cell: String, start: String, end: String },
    /// From the moderator role: a ruling on one report.
    Ruling { report: Hash, malicious: bool, epoch: u32 },
}

impl ReportMsg {
    pub fn encode(&self) -> Vec<u8> {
        pave_kernel::hash::encode(self)
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        ciborium::from_reader(b).ok()
    }
}

fn report_basename(key: &IssueKey) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/report/v0", key.id()))
}

fn clear_basename(issue: &Hash) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/report-cleared/v0", issue))
}

fn report_bytes(key: &IssueKey, observed: &str, note: &str, photo: &Option<Hash>, epoch: u32, standing: &Standing) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/report/v0", key, observed, note, photo, epoch, standing))
}

fn clear_bytes(issue: &Hash, epoch: u32, standing: &Standing) -> Vec<u8> {
    pave_kernel::hash::encode(&("pave/report-cleared/v0", issue, epoch, standing))
}

/// A salted commitment to a photo, for revealing to whoever checks a report.
pub fn commit_photo(salt: &[u8; 32], photo: &[u8]) -> Hash {
    hash_of("pave/report/photo", &(salt, photo))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum PermitStatus {
    /// A mirrored permit covers this cell on the day it was seen.
    Found(Hash),
    /// A permit covers a neighboring area that day, not this cell.
    Nearby(Hash),
    /// No mirrored permit covers it.
    None,
}

#[derive(Clone, Debug, Serialize)]
pub struct Issue {
    pub id: Hash,
    pub key: IssueKey,
    /// Distinct reporters, counted by pseudonym, excluding ruled reports.
    pub reporters: usize,
    /// Reporters by wallet class.
    pub classes: BTreeMap<String, usize>,
    pub notes: Vec<String>,
    pub photos: usize,
    pub permit: PermitStatus,
    pub replies: Vec<(String, Option<Hash>)>,
    pub forwarded: Vec<(String, String)>,
    /// Distinct people who confirmed it cleared.
    pub cleared: usize,
    /// Reports that didn't count: ruled malicious, or without standing.
    pub discounted: usize,
}

/// Whoever may speak for the town's roles in the reports scope.
#[derive(Clone, Debug)]
pub struct Roles<'a> {
    pub mirror: &'a Credential,
    pub moderator: &'a Credential,
    pub classes: &'a BTreeMap<String, crate::node::Class>,
}

fn class_of(roles: &Roles, e: &Endorsement, msg: &[u8], bsn: &[u8]) -> Option<(String, BrioletteV1, Vec<u8>)> {
    roles.classes.iter().find_map(|(name, c)| {
        let s = BrioletteV1 { group_public_key: c.group_public_key.clone() };
        if s.verify(&e.access, msg, Some(bsn), &e.sig) && e.standing.credential == e.access && e.standing.verify(&s) {
            s.nym(&e.sig).map(|n| (name.clone(), s, n))
        } else {
            None
        }
    })
}

/// The reports scope as this view sees it.
pub fn issues<V: Scheme>(view: &View<V>, scope: &Hash, roles: &Roles) -> BTreeMap<Hash, Issue> {
    let mut msgs: Vec<(Hash, Credential, ReportMsg)> = vec![];
    for rec in view.messages() {
        let Op::Send { scope: sc, body, .. } = &rec.op else { continue };
        if sc != scope {
            continue;
        }
        if let Some(m) = ReportMsg::decode(body) {
            msgs.push((rec.id(), rec.signer.clone(), m));
        }
    }
    // Rulings and permits first: only from their roles.
    let mut ruled: BTreeSet<Hash> = BTreeSet::new();
    let mut permits: BTreeMap<Hash, (String, String, String, String)> = BTreeMap::new();
    let mut rulings_at: Vec<(Hash, u32)> = vec![];
    for (id, signer, m) in &msgs {
        match m {
            ReportMsg::Ruling { report, malicious: true, epoch } if signer == roles.moderator => {
                ruled.insert(*report);
                rulings_at.push((*report, *epoch));
            }
            ReportMsg::Permit { kind, cell, start, end, .. } if signer == roles.mirror => {
                permits.insert(*id, (kind.clone(), cell.clone(), start.clone(), end.clone()));
            }
            _ => {}
        }
    }
    // The (basename, pseudonym) of each ruled report, and when it was ruled.
    let mut ruled_list: Vec<(Cheat, u32)> = vec![];
    for (id, _, m) in &msgs {
        if let ReportMsg::Report { key, observed, note, photo, epoch, endorsement } = m {
            if ruled.contains(id) {
                let bsn = report_basename(key);
                if let Some((_, _, nym)) = class_of(roles, endorsement, &report_bytes(key, observed, note, photo, *epoch, &endorsement.standing), &bsn) {
                    let at = rulings_at.iter().find(|(r, _)| r == id).map(|(_, e)| *e).unwrap_or(0);
                    ruled_list.push(((bsn, nym), at));
                }
            }
        }
    }
    let mut out: BTreeMap<Hash, Issue> = BTreeMap::new();
    let mut nyms: BTreeMap<Hash, BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut clearers: BTreeMap<Hash, BTreeSet<Vec<u8>>> = BTreeMap::new();
    for (id, _, m) in &msgs {
        match m {
            ReportMsg::Report { key, observed, note, photo, epoch, endorsement } => {
                let issue = key.id();
                let entry = out.entry(issue).or_insert_with(|| Issue {
                    id: issue,
                    key: key.clone(),
                    reporters: 0,
                    classes: BTreeMap::new(),
                    notes: vec![],
                    photos: 0,
                    permit: permit_status(&permits, key, observed),
                    replies: vec![],
                    forwarded: vec![],
                    cleared: 0,
                    discounted: 0,
                });
                let bsn = report_basename(key);
                let counted = class_of(roles, endorsement, &report_bytes(key, observed, note, photo, *epoch, &endorsement.standing), &bsn).filter(|_| !ruled.contains(id)).filter(|_| {
                    // Standing must cover every ruling made before this report's epoch.
                    ruled_list.iter().filter(|(_, at)| at < epoch).all(|(c, _)| endorsement.standing.cheats.contains(c))
                });
                match counted {
                    Some((class, _, nym)) => {
                        if nyms.entry(issue).or_default().insert(nym) {
                            entry.reporters += 1;
                            *entry.classes.entry(class).or_default() += 1;
                            entry.notes.push(note.clone());
                            entry.photos += photo.is_some() as usize;
                        }
                    }
                    None => entry.discounted += 1,
                }
            }
            ReportMsg::Cleared { issue, epoch, endorsement } => {
                if let Some((_, _, nym)) = class_of(roles, endorsement, &clear_bytes(issue, *epoch, &endorsement.standing), &clear_basename(issue)) {
                    clearers.entry(*issue).or_default().insert(nym);
                }
            }
            _ => {}
        }
    }
    for (_, _, m) in &msgs {
        match m {
            ReportMsg::Reply { issue, text, permit } => {
                if let Some(i) = out.get_mut(issue) {
                    // A permit counts only if it covers the issue's area on the day it opened.
                    let covers = |p: &Hash| {
                        permits.get(p).is_some_and(|(_, cell, start, end)| {
                            cell.len() >= 6 && i.key.cell.len() >= 6 && cell[..6] == i.key.cell[..6] && start.as_str() <= i.key.opened.as_str() && i.key.opened.as_str() <= end.as_str()
                        })
                    };
                    let shown = permit.filter(covers);
                    if let Some(p) = shown {
                        if !matches!(i.permit, PermitStatus::Found(_)) {
                            i.permit = PermitStatus::Found(p);
                        }
                    }
                    i.replies.push((text.clone(), shown));
                }
            }
            ReportMsg::Forwarded { issue, channel, receipt } => {
                if let Some(i) = out.get_mut(issue) {
                    i.forwarded.push((channel.clone(), receipt.clone()));
                }
            }
            _ => {}
        }
    }
    for (issue, set) in clearers {
        if let Some(i) = out.get_mut(&issue) {
            i.cleared = set.len();
        }
    }
    out
}

fn permit_status(permits: &BTreeMap<Hash, (String, String, String, String)>, key: &IssueKey, observed: &str) -> PermitStatus {
    let in_date = |start: &str, end: &str| start <= observed && observed <= end;
    let mut nearby = None;
    for (id, (_kind, cell, start, end)) in permits {
        if !in_date(start, end) {
            continue;
        }
        if *cell == key.cell {
            return PermitStatus::Found(*id);
        }
        if cell.len() >= 6 && key.cell.len() >= 6 && cell[..6] == key.cell[..6] {
            nearby = Some(*id);
        }
    }
    nearby.map_or(PermitStatus::None, PermitStatus::Nearby)
}

/// A permit as a city publishes it, normalized. The sample in
/// `demo/permits_sample.json` uses this shape.
#[derive(Clone, Debug, Deserialize)]
pub struct PublishedPermit {
    pub source: String,
    pub id: String,
    pub kind: String,
    pub lat: f64,
    pub lon: f64,
    pub start: String,
    pub end: String,
}

impl Node {
    fn roles(&self) -> Roles<'_> {
        Roles { mirror: &self.town.mirror, moderator: &self.town.moderator, classes: &self.town.classes }
    }

    pub fn issues(&self) -> BTreeMap<Hash, Issue> {
        issues(&self.view, &self.town.reports, &self.roles())
    }

    fn epoch(&self) -> u32 {
        head(&self.view, &self.town.sequence).map_or(0, |h| h.number)
    }

    /// The ruled reporters this wallet knows of, with when each was ruled.
    fn ruled(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let roles = self.roles();
        let mut ruled = BTreeSet::new();
        for rec in self.view.messages() {
            let Op::Send { scope, body, .. } = &rec.op else { continue };
            if *scope == self.town.reports && rec.signer == self.town.moderator {
                if let Some(ReportMsg::Ruling { report, malicious: true, .. }) = ReportMsg::decode(body) {
                    ruled.insert(report);
                }
            }
        }
        let mut out = vec![];
        for rec in self.view.messages() {
            let Op::Send { body, .. } = &rec.op else { continue };
            if !ruled.contains(&rec.id()) {
                continue;
            }
            if let Some(ReportMsg::Report { key, observed, note, photo, epoch, endorsement }) = ReportMsg::decode(body) {
                let bsn = report_basename(&key);
                if let Some((_, _, nym)) = class_of(&roles, &endorsement, &report_bytes(&key, &observed, &note, &photo, epoch, &endorsement.standing), &bsn) {
                    out.push((bsn, nym));
                }
            }
        }
        out
    }

    fn access_scheme(&self) -> BrioletteV1 {
        BrioletteV1 { group_public_key: self.town.classes[&self.class].group_public_key.clone() }
    }

    fn endorse(&self, msg_bytes: impl Fn(&Standing) -> Vec<u8>, bsn: &[u8]) -> Result<Endorsement, String> {
        let a = self.access_scheme();
        let access = a.credential(&self.access);
        let standing = Standing::prove(&a, &self.access, &access, &self.ruled()).ok_or("this wallet's reports were ruled malicious")?;
        let sig = a.sign(&self.access, &access, &msg_bytes(&standing), Some(bsn));
        Ok(Endorsement { access, sig, standing })
    }

    /// Post to the reports scope under a fresh, unticketed credential. The
    /// wallet's own reports are held back until the next epoch.
    fn post_report(&mut self, msg: ReportMsg, hold: bool) -> Result<Hash, String> {
        let signer = self.view.scheme().credential(&self.key);
        self.mine.insert(signer.clone());
        let rec = pave_kernel::sign(self.view.scheme(), &self.key, &signer, Op::Send { scope: self.town.reports, presenting: None, body: msg.encode(), receipt: Hash([0; 32]) });
        let id = rec.id();
        if hold {
            self.unpublished.push((self.epoch() + 1, rec));
            self.save()?;
        } else {
            apply_ok(&mut self.view, &rec)?;
        }
        Ok(id)
    }

    /// Publish this wallet's held reports whose epoch has come.
    pub fn release_reports(&mut self) -> usize {
        let now = self.epoch();
        let (due, wait): (Vec<_>, Vec<_>) = self.unpublished.drain(..).partition(|(at, _)| *at <= now);
        self.unpublished = wait;
        let n = due.iter().filter(|(_, r)| apply_ok(&mut self.view, r).is_ok()).count();
        if n > 0 {
            let _ = self.save();
        }
        n
    }

    /// Report an issue, or add this wallet's report to one already open.
    /// Returns the issue id.
    pub fn report(&mut self, key: IssueKey, observed: &str, note: &str, photo: Option<Hash>) -> Result<Hash, String> {
        let epoch = self.epoch();
        let bsn = report_basename(&key);
        let endorsement = self.endorse(|st| report_bytes(&key, observed, note, &photo, epoch, st), &bsn)?;
        let issue = key.id();
        self.post_report(ReportMsg::Report { key, observed: observed.into(), note: note.into(), photo, epoch, endorsement }, true)?;
        Ok(issue)
    }

    /// Add this wallet's report to an open issue.
    pub fn corroborate(&mut self, issue: &Hash, observed: &str, note: &str) -> Result<Hash, String> {
        let key = self.issues().get(issue).map(|i| i.key.clone()).ok_or("unknown issue")?;
        self.report(key, observed, note, None)
    }

    pub fn clear_issue(&mut self, issue: &Hash) -> Result<Hash, String> {
        let epoch = self.epoch();
        let endorsement = self.endorse(|st| clear_bytes(issue, epoch, st), &clear_basename(issue))?;
        self.post_report(ReportMsg::Cleared { issue: *issue, epoch, endorsement }, true)
    }

    pub fn reply_issue(&mut self, issue: &Hash, text: &str, permit: Option<Hash>) -> Result<Hash, String> {
        self.post_report(ReportMsg::Reply { issue: *issue, text: text.into(), permit }, false)
    }

    pub fn forward_issue(&mut self, issue: &Hash, channel: &str, receipt: &str) -> Result<Hash, String> {
        self.post_report(ReportMsg::Forwarded { issue: *issue, channel: channel.into(), receipt: receipt.into() }, false)
    }

    fn post_as_role(&mut self, signer: Credential, msg: ReportMsg) -> Result<Hash, String> {
        if self.operator.is_none() {
            return Err("only the town holds that role".into());
        }
        let rec = pave_kernel::sign(self.view.scheme(), &self.key, &signer, Op::Send { scope: self.town.reports, presenting: None, body: msg.encode(), receipt: Hash([0; 32]) });
        apply_ok(&mut self.view, &rec)?;
        Ok(rec.id())
    }

    /// Mirror role: sign permits from a city's published data into the
    /// reports scope. Returns how many were new.
    pub fn mirror_permits(&mut self, permits: &[PublishedPermit]) -> Result<usize, String> {
        let have: BTreeSet<(String, String)> = self
            .view
            .messages()
            .iter()
            .filter_map(|r| match &r.op {
                Op::Send { body, .. } if r.signer == self.town.mirror => match ReportMsg::decode(body) {
                    Some(ReportMsg::Permit { source, source_id, .. }) => Some((source, source_id)),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let mut n = 0;
        for p in permits {
            if have.contains(&(p.source.clone(), p.id.clone())) {
                continue;
            }
            let msg = ReportMsg::Permit { source: p.source.clone(), source_id: p.id.clone(), kind: p.kind.clone(), cell: cell(p.lat, p.lon, CELL_PRECISION), start: p.start.clone(), end: p.end.clone() };
            self.post_as_role(self.town.mirror.clone(), msg)?;
            n += 1;
        }
        self.save()?;
        Ok(n)
    }

    /// Moderator role: rule on a report.
    pub fn rule(&mut self, report: Hash, malicious: bool) -> Result<Hash, String> {
        let epoch = self.epoch();
        let id = self.post_as_role(self.town.moderator.clone(), ReportMsg::Ruling { report, malicious, epoch })?;
        self.save()?;
        Ok(id)
    }

    /// The report records in this view about `issue`, by id.
    pub fn reports_on(&self, issue: &Hash) -> Vec<Hash> {
        self.view
            .messages()
            .iter()
            .filter(|r| matches!(&r.op, Op::Send { scope, body, .. } if *scope == self.town.reports && matches!(ReportMsg::decode(body), Some(ReportMsg::Report { ref key, .. }) if key.id() == *issue)))
            .map(|r| r.id())
            .collect()
    }
}
