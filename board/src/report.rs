//! Civic reports: a board (see [`crate::bulletin`]) for public reports of
//! problems in the street, such as a sidewalk blocked without a permit.
//!
//! It is useful before any city adopts it. Reports are public posts on a
//! town's reports board, and the city's own published permit data is
//! mirrored in, signed by a mirror role, so "no permit" is something anyone
//! can check rather than an accusation.
//!
//! - **Issues.** An issue is a category in a coarse location cell, opened on
//!   a day. Everyone who reports the same thing reports the same issue, and
//!   the issue is the thread.
//! - **One person, one report per issue, unlinkably.** Reports and
//!   clearings are counted posts: their tokens' tickets carry a tag for the
//!   issue (see [`crate::bulletin`]), so ten neighbors count as ten and one
//!   person counts once, and nobody learns who they are. The tag shows
//!   which class of wallet reported, nothing more.
//! - **Rulings without unmasking.** A report ruled malicious puts its tag on
//!   the board mint's list, so its reporter can't get post tokens again (it
//!   can't show standing against the tag), and revokes its ticket group at
//!   the next roll. Nobody else is affected or identified.
//! - **Facts, not verdicts.** A report states what was seen, where (a cell
//!   about 150 m across) and on what day, and commits to a photo by a salted
//!   hash its reporter can reveal to whoever checks it. Whether a permit
//!   covers it comes from the mirrored data, and the subject can reply or
//!   point to a permit in the same thread.
//! - **Sent to the board.** A report goes straight to the board's host, as
//!   a post to any website would. The host sees the connection; the post
//!   shows only what's in it.

use crate::bulletin::{purpose, Cheat, Copy};
use crate::node::Node;
use pave_kernel::hash::{hash_of, Hash};
use pave_kernel::Scheme;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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

/// The content of a post on a reports board.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportMsg {
    /// A report of an issue (counted). The first one opens it.
    Report { key: IssueKey, observed: String, note: String, photo: Option<Hash> },
    /// Someone confirms the issue is cleared (counted).
    Cleared,
    /// A reply, such as from whoever the issue is about, optionally pointing
    /// to a mirrored permit.
    Reply { text: String, permit: Option<Hash> },
    /// The issue was sent on through another channel, with its receipt.
    Forwarded { channel: String, receipt: String },
    /// From the mirror role: a permit from the city's published data.
    Permit { source: String, source_id: String, kind: String, cell: String, start: String, end: String },
    /// From the moderator role: a ruling on one report.
    Ruling { report: Hash, malicious: bool },
}

impl ReportMsg {
    pub fn encode(&self) -> Vec<u8> {
        pave_kernel::hash::encode(self)
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        ciborium::from_reader(b).ok()
    }
    pub fn kind(&self) -> &'static str {
        match self {
            ReportMsg::Report { .. } => "report",
            ReportMsg::Cleared => "cleared",
            ReportMsg::Reply { .. } => "reply",
            ReportMsg::Forwarded { .. } => "forwarded",
            ReportMsg::Permit { .. } => "permit",
            ReportMsg::Ruling { .. } => "ruling",
        }
    }
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
    /// Counted reports signed with an identity, by credential. The reader's
    /// own contacts among them are in `known_by`.
    pub identified: BTreeSet<pave_kernel::Credential>,
    pub known_by: Vec<String>,
}

/// One post, decoded, and only if its kind and thread match its content.
struct Msg<'a> {
    item: crate::bulletin::Item<'a>,
    msg: ReportMsg,
}

fn messages(copy: &Copy) -> Vec<Msg<'_>> {
    copy.items()
        .into_iter()
        .filter_map(|item| {
            let msg = ReportMsg::decode(item.content)?;
            let thread_ok = match &msg {
                ReportMsg::Report { key, .. } => item.post.thread == Some(key.id()),
                ReportMsg::Cleared | ReportMsg::Reply { .. } | ReportMsg::Forwarded { .. } => item.post.thread.is_some(),
                ReportMsg::Permit { .. } | ReportMsg::Ruling { .. } => true,
            };
            (item.post.kind == msg.kind() && thread_ok).then_some(Msg { item, msg })
        })
        .collect()
}

/// Every report the moderator ruled malicious.
fn ruled_reports(copy: &Copy) -> BTreeSet<Hash> {
    let moderator = copy.info.role("moderator");
    messages(copy).iter().filter(|m| Some(m.item.signer) == moderator).filter_map(|m| match m.msg {
        ReportMsg::Ruling { report, malicious: true } => Some(report),
        _ => None,
    }).collect()
}

/// The board mint's ruled list from this board: the tag of every report
/// ruled malicious. A token request needs standing against all of them.
pub fn ruled(copy: &Copy) -> Vec<Cheat> {
    let ruled = ruled_reports(copy);
    copy.items().iter().filter(|i| i.post.kind == "report" && ruled.contains(&i.id)).filter_map(|i| i.cheat()).collect()
}

/// The ticket groups of reports ruled malicious, revoked at the next roll.
pub fn ruled_groups(copy: &Copy) -> Vec<u32> {
    ruled_reports(copy).iter().filter_map(|r| copy.group(r)).collect()
}

/// What a report or clearing on `issue` counts for.
pub fn counts_for(copy: &Copy, kind: &str, issue: &Hash) -> Hash {
    purpose(&copy.info.scope, kind, issue)
}

/// The reports board as a copy has it.
pub fn issues(copy: &Copy) -> BTreeMap<Hash, Issue> {
    let mirror = copy.info.role("mirror");
    let msgs = messages(copy);
    let ruled = ruled_reports(copy);
    let mut permits: BTreeMap<Hash, (String, String, String)> = BTreeMap::new();
    for m in &msgs {
        if let ReportMsg::Permit { cell, start, end, .. } = &m.msg {
            if Some(m.item.signer) == mirror {
                permits.insert(m.item.id, (cell.clone(), start.clone(), end.clone()));
            }
        }
    }
    let mut out: BTreeMap<Hash, Issue> = BTreeMap::new();
    let mut nyms: BTreeMap<Hash, BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut clearers: BTreeMap<Hash, BTreeSet<Vec<u8>>> = BTreeMap::new();
    for m in &msgs {
        match &m.msg {
            ReportMsg::Report { key, observed, note, photo } => {
                let issue = key.id();
                let entry = out.entry(issue).or_insert_with(|| Issue { id: issue, key: key.clone(), reporters: 0, classes: BTreeMap::new(), notes: vec![], photos: 0, permit: permit_status(&permits, key, observed), replies: vec![], forwarded: vec![], cleared: 0, discounted: 0, identified: BTreeSet::new(), known_by: vec![] });
                let counted = m.item.counted(&counts_for(copy, "report", &issue)).filter(|_| !ruled.contains(&m.item.id));
                match counted {
                    Some((class, nym)) => {
                        if nyms.entry(issue).or_default().insert(nym) {
                            entry.reporters += 1;
                            *entry.classes.entry(class).or_default() += 1;
                            entry.notes.push(note.clone());
                            entry.photos += photo.is_some() as usize;
                        }
                        // An identity names the person, whichever of their reports carries it.
                        if let Some(c) = &m.item.by {
                            entry.identified.insert(c.clone());
                        }
                    }
                    None => entry.discounted += 1,
                }
            }
            ReportMsg::Cleared => {
                if let Some((_, nym)) = m.item.counted(&counts_for(copy, "cleared", &m.item.thread())) {
                    clearers.entry(m.item.thread()).or_default().insert(nym);
                }
            }
            _ => {}
        }
    }
    for m in &msgs {
        match &m.msg {
            ReportMsg::Reply { text, permit } => {
                if let Some(i) = out.get_mut(&m.item.thread()) {
                    // A permit counts only if it covers the issue's area on the day it opened.
                    let covers = |p: &Hash| permits.get(p).is_some_and(|(cell, start, end)| cell.len() >= 6 && i.key.cell.len() >= 6 && cell[..6] == i.key.cell[..6] && start.as_str() <= i.key.opened.as_str() && i.key.opened.as_str() <= end.as_str());
                    let shown = permit.filter(covers);
                    if let Some(p) = shown {
                        if !matches!(i.permit, PermitStatus::Found(_)) {
                            i.permit = PermitStatus::Found(p);
                        }
                    }
                    i.replies.push((text.clone(), shown));
                }
            }
            ReportMsg::Forwarded { channel, receipt } => {
                if let Some(i) = out.get_mut(&m.item.thread()) {
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

fn permit_status(permits: &BTreeMap<Hash, (String, String, String)>, key: &IssueKey, observed: &str) -> PermitStatus {
    let in_date = |start: &str, end: &str| start <= observed && observed <= end;
    let mut nearby = None;
    for (id, (cell, start, end)) in permits {
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
    fn reports(&self) -> Result<&Copy, String> {
        self.copy(&self.town.reports.scope)
    }

    /// The reports board, with the reader's contacts named on each issue.
    pub fn issues(&self) -> BTreeMap<Hash, Issue> {
        let mut out = self.reports().map(issues).unwrap_or_default();
        for i in out.values_mut() {
            i.known_by = self.contacts.iter().filter(|(_, c)| i.identified.contains(*c)).map(|(n, _)| n.clone()).collect();
        }
        out
    }

    /// Post to the reports board under a fresh credential, counted once per
    /// person on its issue when `count`, and signed with `identity` if given.
    fn post_report(&mut self, thread: Option<Hash>, msg: ReportMsg, count: bool, identity: Option<&str>) -> Result<Hash, String> {
        let signer = self.view.scheme().credential(&self.key);
        let scope = self.town.reports.scope;
        let count = match (count, thread) {
            (true, Some(t)) => Some(purpose(&scope, msg.kind(), &t)),
            (true, None) => return Err("a counted report needs its issue".into()),
            _ => None,
        };
        self.compose_as(&scope, &signer, msg.kind(), thread, msg.encode(), count, identity)
    }

    /// Report an issue, or add this wallet's report to one already open.
    /// The report goes out at the next sync. Returns the issue id.
    pub fn report(&mut self, key: IssueKey, observed: &str, note: &str, photo: Option<Hash>) -> Result<Hash, String> {
        self.report_as(key, observed, note, photo, None)
    }

    /// Report, signed with one of this wallet's identities, so whoever
    /// holds that identity knows the report is this wallet's.
    pub fn report_as(&mut self, key: IssueKey, observed: &str, note: &str, photo: Option<Hash>, identity: Option<&str>) -> Result<Hash, String> {
        let issue = key.id();
        self.post_report(Some(issue), ReportMsg::Report { key, observed: observed.into(), note: note.into(), photo }, true, identity)?;
        Ok(issue)
    }

    /// Add this wallet's report to an open issue.
    pub fn corroborate(&mut self, issue: &Hash, observed: &str, note: &str) -> Result<Hash, String> {
        let key = self.issues().get(issue).map(|i| i.key.clone()).ok_or("unknown issue")?;
        self.report(key, observed, note, None)
    }

    pub fn clear_issue(&mut self, issue: &Hash) -> Result<Hash, String> {
        self.post_report(Some(*issue), ReportMsg::Cleared, true, None)
    }

    pub fn reply_issue(&mut self, issue: &Hash, text: &str, permit: Option<Hash>) -> Result<Hash, String> {
        self.post_report(Some(*issue), ReportMsg::Reply { text: text.into(), permit }, false, None)
    }

    pub fn forward_issue(&mut self, issue: &Hash, channel: &str, receipt: &str) -> Result<Hash, String> {
        self.post_report(Some(*issue), ReportMsg::Forwarded { channel: channel.into(), receipt: receipt.into() }, false, None)
    }

    fn post_as_role(&mut self, role: &str, msg: ReportMsg) -> Result<Hash, String> {
        let scope = self.town.reports.scope;
        if !self.hosts(&scope) {
            return Err("only the town holds that role".into());
        }
        let signer = self.town.reports.role(role).ok_or("no such role")?.clone();
        self.compose(&scope, &signer, msg.kind(), None, msg.encode(), None)
    }

    /// Mirror role: sign permits from a city's published data onto the
    /// reports board. Returns how many were new.
    pub fn mirror_permits(&mut self, permits: &[PublishedPermit]) -> Result<usize, String> {
        let mirror = self.town.reports.role("mirror").cloned();
        let have: BTreeSet<(String, String)> = self
            .reports()?
            .items()
            .iter()
            .filter(|i| Some(i.signer) == mirror.as_ref())
            .filter_map(|i| match ReportMsg::decode(i.content) {
                Some(ReportMsg::Permit { source, source_id, .. }) => Some((source, source_id)),
                _ => None,
            })
            .collect();
        let mut n = 0;
        for p in permits {
            if have.contains(&(p.source.clone(), p.id.clone())) {
                continue;
            }
            let msg = ReportMsg::Permit { source: p.source.clone(), source_id: p.id.clone(), kind: p.kind.clone(), cell: cell(p.lat, p.lon, CELL_PRECISION), start: p.start.clone(), end: p.end.clone() };
            self.post_as_role("mirror", msg)?;
            n += 1;
        }
        Ok(n)
    }

    /// Moderator role: rule on a report.
    pub fn rule(&mut self, report: Hash, malicious: bool) -> Result<Hash, String> {
        self.post_as_role("moderator", ReportMsg::Ruling { report, malicious })
    }

    /// The report posts in this copy about `issue`, by id.
    pub fn reports_on(&self, issue: &Hash) -> Vec<Hash> {
        let Ok(copy) = self.reports() else {
            return vec![];
        };
        messages(copy).into_iter().filter(|m| matches!(&m.msg, ReportMsg::Report { key, .. } if key.id() == *issue)).map(|m| m.item.id).collect()
    }
}
