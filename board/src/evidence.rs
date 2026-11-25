//! Evidence for dispute panels.
//!
//! - **Sealed, but bound.** A party submits evidence about a subject to the
//!   board's host, signed by a credential it holds. The host keeps the
//!   bytes; a public post records that evidence was submitted, its kind and
//!   its hash, so nothing can be swapped later and everyone can see what
//!   the panel was given, without seeing it.
//! - **Only the panel and the parties look.** The host hands a subject's
//!   evidence only to a request signed, in the current epoch, by a
//!   credential drawn onto a panel of a dispute about that subject, or by
//!   one that opened such a dispute, so each side can answer the other's.
//!   Not to the public, not to offerers who weren't drawn.
//! - **Checkable, not just claims.** Evidence is typed, and a panelist's
//!   wallet checks what it can before anyone reads a word:
//!   - *Custody*: a parcel's manifest and the signed records of its chain,
//!     from the town's issuance on. The panelist applies them to its own
//!     view and works out custody itself.
//!   - *Code*: the shipper reveals a code delivery's code. The panelist
//!     checks whether the courier's closing record commits to it.
//!   - *Drop photo*: the courier's photo of a drop, as shown (its metadata
//!     stripped), with the commitment to the original. The panelist checks
//!     the commitment against the drop note: the original was fixed when
//!     the parcel was dropped.
//!   - *Image*: any party's picture, such as the addressee's own front
//!     door, optionally with a commitment to its original.
//!   - *Original*: the original behind a commitment, with its salt, revealed
//!     when it helps: its metadata (time, place, a C2PA provenance
//!     manifest) can then be inspected. The panelist checks it against the
//!     commitment.
//!   - *Reference*: a public record, such as a street-view image or the
//!     city's tax-assessor photo of an address: where it came from, and
//!     the image as fetched, so a panelist can look and check the source.
//!   - *Statement*: words, from whoever submitted them.
//!
//!   What a party shows is normally stripped of metadata (see
//!   [`crate::media`]); the original stays with the party, who alone holds
//!   the salt, until it chooses to reveal it.
//!
//!   A drop photo that matches the drop note was fixed when the parcel was
//!   dropped, before anyone disputed anything. That proves it wasn't
//!   swapped, not that it shows the right door: the panel compares it with
//!   the addressee's pictures and the public records.
//! - **An examination** sums it up as structured data a person or an AI
//!   agent can rule on: what custody shows, what checked out and what
//!   didn't, and which party submitted what.

use crate::board::BoardMsg;
use crate::node::{apply_ok, Node};
use crate::parcel::{code_receipt, Delivery, Manifest, Mode, Step};
use pave_kernel::hash::{encode, hash_bytes, hash_of, Hash};
use pave_kernel::{Credential, Op, Record, Scheme, Sig};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Largest evidence a host takes in one submission.
pub const MAX_EVIDENCE: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    /// A parcel's manifest and the records of its custody chain.
    Custody { manifest: Manifest, records: Vec<Record> },
    /// The code a code delivery was shipped with.
    Code { code: String },
    /// A drop's photo as shown, and the commitment to its original.
    DropPhoto {
        #[serde(with = "serde_bytes")]
        image: Vec<u8>,
        commitment: Hash,
    },
    /// A party's picture as shown, and optionally a commitment to its original.
    Image {
        caption: String,
        #[serde(with = "serde_bytes")]
        image: Vec<u8>,
        original: Option<Hash>,
    },
    /// The original behind a commitment, and its salt.
    Original {
        #[serde(with = "serde_bytes")]
        salt: Vec<u8>,
        #[serde(with = "serde_bytes")]
        original: Vec<u8>,
    },
    /// A public record: its source, where to find it, and the image as fetched.
    Reference {
        source: String,
        url: String,
        caption: String,
        #[serde(with = "serde_bytes")]
        image: Vec<u8>,
    },
    Statement { text: String },
}

impl Evidence {
    pub fn kind(&self) -> &'static str {
        match self {
            Evidence::Custody { .. } => "custody",
            Evidence::Code { .. } => "code",
            Evidence::DropPhoto { .. } => "photo",
            Evidence::Image { .. } => "image",
            Evidence::Original { .. } => "original",
            Evidence::Reference { .. } => "reference",
            Evidence::Statement { .. } => "statement",
        }
    }
}

/// The commitment a drop's receipt and note carry for its photo.
pub fn photo_commitment(salt: &[u8], photo: &[u8]) -> Hash {
    hash_bytes("pave/parcel/photo", &[salt, photo].concat())
}

/// Evidence as submitted: who submitted it about what, signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub subject: Hash,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
    pub from: Credential,
    pub sig: Sig,
}

fn sealed_bytes(subject: &Hash, bytes: &[u8]) -> Vec<u8> {
    encode(&("pave/evidence/v0", subject, hash_bytes("pave/evidence/bytes", bytes)))
}

impl Sealed {
    pub fn hash(&self) -> Hash {
        hash_bytes("pave/evidence/bytes", &self.bytes)
    }
    pub fn verify(&self, s: &crate::node::S) -> bool {
        s.verify(&self.from, &sealed_bytes(&self.subject, &self.bytes), None, &self.sig)
    }
    pub fn evidence(&self) -> Option<Evidence> {
        ciborium::from_reader(self.bytes.as_slice()).ok()
    }
}

/// A panelist's request for a subject's evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ask {
    pub subject: Hash,
    pub epoch: u32,
    pub panelist: Credential,
    pub sig: Sig,
}

fn ask_bytes(subject: &Hash, epoch: u32) -> Vec<u8> {
    encode(&("pave/evidence/ask/v0", subject, epoch))
}

/// What a check found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Check {
    Yes,
    No,
    /// Not enough evidence to check.
    Unknown,
}

/// One piece of evidence as a panelist sees it.
#[derive(Clone, Debug, Serialize)]
pub struct Exhibit {
    pub kind: String,
    /// The submitter's role in the parcel, if custody shows it.
    pub from: String,
    pub hash: Hash,
    /// Statement text, or a photo's size.
    pub detail: String,
}

/// A picture for the panel to look at.
#[derive(Clone, Debug, Serialize)]
pub struct Picture {
    /// What it is: "drop photo", the caption, or "source: caption".
    pub label: String,
    pub from: String,
    /// Fixed before any dispute: a drop photo that matches its drop note.
    pub committed_at_drop: bool,
    /// Whether the original behind this picture was revealed and matches
    /// (Yes), revealed and doesn't (No), or wasn't revealed (Unknown).
    pub original: Check,
    /// For a revealed original: the metadata it carries.
    pub metadata: Vec<String>,
    /// Where a public record came from.
    pub url: Option<String>,
    #[serde(skip)]
    commitment: Option<Hash>,
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

/// What a panelist's wallet makes of a parcel's evidence.
#[derive(Clone, Debug, Serialize)]
pub struct Examination {
    pub subject: Hash,
    /// The manifest's delivery mode, if custody evidence came.
    pub mode: Option<String>,
    /// Custody steps, as the panelist's own view works them out.
    pub custody: Vec<String>,
    /// Delivery as the panelist can tell from the records alone.
    pub delivery: Option<String>,
    /// Whether the courier's closing commits to the revealed code.
    pub code_matches: Check,
    /// Whether a revealed photo matches the drop note.
    pub photo_matches: Check,
    /// Whether the drop note's cell is the manifest's destination cell.
    pub cell_matches: Check,
    /// Every picture, side by side: the drop photo, the parties' pictures
    /// and public records.
    pub pictures: Vec<Picture>,
    pub exhibits: Vec<Exhibit>,
}

impl Node {
    /// Submit evidence about a subject, signed as `as_cred` (a credential
    /// this wallet holds that makes it a party) or a fresh one. The bytes
    /// go to the host at the next sync; a public note of their kind and
    /// hash is posted with them.
    pub fn submit_evidence(&mut self, subject: Hash, evidence: &Evidence, as_cred: Option<Credential>) -> Result<Hash, String> {
        let bytes = encode(evidence);
        if bytes.len() > MAX_EVIDENCE {
            return Err(format!("evidence over {MAX_EVIDENCE} bytes"));
        }
        let from = match as_cred {
            Some(c) if self.mine.contains(&c) => c,
            Some(_) => return Err("this wallet doesn't hold that credential".into()),
            None => self.fresh()?,
        };
        let sig = self.view.scheme().sign(&self.key, &from, &sealed_bytes(&subject, &bytes), None);
        let sealed = Sealed { subject, bytes, from: from.clone(), sig };
        let hash = sealed.hash();
        let note = BoardMsg::EvidenceNote { subject, kind: evidence.kind().into(), hash };
        let scope = self.town.jobs.scope;
        self.compose(&scope, &from, note.kind(), Some(subject), note.encode(), None)?;
        if self.hosts(&scope) {
            self.host_evidence(&sealed)?;
        } else {
            self.evidence_out.push(sealed);
            self.save()?;
        }
        Ok(hash)
    }

    /// Host: keep a submission, if it is signed and not too big.
    pub fn host_evidence(&mut self, sealed: &Sealed) -> Result<(), String> {
        if !self.hosts(&self.town.jobs.scope) {
            return Err("this node doesn't host the job board".into());
        }
        if sealed.bytes.len() > MAX_EVIDENCE || !sealed.verify(self.view.scheme()) {
            return Err("evidence isn't signed by its submitter".into());
        }
        let list = self.held_evidence.entry(sealed.subject).or_default();
        if !list.iter().any(|e| e == sealed) {
            list.push(sealed.clone());
        }
        self.save()
    }

    /// A request for a subject's evidence, signed with the credential this
    /// wallet was drawn onto a panel with, or opened a dispute about it with.
    pub fn ask_evidence(&self, subject: &Hash) -> Result<Ask, String> {
        let (ds, _) = self.disputes();
        let about: Vec<_> = ds.values().filter(|d| d.subject == *subject).collect();
        let cred = about
            .iter()
            .flat_map(|d| d.panel.iter().flatten().map(|(c, _)| c))
            .chain(about.iter().map(|d| &d.opener))
            .find(|c| self.mine.contains(*c))
            .cloned()
            .ok_or("this wallet isn't on a panel about that, and didn't open a dispute about it")?;
        Ok(self.ask_evidence_as(subject, &cred))
    }

    /// A request for a subject's evidence signed with `cred`, whatever it is.
    pub fn ask_evidence_as(&self, subject: &Hash, cred: &Credential) -> Ask {
        let epoch = self.epoch();
        let sig = self.view.scheme().sign(&self.key, cred, &ask_bytes(subject, epoch), None);
        Ask { subject: *subject, epoch, panelist: cred.clone(), sig }
    }

    /// Host: answer a panelist, and only a panelist.
    pub fn answer_evidence(&self, ask: &Ask) -> Result<Vec<Sealed>, String> {
        let now = self.epoch();
        if ask.epoch > now || ask.epoch + 1 < now {
            return Err("that request isn't current".into());
        }
        if !self.view.scheme().verify(&ask.panelist, &ask_bytes(&ask.subject, ask.epoch), None, &ask.sig) {
            return Err("that request isn't signed by its panelist".into());
        }
        let (ds, _) = self.disputes();
        let allowed = ds.values().filter(|d| d.subject == ask.subject).any(|d| d.opener == ask.panelist || d.panel.iter().flatten().any(|(c, _)| *c == ask.panelist));
        if !allowed {
            return Err("only a panel on a dispute about this, or its parties, see its evidence".into());
        }
        Ok(self.held_evidence.get(&ask.subject).cloned().unwrap_or_default())
    }

    /// The evidence notes posted about a subject: kind, hash and submitter.
    pub fn evidence_notes(&self, subject: &Hash) -> Vec<(String, Hash, Credential)> {
        let Ok(copy) = self.copy(&self.town.jobs.scope) else { return vec![] };
        copy.items()
            .into_iter()
            .filter_map(|i| match BoardMsg::decode(i.content) {
                Some(BoardMsg::EvidenceNote { subject: s, kind, hash }) if s == *subject && i.post.thread == Some(s) => Some((kind, hash, i.signer.clone())),
                _ => None,
            })
            .collect()
    }

    /// The records of a parcel's custody, from the town's issuance on.
    pub fn custody_records(&self, m: &Manifest) -> Vec<Record> {
        let mut state = m.parcel;
        let mut tail = vec![];
        while let Some(r) = self.view.spender(&state) {
            match r.op {
                Op::Retire { .. } => {
                    tail.push(r.clone());
                    break;
                }
                _ => state = r.output(0),
            }
        }
        let mut out = self.provenance(&state);
        out.extend(tail);
        out
    }

    /// Commit to an original about a subject with a fresh salt this wallet
    /// keeps. Returns the commitment.
    fn commit_original(&mut self, subject: &Hash, original: &[u8]) -> Hash {
        let mut salt = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        let c = photo_commitment(&salt, original);
        self.originals.insert(c, (*subject, salt, original.to_vec()));
        c
    }

    /// Courier: drop a parcel with a photo. The drop note commits to the
    /// original, metadata and provenance included; the wallet keeps it and
    /// its salt, and shows a panel a stripped copy unless it reveals more.
    pub fn drop_off_photo(&mut self, m: &Manifest, cell: &str, photo: &[u8]) -> Result<Hash, String> {
        let c = self.commit_original(&m.parcel, photo);
        let state = self.drop_off(m, cell, c)?;
        self.drop_photos.insert(m.parcel, c);
        self.save()?;
        Ok(state)
    }

    /// Submit a picture about a subject. With `redact`, what is shown is
    /// stripped of metadata and carries a commitment to the original, which
    /// this wallet keeps to reveal if it helps.
    pub fn submit_image(&mut self, subject: Hash, caption: &str, original: &[u8], redact: bool, as_cred: Option<Credential>) -> Result<Hash, String> {
        let (image, commitment) = if redact { (crate::media::strip_metadata(original), Some(self.commit_original(&subject, original))) } else { (original.to_vec(), None) };
        self.submit_evidence(subject, &Evidence::Image { caption: caption.into(), image, original: commitment }, as_cred)
    }

    /// Reveal the originals this wallet committed to about a subject.
    pub fn reveal_originals(&mut self, subject: &Hash, as_cred: Option<Credential>) -> Result<Vec<Hash>, String> {
        let mine: Vec<(Vec<u8>, Vec<u8>)> = self.originals.values().filter(|(s, _, _)| s == subject).map(|(_, salt, o)| (salt.clone(), o.clone())).collect();
        if mine.is_empty() {
            return Err("no originals about that".into());
        }
        mine.into_iter().map(|(salt, original)| self.submit_evidence(*subject, &Evidence::Original { salt, original }, as_cred.clone())).collect()
    }

    /// Everything this wallet can show about a parcel: its custody, the
    /// code if it shipped by code, the photo if it dropped it, and any
    /// statement. Submitted as `as_cred`, or a credential from the custody
    /// chain this wallet holds, so the panel sees which party it is.
    pub fn submit_parcel_evidence(&mut self, m: &Manifest, statement: Option<&str>) -> Result<Vec<Hash>, String> {
        let parties = self.parties(m);
        let as_cred = parties.iter().find(|c| self.mine.contains(*c)).cloned();
        let mut items = vec![Evidence::Custody { manifest: m.clone(), records: self.custody_records(m) }];
        if let Some(code) = self.codes.get(&m.parcel) {
            items.push(Evidence::Code { code: code.clone() });
        }
        if let Some((_, _, original)) = self.drop_photos.get(&m.parcel).and_then(|c| self.originals.get(c)) {
            let commitment = self.drop_photos[&m.parcel];
            items.push(Evidence::DropPhoto { image: crate::media::strip_metadata(original), commitment });
        }
        if let Some(t) = statement {
            items.push(Evidence::Statement { text: t.into() });
        }
        items.iter().map(|e| self.submit_evidence(m.parcel, e, as_cred.clone())).collect()
    }

    /// Panelist: examine a parcel's evidence. Custody records are applied
    /// to this wallet's own view and custody is worked out from them; codes
    /// and photos are checked against the records and the drop note.
    pub fn examine_parcel(&mut self, subject: &Hash, evidence: &[Sealed]) -> Examination {
        let s = self.view.scheme().clone();
        let good: Vec<(Credential, Evidence, Hash)> = evidence.iter().filter(|e| e.subject == *subject && e.verify(&s)).filter_map(|e| e.evidence().map(|ev| (e.from.clone(), ev, e.hash()))).collect();
        // Custody first: apply every record we can.
        let mut manifest: Option<Manifest> = None;
        for (_, ev, _) in &good {
            if let Evidence::Custody { manifest: m, records } = ev {
                if m.parcel != *subject {
                    continue;
                }
                for r in records {
                    let _ = apply_ok(&mut self.view, r);
                }
                manifest.get_or_insert_with(|| m.clone());
            }
        }
        let mut ex = Examination { subject: *subject, mode: None, custody: vec![], delivery: None, code_matches: Check::Unknown, photo_matches: Check::Unknown, cell_matches: Check::Unknown, pictures: vec![], exhibits: vec![] };
        let roles: BTreeMap<Credential, String> = match &manifest {
            Some(m) => self.roles(m),
            None => BTreeMap::new(),
        };
        if let Some(m) = &manifest {
            ex.mode = Some(format!("{:?}", m.mode));
            let c = self.custody(m);
            ex.custody = c
                .steps
                .iter()
                .map(|st| match st {
                    Step::Handoff { from, to } => format!("handoff {} → {}", roles.get(from).map_or("?", |s| s.as_str()), roles.get(to).map_or("?", |s| s.as_str())),
                    Step::Take { by } => format!("take by {}", roles.get(by).map_or("?", |s| s.as_str())),
                    Step::Retired { by } => format!("retired by {}", roles.get(by).map_or("?", |s| s.as_str())),
                    Step::Closed { by, .. } => format!("closed by {}", roles.get(by).map_or("?", |s| s.as_str())),
                })
                .collect();
            if c.delivered {
                ex.delivery = Some(format!("{:?}", Delivery::Delivered("signed")));
            }
            let closings: Vec<(Hash, u32)> = c.steps.iter().filter_map(|st| if let Step::Closed { receipt, hop, .. } = st { Some((*receipt, *hop)) } else { None }).collect();
            let h = m.hash();
            // Where the drop note says it was left, against where it was going.
            let note_cell = self.copy(&self.town.jobs.scope).ok().and_then(|copy| {
                copy.items().into_iter().find_map(|i| match BoardMsg::decode(i.content) {
                    Some(BoardMsg::Dropped { parcel, cell, photo }) if parcel == *subject && closings.iter().any(|(r, hop)| *r == crate::parcel::drop_receipt(&h, *hop, &cell, &photo)) => Some(cell),
                    _ => None,
                })
            });
            if let Some(cell) = note_cell {
                ex.cell_matches = if cell == m.to_cell { Check::Yes } else { Check::No };
            }
            for (_, ev, _) in &good {
                match ev {
                    Evidence::Code { code } if m.mode == Mode::Code => {
                        let hit = closings.iter().any(|(r, hop)| *r == code_receipt(&h, *hop, code));
                        if hit || ex.code_matches == Check::Unknown {
                            ex.code_matches = if hit { Check::Yes } else { Check::No };
                        }
                    }
                    Evidence::DropPhoto { commitment, .. } if matches!(m.mode, Mode::Drop { .. }) => {
                        let noted = self.copy(&self.town.jobs.scope).ok().is_some_and(|copy| {
                            copy.items().into_iter().any(|i| matches!(BoardMsg::decode(i.content), Some(BoardMsg::Dropped { parcel, photo: p, .. }) if parcel == *subject && p == *commitment))
                        });
                        if noted || ex.photo_matches == Check::Unknown {
                            ex.photo_matches = if noted { Check::Yes } else { Check::No };
                        }
                    }
                    _ => {}
                }
            }
        }
        let commits: Vec<Hash> = self
            .copy(&self.town.jobs.scope)
            .ok()
            .map(|copy| copy.items().into_iter().filter_map(|i| match BoardMsg::decode(i.content) {
                Some(BoardMsg::Dropped { parcel, photo, .. }) if parcel == *subject => Some(photo),
                _ => None,
            }).collect())
            .unwrap_or_default();
        let pic = |label: String, from: &str, committed: bool, url: Option<String>, bytes: &[u8], commitment: Option<Hash>| Picture {
            label,
            from: from.into(),
            committed_at_drop: committed,
            original: Check::Unknown,
            metadata: vec![],
            url,
            bytes: bytes.to_vec(),
            commitment,
        };
        for (from, ev, hash) in &good {
            let who = roles.get(from).cloned().unwrap_or_else(|| "not a party".into());
            let detail = match ev {
                Evidence::Statement { text } => text.clone(),
                Evidence::DropPhoto { image, .. } => format!("{} bytes as shown", image.len()),
                Evidence::Image { caption, image, .. } => format!("{caption} ({} bytes)", image.len()),
                Evidence::Original { original, .. } => format!("{} bytes; metadata: {}", original.len(), crate::media::metadata_kinds(original).join(", ")),
                Evidence::Reference { source, url, caption, image } => format!("{source}: {caption} <{url}> ({} bytes)", image.len()),
                Evidence::Custody { records, .. } => format!("{} records", records.len()),
                Evidence::Code { code } => code.clone(),
            };
            match ev {
                Evidence::DropPhoto { image, commitment } => ex.pictures.push(pic("drop photo".into(), &who, commits.contains(commitment), None, image, Some(*commitment))),
                Evidence::Image { caption, image, original } => ex.pictures.push(pic(caption.clone(), &who, false, None, image, *original)),
                Evidence::Reference { source, url, caption, image } => ex.pictures.push(pic(format!("{source}: {caption}"), &who, false, Some(url.clone()), image, None)),
                _ => {}
            }
            ex.exhibits.push(Exhibit { kind: ev.kind().into(), from: who, hash: *hash, detail });
        }
        // Originals last: each is checked against the commitment it claims to
        // open, and shown beside the picture it is the original of.
        for (from, ev, _) in &good {
            let Evidence::Original { salt, original } = ev else { continue };
            let who = roles.get(from).cloned().unwrap_or_else(|| "not a party".into());
            let c = photo_commitment(salt, original);
            let of = ex.pictures.iter_mut().find(|p| p.commitment == Some(c));
            let (label, committed, check) = match of {
                Some(p) => {
                    p.original = Check::Yes;
                    (format!("original of {}", p.label), p.committed_at_drop, Check::Yes)
                }
                None if commits.contains(&c) => ("original of the drop photo".into(), true, Check::Yes),
                None => ("an original that matches nothing shown".into(), false, Check::No),
            };
            let mut p = pic(label, &who, committed, None, original, Some(c));
            p.original = check;
            p.metadata = crate::media::metadata_kinds(original);
            ex.pictures.push(p);
        }
        ex
    }

    /// Each party's role in a parcel, by credential.
    fn roles(&self, m: &Manifest) -> BTreeMap<Credential, String> {
        let mut roles = BTreeMap::new();
        roles.insert(m.addressee.clone(), "addressee".to_string());
        let mut courier = 0;
        for (i, st) in self.custody(m).steps.iter().enumerate() {
            match st {
                Step::Handoff { from, to } => {
                    if i == 0 {
                        roles.entry(from.clone()).or_insert_with(|| "shipper".into());
                    }
                    if !roles.contains_key(to) {
                        courier += 1;
                        roles.insert(to.clone(), format!("courier {courier}"));
                    }
                }
                Step::Take { by } | Step::Closed { by, .. } | Step::Retired { by } => {
                    // A take's signer is the credential handed to; the next
                    // step is signed by the courier's fresh one.
                    let _ = by;
                }
            }
        }
        // Fresh credentials a courier took with sign its next step: name them
        // after the courier whose take produced them.
        let steps = self.custody(m).steps;
        for w in steps.windows(2) {
            if let (Step::Take { by }, next) = (&w[0], &w[1]) {
                let who = roles.get(by).cloned();
                let next_by = match next {
                    Step::Handoff { from, .. } => Some(from),
                    Step::Closed { by, .. } | Step::Retired { by } | Step::Take { by } => Some(by),
                };
                if let (Some(who), Some(n)) = (who, next_by) {
                    roles.entry(n.clone()).or_insert(who);
                }
            }
        }
        roles
    }

    /// The hash of everything a panelist was given about a subject, for
    /// its ruling to refer to.
    pub fn evidence_digest(evidence: &[Sealed]) -> Hash {
        hash_of("pave/evidence/digest", &evidence.iter().map(|e| e.hash()).collect::<Vec<_>>())
    }
}
