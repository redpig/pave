//! The board profile: posting to an online service with pave credentials.
//!
//! A board is a service someone hosts, such as a town's reports board or its
//! job board. Content goes straight to the host and lives there. Pave adds
//! two things: who may post, and a binding anyone can check.
//!
//! - **A post is a small record.** It is a kernel record in the board's
//!   scope whose body is a fixed binding: the post's kind, the thread it
//!   belongs to, the hash of its content, the epoch, and optionally an
//!   endorsement. The content itself is never in the record.
//! - **The signer is the author's key for that post.** It is a fresh
//!   credential, unlinkable to the author's others. The author signs later
//!   posts with the same key to act as the author: a poster accepting a
//!   worker, say. Hosts index posts by the hash of that key and by the
//!   content hash.
//! - **Endorsements count people.** An endorsement is a signature by a fresh
//!   randomization of the author's access credential, with (board, kind,
//!   thread) as basename. Its pseudonym is the same for one person on one
//!   thread and unrelated across threads, so a thread can count distinct
//!   people without learning who they are. It carries standing against the
//!   endorsements a profile has ruled out.
//! - **Identities are the author's choice.** A post may also carry a
//!   signature by one of the author's stable credentials over the binding.
//!   A wallet keeps one per privacy tier: one shared with a few people, one
//!   with its contacts, one public. Whoever was given that credential knows
//!   who posted; anyone else sees one unnamed author behind every post it
//!   signed. Without one, a post is as anonymous as its fresh key.
//! - **The host keeps time.** A post's epoch is the poster's word, so the
//!   host takes a post only in its current epoch or the one before. Windows
//!   that count from a post (a drop's dispute window, a dispute's offers)
//!   can't be backdated.
//! - **Receipts make dropping visible.** The host answers every accepted post
//!   with a signed receipt. If the host later omits the post, its author can
//!   show the receipt.
//! - **Copies are a choice.** Anyone holding a copy of a board can serve it,
//!   and a reader checks every record, every content hash and the host's
//!   receipt for every post, so a copy needn't be trusted: it can serve the
//!   board, and can't add to it. Wallets never carry posts when they meet: that path
//!   is for value, epochs and evidence.

use crate::node::{Class, Node, S};
use crate::pay::{prefix, Prefix};
use pave_kernel::hash::{encode, hash_bytes, hash_of, Hash};
use pave_kernel::{Applied, Credential, Genesis, Op, Record, Scheme, Sig, View};
use pave_protocol::{head, Standing};
use pave_scheme_briolette::BrioletteV1;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A (basename, pseudonym) pair: one endorsement, as on a ruled list.
pub type Cheat = (Vec<u8>, Vec<u8>);

/// Largest content a host takes for one post.
pub const MAX_CONTENT: usize = 64 * 1024;

/// What a member knows about one board: its scope, the host's credential,
/// and the credentials of the roles whose posts the profile gives weight.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardInfo {
    pub scope: Hash,
    pub host: Credential,
    pub roles: BTreeMap<String, Credential>,
}

impl BoardInfo {
    pub fn role(&self, name: &str) -> Option<&Credential> {
        self.roles.get(name)
    }
}

/// An author's anonymous endorsement of one post.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endorsement {
    /// A fresh randomization of the author's access credential.
    pub access: Credential,
    pub sig: Sig,
    /// Standing against every ruled endorsement the author knew of.
    pub standing: Standing,
}

/// A stable credential's signature over a post's binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub key: Credential,
    pub sig: Sig,
}

fn by_bytes(scope: &Hash, kind: &str, thread: &Option<Hash>, content: &Hash, epoch: u32) -> Vec<u8> {
    encode(&("pave/board/by/v0", scope, kind, thread, content, epoch))
}

/// The binding a post record carries in place of its content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Post {
    pub kind: String,
    /// The thread this post belongs to. None opens a thread named by the
    /// post's own record id.
    pub thread: Option<Hash>,
    pub content: Hash,
    pub epoch: u32,
    pub endorsement: Option<Endorsement>,
    /// One of the author's stable credentials, if it chose to sign with one.
    pub by: Option<Signed>,
}

impl Post {
    pub fn encode(&self) -> Vec<u8> {
        encode(self)
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        ciborium::from_reader(b).ok()
    }
}

pub fn content_hash(content: &[u8]) -> Hash {
    hash_bytes("pave/board/content", content)
}

/// How hosts index an author's key.
pub fn author(signer: &Credential) -> Hash {
    hash_of("pave/board/author", signer)
}

pub fn endorse_basename(scope: &Hash, kind: &str, thread: &Hash) -> Vec<u8> {
    encode(&("pave/board/endorse/v0", scope, kind, thread))
}

fn endorse_bytes(scope: &Hash, kind: &str, thread: &Hash, content: &Hash, epoch: u32, standing: &Standing) -> Vec<u8> {
    encode(&("pave/board/endorse/v0", scope, kind, thread, content, epoch, standing))
}

/// The class that endorsed `post`, and the endorser's pseudonym on its
/// thread, if the endorsement checks out.
pub fn endorser(classes: &BTreeMap<String, Class>, scope: &Hash, post: &Post) -> Option<(String, Vec<u8>)> {
    let e = post.endorsement.as_ref()?;
    let thread = post.thread?;
    let bsn = endorse_basename(scope, &post.kind, &thread);
    let msg = endorse_bytes(scope, &post.kind, &thread, &post.content, post.epoch, &e.standing);
    classes.iter().find_map(|(name, c)| {
        let s = BrioletteV1 { group_public_key: c.group_public_key.clone() };
        if s.verify(&e.access, &msg, Some(&bsn), &e.sig) && e.standing.credential == e.access && e.standing.verify(&s) {
            s.nym(&e.sig).map(|n| (name.clone(), n))
        } else {
            None
        }
    })
}

/// A post on its way to a host, or served from a copy: the record and its content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submission {
    pub record: Record,
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
    /// The host's receipt, once the host has taken it. Readers take a post
    /// from a copy only with this.
    #[serde(default)]
    pub taken: Option<PostReceipt>,
}

impl Submission {
    pub fn scope(&self) -> Option<Hash> {
        match &self.record.op {
            Op::Send { scope, .. } => Some(*scope),
            _ => None,
        }
    }
    pub fn post(&self) -> Option<Post> {
        match &self.record.op {
            Op::Send { body, .. } => Post::decode(body),
            _ => None,
        }
    }
}

/// The host's signed word that it took a post.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostReceipt {
    pub scope: Hash,
    pub post: Hash,
    pub content: Hash,
    pub sig: Sig,
}

fn receipt_bytes(scope: &Hash, post: &Hash, content: &Hash) -> Vec<u8> {
    encode(&("pave/board/receipt/v0", scope, post, content))
}

impl PostReceipt {
    pub fn verify(&self, s: &S, host: &Credential) -> bool {
        s.verify(host, &receipt_bytes(&self.scope, &self.post, &self.content), None, &self.sig)
    }
}

/// One checked post with its content.
pub struct Item<'a> {
    pub id: Hash,
    pub signer: &'a Credential,
    pub post: Post,
    pub content: &'a [u8],
    /// The stable credential that signed this post's binding, if its
    /// signature checks out.
    pub by: Option<Credential>,
}

impl Item<'_> {
    /// The thread this post is in: its own id if it opened one.
    pub fn thread(&self) -> Hash {
        self.post.thread.unwrap_or(self.id)
    }
}

/// A copy of one board: its records, checked, and their content.
pub struct Copy {
    pub info: BoardInfo,
    view: View<S>,
    content: BTreeMap<Hash, Vec<u8>>,
    /// The host's receipt for every post.
    taken: BTreeMap<Hash, PostReceipt>,
    /// Receipts for this node's own posts.
    pub receipts: BTreeMap<Hash, PostReceipt>,
}

impl Copy {
    /// An empty copy, from the record that created the board's scope.
    pub fn new(info: BoardInfo, scheme: S, genesis: Genesis, create: &Record) -> Result<Copy, String> {
        let mut view = View::new(scheme, genesis);
        match view.apply(create) {
            Ok(Applied::Accepted) | Ok(Applied::Duplicate) => {}
            other => return Err(format!("board scope: {other:?}")),
        }
        if create.output(0) != info.scope {
            return Err("that record doesn't create this board".into());
        }
        Ok(Copy { info, view, content: BTreeMap::new(), taken: BTreeMap::new(), receipts: BTreeMap::new() })
    }

    /// Check a post and keep it: a validly signed record in this board's
    /// scope, with a binding, and content matching it. Returns whether it
    /// was new.
    pub fn absorb(&mut self, sub: &Submission) -> Result<bool, String> {
        let r = sub.taken.as_ref().ok_or("no receipt from the host")?;
        if r.scope != self.info.scope || r.post != sub.record.id() || r.content != content_hash(&sub.content) || !r.verify(self.view.scheme(), &self.info.host) {
            return Err("that receipt isn't the host's for this post".into());
        }
        let new = self.take(sub)?;
        self.taken.insert(r.post, r.clone());
        Ok(new)
    }

    /// Check a post and keep it, without a receipt: the host's own intake.
    fn take(&mut self, sub: &Submission) -> Result<bool, String> {
        if sub.scope() != Some(self.info.scope) {
            return Err("not a post on this board".into());
        }
        let post = sub.post().ok_or("no binding in the record")?;
        if sub.content.len() > MAX_CONTENT {
            return Err(format!("content over {MAX_CONTENT} bytes"));
        }
        if content_hash(&sub.content) != post.content {
            return Err("content doesn't match its hash".into());
        }
        match self.view.apply(&sub.record) {
            Ok(Applied::Accepted) => {
                self.content.insert(sub.record.id(), sub.content.clone());
                Ok(true)
            }
            Ok(Applied::Duplicate) => Ok(false),
            other => Err(format!("{other:?}")),
        }
    }

    /// Every post with its content, in the order this copy took them.
    pub fn items(&self) -> Vec<Item<'_>> {
        self.view
            .messages()
            .iter()
            .filter_map(|r| {
                let id = r.id();
                let content = self.content.get(&id)?;
                let Op::Send { body, .. } = &r.op else {
                    return None;
                };
                let post = Post::decode(body)?;
                let scope = self.info.scope;
                let by = post.by.as_ref().filter(|b| self.view.scheme().verify(&b.key, &by_bytes(&scope, &post.kind, &post.thread, &post.content, post.epoch), None, &b.sig)).map(|b| b.key.clone());
                Some(Item { id, signer: &r.signer, post, content, by })
            })
            .collect()
    }

    pub fn scheme(&self) -> &S {
        self.view.scheme()
    }

    pub fn have(&self) -> BTreeSet<Prefix> {
        self.view.messages().iter().map(|r| prefix(&r.id())).collect()
    }

    /// The posts a reader lacks, given what it has.
    pub fn since(&self, have: &BTreeSet<Prefix>) -> Vec<Submission> {
        self.view.messages().iter().filter(|r| !have.contains(&prefix(&r.id()))).filter_map(|r| self.content.get(&r.id()).map(|c| Submission { record: r.clone(), content: c.clone(), taken: self.taken.get(&r.id()).cloned() })).collect()
    }

    pub fn submissions(&self) -> Vec<Submission> {
        self.since(&BTreeSet::new())
    }

    /// Posts whose author key hashes to `author`.
    pub fn by_author(&self, a: &Hash) -> Vec<Hash> {
        self.items().into_iter().filter(|i| author(i.signer) == *a).map(|i| i.id).collect()
    }

    /// Posts whose content hashes to `content`.
    pub fn by_content(&self, c: &Hash) -> Vec<Hash> {
        self.items().into_iter().filter(|i| i.post.content == *c).map(|i| i.id).collect()
    }
}

impl Node {
    /// The boards this town runs.
    pub fn board_infos(&self) -> Vec<BoardInfo> {
        vec![self.town.jobs.clone(), self.town.reports.clone()]
    }

    pub fn copy(&self, scope: &Hash) -> Result<&Copy, String> {
        self.boards.get(scope).ok_or_else(|| "no copy of that board".into())
    }

    /// Open an empty copy of each of the town's boards this node lacks.
    pub(crate) fn open_boards(&mut self) -> Result<(), String> {
        for info in self.board_infos() {
            if self.boards.contains_key(&info.scope) {
                continue;
            }
            let create = self.view.records().iter().find(|r| matches!(r.op, Op::CreateScope { .. }) && r.output(0) == info.scope).ok_or("the board's scope record is missing")?.clone();
            let copy = Copy::new(info.clone(), self.view.scheme().clone(), self.town.genesis.clone(), &create)?;
            self.boards.insert(info.scope, copy);
        }
        Ok(())
    }

    /// The latest epoch this wallet knows.
    pub fn epoch(&self) -> u32 {
        head(&self.view, &self.town.sequence).map_or(0, |h| h.number)
    }

    /// Sign a post. A host takes its own posts at once; anyone else queues
    /// them for the host, to go out at the next sync. With `endorse`, the
    /// post carries an endorsement with standing against that list.
    /// Returns the post's record id.
    pub fn compose(&mut self, scope: &Hash, signer: &Credential, kind: &str, thread: Option<Hash>, content: Vec<u8>, endorse: Option<&[Cheat]>) -> Result<Hash, String> {
        self.compose_as(scope, signer, kind, thread, content, endorse, None)
    }

    /// As [`Node::compose`], also signed with this wallet's identity
    /// `identity` (see [`Node::identity`]) when given.
    #[allow(clippy::too_many_arguments)]
    pub fn compose_as(&mut self, scope: &Hash, signer: &Credential, kind: &str, thread: Option<Hash>, content: Vec<u8>, endorse: Option<&[Cheat]>, identity: Option<&str>) -> Result<Hash, String> {
        if content.len() > MAX_CONTENT {
            return Err(format!("content over {MAX_CONTENT} bytes"));
        }
        let epoch = self.epoch();
        let ch = content_hash(&content);
        let endorsement = match endorse {
            None => None,
            Some(list) => {
                let thread = thread.ok_or("an endorsed post needs a thread")?;
                let a = BrioletteV1 { group_public_key: self.town.classes[&self.class].group_public_key.clone() };
                let access = a.credential(&self.access);
                let standing = Standing::prove(&a, &self.access, &access, list).ok_or("this wallet's endorsements were ruled out")?;
                let sig = a.sign(&self.access, &access, &endorse_bytes(scope, kind, &thread, &ch, epoch, &standing), Some(&endorse_basename(scope, kind, &thread)));
                Some(Endorsement { access, sig, standing })
            }
        };
        let by = match identity {
            Some(label) => {
                let key = self.identity(label)?;
                let sig = self.view.scheme().sign(&self.key, &key, &by_bytes(scope, kind, &thread, &ch, epoch), None);
                Some(Signed { key, sig })
            }
            None => None,
        };
        let post = Post { kind: kind.into(), thread, content: ch, epoch, endorsement, by };
        let record = pave_kernel::sign(self.view.scheme(), &self.key, signer, Op::Send { scope: *scope, presenting: None, body: post.encode(), receipt: ch });
        let id = record.id();
        let sub = Submission { record, content, taken: None };
        if self.hosts(scope) {
            let r = self.host_post(&sub)?;
            self.posted(&sub, &r)?;
        } else {
            self.outgoing.push(sub);
            self.save()?;
        }
        Ok(id)
    }

    /// Whether this node hosts `scope`. In the prototype the town operator
    /// hosts every town board.
    pub fn hosts(&self, scope: &Hash) -> bool {
        self.operator.is_some() && self.boards.contains_key(scope)
    }

    /// Host: take a post, keep it with its content, and sign a receipt.
    pub fn host_post(&mut self, sub: &Submission) -> Result<PostReceipt, String> {
        let scope = sub.scope().ok_or("not a post")?;
        if !self.hosts(&scope) {
            return Err("this node doesn't host that board".into());
        }
        let post = sub.post().ok_or("no binding in the record")?;
        // The host keeps time for its board: a post's epoch is the poster's
        // word, so it must be the host's current epoch or the one before.
        let now = self.epoch();
        if post.epoch > now || post.epoch + 1 < now {
            return Err(format!("post epoch {} isn't current (the board is at {now})", post.epoch));
        }
        if post.endorsement.is_some() && endorser(&self.town.classes, &scope, &post).is_none() {
            return Err("endorsement doesn't check out".into());
        }
        let host = self.boards[&scope].info.host.clone();
        let (post_id, content) = (sub.record.id(), post.content);
        let sig = self.view.scheme().sign(&self.key, &host, &receipt_bytes(&scope, &post_id, &content), None);
        let receipt = PostReceipt { scope, post: post_id, content, sig };
        let copy = self.boards.get_mut(&scope).unwrap();
        copy.take(sub)?;
        copy.taken.insert(post_id, receipt.clone());
        self.save()?;
        Ok(receipt)
    }

    /// Author: the host took a post. Check its receipt, keep the post in
    /// this node's copy and drop it from the queue.
    pub fn posted(&mut self, sub: &Submission, r: &PostReceipt) -> Result<(), String> {
        let scope = sub.scope().ok_or("not a post")?;
        let s = self.view.scheme().clone();
        let copy = self.boards.get_mut(&scope).ok_or("no copy of that board")?;
        if r.scope != scope || r.post != sub.record.id() || r.content != content_hash(&sub.content) || !r.verify(&s, &copy.info.host) {
            return Err("that receipt isn't the host's for this post".into());
        }
        copy.absorb(&Submission { taken: Some(r.clone()), ..sub.clone() })?;
        copy.receipts.insert(r.post, r.clone());
        self.outgoing.retain(|o| o.record.id() != r.post);
        self.save()
    }

    /// The host refused a queued post: drop it.
    pub fn refused(&mut self, sub: &Submission) -> Result<(), String> {
        let id = sub.record.id();
        self.outgoing.retain(|o| o.record.id() != id);
        self.save()
    }

    pub fn board_have(&self, scope: &Hash) -> BTreeSet<Prefix> {
        self.boards.get(scope).map(Copy::have).unwrap_or_default()
    }

    /// Serve a reader from this node's copy.
    pub fn posts_since(&self, scope: &Hash, have: &BTreeSet<Prefix>) -> Vec<Submission> {
        self.boards.get(scope).map(|c| c.since(have)).unwrap_or_default()
    }

    /// Take posts from a host or another copy. Each is checked; bad ones are
    /// dropped. Returns how many were new.
    pub fn absorb_posts(&mut self, scope: &Hash, posts: &[Submission]) -> usize {
        let Some(copy) = self.boards.get_mut(scope) else {
            return 0;
        };
        let n = posts.iter().filter(|p| copy.absorb(p) == Ok(true)).count();
        if n > 0 {
            let _ = self.save();
        }
        n
    }
}

/// What syncing with a host did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Synced {
    pub sent: usize,
    pub refused: Vec<String>,
    pub received: usize,
}

impl Node {
    /// Sync with a host in process, as [`crate::net::sync_boards`] does over
    /// the network: send queued posts, then fetch what this node lacks.
    pub fn sync_with(&mut self, host: &mut Node) -> Synced {
        let mut out = Synced::default();
        for sub in self.outgoing.clone() {
            match host.host_post(&sub) {
                Ok(r) => {
                    if self.posted(&sub, &r).is_ok() {
                        out.sent += 1;
                    }
                }
                Err(e) => {
                    let _ = self.refused(&sub);
                    out.refused.push(e);
                }
            }
        }
        for info in self.board_infos() {
            let posts = host.posts_since(&info.scope, &self.board_have(&info.scope));
            out.received += self.absorb_posts(&info.scope, &posts);
        }
        out
    }
}
