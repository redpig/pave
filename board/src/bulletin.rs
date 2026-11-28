//! The board profile: posting to an online service with pave credentials.
//!
//! A board is a service someone hosts, such as a town's reports board or its
//! job board. Content goes straight to a board server and lives there. Pave
//! adds who may post, and a binding anyone can check, from parts the town
//! already has:
//!
//! - **A board mint is a clerk.** It holds a capability to issue post
//!   tokens, derived from the town's root. A wallet asks it for tokens the
//!   way it asks for tickets: anonymously, signed with a fresh randomization
//!   of its access credential, with (sequence, epoch, slot) as basename, so
//!   a wallet's first few requests an epoch can't be linked to each other
//!   and later ones are linked to earlier ones (see [`crate::slots`]); the
//!   mint learns nothing else. The mint issues a ticket
//!   for each credential and mints one token to it.
//! - **A post spends a token.** It is a `Transfer` of the token to a board
//!   server, signed by the credential holding it, whose receipt is the hash
//!   of the post's binding: the board, the post's kind and thread, the hash
//!   of its content, a prior post, and the epoch and wall clock the board
//!   proposed. The content is never in the record. Using one token twice is
//!   a double spend like any other, so a post can't be counted twice even by
//!   board servers that never talk to each other.
//! - **Most wallets won't take a token; board servers will.** A token is a
//!   capability under its own schema. Ordinary wallets don't accept it, and
//!   any board server that trusts the mint does, so one mint can serve many
//!   boards and a board can add servers.
//! - **A server takes a post by retiring its token.** It runs the ordinary
//!   acceptance check (a trusted clerk's ticket, in date, not revoked) and
//!   then retires the token. The retire is its signed word that it took the
//!   post: the author can show it if the post later goes missing, and a copy
//!   can't add a post the server never took.
//! - **The signer is the author's key for that post.** A wallet asks for a
//!   token for whichever credential it wants to post as, and signs later
//!   posts with the same key to act as the author: a poster accepting a
//!   worker, say. Servers index posts by the hash of that key and by the
//!   content hash. A post's name, which threads and replies use, is fixed
//!   when it is written: its binding without the epoch and clock, plus its
//!   signer.
//! - **Counting people is a ticket's tag.** For a post that should count one
//!   person once (a report on one issue), the token request is also signed
//!   with the purpose as basename. The pseudonym is the same for one person
//!   and one purpose and unrelated across purposes; the mint puts it and the
//!   class in the ticket's tag, so readers count distinct tags.
//! - **Rulings use the same tools.** A ruled post's tag goes on the mint's
//!   list: every later token request needs standing against it, which the
//!   ruled person can't produce and nobody else is affected by. Its ticket
//!   group is revoked at the next roll, which stops its other tokens.
//! - **Identities are the author's choice.** A post may also carry a
//!   signature by one of the author's stable credentials over the binding.
//!   A wallet keeps one per privacy tier: one shared with a few people, one
//!   with its contacts, one public. Whoever was given that credential knows
//!   who posted; anyone else sees one unnamed author behind every post it
//!   signed. Without one, a post is as anonymous as its fresh key.
//! - **Copies are a choice.** Anyone holding a copy of a board can serve it,
//!   and a reader checks every record, every content hash and the server's
//!   retire for every post, so a copy needn't be trusted. Wallets never carry
//!   posts when they meet: that path is for value, epochs and evidence.

use crate::node::{apply_ok, Node, S};
use crate::pay::{prefix, Prefix};
use pave_kernel::hash::{encode, hash_bytes, hash_of, Hash};
use pave_kernel::{Applied, Credential, Genesis, Kind, Op, Record, Schema, Scheme, Sig, View};
use pave_protocol::{cheat_list, head, Policy, SignedTicket, Standing, Tag};
use pave_scheme_briolette::BrioletteV1;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A (basename, pseudonym) pair, as on a ruled list.
pub type Cheat = (Vec<u8>, Vec<u8>);

/// Largest content a server takes for one post.
pub const MAX_CONTENT: usize = 64 * 1024;
/// Most credentials in one token request.
pub const MAX_TOKENS: usize = 16;
/// Token requests a wallet makes per epoch that can't be linked to each
/// other. More are served, each linked to an earlier one (see [`crate::slots`]).
pub const TOKEN_SLOTS: u32 = 8;
/// How far a post's clock may be from the server's when it arrives, in
/// seconds: the clock is the one the server proposed for it.
pub const CLOCK_SLACK: u64 = 600;

/// The post token schema: one post each, not passed on.
pub fn post_schema() -> Schema {
    Schema {
        label: "board post token".into(),
        divisible: false,
        soft_expiry: Some(4),
        hard_expiry: Some(8),
        offline_transfers: Some(1),
        max_per_holder: Some(1),
        sequence: None,
    }
}

/// What a member knows about one board: its scope (the board's name), the
/// server's credential, and the credentials of the roles whose posts the
/// profile gives weight.
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

/// A stable credential's signature over a post's binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub key: Credential,
    pub sig: Sig,
}

fn by_bytes(board: &Hash, kind: &str, thread: &Option<Hash>, content: &Hash) -> Vec<u8> {
    encode(&("pave/board/by/v1", board, kind, thread, content))
}

/// A post's binding: what its token's transfer commits to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Post {
    pub board: Hash,
    pub kind: String,
    /// The thread this post belongs to. None opens a thread named by the
    /// post's own name.
    pub thread: Option<Hash>,
    pub content: Hash,
    /// Makes two otherwise identical posts by one key distinct.
    pub nonce: [u8; 16],
    /// Any post the author knew of on this board, by name.
    pub prior: Option<Hash>,
    /// The epoch and wall clock (seconds) the server proposed.
    pub epoch: u32,
    pub clock: u64,
    /// One of the author's stable credentials, if it chose to sign with one.
    pub by: Option<Signed>,
}

impl Post {
    /// The hash the token's transfer carries as its receipt.
    pub fn receipt(&self) -> Hash {
        hash_of("pave/board/post/v1", self)
    }
    /// The post's name: fixed when written, before a server proposes the
    /// epoch and clock.
    pub fn name(&self, signer: &Credential) -> Hash {
        name(
            &self.board,
            &self.kind,
            &self.thread,
            &self.content,
            &self.nonce,
            signer,
        )
    }
}

fn name(
    board: &Hash,
    kind: &str,
    thread: &Option<Hash>,
    content: &Hash,
    nonce: &[u8; 16],
    signer: &Credential,
) -> Hash {
    hash_of(
        "pave/board/name/v1",
        &(board, kind, thread, content, nonce, signer),
    )
}

pub fn content_hash(content: &[u8]) -> Hash {
    hash_bytes("pave/board/content", content)
}

/// How servers index an author's key.
pub fn author(signer: &Credential) -> Hash {
    hash_of("pave/board/author", signer)
}

/// The purpose for counting one person once per (board, kind, thread).
pub fn purpose(board: &Hash, kind: &str, thread: &Hash) -> Hash {
    hash_of("pave/board/purpose/v1", &(board, kind, thread))
}

/// The basename a token request is signed with to show its purpose.
pub fn count_basename(purpose: &Hash) -> Vec<u8> {
    encode(&("pave/board/count/v1", purpose))
}

/// A post written and waiting for a server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Draft {
    pub board: Hash,
    pub signer: Credential,
    pub kind: String,
    pub thread: Option<Hash>,
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
    pub nonce: [u8; 16],
    /// Count the author once for this purpose.
    pub count: Option<Hash>,
    /// Sign with this identity tier.
    pub identity: Option<String>,
}

impl Draft {
    pub fn name(&self) -> Hash {
        name(
            &self.board,
            &self.kind,
            &self.thread,
            &content_hash(&self.content),
            &self.nonce,
            &self.signer,
        )
    }
}

/// A post on its way to a server, or served from a copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submission {
    /// The token's transfer to the server.
    pub record: Record,
    pub post: Post,
    #[serde(with = "serde_bytes")]
    pub content: Vec<u8>,
    /// The token's history from the mint's budget, in order.
    pub provenance: Vec<Record>,
    /// The signer's ticket.
    pub ticket: Option<SignedTicket>,
    /// The server's retire of the token, once it took the post. Readers
    /// take a post from a copy only with this.
    #[serde(default)]
    pub taken: Option<Record>,
}

impl Submission {
    pub fn scope(&self) -> Hash {
        self.post.board
    }
    pub fn name(&self) -> Hash {
        self.post.name(&self.record.signer)
    }
}

/// A server's proposal for posts sent now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Clock {
    pub epoch: u32,
    pub clock: u64,
}

/// What the mint asks of a token request this epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenTerms {
    pub epoch: u32,
    /// Every double spender the mint knows of: each credential needs standing against them.
    pub cheats: Vec<Cheat>,
    /// Every ruled tag: the access credential needs standing against them.
    pub ruled: Vec<Cheat>,
}

/// An anonymous token request.
pub type TokenRequest = crate::request::Request<TokenBody>;

/// What a token request asks for.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenBody {
    /// The credentials to post as, one token each (repeat one for more).
    pub creds: Vec<Credential>,
    pub standing: Vec<Standing>,
    /// Count the holder once for this purpose: then the request is also
    /// signed under the purpose's basename.
    pub purpose: Option<Hash>,
}

/// The mint's answer: a ticket per credential, and the budget and mints.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenGrant {
    pub tickets: Vec<SignedTicket>,
    pub records: Vec<Record>,
}

/// A board server, in process or over the network.
pub trait Host {
    fn clock(&mut self, board: &Hash) -> Result<Clock, String>;
    fn terms(&mut self) -> Result<TokenTerms, String>;
    fn tokens(&mut self, req: &TokenRequest) -> Result<TokenGrant, String>;
    /// Take a post; the answer is the server's retire of its token.
    fn post(&mut self, sub: &Submission) -> Result<Record, String>;
}

/// One checked post with its content.
pub struct Item<'a> {
    /// The post's name.
    pub id: Hash,
    pub signer: &'a Credential,
    pub post: &'a Post,
    pub content: &'a [u8],
    /// The stable credential that signed this post's binding, if its
    /// signature checks out.
    pub by: Option<Credential>,
    /// The signer's ticket tag, if its ticket carried one.
    pub tag: Option<&'a Tag>,
}

impl Item<'_> {
    /// The thread this post is in: its own name if it opened one.
    pub fn thread(&self) -> Hash {
        self.post.thread.unwrap_or(self.id)
    }
    /// The author's class and pseudonym for `purpose`, if the post counts one
    /// person for it.
    pub fn counted(&self, purpose: &Hash) -> Option<(String, Vec<u8>)> {
        self.tag
            .filter(|t| &t.purpose == purpose)
            .map(|t| (t.class.clone(), t.nym.clone()))
    }
    /// The ruled-list entry that would rule this post's author out.
    pub fn cheat(&self) -> Option<Cheat> {
        self.tag
            .map(|t| (count_basename(&t.purpose), t.nym.clone()))
    }
}

/// A copy of one board: its records, checked, and their content.
pub struct Copy {
    pub info: BoardInfo,
    view: View<S>,
    clerk: Credential,
    schema: Hash,
    mint: Hash,
    subs: BTreeMap<Hash, Submission>,
    order: Vec<Hash>,
}

impl Copy {
    /// An empty copy, given the record deriving the mint's capability, the
    /// token schema and the clerk whose tickets count.
    pub fn new(
        info: BoardInfo,
        scheme: S,
        genesis: Genesis,
        mint: &Record,
        schema: Hash,
        clerk: Credential,
    ) -> Result<Copy, String> {
        let mut view = View::new(scheme, genesis);
        apply_ok(&mut view, mint).map_err(|e| format!("board mint: {e}"))?;
        Ok(Copy {
            info,
            view,
            clerk,
            schema,
            mint: mint.output(0),
            subs: BTreeMap::new(),
            order: vec![],
        })
    }

    /// Check a post and keep it: a token from the mint, transferred to this
    /// board's server with the post's binding as receipt, and retired by the
    /// server, with content matching. Returns whether it was new.
    pub fn absorb(&mut self, sub: &Submission) -> Result<bool, String> {
        let id = sub.name();
        if self.subs.contains_key(&id) {
            return Ok(false);
        }
        if sub.post.board != self.info.scope {
            return Err("not a post on this board".into());
        }
        if sub.content.len() > MAX_CONTENT {
            return Err(format!("content over {MAX_CONTENT} bytes"));
        }
        if content_hash(&sub.content) != sub.post.content {
            return Err("content doesn't match its hash".into());
        }
        let Op::Transfer { state, to, receipt } = &sub.record.op else {
            return Err("a post is a token's transfer".into());
        };
        if to != &self.info.host || *receipt != sub.post.receipt() {
            return Err("the token isn't sent to this board's server with this post".into());
        }
        let taken = sub.taken.as_ref().ok_or("the server hasn't taken it")?;
        if taken.signer != self.info.host
            || taken.op
                != (Op::Retire {
                    state: sub.record.output(0),
                })
        {
            return Err("that isn't the server's retire of this post's token".into());
        }
        for r in &sub.provenance {
            if let Op::IssueBudget { authority, .. } = &r.op {
                if *authority != self.mint {
                    return Err("a token from another mint".into());
                }
            }
            apply_ok(&mut self.view, r)?;
        }
        let coin = self
            .view
            .coin(state)
            .ok_or("the token's history is missing")?;
        if coin.schema != self.schema || coin.kind != Kind::Value {
            return Err("not a post token".into());
        }
        match self.view.apply(&sub.record) {
            Ok(Applied::Accepted) => {}
            Ok(Applied::Duplicate) => return Ok(false),
            other => return Err(format!("{other:?}")),
        }
        apply_ok(&mut self.view, taken)?;
        let s = self.view.scheme();
        let ticket = sub.ticket.clone().filter(|t| {
            t.clerk == self.clerk && t.ticket.credential == sub.record.signer && t.verify(s)
        });
        self.subs.insert(
            id,
            Submission {
                ticket,
                ..sub.clone()
            },
        );
        self.order.push(id);
        Ok(true)
    }

    /// Every post with its content, in the order this copy took them.
    pub fn items(&self) -> Vec<Item<'_>> {
        let s = self.view.scheme();
        self.order
            .iter()
            .map(|id| {
                let sub = &self.subs[id];
                let p = &sub.post;
                let by =
                    p.by.as_ref()
                        .filter(|b| {
                            s.verify(
                                &b.key,
                                &by_bytes(&p.board, &p.kind, &p.thread, &p.content),
                                None,
                                &b.sig,
                            )
                        })
                        .map(|b| b.key.clone());
                Item {
                    id: *id,
                    signer: &sub.record.signer,
                    post: p,
                    content: &sub.content,
                    by,
                    tag: sub.ticket.as_ref().and_then(|t| t.ticket.tag.as_ref()),
                }
            })
            .collect()
    }

    pub fn scheme(&self) -> &S {
        self.view.scheme()
    }

    pub fn latest(&self) -> Option<Hash> {
        self.order.last().copied()
    }

    /// The signer's ticket for a post, if it came with it and checks out.
    pub fn ticket(&self, post: &Hash) -> Option<&SignedTicket> {
        self.subs.get(post)?.ticket.as_ref()
    }

    /// The ticket group of a post's signer, if its ticket came with it.
    pub fn group(&self, post: &Hash) -> Option<u32> {
        self.subs.get(post)?.ticket.as_ref().map(|t| t.ticket.group)
    }

    pub fn have(&self) -> BTreeSet<Prefix> {
        self.order.iter().map(prefix).collect()
    }

    /// The posts a reader lacks, given what it has.
    pub fn since(&self, have: &BTreeSet<Prefix>) -> Vec<Submission> {
        self.order
            .iter()
            .filter(|id| !have.contains(&prefix(id)))
            .map(|id| self.subs[id].clone())
            .collect()
    }

    pub fn submissions(&self) -> Vec<Submission> {
        self.since(&BTreeSet::new())
    }

    /// Posts whose author key hashes to `author`.
    pub fn by_author(&self, a: &Hash) -> Vec<Hash> {
        self.items()
            .into_iter()
            .filter(|i| author(i.signer) == *a)
            .map(|i| i.id)
            .collect()
    }

    /// Posts whose content hashes to `content`.
    pub fn by_content(&self, c: &Hash) -> Vec<Hash> {
        self.items()
            .into_iter()
            .filter(|i| i.post.content == *c)
            .map(|i| i.id)
            .collect()
    }
}

/// Seconds since 1970, as a server keeps its clock.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Node {
    /// The boards this town runs.
    pub fn board_infos(&self) -> Vec<BoardInfo> {
        vec![self.town.jobs.clone(), self.town.reports.clone()]
    }

    pub fn copy(&self, scope: &Hash) -> Result<&Copy, String> {
        self.boards
            .get(scope)
            .ok_or_else(|| "no copy of that board".into())
    }

    /// Open an empty copy of each of the town's boards this node lacks.
    pub(crate) fn open_boards(&mut self) -> Result<(), String> {
        for info in self.board_infos() {
            if !self.boards.contains_key(&info.scope) {
                let copy = Copy::new(
                    info.clone(),
                    self.view.scheme().clone(),
                    self.town.genesis.clone(),
                    &self.town.post_mint,
                    self.town.posts,
                    self.town.clerk.clone(),
                )?;
                self.boards.insert(info.scope, copy);
            }
        }
        Ok(())
    }

    /// The latest epoch this wallet knows.
    pub fn epoch(&self) -> u32 {
        head(&self.view, &self.town.sequence).map_or(0, |h| h.number)
    }

    /// Write a post as `signer`. It waits for the next sync with a server;
    /// a node that serves the board takes it at once. Returns its name.
    pub fn compose(
        &mut self,
        scope: &Hash,
        signer: &Credential,
        kind: &str,
        thread: Option<Hash>,
        content: Vec<u8>,
        count: Option<Hash>,
    ) -> Result<Hash, String> {
        self.compose_as(scope, signer, kind, thread, content, count, None)
    }

    /// As [`Node::compose`], also signed with this wallet's identity
    /// `identity` (see [`Node::identity`]) when given.
    #[allow(clippy::too_many_arguments)]
    pub fn compose_as(
        &mut self,
        scope: &Hash,
        signer: &Credential,
        kind: &str,
        thread: Option<Hash>,
        content: Vec<u8>,
        count: Option<Hash>,
        identity: Option<&str>,
    ) -> Result<Hash, String> {
        if content.len() > MAX_CONTENT {
            return Err(format!("content over {MAX_CONTENT} bytes"));
        }
        if let Some(label) = identity {
            self.identity(label)?;
        }
        // A key holds one ticket. Posting would put a post ticket on it,
        // replacing a badge or shift ticket from another clerk.
        if self
            .know
            .tickets
            .get(signer)
            .is_some_and(|t| t.clerk != self.town.clerk)
        {
            return Err("this key carries another clerk's ticket (a badge or shift); post under another key".into());
        }
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let d = Draft {
            board: *scope,
            signer: signer.clone(),
            kind: kind.into(),
            thread,
            content,
            nonce,
            count,
            identity: identity.map(String::from),
        };
        let id = d.name();
        self.outgoing.push(d);
        self.save()?;
        if self.hosts(scope) {
            self.post_own()?;
        }
        Ok(id)
    }

    /// Whether this node serves `scope`. In the prototype the town operator
    /// serves every town board and runs the mint.
    pub fn hosts(&self, scope: &Hash) -> bool {
        self.operator.is_some() && self.boards.contains_key(scope)
    }

    /// Server and mint: post this node's own drafts at once.
    fn post_own(&mut self) -> Result<(), String> {
        let drafts = std::mem::take(&mut self.outgoing);
        for d in &drafts {
            let tag = match d.count {
                Some(p) => Some(Tag {
                    purpose: p,
                    nym: self.own_nym(&p),
                    class: self.class.clone(),
                }),
                None => None,
            };
            let class = self.class.clone();
            let grant = self.mint_tokens(std::slice::from_ref(&d.signer), &class, tag)?;
            self.take_grant(grant)?;
            let clock = self.board_clock(&d.board)?;
            let sub = self.sign_post(d, &clock)?;
            let r = self.host_post(&sub)?;
            self.posted(&sub, &r)?;
        }
        Ok(())
    }

    /// The mint's own pseudonym for `purpose`, as its access credential
    /// would show it.
    fn own_nym(&self, purpose: &Hash) -> Vec<u8> {
        let a = BrioletteV1 {
            group_public_key: self.town.classes[&self.class].group_public_key.clone(),
        };
        let access = a.credential(&self.access);
        let sig = a.sign(
            &self.access,
            &access,
            b"pave/board/own",
            Some(&count_basename(purpose)),
        );
        a.nym(&sig).unwrap_or_default()
    }

    /// Server: the epoch and clock it proposes for posts sent now.
    pub fn board_clock(&self, board: &Hash) -> Result<Clock, String> {
        if !self.hosts(board) {
            return Err("this node doesn't serve that board".into());
        }
        Ok(Clock {
            epoch: self.epoch(),
            clock: now(),
        })
    }

    /// Mint: what a token request must meet this epoch.
    pub fn token_terms(&self) -> Result<TokenTerms, String> {
        self.operator
            .as_ref()
            .ok_or("only the mint issues tokens")?;
        Ok(TokenTerms {
            epoch: self.epoch(),
            cheats: cheat_list(&self.view),
            ruled: self.ruled_tags(),
        })
    }

    /// Every tag a board's ruling put on the mint's list.
    pub fn ruled_tags(&self) -> Vec<Cheat> {
        self.boards
            .get(&self.town.reports.scope)
            .map(crate::report::ruled)
            .unwrap_or_default()
    }

    /// Ask for a token for each of `creds`, anonymously, counted for
    /// `purpose` if given.
    /// The board mint's request spec: slotted per epoch.
    pub fn token_spec(&self) -> crate::request::RequestSpec {
        crate::request::RequestSpec {
            domain: "pave/board/tokens/v3".into(),
            scope: self.town.post_mint.output(0),
            linkage: crate::request::Linkage::Slots(TOKEN_SLOTS),
            max_skew_ms: None,
        }
    }

    pub fn token_request(
        &mut self,
        terms: &TokenTerms,
        creds: &[Credential],
        purpose: Option<Hash>,
    ) -> Result<TokenRequest, String> {
        let slot = self.slots.take(
            &self.town.post_mint.output(0),
            terms.epoch as u64,
            TOKEN_SLOTS,
        );
        let s = self.view.scheme();
        let standing = creds
            .iter()
            .map(|c| {
                Standing::prove(s, &self.key, c, &terms.cheats)
                    .ok_or_else(|| "this wallet is a known cheat".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let group = self.town.classes[&self.class].group_public_key.clone();
        let basenames: Vec<Vec<u8>> = purpose.iter().map(count_basename).collect();
        self.token_spec().sign(
            &self.access,
            &group,
            terms.epoch as u64,
            slot,
            TokenBody {
                creds: creds.to_vec(),
                standing,
                purpose,
            },
            &terms.ruled,
            &basenames,
            &[],
        )
    }

    /// Mint: answer an anonymous token request. The access signature shows
    /// the class; its pseudonym is fresh per slot, and links a request past
    /// the slots to an earlier one; standing
    /// keeps double spenders' credentials and ruled authors out; a purpose
    /// signature gives the tickets a tag.
    pub fn answer_tokens(&mut self, req: &TokenRequest) -> Result<TokenGrant, String> {
        let terms = self.token_terms()?;
        if req.period != terms.epoch as u64 {
            return Err(format!(
                "stale request: the mint is at epoch {}",
                terms.epoch
            ));
        }
        let b = &req.body;
        if b.creds.is_empty() || b.creds.len() > MAX_TOKENS || b.standing.len() != b.creds.len() {
            return Err(format!(
                "ask for 1 to {MAX_TOKENS} tokens, each with standing"
            ));
        }
        let groups = self
            .town
            .classes
            .iter()
            .map(|(n, c)| (n, &c.group_public_key));
        let expect: Vec<crate::request::Expect> = b
            .purpose
            .iter()
            .map(|p| crate::request::Expect::Basename(count_basename(p)))
            .collect();
        let v = self
            .token_spec()
            .verify(req, groups, &terms.ruled, &expect)?;
        let (class, nym) = (v.group, v.nym);
        let s = self.view.scheme().clone();
        for (c, st) in b.creds.iter().zip(&b.standing) {
            if st.credential != *c || !st.covers(&terms.cheats) || !st.verify(&s) {
                return Err("a credential lacks standing".into());
            }
        }
        let tag = match (b.purpose, v.also.first()) {
            (Some(p), Some(Some(n))) => Some(Tag {
                purpose: p,
                nym: n.clone(),
                class: class.clone(),
            }),
            _ => None,
        };
        let op = self
            .operator
            .as_mut()
            .ok_or("only the mint issues tokens")?;
        if op.closed.contains(&class) {
            return Err(format!(
                "class {class} is closed: update the wallet and enroll again"
            ));
        }
        op.tokens.note(req.period, nym);
        self.mint_tokens(&b.creds, &class, tag)
    }

    /// Mint: ticket each credential in one fresh group and mint it a token,
    /// from a budget of its own so a token's history stays short.
    pub(crate) fn mint_tokens(
        &mut self,
        creds: &[Credential],
        class: &str,
        tag: Option<Tag>,
    ) -> Result<TokenGrant, String> {
        let (_, tickets) = self.issue_tickets_tagged(creds, class, tag)?;
        let op = self
            .operator
            .as_ref()
            .ok_or("only the mint issues tokens")?;
        let (key, me) = (op.minter.clone(), op.minter_cred.clone());
        let s = self.view.scheme().clone();
        let budget = pave_kernel::sign(
            &s,
            &key,
            &me,
            Op::IssueBudget {
                authority: self.town.post_mint.output(0),
                schema: post_schema(),
                amount: creds.len() as u64,
                to: me.clone(),
            },
        );
        apply_ok(&mut self.view, &budget)?;
        let mut records = vec![budget.clone()];
        let mut state = budget.output(0);
        for c in creds {
            let m = self.guard(pave_kernel::sign(
                &s,
                &key,
                &me,
                Op::Mint {
                    budget: state,
                    amount: 1,
                    to: c.clone(),
                    change_to: me.clone(),
                },
            ))?;
            apply_ok(&mut self.view, &m)?;
            state = m.output(1);
            records.push(m);
        }
        Ok(TokenGrant { tickets, records })
    }

    /// Keep a grant: its records, and its tickets for credentials this
    /// wallet holds.
    pub fn take_grant(&mut self, g: TokenGrant) -> Result<(), String> {
        let mint = self.town.post_mint.clone();
        apply_ok(&mut self.view, &mint)?;
        for r in &g.records {
            apply_ok(&mut self.view, r)?;
        }
        let s = self.view.scheme().clone();
        for t in g.tickets {
            if t.clerk == self.town.clerk {
                self.mine.insert(t.ticket.credential.clone());
                self.know.add_ticket(&s, t);
            }
        }
        Ok(())
    }

    /// An unused post token held by `signer`.
    fn token_for(&self, signer: &Credential) -> Option<Hash> {
        self.view
            .unspent()
            .find(|c| {
                c.schema == self.town.posts
                    && c.kind == Kind::Value
                    && &c.holder == signer
                    && !self.signed_log.contains_key(&c.state)
            })
            .map(|c| c.state)
    }

    /// Sign a draft with a server's proposed epoch and clock: the token's
    /// transfer to the server, committing to the post.
    pub fn sign_post(&mut self, d: &Draft, clock: &Clock) -> Result<Submission, String> {
        let info = self
            .boards
            .get(&d.board)
            .ok_or("no copy of that board")?
            .info
            .clone();
        let state = self
            .token_for(&d.signer)
            .ok_or("no post token for that key")?;
        let ch = content_hash(&d.content);
        let by = match &d.identity {
            Some(label) => {
                let key = self.identity(label)?;
                let sig = self.view.scheme().sign(
                    &self.key,
                    &key,
                    &by_bytes(&d.board, &d.kind, &d.thread, &ch),
                    None,
                );
                Some(Signed { key, sig })
            }
            None => None,
        };
        let prior = self.boards[&d.board].latest();
        let post = Post {
            board: d.board,
            kind: d.kind.clone(),
            thread: d.thread,
            content: ch,
            nonce: d.nonce,
            prior,
            epoch: clock.epoch,
            clock: clock.clock,
            by,
        };
        let record = self.signed(
            &d.signer,
            Op::Transfer {
                state,
                to: info.host,
                receipt: post.receipt(),
            },
        )?;
        let mut provenance: Vec<Record> = pave_protocol::accept::ancestry(&self.view, &state)
            .iter()
            .filter_map(|s| self.view.creator(s).cloned())
            .collect();
        let at: BTreeMap<Hash, usize> = self
            .view
            .records()
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id(), i))
            .collect();
        provenance.sort_by_key(|r| at.get(&r.id()).copied().unwrap_or(usize::MAX));
        provenance.dedup();
        let ticket = self.know.tickets.get(&d.signer).cloned();
        Ok(Submission {
            record,
            post,
            content: d.content.clone(),
            provenance,
            ticket,
            taken: None,
        })
    }

    /// Server: take a post. Its epoch and clock must be what this server
    /// proposes now; its token must pass the ordinary acceptance check with
    /// the town clerk trusted. Answers with the retire of the token.
    pub fn host_post(&mut self, sub: &Submission) -> Result<Record, String> {
        let scope = sub.scope();
        let p = self.board_clock(&scope)?;
        if sub.post.epoch != p.epoch && sub.post.epoch + 1 != p.epoch {
            return Err(format!(
                "post epoch {} isn't current (the board is at {})",
                sub.post.epoch, p.epoch
            ));
        }
        if sub.post.clock.abs_diff(p.clock) > CLOCK_SLACK {
            return Err("post clock isn't the one this board proposed".into());
        }
        let host = self.boards[&scope].info.host.clone();
        let Op::Transfer { state, to, receipt } = &sub.record.op else {
            return Err("a post is a token's transfer".into());
        };
        if to != &host || *receipt != sub.post.receipt() {
            return Err("the token isn't sent to this board's server with this post".into());
        }
        let mint = self.town.post_mint.clone();
        apply_ok(&mut self.view, &mint)?;
        for r in &sub.provenance {
            if matches!(&r.op, Op::IssueBudget { authority, .. } if *authority != mint.output(0)) {
                return Err("a token from another mint".into());
            }
            apply_ok(&mut self.view, r)?;
        }
        if self.view.coin(state).map(|c| c.schema) != Some(self.town.posts) {
            return Err("not a post token".into());
        }
        let s = self.view.scheme().clone();
        if let Some(t) = &sub.ticket {
            self.know.add_ticket(&s, t.clone());
        }
        let policy = Policy {
            require_standing: false,
            honor_ticket_caps: false,
            ..self.policy()
        };
        pave_protocol::check(&self.view, &self.know, state, &sub.record.signer, &policy)
            .map_err(|e| format!("token refused: {e:?}"))?;
        apply_ok(&mut self.view, &sub.record)?;
        let taken = self.guard(pave_kernel::sign(
            &s,
            &self.key,
            &host,
            Op::Retire {
                state: sub.record.output(0),
            },
        ))?;
        apply_ok(&mut self.view, &taken)?;
        let copy = self.boards.get_mut(&scope).unwrap();
        copy.absorb(&Submission {
            taken: Some(taken.clone()),
            ..sub.clone()
        })?;
        self.save()?;
        Ok(taken)
    }

    /// Author: a server took a post. Keep it in this node's copy and drop
    /// the draft.
    pub fn posted(&mut self, sub: &Submission, taken: &Record) -> Result<(), String> {
        let _ = self.view.apply(&sub.record);
        let _ = self.view.apply(taken);
        let name = sub.name();
        let copy = self
            .boards
            .get_mut(&sub.scope())
            .ok_or("no copy of that board")?;
        copy.absorb(&Submission {
            taken: Some(taken.clone()),
            ..sub.clone()
        })?;
        self.outgoing.retain(|d| d.name() != name);
        self.save()
    }

    /// A server refused a draft: drop it.
    pub fn refused(&mut self, name: &Hash) -> Result<(), String> {
        self.outgoing.retain(|d| d.name() != *name);
        self.save()
    }

    pub fn board_have(&self, scope: &Hash) -> BTreeSet<Prefix> {
        self.boards.get(scope).map(Copy::have).unwrap_or_default()
    }

    /// Serve a reader from this node's copy.
    pub fn posts_since(&self, scope: &Hash, have: &BTreeSet<Prefix>) -> Vec<Submission> {
        self.boards
            .get(scope)
            .map(|c| c.since(have))
            .unwrap_or_default()
    }

    /// Take posts from a server or another copy. Each is checked; bad ones
    /// are dropped. Returns how many were new.
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

    /// Send every draft to `host`: get tokens for the keys that lack them
    /// (one request for uncounted posts, one per purpose), then sign each
    /// with the server's clock and send it.
    pub fn send_drafts(&mut self, host: &mut dyn Host) -> Synced {
        let mut out = Synced::default();
        let drafts = self.outgoing.clone();
        if drafts.is_empty() {
            return out;
        }
        // A key needs a token per draft, and a counted draft needs its key's
        // ticket tagged for its purpose.
        let mut need: BTreeMap<Option<Hash>, Vec<Credential>> = BTreeMap::new();
        let mut have: BTreeMap<Credential, usize> = BTreeMap::new();
        for d in &drafts {
            let tagged = self
                .know
                .tickets
                .get(&d.signer)
                .and_then(|t| t.ticket.tag.as_ref())
                .map(|t| t.purpose);
            let held = have.entry(d.signer.clone()).or_insert_with(|| {
                self.view
                    .unspent()
                    .filter(|c| {
                        c.schema == self.town.posts
                            && c.holder == d.signer
                            && !self.signed_log.contains_key(&c.state)
                    })
                    .count()
            });
            if *held == 0 || (d.count.is_some() && d.count != tagged) {
                need.entry(d.count).or_default().push(d.signer.clone());
            } else {
                *held -= 1;
            }
        }
        if !need.is_empty() {
            match host.terms() {
                Ok(terms) => {
                    for (purpose, creds) in need {
                        for chunk in creds.chunks(MAX_TOKENS) {
                            let got = self
                                .token_request(&terms, chunk, purpose)
                                .and_then(|req| host.tokens(&req))
                                .and_then(|g| self.take_grant(g));
                            if let Err(e) = got {
                                out.refused.push(e);
                            }
                        }
                    }
                }
                Err(e) => out.refused.push(e),
            }
        }
        for d in drafts {
            let sent = host
                .clock(&d.board)
                .and_then(|c| self.sign_post(&d, &c))
                .and_then(|sub| host.post(&sub).map(|r| (sub, r)));
            match sent {
                Ok((sub, r)) => {
                    if self.posted(&sub, &r).is_ok() {
                        out.sent += 1;
                    }
                }
                Err(e) => {
                    let _ = self.refused(&d.name());
                    out.refused.push(e);
                }
            }
        }
        out
    }
}

impl Host for Node {
    fn clock(&mut self, board: &Hash) -> Result<Clock, String> {
        self.board_clock(board)
    }
    fn terms(&mut self) -> Result<TokenTerms, String> {
        self.token_terms()
    }
    fn tokens(&mut self, req: &TokenRequest) -> Result<TokenGrant, String> {
        self.answer_tokens(req)
    }
    fn post(&mut self, sub: &Submission) -> Result<Record, String> {
        self.host_post(sub)
    }
}

/// What syncing with a server did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Synced {
    pub sent: usize,
    pub refused: Vec<String>,
    pub received: usize,
}

impl Node {
    /// Sync with a server in process, as [`crate::net::sync_boards`] does
    /// over the network: send drafts, then fetch what this node lacks.
    pub fn sync_with(&mut self, host: &mut Node) -> Synced {
        let mut out = self.send_drafts(host);
        for e in std::mem::take(&mut self.evidence_out) {
            match host.host_evidence(&e) {
                Ok(()) => out.sent += 1,
                Err(err) => out.refused.push(err),
            }
        }
        for info in self.board_infos() {
            let posts = host.posts_since(&info.scope, &self.board_have(&info.scope));
            out.received += self.absorb_posts(&info.scope, &posts);
        }
        out
    }
}
