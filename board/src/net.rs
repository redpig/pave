//! The peer link: length-prefixed CBOR over TCP.
//!
//! - Meet: two wallets swap bundles, as two phones would on meeting, then
//!   standing proofs against every cheat either now knows of.
//! - Gossip: the two tiers. Hints first (fits one packet), then per-hint
//!   wants answered with proofs.

use crate::bulletin::{Clock, Submission, TokenGrant, TokenRequest, TokenTerms};
use crate::node::{Bundle, Have, Node, RefillRequest, RefillTerms};
use crate::pay::{Ack, Invoice, Offer, PayVerdict, Prefix, Proposal};
use crate::swap::{Quote, QuoteRequest, SwapOutcome, SwapRequest, Verdict};
use pave_kernel::Record;
use pave_kernel::{Credential, Hash};
use pave_protocol::gossip::{self, Hint, Proof, Want};
use pave_protocol::{SignedTicket, Standing};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize)]
pub enum Wire {
    Meet(Box<Bundle>),
    Hints(Vec<Hint>),
    Wants(Vec<Want>),
    Proofs(Vec<Proof>),
    /// Ask the town what a ticket request must meet this epoch.
    RefillAsk,
    RefillTerms(RefillTerms),
    /// An anonymous ticket request.
    Refill(Box<RefillRequest>),
    Tickets(Vec<SignedTicket>),
    Refused(String),
    /// Swaps: a quote on a coin, the transfer, and collecting after a hold.
    QuoteAsk(Box<QuoteRequest>),
    Quote(Box<Quote>),
    Swap(Box<SwapRequest>),
    Collect(Credential),
    Swapped(Box<SwapOutcome>),
    /// Incremental meet: what each side has, before the bundles.
    Have(Box<Have>),
    /// Payments: the handshake in `pay`.
    PayAsk {
        amount: u64,
        memo: String,
    },
    Invoice(Box<Invoice>),
    Offer(Box<Offer>),
    Lacks(Vec<Prefix>),
    Proposal(Box<Proposal>),
    Verdict(PayVerdict),
    Payment(Box<Record>),
    Ack(Box<Ack>),
    /// Proofs that the credentials a wallet paid from aren't known cheats.
    Standing(Vec<Standing>),
    /// Boards: the server's clock, post tokens from the mint, a post and the
    /// server's retire of its token, and fetching what a reader lacks from
    /// any node holding a copy.
    ClockAsk(Hash),
    Clock(Clock),
    TokenTermsAsk,
    TokenTerms(Box<TokenTerms>),
    Tokens(Box<TokenRequest>),
    Granted(Box<TokenGrant>),
    Post(Box<Submission>),
    Posted(Box<Record>),
    Fetch {
        scope: Hash,
        have: std::collections::BTreeSet<Prefix>,
    },
    Posts(Vec<Submission>),
    /// The network access gate: the server's challenge and the client's answer.
    Challenge(crate::nac::Challenge),
    Nac(Box<crate::nac::NacProof>),
    /// Evidence for the host to hold, and a panelist asking for it.
    Evidence(Box<crate::evidence::Sealed>),
    Kept,
    AskEvidence(Box<crate::evidence::Ask>),
    EvidenceList(Vec<crate::evidence::Sealed>),
}

/// Dial a service at `addr` and pass its network access gate, naming the
/// service by the address dialed.
pub fn connect(node: &Arc<Mutex<Node>>, addr: &str) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(addr)?;
    match read_msg(&mut s)?.0 {
        Wire::Challenge(c) => {
            let p = node
                .lock()
                .unwrap()
                .nac_prove(addr, &c)
                .map_err(std::io::Error::other)?;
            write_msg(&mut s, &Wire::Nac(Box::new(p)))?;
            Ok(s)
        }
        _ => Err(std::io::Error::other(
            "the service didn't open with a challenge",
        )),
    }
}

pub fn write_msg(s: &mut TcpStream, m: &Wire) -> std::io::Result<usize> {
    let b = pave_kernel::hash::encode(m);
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(&b)?;
    Ok(b.len())
}

pub fn read_msg(s: &mut TcpStream) -> std::io::Result<(Wire, usize)> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > 64 << 20 {
        return Err(std::io::Error::other("message too large"));
    }
    let mut b = vec![0u8; n];
    s.read_exact(&mut b)?;
    let m =
        ciborium::from_reader(b.as_slice()).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok((m, n))
}

/// Serve one peer connection.
/// Serve one connection to this node's `service` (the name clients dial),
/// starting with the network access gate (see [`crate::nac`]).
pub fn serve_peer(node: Arc<Mutex<Node>>, mut s: TcpStream, service: &str) -> std::io::Result<()> {
    let c = node.lock().unwrap().nac_challenge();
    write_msg(&mut s, &Wire::Challenge(c.clone()))?;
    let admitted = match read_msg(&mut s)?.0 {
        Wire::Nac(p) => node.lock().unwrap().nac_admit(service, &c, &p),
        _ => Err("a network access credential first".into()),
    };
    if let Err(e) = admitted {
        write_msg(&mut s, &Wire::Refused(e))?;
        return Ok(());
    }
    let mut peer_have: Option<Have> = None;
    loop {
        let (msg, _) = match read_msg(&mut s) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        let reply = {
            let mut n = node.lock().unwrap();
            let r = match msg {
                Wire::Have(h) => {
                    let mine = n.have();
                    peer_have = Some(*h);
                    Wire::Have(Box::new(mine))
                }
                Wire::PayAsk { amount, memo } => match n.invoice(amount, &memo) {
                    Ok(i) => Wire::Invoice(Box::new(i)),
                    Err(e) => Wire::Refused(e),
                },
                Wire::Offer(o) => Wire::Lacks(n.lacks(&o)),
                Wire::Proposal(p) => Wire::Verdict(n.judge(&p)),
                Wire::Payment(r) => {
                    match n.re_ack(&r).map(Ok).unwrap_or_else(|| n.take_payment(&r)) {
                        Ok(a) => Wire::Ack(Box::new(a)),
                        Err(e) => Wire::Refused(e),
                    }
                }
                Wire::Meet(b) => {
                    let mine = match &peer_have {
                        Some(h) => n.bundle_for(h),
                        None => n.bundle(),
                    };
                    if b.genesis == n.town.genesis.root_scope() {
                        n.absorb_bundle(&b);
                    }
                    Wire::Meet(Box::new(mine))
                }
                Wire::Hints(h) => {
                    gossip::absorb_hints(&mut n.know, &h);
                    Wire::Hints(gossip::hints(&n.view, &n.know, &n.carries()))
                }
                Wire::Wants(w) => Wire::Proofs(gossip::serve(&n.view, &n.know, &n.carries(), &w)),
                Wire::Proofs(p) => {
                    let n = &mut *n;
                    gossip::absorb(&mut n.view, &mut n.know, p);
                    Wire::Proofs(vec![])
                }
                Wire::RefillAsk => match n.refill_terms() {
                    Ok(t) => Wire::RefillTerms(t),
                    Err(e) => Wire::Refused(e),
                },
                Wire::Refill(req) => match n.answer_refill(&req) {
                    Ok(t) => Wire::Tickets(t),
                    Err(e) => Wire::Refused(e),
                },
                Wire::QuoteAsk(q) => match n.quote(&q) {
                    Ok(q) => Wire::Quote(Box::new(q)),
                    Err(e) => Wire::Refused(e),
                },
                Wire::Swap(r) => match n.answer_swap(&r) {
                    Ok(o) => Wire::Swapped(Box::new(o)),
                    Err(e) => Wire::Refused(e),
                },
                Wire::Collect(to) => match n.collect_swap(&to) {
                    Ok(o) => Wire::Swapped(Box::new(o)),
                    Err(e) => Wire::Refused(e),
                },
                Wire::ClockAsk(b) => match n.board_clock(&b) {
                    Ok(c) => Wire::Clock(c),
                    Err(e) => Wire::Refused(e),
                },
                Wire::TokenTermsAsk => match n.token_terms() {
                    Ok(t) => Wire::TokenTerms(Box::new(t)),
                    Err(e) => Wire::Refused(e),
                },
                Wire::Tokens(req) => match n.answer_tokens(&req) {
                    Ok(g) => Wire::Granted(Box::new(g)),
                    Err(e) => Wire::Refused(e),
                },
                Wire::Post(sub) => match n.host_post(&sub) {
                    Ok(r) => Wire::Posted(Box::new(r)),
                    Err(e) => Wire::Refused(e),
                },
                Wire::Fetch { scope, have } => Wire::Posts(n.posts_since(&scope, &have)),
                Wire::Evidence(e) => match n.host_evidence(&e) {
                    Ok(()) => Wire::Kept,
                    Err(e) => Wire::Refused(e),
                },
                Wire::AskEvidence(a) => match n.answer_evidence(&a) {
                    Ok(list) => Wire::EvidenceList(list),
                    Err(e) => Wire::Refused(e),
                },
                Wire::RefillTerms(_)
                | Wire::Tickets(_)
                | Wire::Refused(_)
                | Wire::Quote(_)
                | Wire::Swapped(_)
                | Wire::Invoice(_)
                | Wire::Lacks(_)
                | Wire::Verdict(_)
                | Wire::Ack(_)
                | Wire::Posted(_)
                | Wire::Clock(_)
                | Wire::TokenTerms(_)
                | Wire::Granted(_)
                | Wire::Posts(_)
                | Wire::Kept
                | Wire::EvidenceList(_)
                | Wire::Challenge(_)
                | Wire::Nac(_) => Wire::Refused("unexpected".into()),
                Wire::Standing(v) => {
                    n.absorb_standings(v);
                    Wire::Standing(n.standings())
                }
            };
            let _ = n.save();
            r
        };
        write_msg(&mut s, &reply)?;
    }
}

/// Meet a peer: swap bundles. Returns states with new evidence here.
pub fn meet(
    node: &Arc<Mutex<Node>>,
    addr: &str,
) -> std::io::Result<(Vec<pave_kernel::Hash>, usize)> {
    let mut s = connect(node, addr)?;
    // Summaries first, then only what each side lacks.
    let have = node.lock().unwrap().have();
    let sent0 = write_msg(&mut s, &Wire::Have(Box::new(have)))?;
    let (reply, got0) = read_msg(&mut s)?;
    let Wire::Have(theirs) = reply else {
        return Err(std::io::Error::other("unexpected reply"));
    };
    let mine = node.lock().unwrap().bundle_for(&theirs);
    let sent = write_msg(&mut s, &Wire::Meet(Box::new(mine)))? + sent0 + got0;
    let (reply, got) = read_msg(&mut s)?;
    let mut n = node.lock().unwrap();
    let new = match reply {
        Wire::Meet(b) => {
            let new = n.absorb_bundle(&b);
            // What we handed over in the outbox is now the peer's to keep.
            n.outbox.clear();
            new
        }
        _ => vec![],
    };
    // Now both sides know the same cheats: swap standing against them.
    let mine = n.standings();
    let sent2 = write_msg(&mut s, &Wire::Standing(mine))?;
    let (reply, got2) = read_msg(&mut s)?;
    if let Wire::Standing(v) = reply {
        n.absorb_standings(v);
    }
    let _ = n.save();
    Ok((new, sent + got + sent2 + got2))
}

/// Two-tier gossip with a peer. Returns (compressed bytes each way, extended bytes received, wants sent).
pub fn gossip_with(node: &Arc<Mutex<Node>>, addr: &str) -> std::io::Result<(usize, usize, usize)> {
    let mut s = connect(node, addr)?;
    let my_hints = {
        let n = node.lock().unwrap();
        gossip::hints(&n.view, &n.know, &n.carries())
    };
    let compressed: usize = gossip::compressed_frames(&my_hints)
        .iter()
        .map(|f| f.len())
        .sum();
    write_msg(&mut s, &Wire::Hints(my_hints))?;
    let (reply, _) = read_msg(&mut s)?;
    let Wire::Hints(theirs) = reply else {
        return Ok((compressed, 0, 0));
    };
    let theirs_bytes: usize = gossip::compressed_frames(&theirs)
        .iter()
        .map(|f| f.len())
        .sum();
    let wants = {
        let mut n = node.lock().unwrap();
        gossip::absorb_hints(&mut n.know, &theirs);
        let watch = n.watch();
        gossip::wants(&n.view, &n.know, &n.carries(), &watch)
    };
    if wants.is_empty() {
        let _ = node.lock().unwrap().save();
        return Ok((compressed.max(theirs_bytes), 0, 0));
    }
    let n_wants = wants.len();
    write_msg(&mut s, &Wire::Wants(wants))?;
    let (reply, got) = read_msg(&mut s)?;
    if let Wire::Proofs(p) = reply {
        let mut n = node.lock().unwrap();
        let n = &mut *n;
        gossip::absorb(&mut n.view, &mut n.know, p);
        let _ = n.save();
    }
    Ok((compressed.max(theirs_bytes), got, n_wants))
}

/// Refill this wallet's ticket pool from the town, anonymously. Returns
/// tickets received.
pub fn refill(node: &Arc<Mutex<Node>>, addr: &str, count: usize) -> std::io::Result<usize> {
    let mut s = connect(node, addr)?;
    write_msg(&mut s, &Wire::RefillAsk)?;
    let terms = match read_msg(&mut s)?.0 {
        Wire::RefillTerms(t) => t,
        Wire::Refused(e) => return Err(std::io::Error::other(e)),
        _ => return Err(std::io::Error::other("unexpected reply")),
    };
    let req = node
        .lock()
        .unwrap()
        .refill_request(&terms, count)
        .map_err(std::io::Error::other)?;
    write_msg(&mut s, &Wire::Refill(Box::new(req)))?;
    let (reply, _) = read_msg(&mut s)?;
    let mut n = node.lock().unwrap();
    let got = match reply {
        Wire::Tickets(t) => n.take_tickets(t),
        Wire::Refused(e) => return Err(std::io::Error::other(e)),
        _ => 0,
    };
    let _ = n.save();
    Ok(got)
}

/// What a swap came to, for the holder.
pub enum SwapResult {
    Paid(Hash),
    Held(u32),
}

fn ask(s: &mut TcpStream, m: &Wire) -> std::io::Result<Wire> {
    write_msg(s, m)?;
    match read_msg(s)?.0 {
        Wire::Refused(e) => Err(std::io::Error::other(e)),
        w => Ok(w),
    }
}

/// Swap the coin at `state` with the town: a quote first, then the transfer.
pub fn swap(node: &Arc<Mutex<Node>>, addr: &str, state: Hash) -> std::io::Result<SwapResult> {
    let mut s = connect(node, addr)?;
    let mut cheats = pave_protocol::cheat_list(&node.lock().unwrap().view);
    let quote = loop {
        let req = node
            .lock()
            .unwrap()
            .quote_request(state, &cheats)
            .map_err(std::io::Error::other)?;
        let Wire::Quote(q) = ask(&mut s, &Wire::QuoteAsk(Box::new(req)))? else {
            return Err(std::io::Error::other("unexpected reply"));
        };
        match &q.verdict {
            Verdict::NeedStanding(list) if *list != cheats => cheats = list.clone(),
            _ => break q,
        }
    };
    let req = node
        .lock()
        .unwrap()
        .swap_request(&quote)
        .map_err(std::io::Error::other)?;
    let to = req.to.clone();
    let Wire::Swapped(out) = ask(&mut s, &Wire::Swap(Box::new(req)))? else {
        return Err(std::io::Error::other("unexpected reply"));
    };
    finish_swap(node, &to, &out)
}

/// Collect every swap this wallet is owed whose hold is over.
pub fn collect(node: &Arc<Mutex<Node>>, addr: &str) -> std::io::Result<Vec<SwapResult>> {
    let mut s = connect(node, addr)?;
    let owed = node.lock().unwrap().swaps_held.clone();
    let mut out = vec![];
    for to in owed {
        let Wire::Swapped(o) = ask(&mut s, &Wire::Collect(to.clone()))? else {
            return Err(std::io::Error::other("unexpected reply"));
        };
        out.push(finish_swap(node, &to, &o)?);
    }
    Ok(out)
}

fn finish_swap(
    node: &Arc<Mutex<Node>>,
    to: &Credential,
    out: &SwapOutcome,
) -> std::io::Result<SwapResult> {
    let mut n = node.lock().unwrap();
    let r = match out {
        SwapOutcome::Held { until } => {
            if !n.swaps_held.contains(to) {
                n.swaps_held.push(to.clone());
            }
            SwapResult::Held(*until)
        }
        SwapOutcome::Paid { .. } => {
            let fresh = n
                .take_swap(out)
                .map_err(std::io::Error::other)?
                .expect("paid");
            n.swaps_held.retain(|c| c != to);
            SwapResult::Paid(fresh)
        }
    };
    let _ = n.save();
    Ok(r)
}

/// What a payment cost on the wire, message by message.
#[derive(Debug, Default)]
pub struct PayReport {
    pub paid: Option<Hash>,
    pub steps: Vec<(&'static str, usize)>,
    pub refused: Option<String>,
}

fn step(
    s: &mut TcpStream,
    r: &mut PayReport,
    name: &'static str,
    m: &Wire,
) -> std::io::Result<Wire> {
    let out = write_msg(s, m)?;
    let (reply, got) = read_msg(s)?;
    r.steps.push((name, out + got));
    Ok(reply)
}

/// Pay `amount` to the wallet at `addr`: the handshake in [`crate::pay`].
pub fn pay(
    node: &Arc<Mutex<Node>>,
    addr: &str,
    amount: u64,
    memo: &str,
) -> std::io::Result<PayReport> {
    let mut r = PayReport::default();
    // Agree on epochs first: two-tier gossip, usually one packet each way.
    let (c, e, _) = gossip_with(node, addr)?;
    r.steps.push(("gossip", 2 * c + e));
    let mut s = connect(node, addr)?;
    let refuse = |r: &mut PayReport, why: String| {
        r.refused = Some(why);
    };
    let inv = match step(
        &mut s,
        &mut r,
        "invoice",
        &Wire::PayAsk {
            amount,
            memo: memo.into(),
        },
    )? {
        Wire::Invoice(i) => *i,
        Wire::Refused(e) => {
            refuse(&mut r, e);
            return Ok(r);
        }
        _ => return Err(std::io::Error::other("unexpected reply")),
    };
    let offer = {
        let mut n = node.lock().unwrap();
        if let Err(e) = n.check_invoice(&inv) {
            refuse(&mut r, format!("payer refused the invoice: {e}"));
            return Ok(r);
        }
        n.offer(&inv).map_err(std::io::Error::other)?
    };
    let Wire::Lacks(lacks) = step(
        &mut s,
        &mut r,
        "offer",
        &Wire::Offer(Box::new(offer.clone())),
    )?
    else {
        return Err(std::io::Error::other("unexpected reply"));
    };
    let mut cheats = pave_protocol::cheat_list(&node.lock().unwrap().view);
    let mut sent_records = false;
    loop {
        let p = node
            .lock()
            .unwrap()
            .propose(&offer, if sent_records { &[] } else { &lacks }, &cheats)
            .map_err(std::io::Error::other)?;
        sent_records = true;
        match step(&mut s, &mut r, "proposal", &Wire::Proposal(Box::new(p)))? {
            Wire::Verdict(PayVerdict::Accept) => break,
            Wire::Verdict(PayVerdict::NeedStanding(list)) if list != cheats => cheats = list,
            Wire::Verdict(v) => {
                refuse(&mut r, format!("{v:?}"));
                return Ok(r);
            }
            _ => return Err(std::io::Error::other("unexpected reply")),
        }
    }
    let rec = node
        .lock()
        .unwrap()
        .pay_invoice(&inv, offer.state)
        .map_err(std::io::Error::other)?;
    match step(
        &mut s,
        &mut r,
        "payment",
        &Wire::Payment(Box::new(rec.clone())),
    )? {
        Wire::Ack(a) => {
            node.lock()
                .unwrap()
                .confirm(&rec, &a)
                .map_err(std::io::Error::other)?;
            r.paid = Some(rec.output(0));
        }
        Wire::Refused(e) => refuse(&mut r, e),
        _ => return Err(std::io::Error::other("unexpected reply")),
    }
    Ok(r)
}

/// Resend every payment still waiting for its acknowledgment.
pub fn resume(node: &Arc<Mutex<Node>>, addr: &str) -> std::io::Result<usize> {
    let pending = node.lock().unwrap().pending.clone();
    let mut s = connect(node, addr)?;
    let mut done = 0;
    for rec in pending {
        if let Wire::Ack(a) = ask(&mut s, &Wire::Payment(Box::new(rec.clone())))? {
            if node.lock().unwrap().confirm(&rec, &a).is_ok() {
                done += 1;
            }
        }
    }
    Ok(done)
}

/// What a board sync did.
#[derive(Debug, Default)]
pub struct BoardSync {
    pub sent: usize,
    pub refused: Vec<String>,
    pub received: usize,
}

/// A board server at the other end of a connection.
struct NetHost<'a>(&'a mut TcpStream);

impl NetHost<'_> {
    fn ask(&mut self, m: Wire) -> Result<Wire, String> {
        write_msg(self.0, &m).map_err(|e| e.to_string())?;
        match read_msg(self.0).map_err(|e| e.to_string())?.0 {
            Wire::Refused(e) => Err(e),
            w => Ok(w),
        }
    }
}

impl crate::bulletin::Host for NetHost<'_> {
    fn clock(&mut self, board: &Hash) -> Result<Clock, String> {
        match self.ask(Wire::ClockAsk(*board))? {
            Wire::Clock(c) => Ok(c),
            _ => Err("unexpected reply".into()),
        }
    }
    fn terms(&mut self) -> Result<TokenTerms, String> {
        match self.ask(Wire::TokenTermsAsk)? {
            Wire::TokenTerms(t) => Ok(*t),
            _ => Err("unexpected reply".into()),
        }
    }
    fn tokens(&mut self, req: &TokenRequest) -> Result<TokenGrant, String> {
        match self.ask(Wire::Tokens(Box::new(req.clone())))? {
            Wire::Granted(g) => Ok(*g),
            _ => Err("unexpected reply".into()),
        }
    }
    fn post(&mut self, sub: &Submission) -> Result<Record, String> {
        match self.ask(Wire::Post(Box::new(sub.clone())))? {
            Wire::Posted(r) => Ok(*r),
            _ => Err("unexpected reply".into()),
        }
    }
}

/// Sync with a board server: send every draft (getting post tokens from
/// the mint first if need be), then fetch what this node lacks of each of
/// the town's boards. Posts go directly to the server, as to any website;
/// nothing about them passes through other wallets.
pub fn sync_boards(node: &Arc<Mutex<Node>>, addr: &str) -> std::io::Result<BoardSync> {
    let mut s = connect(node, addr)?;
    let synced = node.lock().unwrap().send_drafts(&mut NetHost(&mut s));
    let mut out = BoardSync {
        sent: synced.sent,
        refused: synced.refused,
        received: 0,
    };
    let evidence = node.lock().unwrap().evidence_out.clone();
    for e in evidence {
        write_msg(&mut s, &Wire::Evidence(Box::new(e.clone())))?;
        let (reply, _) = read_msg(&mut s)?;
        let mut n = node.lock().unwrap();
        n.evidence_out.retain(|x| *x != e);
        let _ = n.save();
        match reply {
            Wire::Kept => out.sent += 1,
            Wire::Refused(e) => out.refused.push(e),
            _ => return Err(std::io::Error::other("unexpected reply")),
        }
    }
    let scopes: Vec<Hash> = node
        .lock()
        .unwrap()
        .board_infos()
        .iter()
        .map(|b| b.scope)
        .collect();
    for scope in scopes {
        let have = node.lock().unwrap().board_have(&scope);
        write_msg(&mut s, &Wire::Fetch { scope, have })?;
        if let (Wire::Posts(p), _) = read_msg(&mut s)? {
            out.received += node.lock().unwrap().absorb_posts(&scope, &p);
        }
    }
    Ok(out)
}

/// Panelist: fetch a subject's evidence from the board's host.
pub fn fetch_evidence(
    node: &Arc<Mutex<Node>>,
    addr: &str,
    subject: &Hash,
) -> std::io::Result<Vec<crate::evidence::Sealed>> {
    let ask = node
        .lock()
        .unwrap()
        .ask_evidence(subject)
        .map_err(std::io::Error::other)?;
    let mut s = connect(node, addr)?;
    write_msg(&mut s, &Wire::AskEvidence(Box::new(ask)))?;
    match read_msg(&mut s)?.0 {
        Wire::EvidenceList(list) => Ok(list),
        Wire::Refused(e) => Err(std::io::Error::other(e)),
        _ => Err(std::io::Error::other("unexpected reply")),
    }
}
