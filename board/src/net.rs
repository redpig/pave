//! The peer link: length-prefixed CBOR over TCP.
//!
//! - Meet: two wallets swap bundles, as two phones would on meeting, then
//!   standing proofs against every cheat either now knows of.
//! - Gossip: the two tiers. Hints first (fits one packet), then per-hint
//!   wants answered with proofs.

use crate::node::{Bundle, Node, RefillRequest, RefillTerms};
use pave_protocol::{SignedTicket, Standing};
use pave_protocol::gossip::{self, Hint, Proof, Want};
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
    /// Proofs that the credentials a wallet paid from aren't known cheats.
    Standing(Vec<Standing>),
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
    let m = ciborium::from_reader(b.as_slice()).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok((m, n))
}

/// Serve one peer connection.
pub fn serve_peer(node: Arc<Mutex<Node>>, mut s: TcpStream) -> std::io::Result<()> {
    loop {
        let (msg, _) = match read_msg(&mut s) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        let reply = {
            let mut n = node.lock().unwrap();
            let r = match msg {
                Wire::Meet(b) => {
                    let mine = n.bundle();
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
                Wire::RefillTerms(_) | Wire::Tickets(_) | Wire::Refused(_) => Wire::Refused("unexpected".into()),
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
pub fn meet(node: &Arc<Mutex<Node>>, addr: &str) -> std::io::Result<(Vec<pave_kernel::Hash>, usize)> {
    let mut s = TcpStream::connect(addr)?;
    let mine = node.lock().unwrap().bundle();
    let sent = write_msg(&mut s, &Wire::Meet(Box::new(mine)))?;
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
    let mut s = TcpStream::connect(addr)?;
    let my_hints = {
        let n = node.lock().unwrap();
        gossip::hints(&n.view, &n.know, &n.carries())
    };
    let compressed: usize = gossip::compressed_frames(&my_hints).iter().map(|f| f.len()).sum();
    write_msg(&mut s, &Wire::Hints(my_hints))?;
    let (reply, _) = read_msg(&mut s)?;
    let Wire::Hints(theirs) = reply else { return Ok((compressed, 0, 0)) };
    let theirs_bytes: usize = gossip::compressed_frames(&theirs).iter().map(|f| f.len()).sum();
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
    let mut s = TcpStream::connect(addr)?;
    write_msg(&mut s, &Wire::RefillAsk)?;
    let terms = match read_msg(&mut s)?.0 {
        Wire::RefillTerms(t) => t,
        Wire::Refused(e) => return Err(std::io::Error::other(e)),
        _ => return Err(std::io::Error::other("unexpected reply")),
    };
    let req = node.lock().unwrap().refill_request(&terms, count).map_err(std::io::Error::other)?;
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
