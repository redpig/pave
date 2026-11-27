//! What pave asks of a device: message sizes and crypto times, measured on
//! the real flows. Prints JSON; docs/devices.md reads it.
//!
//!     cargo run --release -p pave-board --example devices

use pave_board::board::Known;
use pave_board::node::{Node, PendingJoin};
use pave_board::pay::PayVerdict;
use pave_kernel::hash::encode;
use pave_kernel::Scheme;
use serde_json::json;
use std::time::Instant;

fn join(town: &mut Node, name: &str, dir: &std::path::Path, credits: &[u64]) -> Node {
    let (pending, req) = PendingJoin::generate();
    let e = town.enroll(&req, "hardware", credits).unwrap();
    let mut n = Node::finish_enrollment(pending, &e, name, &dir.join(name)).unwrap();
    for _ in 0..2 {
        let t = town.answer_refill(&n.refill_request(&town.refill_terms().unwrap(), 16).unwrap()).unwrap();
        n.take_tickets(t);
    }
    n
}

/// Both directions of a meet, and its size in bytes.
fn meet(a: &mut Node, b: &mut Node) -> usize {
    let (ba, bb) = (a.bundle_for(&b.have()), b.bundle_for(&a.have()));
    let size = encode(&ba).len() + encode(&bb).len();
    b.absorb_bundle(&ba);
    a.absorb_bundle(&bb);
    a.outbox.clear();
    b.outbox.clear();
    size
}

/// Median milliseconds of `f` over `n` runs.
fn time(n: usize, mut f: impl FnMut()) -> f64 {
    let mut v: Vec<f64> = (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1e3
        })
        .collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (v[n / 2] * 1000.0).round() / 1000.0
}

/// Pay `amount` from `a` to `b`, returning the size of what crossed: the
/// proposal (the coin and its history) and the payment record.
fn pay(a: &mut Node, b: &mut Node, amount: u64) -> Result<(usize, f64), String> {
    let inv = b.invoice_for(amount, pave_kernel::Hash([9; 32])).unwrap();
    a.check_invoice(&inv).map_err(|e| format!("{e:?}"))?;
    let offer = a.offer(&inv)?;
    let lacks = b.lacks(&offer);
    let mut p = a.propose(&offer, &lacks, &pave_protocol::cheat_list(&a.view)).unwrap();
    let t = Instant::now();
    let mut v = b.judge(&p);
    if let PayVerdict::NeedStanding(list) = v {
        p = a.propose(&offer, &[], &list).unwrap();
        v = b.judge(&p);
    }
    let judge_ms = t.elapsed().as_secs_f64() * 1e3;
    assert_eq!(v, PayVerdict::Accept);
    let rec = a.pay_invoice(&inv, offer.state).unwrap();
    let size = encode(&p).len() + encode(&rec).len();
    let ack = b.take_payment(&rec)?;
    a.confirm(&rec, &ack).unwrap();
    Ok((size, (judge_ms * 1000.0).round() / 1000.0))
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pave-devices-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut town = Node::init_town(&dir.join("town"), "test").unwrap();
    let mut w: Vec<Node> = (0..6).map(|i| join(&mut town, &format!("w{i}"), &dir, if i == 0 { &[1000] } else { &[] })).collect();

    // Primitives.
    let s = w[0].view.scheme().clone();
    let key = &w[0].key;
    let cred = s.credential(key);
    let msg = [7u8; 64];
    let sig = s.sign(key, &cred, &msg, None);
    let sig_b = s.sign(key, &cred, &msg, Some(b"pave/basename"));
    let prims = json!({
        "credential_bytes": cred.0.len(),
        "signature_bytes": encode(&sig).len(),
        "signature_with_basename_bytes": encode(&sig_b).len(),
        "ms_new_credential": time(50, || { s.credential(key); }),
        "ms_sign": time(50, || { s.sign(key, &cred, &msg, None); }),
        "ms_sign_with_basename": time(50, || { s.sign(key, &cred, &msg, Some(b"pave/basename")); }),
        "ms_verify": time(50, || { assert!(s.verify(&cred, &msg, None, &sig)); }),
    });

    // A coin passed hand to hand: what a payment carries grows with hops.
    let mut hops = vec![];
    for i in 0..5 {
        let (a, b) = w.split_at_mut(i + 1);
        meet(&mut a[i], &mut town);
        match pay(&mut a[i], &mut b[0], 100 - 10 * i as u64) {
            Ok((size, judge)) => hops.push(json!({ "hop": i + 1, "bytes": size, "ms_payee_checks": judge })),
            Err(e) => {
                hops.push(json!({ "hop": i + 1, "refused": e }));
                break;
            }
        }
    }

    // Meets: first between two wallets that know only the town, then again
    // after one more payment.
    let (mut a, mut b) = (join(&mut town, "a", &dir, &[500]), join(&mut town, "b", &dir, &[]));
    let first = meet(&mut a, &mut b);
    pay(&mut a, &mut b, 50).unwrap();
    let again = meet(&mut a, &mut b);
    let t = Instant::now();
    meet(&mut a, &mut town);
    let meet_ms = t.elapsed().as_secs_f64() * 1e3;

    // The pieces a food delivery shows in person.
    let d = town.open_dispatch("Pine Co-op").unwrap();
    let badge_key = a.identity("courier").unwrap();
    let badge = town.issue_badge(&d.id, "courier-47", &badge_key).unwrap();
    a.take_badge(&d, badge.clone()).unwrap();
    let budget = b.receive().unwrap();
    town.issue_parcel_budget(budget, 5).unwrap();
    meet(&mut b, &mut town);
    let to = a.receive().unwrap();
    let m = b.ship("order", "dn5bpsb", "dn5bpth", to, 400).unwrap();
    let m = b.name_dispatch(&m.parcel, d.clone()).unwrap();
    let job = b.post_known("Deliver", 10, Known::Badge(d.roster.clone())).unwrap();
    b.sync_with(&mut town);
    a.sync_with(&mut town);
    a.reply(job, "here").unwrap();
    a.sync_with(&mut town);
    let shown = a.show_known(job).unwrap();
    let refill = a.refill_request(&town.refill_terms().unwrap(), 16).unwrap();
    let tickets = town.answer_refill(&refill).unwrap();
    let pieces = json!({
        "badge_ticket_bytes": encode(&badge).len(),
        "shown_badge_bytes": encode(&shown).len(),
        "manifest_with_dispatch_bytes": encode(&m).len(),
        "dispatch_bytes": encode(&d).len(),
        "refill_request_16_bytes": encode(&refill).len(),
        "tickets_16_bytes": encode(&tickets).len(),
    });

    println!("{}", serde_json::to_string_pretty(&json!({
        "machine": "one core of the build machine; see docs/devices.md for phones",
        "primitives": prims,
        "payment_by_hop": hops,
        "meets": { "first_bytes": first, "after_one_payment_bytes": again, "ms_meet_with_town": (meet_ms * 1000.0).round() / 1000.0 },
        "food": pieces,
    })).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}
