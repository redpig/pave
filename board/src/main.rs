//! pave-node: one wallet as a process.
//!
//! ```text
//! pave-node init   --town town.pave [--label NAME]
//! pave-node join   --key alice.key --request alice.join          (wallet)
//! pave-node enroll --town town.pave --request alice.join --reply alice.reply [--class hardware|software] [--credit 100,20]
//! pave-node finish --key alice.key --reply alice.reply --name alice --out alice.pave
//! pave-node run    --state alice.pave --listen 127.0.0.1:7001
//! ```
//!
//! `run` listens for peers and reads one JSON command per line on stdin,
//! answering with one JSON object per line on stdout, so a person, a script
//! or an agent can drive it the same way. Send `{"cmd":"help"}` for the list.

use pave_board::node::{Enrollment, Join, Node, PendingJoin};
use pave_board::report;
use pave_board::net;
use pave_kernel::{Credential, Hash};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn need(args: &[String], name: &str) -> String {
    arg(args, name).unwrap_or_else(|| {
        eprintln!("missing {name}");
        std::process::exit(2)
    })
}

fn hx(h: &Hash) -> String {
    hex::encode(h.0)
}
fn cx(c: &Credential) -> String {
    hex::encode(&c.0)
}
fn parse_hash(v: &Value, k: &str) -> Result<Hash, String> {
    let s = v[k].as_str().ok_or(format!("missing {k}"))?;
    let b = hex::decode(s).map_err(|e| format!("{k}: {e}"))?;
    Ok(Hash(b.try_into().map_err(|_| format!("{k}: want 32 bytes"))?))
}
fn parse_cred(v: &Value, k: &str) -> Result<Credential, String> {
    let s = v[k].as_str().ok_or(format!("missing {k}"))?;
    Ok(Credential(hex::decode(s).map_err(|e| format!("{k}: {e}"))?))
}

const HELP: &[&str] = &[
    "whoami", "board", "post {title, pay}", "reply {job, note}", "accept {job, worker}", "done {job}",
    "pay {job} or {job, vouch, note, as: stable label}", "stable {label} (a stable credential to share with contacts)", "add_contact {name, credential}", "reply {job, note, trade: true}", "reputation {contractor}", "receive", "check {state}", "spend {state, to}", "cheat {state, to}", "meet {peer}",
    "gossip {peer}", "refill {peer, count}", "sync {peer} (send queued posts to the board host, fetch the boards)",
    "evidence", "issues", "report {category, lat, lon, observed, note, photo} or {issue, observed, note}", "respond {issue, text, permit}", "forward {issue, channel, receipt}", "clear {issue}", "reports_on {issue}", "mirror {file} (town)", "rule {report, malicious} (town)", "send {peer, amount, memo}", "resume {peer}", "swap {peer, state}", "collect {peer}", "roll {revoke: [group, ...], revoke_class: [class, ...]} (operator)", "help",
];

fn command(node: &Arc<Mutex<Node>>, v: &Value) -> Result<Value, String> {
    let cmd = v["cmd"].as_str().ok_or("missing cmd")?;
    match cmd {
        "help" => Ok(json!({ "commands": HELP })),
        "meet" => {
            let peer = v["peer"].as_str().ok_or("missing peer")?;
            let (new, bytes) = net::meet(node, peer).map_err(|e| e.to_string())?;
            Ok(json!({ "new_evidence": new.iter().map(hx).collect::<Vec<_>>(), "bytes": bytes }))
        }
        "refill" => {
            let peer = v["peer"].as_str().ok_or("missing peer")?;
            let count = v["count"].as_u64().unwrap_or(8) as usize;
            Ok(json!({ "tickets": net::refill(node, peer, count).map_err(|e| e.to_string())? }))
        }
        "send" => {
            let peer = v["peer"].as_str().ok_or("missing peer")?;
            let amount = v["amount"].as_u64().ok_or("missing amount")?;
            let memo = v["memo"].as_str().unwrap_or("");
            let r = net::pay(node, peer, amount, memo).map_err(|e| e.to_string())?;
            let steps: Vec<Value> = r.steps.iter().map(|(k, b)| json!({ "step": k, "bytes": b })).collect();
            match (r.paid, r.refused) {
                (Some(h), _) => Ok(json!({ "paid": hx(&h), "steps": steps })),
                (None, Some(why)) => Ok(json!({ "refused": why, "steps": steps })),
                _ => Ok(json!({ "steps": steps })),
            }
        }
        "resume" => {
            let peer = v["peer"].as_str().ok_or("missing peer")?;
            Ok(json!({ "acknowledged": net::resume(node, peer).map_err(|e| e.to_string())? }))
        }
        "swap" => {
            let peer = v["peer"].as_str().ok_or("missing peer")?;
            let state = parse_hash(v, "state")?;
            match net::swap(node, peer, state).map_err(|e| e.to_string())? {
                net::SwapResult::Paid(h) => Ok(json!({ "paid": hx(&h) })),
                net::SwapResult::Held(until) => Ok(json!({ "held_until": until })),
            }
        }
        "collect" => {
            let peer = v["peer"].as_str().ok_or("missing peer")?;
            let got = net::collect(node, peer).map_err(|e| e.to_string())?;
            let paid: Vec<String> = got.iter().filter_map(|r| if let net::SwapResult::Paid(h) = r { Some(hx(h)) } else { None }).collect();
            let held: Vec<u32> = got.iter().filter_map(|r| if let net::SwapResult::Held(u) = r { Some(*u) } else { None }).collect();
            Ok(json!({ "paid": paid, "held_until": held }))
        }
        "sync" => {
            let peer = v["peer"].as_str().ok_or("missing peer")?;
            let r = net::sync_boards(node, peer).map_err(|e| e.to_string())?;
            Ok(json!({ "sent": r.sent, "refused": r.refused, "received": r.received }))
        }
        "gossip" => {
            let peer = v["peer"].as_str().ok_or("missing peer")?;
            let (compressed, extended, wants) = net::gossip_with(node, peer).map_err(|e| e.to_string())?;
            Ok(json!({ "compressed_bytes": compressed, "extended_bytes": extended, "wants": wants }))
        }
        _ => {
            let mut n = node.lock().unwrap();
            let out = local(&mut n, cmd, v)?;
            n.save()?;
            Ok(out)
        }
    }
}

fn local(n: &mut Node, cmd: &str, v: &Value) -> Result<Value, String> {
    match cmd {
        "issues" => {
            let issues: Vec<Value> = n
                .issues()
                .values()
                .map(|i| json!({
                    "issue": hx(&i.id), "category": i.key.category, "cell": i.key.cell, "opened": i.key.opened,
                    "reporters": i.reporters, "by_class": i.classes, "notes": i.notes, "photos": i.photos,
                    "permit": match &i.permit {
                        report::PermitStatus::Found(p) => json!({ "found": hx(p) }),
                        report::PermitStatus::Nearby(p) => json!({ "nearby": hx(p) }),
                        report::PermitStatus::None => json!("none"),
                    },
                    "replies": i.replies.iter().map(|(t, p)| json!({ "text": t, "permit": p.as_ref().map(hx) })).collect::<Vec<_>>(),
                    "forwarded": i.forwarded.iter().map(|(c, r)| json!({ "channel": c, "receipt": r })).collect::<Vec<_>>(),
                    "cleared": i.cleared, "discounted": i.discounted,
                }))
                .collect();
            Ok(json!({ "issues": issues, "queued": n.outgoing.len() }))
        }
        "report" => {
            let observed = v["observed"].as_str().ok_or("missing observed (YYYY-MM-DD)")?;
            let note = v["note"].as_str().unwrap_or("");
            let photo = v["photo"].as_str().map(|p| {
                let mut salt = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
                report::commit_photo(&salt, p.as_bytes())
            });
            let issue = if v.get("issue").is_some() {
                let issue = parse_hash(v, "issue")?;
                n.corroborate(&issue, observed, note)?
            } else {
                let category = v["category"].as_str().ok_or("missing category")?;
                let (lat, lon) = (v["lat"].as_f64().ok_or("missing lat")?, v["lon"].as_f64().ok_or("missing lon")?);
                let key = report::IssueKey { category: category.into(), cell: report::cell(lat, lon, report::CELL_PRECISION), opened: observed.into() };
                n.report(key, observed, note, photo)?
            };
            Ok(json!({ "issue": hx(&issue), "queued": n.outgoing.len() }))
        }
        "respond" => {
            let issue = parse_hash(v, "issue")?;
            let permit = if v.get("permit").is_some() { Some(parse_hash(v, "permit")?) } else { None };
            Ok(json!({ "posted": hx(&n.reply_issue(&issue, v["text"].as_str().unwrap_or(""), permit)?) }))
        }
        "forward" => {
            let issue = parse_hash(v, "issue")?;
            let channel = v["channel"].as_str().ok_or("missing channel")?;
            let receipt = v["receipt"].as_str().ok_or("missing receipt")?;
            Ok(json!({ "posted": hx(&n.forward_issue(&issue, channel, receipt)?) }))
        }
        "clear" => {
            let issue = parse_hash(v, "issue")?;
            Ok(json!({ "posted": hx(&n.clear_issue(&issue)?) }))
        }
        "mirror" => {
            let file = v["file"].as_str().ok_or("missing file")?;
            let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
            let permits: Vec<report::PublishedPermit> = serde_json::from_str(&text).map_err(|e| format!("{file}: {e}"))?;
            Ok(json!({ "mirrored": n.mirror_permits(&permits)?, "of": permits.len() }))
        }
        "rule" => {
            let report = parse_hash(v, "report")?;
            let malicious = v["malicious"].as_bool().unwrap_or(true);
            Ok(json!({ "ruling": hx(&n.rule(report, malicious)?) }))
        }
        "reports_on" => {
            let issue = parse_hash(v, "issue")?;
            Ok(json!({ "reports": n.reports_on(&issue).iter().map(hx).collect::<Vec<_>>() }))
        }
        "whoami" => {
            let coins: Vec<Value> = n.my_coins().iter().map(|c| json!({ "state": hx(&c.state), "amount": c.amount, "hops": c.hops })).collect();
            let balance: u64 = n.my_coins().iter().map(|c| c.amount).sum();
            let epoch = pave_protocol::head(&n.view, &n.town.sequence).map(|h| h.number);
            let flagged: Vec<Value> = n.view.flagged().iter().map(|c| json!(n.group_of(c))).collect();
            Ok(json!({
                "name": n.name, "class": n.class, "group": n.group, "balance": balance, "coins": coins, "epoch": epoch,
                "tickets_left": n.pool.len(), "flagged_groups": flagged, "pending_payments": n.pending.len(),
            }))
        }
        "board" => {
            let jobs: Vec<Value> = n
                .jobs()
                .values()
                .map(|j| json!({
                    "job": hx(&j.id), "title": j.title, "pay": j.pay, "poster": cx(&j.poster),
                    "status": format!("{:?}", j.status), "worker": j.worker.as_ref().map(cx),
                    "replies": j.replies.iter().map(|(c, note)| json!({ "from": cx(c), "note": note })).collect::<Vec<_>>(),
                }))
                .collect();
            Ok(json!({ "jobs": jobs, "queued": n.outgoing.len() }))
        }
        "post" => {
            let title = v["title"].as_str().ok_or("missing title")?;
            let pay = v["pay"].as_u64().ok_or("missing pay")?;
            Ok(json!({ "job": hx(&n.post(title, pay)?) }))
        }
        "reply" => {
            let (job, note) = (parse_hash(v, "job")?, v["note"].as_str().unwrap_or(""));
            let id = if v["trade"].as_bool() == Some(true) { n.reply_as_contractor(job, note)? } else { n.reply(job, note)? };
            Ok(json!({ "message": hx(&id), "contractor": n.contractor().as_ref().map(hx) }))
        }
        "stable" => Ok(json!({ "credential": cx(&n.stable(v["label"].as_str().ok_or("missing label")?)?) })),
        "add_contact" => {
            let name = v["name"].as_str().ok_or("missing name")?;
            n.add_contact(name, parse_cred(v, "credential")?)?;
            Ok(json!({ "contacts": n.contacts.keys().collect::<Vec<_>>() }))
        }
        "reputation" => {
            let who = if v.get("contractor").is_some() { parse_hash(v, "contractor")? } else { n.contractor().ok_or("this wallet has no trade key")? };
            let (counts, vouches) = n.reputation(&who);
            Ok(json!({
                "contractor": hx(&who), "people_by_type": counts,
                "vouches": vouches.iter().map(|x| json!({ "job": hx(&x.job), "type": x.category, "note": x.note, "coin": hx(&x.coin), "class": x.class, "by": x.by.as_ref().map(cx), "known_by": x.known_by })).collect::<Vec<_>>(),
                "coins_held": n.vouch_coins().iter().map(hx).collect::<Vec<_>>(),
            }))
        }
        "accept" => Ok(json!({ "message": hx(&n.accept(parse_hash(v, "job")?, parse_cred(v, "worker")?)?) })),
        "done" => Ok(json!({ "message": hx(&n.done(parse_hash(v, "job")?)?) })),
        "pay" => {
            let job = parse_hash(v, "job")?;
            let payment = match v["vouch"].as_str() {
                Some(category) => n.pay_and_vouch(job, category, v["note"].as_str().unwrap_or(""), v["as"].as_str())?,
                None => n.pay(job)?,
            };
            Ok(json!({ "payment": hx(&payment) }))
        }
        "check" => {
            let state = parse_hash(v, "state")?;
            Ok(match n.check(&state) {
                Ok(()) => json!({ "accept": true }),
                Err(r) => json!({ "accept": false, "refusal": format!("{r:?}") }),
            })
        }
        "receive" => Ok(json!({ "credential": cx(&n.receive()?) })),
        "spend" => Ok(json!({ "state": hx(&n.spend(parse_hash(v, "state")?, parse_cred(v, "to")?)?) })),
        "cheat" => Ok(json!({ "state": hx(&n.cheat(parse_hash(v, "state")?, parse_cred(v, "to")?)?) })),
        "evidence" => Ok(json!({
            "evidence": n.view.evidence().map(|e| json!({
                "state": hx(&e.basename), "signer": cx(&e.signer), "group": n.group_of(&e.signer), "nym_bytes": e.nym.len(),
            })).collect::<Vec<_>>()
        })),
        "roll" => {
            let groups: BTreeSet<u32> = v["revoke"].as_array().map(|a| a.iter().filter_map(|x| x.as_u64()).map(|x| x as u32).collect()).unwrap_or_default();
            let classes: BTreeSet<String> = v["revoke_class"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).map(String::from).collect()).unwrap_or_default();
            let epoch = n.roll_epoch(groups, classes)?;
            let revoked = n.operator.as_ref().map(|o| o.revoked.len()).unwrap_or(0);
            Ok(json!({ "epoch": epoch, "revoked_groups": revoked }))
        }
        other => Err(format!("unknown command {other}; try help")),
    }
}

fn run(state: PathBuf, listen: String) {
    let node = Arc::new(Mutex::new(Node::load(&state).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1)
    })));
    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("listen {listen}: {e}");
        std::process::exit(1)
    });
    let srv = node.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let n = srv.clone();
            std::thread::spawn(move || net::serve_peer(n, conn));
        }
    });
    let (name, group) = {
        let n = node.lock().unwrap();
        (n.name.clone(), n.group)
    };
    let mut out = std::io::stdout();
    writeln!(out, "{}", json!({ "event": "ready", "name": name, "group": group, "listen": listen })).ok();
    out.flush().ok();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(v) => match command(&node, &v) {
                Ok(mut r) => {
                    r["ok"] = json!(true);
                    r
                }
                Err(e) => json!({ "ok": false, "error": e }),
            },
            Err(e) => json!({ "ok": false, "error": format!("bad json: {e}") }),
        };
        writeln!(out, "{reply}").ok();
        out.flush().ok();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => {
            let town = PathBuf::from(need(&args, "--town"));
            let label = arg(&args, "--label").unwrap_or_else(|| "test town".into());
            let n = Node::init_town(&town, &label).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1)
            });
            println!("{}", json!({ "ok": true, "town": town, "jobs": hx(&n.town.jobs.scope), "reports": hx(&n.town.reports.scope), "sequence": hx(&n.town.sequence) }));
        }
        Some("join") => {
            // Wallet side: generate a key here and write a join request.
            let key = PathBuf::from(need(&args, "--key"));
            let request = PathBuf::from(need(&args, "--request"));
            let (pending, req) = PendingJoin::generate();
            write_cbor(&key, &pending);
            write_cbor(&request, &req);
            println!("{}", json!({ "ok": true, "key": key, "request": request }));
        }
        Some("enroll") => {
            // Town side: answer a join request.
            let town = PathBuf::from(need(&args, "--town"));
            let request: Join = read_cbor(&PathBuf::from(need(&args, "--request")));
            let class = arg(&args, "--class").unwrap_or_else(|| "hardware".into());
            let reply = PathBuf::from(need(&args, "--reply"));
            let credits: Vec<u64> = arg(&args, "--credit").map(|c| c.split(',').filter_map(|x| x.parse().ok()).collect()).unwrap_or_default();
            let mut t = Node::load(&town).unwrap_or_else(|e| die(e));
            let e = t.enroll(&request, &class, &credits).unwrap_or_else(|e| die(e));
            write_cbor(&reply, &e);
            println!("{}", json!({ "ok": true, "class": class, "group": e.group, "credit": credits, "reply": reply }));
        }
        Some("finish") => {
            // Wallet side: take the town's answer and become a node.
            let key: PendingJoin = read_cbor(&PathBuf::from(need(&args, "--key")));
            let e: Enrollment = read_cbor(&PathBuf::from(need(&args, "--reply")));
            let name = need(&args, "--name");
            let out = PathBuf::from(need(&args, "--out"));
            let p = Node::finish_enrollment(key, &e, &name, &out).unwrap_or_else(|e| die(e));
            println!("{}", json!({ "ok": true, "name": name, "class": p.class, "group": p.group, "out": out }));
        }
        Some("run") => run(PathBuf::from(need(&args, "--state")), need(&args, "--listen")),
        _ => {
            eprintln!("usage: pave-node init|join|enroll|finish|run ... (see the source header)");
            std::process::exit(2);
        }
    }
}

fn die(e: String) -> ! {
    eprintln!("{e}");
    std::process::exit(1)
}

fn write_cbor<T: serde::Serialize>(path: &std::path::Path, v: &T) {
    std::fs::write(path, pave_kernel::hash::encode(v)).unwrap_or_else(|e| die(format!("{}: {e}", path.display())));
}

fn read_cbor<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> T {
    let bytes = std::fs::read(path).unwrap_or_else(|e| die(format!("{}: {e}", path.display())));
    ciborium::from_reader(bytes.as_slice()).unwrap_or_else(|e| die(format!("{}: {e}", path.display())))
}
