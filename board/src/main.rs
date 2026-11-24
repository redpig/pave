//! pave-node: one wallet as a process.
//!
//! ```text
//! pave-node init   --town town.pave [--label NAME]
//! pave-node enroll --town town.pave --name alice --out alice.pave [--credit 100]
//! pave-node run    --state alice.pave --listen 127.0.0.1:7001
//! ```
//!
//! `run` listens for peers and reads one JSON command per line on stdin,
//! answering with one JSON object per line on stdout, so a person, a script
//! or an agent can drive it the same way. Send `{"cmd":"help"}` for the list.

use pave_board::node::Node;
use pave_board::{board, net};
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
    "pay {job}", "check {state}", "spend {state, to}", "cheat {state, to}", "meet {peer}", "gossip {peer}",
    "evidence", "roll {revoke: [group, ...]} (operator)", "help",
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
        "whoami" => {
            let coins: Vec<Value> = n.my_coins().iter().map(|c| json!({ "state": hx(&c.state), "amount": c.amount, "hops": c.hops })).collect();
            let balance: u64 = n.my_coins().iter().map(|c| c.amount).sum();
            let epoch = pave_protocol::head(&n.view, &n.town.sequence).map(|h| h.number);
            Ok(json!({
                "name": n.name, "me": cx(&n.me), "group": n.group(), "balance": balance, "coins": coins, "epoch": epoch,
                "flagged": n.view.flagged().iter().map(cx).collect::<Vec<_>>(),
            }))
        }
        "board" => {
            let jobs: Vec<Value> = board::jobs(&n.view, &n.town.board)
                .values()
                .map(|j| json!({
                    "job": hx(&j.id), "title": j.title, "pay": j.pay, "poster": cx(&j.poster),
                    "status": format!("{:?}", j.status), "worker": j.worker.as_ref().map(cx),
                    "replies": j.replies.iter().map(|(c, note)| json!({ "from": cx(c), "note": note })).collect::<Vec<_>>(),
                }))
                .collect();
            Ok(json!({ "jobs": jobs }))
        }
        "post" => {
            let title = v["title"].as_str().ok_or("missing title")?;
            let pay = v["pay"].as_u64().ok_or("missing pay")?;
            Ok(json!({ "job": hx(&n.post(title, pay)?) }))
        }
        "reply" => Ok(json!({ "message": hx(&n.reply(parse_hash(v, "job")?, v["note"].as_str().unwrap_or(""))?) })),
        "accept" => Ok(json!({ "message": hx(&n.accept(parse_hash(v, "job")?, parse_cred(v, "worker")?)?) })),
        "done" => Ok(json!({ "message": hx(&n.done(parse_hash(v, "job")?)?) })),
        "pay" => Ok(json!({ "payment": hx(&n.pay(parse_hash(v, "job")?)?) })),
        "check" => {
            let state = parse_hash(v, "state")?;
            Ok(match n.check(&state) {
                Ok(()) => json!({ "accept": true }),
                Err(r) => json!({ "accept": false, "refusal": format!("{r:?}") }),
            })
        }
        "spend" => Ok(json!({ "state": hx(&n.spend(parse_hash(v, "state")?, parse_cred(v, "to")?)?) })),
        "cheat" => Ok(json!({ "state": hx(&n.cheat(parse_hash(v, "state")?, parse_cred(v, "to")?)?) })),
        "evidence" => Ok(json!({
            "evidence": n.view.evidence().map(|e| json!({ "state": hx(&e.basename), "signer": cx(&e.signer) })).collect::<Vec<_>>()
        })),
        "roll" => {
            let revoked: BTreeSet<u32> = v["revoke"].as_array().map(|a| a.iter().filter_map(|x| x.as_u64()).map(|x| x as u32).collect()).unwrap_or_default();
            Ok(json!({ "epoch": n.roll_epoch(revoked)? }))
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
    let (name, me) = {
        let n = node.lock().unwrap();
        (n.name.clone(), cx(&n.me))
    };
    let mut out = std::io::stdout();
    writeln!(out, "{}", json!({ "event": "ready", "name": name, "me": me, "listen": listen })).ok();
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
            println!("{}", json!({ "ok": true, "town": town, "board": hx(&n.town.board), "sequence": hx(&n.town.sequence) }));
        }
        Some("enroll") => {
            let town = PathBuf::from(need(&args, "--town"));
            let name = need(&args, "--name");
            let out = PathBuf::from(need(&args, "--out"));
            let credit: u64 = arg(&args, "--credit").and_then(|c| c.parse().ok()).unwrap_or(0);
            let mut t = Node::load(&town).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1)
            });
            let p = t.enroll(&name, &out, credit).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1)
            });
            println!("{}", json!({ "ok": true, "name": name, "me": cx(&p.me), "credit": credit }));
        }
        Some("run") => run(PathBuf::from(need(&args, "--state")), need(&args, "--listen")),
        _ => {
            eprintln!("usage: pave-node init|enroll|run ... (see the source header)");
            std::process::exit(2);
        }
    }
}
