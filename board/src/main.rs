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

use pave_board::commands::{command, hx};
use pave_board::node::{Enrollment, Join, Node, PendingJoin};
use pave_board::net;
use serde_json::{json, Value};
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
    // Clients name this service by the address they dial.
    let service = listen.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let (n, service) = (srv.clone(), service.clone());
            std::thread::spawn(move || net::serve_peer(n, conn, &service));
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
