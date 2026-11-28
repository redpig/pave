//! The JSON command set a wallet speaks: one object in, one out, with
//! binary values as hex. `pave-node` serves it on stdin and a socket; the
//! mobile core serves it through its C interface.

mod attest;
mod food;
mod link;

use crate::node::Node;
use crate::report;
use crate::net;
use pave_kernel::{Credential, Hash};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

pub fn hx(h: &Hash) -> String {
    hex::encode(h.0)
}
pub fn cx(c: &Credential) -> String {
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

pub const HELP: &[&str] = &[
    "whoami", "board", "post {title, pay}", "reply {job, note}", "accept {job, worker}", "done {job}",
    "pay {job} or {job, vouch, note, as: identity}", "parcel_budget {to, count} (town)", "ship {what, from, to, addressee, pay, mode: signed|code|drop, window}", "deliver_code {manifest, code}", "drop {manifest, cell, photo_file}", "parcel_evidence {parcel, statement?} (submit what this wallet can show)", "submit_evidence {subject, kind: image|reference|statement, image_file, caption, redact (default true), source, url, text, as?}", "reveal {subject, as?} (reveal the originals behind your redacted pictures)", "examine {subject, peer, out_dir?} (panel or party: fetch and check the evidence)", "dispute {subject, question, claim, panel, pay, appeal_of?, against?, as?}", "release_escrow {dispute} (town)", "fund {dispute} (fund a first round into escrow)", "terms {min_losses, deposit} (your terms for filers against you)", "dispute_records {against}", "offer {dispute}", "arbitrate {dispute, answer: yes|no|refer, to}", "disputes", "pay_arbiters {dispute}", "handoff {parcel, to}", "take {manifest, as?: identity}", "name_provider {parcel, provider}", "pay_provider {parcel, price}", "who_took {parcel}", "deliver {manifest}", "custody {parcel}", "pay_couriers {parcel}", "identities", "identity {label} (a stable credential to share with the people who should recognize you)", "add_contact {name, credential}", "reply {job, note, trade: true}", "reputation {contractor}", "receive", "trade (this wallet's contractor id, made on first use)", "check {state}", "spend {state, to}", "cheat {state, to}", "meet {peer}",
    "gossip {peer}", "refill {peer, count}", "sync {peer} (send queued posts to the board host, fetch the boards)",
    "evidence", "issues", "report {category, lat, lon, observed, note, photo} or {issue, observed, note}", "respond {issue, text, permit}", "forward {issue, channel, receipt}", "clear {issue}", "reports_on {issue}", "mirror {file} (town)", "rule {report, malicious} (town)", "send {peer, amount, memo}", "resume {peer}", "swap {peer, state}", "collect {peer}", "roll {revoke: [group, ...], revoke_class: [class, ...]} (operator)", "help",
];

/// Run one command against a wallet.
pub fn command(node: &Arc<Mutex<Node>>, v: &Value) -> Result<Value, String> {
    let cmd = v["cmd"].as_str().ok_or("missing cmd")?;
    match cmd {
        "help" => Ok(json!({ "commands": HELP.iter().chain(food::HELP).chain(link::HELP).chain(attest::HELP).collect::<Vec<_>>() })),
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
        "examine" => {
            let peer = v["peer"].as_str().ok_or("missing peer")?;
            let subject = parse_hash(v, "subject")?;
            let given = net::fetch_evidence(node, peer, &subject).map_err(|e| e.to_string())?;
            let mut n = node.lock().unwrap();
            let ex = n.examine_parcel(&subject, &given);
            // Pictures go to files, for whoever rules to look at.
            let dir = match v["out_dir"].as_str() {
                Some(d) => std::path::PathBuf::from(d),
                None => n.path.with_extension(format!("evidence-{}", &hx(&subject)[..8])),
            };
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let mut pictures = vec![];
            for (i, p) in ex.pictures.iter().enumerate() {
                let file = dir.join(format!("{:02}-{}.img", i + 1, p.label.chars().map(|c| if c.is_alphanumeric() { c } else { '-' }).collect::<String>()));
                std::fs::write(&file, &p.bytes).map_err(|e| e.to_string())?;
                pictures.push(json!({ "label": p.label, "from": p.from, "committed_at_drop": p.committed_at_drop, "original": format!("{:?}", p.original), "metadata": p.metadata, "url": p.url, "file": file.display().to_string() }));
            }
            Ok(json!({
                "mode": ex.mode, "custody": ex.custody, "delivery": ex.delivery,
                "code_matches": format!("{:?}", ex.code_matches), "photo_matches": format!("{:?}", ex.photo_matches), "cell_matches": format!("{:?}", ex.cell_matches),
                "pictures": pictures,
                "exhibits": ex.exhibits.iter().map(|e| json!({ "kind": e.kind, "from": e.from, "detail": e.detail })).collect::<Vec<_>>(),
            }))
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
    if let Some(r) = food::command(n, cmd, v) {
        return r;
    }
    if let Some(r) = link::command(n, cmd, v) {
        return r;
    }
    if let Some(r) = attest::command(n, cmd, v) {
        return r;
    }
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
                    "cleared": i.cleared, "discounted": i.discounted, "identified": i.identified.len(), "known_by": i.known_by,
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
                n.report_as(key, observed, note, photo, v["as"].as_str())?
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
        "parcel_budget" => Ok(json!({ "budget": hx(&n.issue_parcel_budget(parse_cred(v, "to")?, v["count"].as_u64().unwrap_or(10))?) })),
        "ship" => {
            use crate::parcel::Mode;
            let mode = match v["mode"].as_str().unwrap_or("signed") {
                "signed" => Mode::Signed,
                "code" => Mode::Code,
                "drop" => Mode::Drop { window: v["window"].as_u64().unwrap_or(2) as u32 },
                other => return Err(format!("unknown mode {other}")),
            };
            let (m, code) = n.ship_with(v["what"].as_str().unwrap_or(""), v["from"].as_str().unwrap_or(""), v["to"].as_str().unwrap_or(""), parse_cred(v, "addressee")?, v["pay"].as_u64().unwrap_or(0), mode)?;
            Ok(json!({ "parcel": hx(&m.parcel), "manifest": hex::encode(pave_kernel::hash::encode(&m)), "code": code }))
        }
        "deliver_code" | "drop" => {
            let bytes = hex::decode(v["manifest"].as_str().ok_or("missing manifest")?).map_err(|e| e.to_string())?;
            let m: crate::parcel::Manifest = ciborium::from_reader(bytes.as_slice()).map_err(|e| e.to_string())?;
            let state = if cmd == "drop" {
                // A photo file, or for a quick test a description standing in for one.
                let photo = match v["photo_file"].as_str() {
                    Some(f) => std::fs::read(f).map_err(|e| format!("{f}: {e}"))?,
                    None => v["photo"].as_str().unwrap_or("").as_bytes().to_vec(),
                };
                n.drop_off_photo(&m, v["cell"].as_str().ok_or("missing cell")?, &photo)?
            } else {
                n.deliver_by_code(&m, v["code"].as_str().ok_or("missing code")?)?
            };
            Ok(json!({ "parcel": hx(&m.parcel), "state": hx(&state) }))
        }
        "parcel_evidence" => {
            let parcel = parse_hash(v, "parcel")?;
            let m = n.parcels.get(&parcel).ok_or("no manifest for that parcel")?.clone();
            let hashes = n.submit_parcel_evidence(&m, v["statement"].as_str())?;
            Ok(json!({ "submitted": hashes.iter().map(hx).collect::<Vec<_>>(), "queued": n.evidence_out.len() }))
        }
        "submit_evidence" => {
            use crate::evidence::Evidence;
            let read = |k: &str| -> Result<Vec<u8>, String> {
                match (v[format!("{k}_file")].as_str(), v[k].as_str()) {
                    (Some(f), _) => std::fs::read(f).map_err(|e| format!("{f}: {e}")),
                    (None, Some(s)) => Ok(s.as_bytes().to_vec()),
                    _ => Err(format!("missing {k} or {k}_file")),
                }
            };
            let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
            let as_cred = if v.get("as").is_some() { Some(parse_cred(v, "as")?) } else { None };
            let subject = parse_hash(v, "subject")?;
            if v["kind"].as_str() == Some("image") {
                // Shown without metadata unless asked; the original stays here to reveal.
                let redact = v["redact"].as_bool().unwrap_or(true);
                return Ok(json!({ "submitted": hx(&n.submit_image(subject, &s("caption"), &read("image")?, redact, as_cred)?) }));
            }
            let ev = match v["kind"].as_str().unwrap_or("") {
                "reference" => Evidence::Reference { source: s("source"), url: s("url"), caption: s("caption"), image: read("image")? },
                "statement" => Evidence::Statement { text: s("text") },
                other => return Err(format!("kind image, reference or statement, not {other}")),
            };
            Ok(json!({ "submitted": hx(&n.submit_evidence(subject, &ev, as_cred)?) }))
        }
        "reveal" => {
            let as_cred = if v.get("as").is_some() { Some(parse_cred(v, "as")?) } else { None };
            Ok(json!({ "revealed": n.reveal_originals(&parse_hash(v, "subject")?, as_cred)?.iter().map(hx).collect::<Vec<_>>() }))
        }
        "dispute" => {
            let appeal_of = if v.get("appeal_of").is_some() { Some(parse_hash(v, "appeal_of")?) } else { None };
            let party = if v.get("as").is_some() { Some(parse_cred(v, "as")?) } else { None };
            let mut f = crate::dispute::Filing::new(parse_hash(v, "subject")?, v["question"].as_str().unwrap_or(""), v["claim"].as_bool().unwrap_or(false), v["panel"].as_u64().unwrap_or(1) as u32, v["pay"].as_u64().unwrap_or(0));
            f.appeal_of = appeal_of;
            f.party = party;
            if v.get("against").is_some() {
                f.against = Some(parse_hash(v, "against")?);
            }
            let id = n.open_dispute(f)?;
            Ok(json!({ "dispute": hx(&id) }))
        }
        "offer" => Ok(json!({ "message": hx(&n.offer_to_arbitrate(parse_hash(v, "dispute")?)?), "contractor": n.contractor().as_ref().map(hx) })),
        "arbitrate" => {
            use crate::dispute::Answer;
            let answer = match v["answer"].as_str().unwrap_or("") {
                "yes" => Answer::Yes,
                "no" => Answer::No,
                "refer" => Answer::Refer(v["to"].as_str().unwrap_or("court").into()),
                other => return Err(format!("answer yes, no or refer, not {other}")),
            };
            Ok(json!({ "ruling": hx(&n.arbitrate(parse_hash(v, "dispute")?, answer)?) }))
        }
        "disputes" => {
            let (ds, scores) = n.disputes();
            let list: Vec<Value> = ds.values().map(|d| json!({
                "id": hx(&d.id), "subject": hx(&d.subject), "question": d.question, "tier": d.tier, "panel_size": d.panel_size,
                "pay_each": d.pay_each, "appeal_of": d.appeal_of.as_ref().map(hx), "offers": d.offers.len(),
                "panel": d.panel.as_ref().map(|p| p.iter().map(|(_, k)| hx(k)).collect::<Vec<_>>()),
                "rulings": d.rulings.len(), "outcome": d.outcome.as_ref().map(|a| format!("{a:?}")), "lapsed": d.lapsed,
                "claim": d.claim, "against": d.against.as_ref().map(hx), "escrowed": d.deposit.is_some(), "funded_by_other": d.funder.is_some(),
                "filer_deposit": d.filer_deposit.is_some(), "decided_at": d.decided_at,
                "settled": crate::dispute::settled(&ds, &crate::dispute::root_of(&ds, d), n.epoch()),
                "liability": crate::dispute::liability(&ds, &crate::dispute::root_of(&ds, d)),
            })).collect();
            Ok(json!({ "disputes": list, "arbiter_scores": scores.iter().map(|(k, s)| (hx(k), *s)).collect::<std::collections::BTreeMap<_, _>>() }))
        }
        "fund" => Ok(json!({ "message": hx(&n.fund_dispute(parse_hash(v, "dispute")?)?) })),
        "terms" => Ok(json!({ "message": hx(&n.publish_terms(v["min_losses"].as_u64().unwrap_or(1) as u32, v["deposit"].as_u64().unwrap_or(0))?) })),
        "release_escrow" => Ok(json!({ "minted": n.release_escrow(parse_hash(v, "dispute")?)?.iter().map(hx).collect::<Vec<_>>() })),
        "dispute_records" => {
            let (filers, theirs) = n.dispute_records(&parse_hash(v, "against")?);
            Ok(json!({ "counterparty": theirs, "filers": filers.values().collect::<Vec<_>>() }))
        }
        "pay_arbiters" => Ok(json!({ "payments": n.pay_arbiters(parse_hash(v, "dispute")?)?.iter().map(hx).collect::<Vec<_>>() })),
        "handoff" => {
            let parcel = parse_hash(v, "parcel")?;
            let state = n.hand_off(&parcel, parse_cred(v, "to")?)?;
            Ok(json!({ "state": hx(&state), "manifest": hex::encode(pave_kernel::hash::encode(&n.parcels[&parcel])) }))
        }
        "take" | "deliver" => {
            let bytes = hex::decode(v["manifest"].as_str().ok_or("missing manifest")?).map_err(|e| e.to_string())?;
            let m: crate::parcel::Manifest = ciborium::from_reader(bytes.as_slice()).map_err(|e| e.to_string())?;
            let id = if cmd == "take" { n.take_parcel_as(&m, v["as"].as_str())? } else { n.confirm_delivery(&m)? };
            Ok(json!({ "parcel": hx(&m.parcel), "record": hx(&id) }))
        }
        "custody" => {
            let parcel = parse_hash(v, "parcel")?;
            let m = n.parcels.get(&parcel).ok_or("no manifest for that parcel")?;
            let c = n.custody(m);
            let steps: Vec<Value> = c.steps.iter().map(|s| match s {
                crate::parcel::Step::Handoff { from, to } => json!({ "handoff": { "from": cx(from), "to": cx(to) } }),
                crate::parcel::Step::Take { by } => json!({ "take": cx(by) }),
                crate::parcel::Step::Retired { by } => json!({ "retired": cx(by) }),
                crate::parcel::Step::Closed { by, .. } => json!({ "closed": cx(by) }),
            }).collect();
            Ok(json!({ "what": m.what, "steps": steps, "holder": c.holder.as_ref().map(cx), "delivery": format!("{:?}", n.delivery(m)) }))
        }
        "name_provider" => {
            let m = n.name_provider(&parse_hash(v, "parcel")?, parse_cred(v, "provider")?)?;
            Ok(json!({ "manifest": hex::encode(pave_kernel::hash::encode(&m)) }))
        }
        "pay_provider" => {
            let parcel = parse_hash(v, "parcel")?;
            let m = n.parcels.get(&parcel).ok_or("no manifest for that parcel")?.clone();
            Ok(json!({ "payment": hx(&n.pay_provider(&m, v["price"].as_u64().unwrap_or(0))?) }))
        }
        "who_took" => {
            let parcel = parse_hash(v, "parcel")?;
            let m = n.parcels.get(&parcel).ok_or("no manifest for that parcel")?.clone();
            Ok(json!({ "takes": n.who_took(&m).iter().map(|(hop, c, name)| json!({ "hop": hop, "identity": cx(c), "name": name })).collect::<Vec<_>>() }))
        }
        "pay_couriers" => {
            let parcel = parse_hash(v, "parcel")?;
            let m = n.parcels.get(&parcel).ok_or("no manifest for that parcel")?.clone();
            Ok(json!({ "payments": n.pay_couriers(&m)?.iter().map(hx).collect::<Vec<_>>() }))
        }
        "identity" => Ok(json!({ "credential": cx(&n.identity(v["label"].as_str().ok_or("missing label")?)?) })),
        "identities" => Ok(json!({ "identities": n.identities.iter().map(|(l, c)| (l.clone(), cx(c))).collect::<std::collections::BTreeMap<_, _>>() })),
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
        "trade" => {
            n.trade_key()?;
            Ok(json!({ "contractor": n.contractor().as_ref().map(hx) }))
        }
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
