//! pave-node commands for food delivery by badged couriers: the co-op's
//! dispatch and badges, the order binding, the food profile's actions,
//! offering and paying the delivery as a job, outcomes, vouches, no-shows
//! and refunds. Binary values travel as hex of their CBOR.

use crate::food::Outcome;
use crate::node::Node;
use crate::parcel::{Manifest, Step};
use crate::profile::{value, Params, Profile};
use pave_kernel::{Credential, Hash};
use serde_json::{json, Value};

const FOOD: &str = include_str!("../../../profiles/food.json");
const ORDERS: &str = include_str!("../../../profiles/orders.json");

pub const HELP: &[&str] = &[
    "open_dispatch {label} (town: a co-op's roster)",
    "issue_badge {dispatch, courier, key} (town)",
    "revoke_badge {dispatch, courier} (town)",
    "take_badge {dispatch, badge}",
    "present {key} (show the ticket a key holds)",
    "learn_ticket {ticket, dispatch?} (and read its badge id)",
    "name_dispatch {parcel, dispatch}",
    "name_about {parcel, about}",
    "seal {parcel} (the label code for the bag's sticker)",
    "food_order {restaurant, order, total, fee, cell, address, deliver_to, provider, due_in} (customer: the order binding)",
    "check_address {binding, address, salt}",
    "pay_to {to, amount, receipt}",
    "received {receipt}",
    "act {action: hand_off|take|confirm, manifest, to?} (the food profile)",
    "food_custody {manifest}",
    "manifest {manifest} (what a manifest says: parcel, addressee, dispatch, provider, about)",
    "offer_delivery {manifest, pay, pickup_in} (provider: seconds from now, may be negative)",
    "show_known {job} (courier: its badge, for the poster)",
    "accept_shown {job, worker, shown}",
    "assigned_courier {manifest}",
    "release_delivery {manifest}",
    "pay_delivery {manifest, note}",
    "note_delivered {manifest, order, seal}",
    "food_outcome {manifest, order, due}",
    "vouch_delivery {manifest, note}",
    "delivery_vouches {courier}",
    "refund {manifest, amount, receipt}",
];

fn hx(h: &Hash) -> String {
    hex::encode(h.0)
}
fn cx(c: &Credential) -> String {
    hex::encode(&c.0)
}
fn enc<T: serde::Serialize>(t: &T) -> String {
    hex::encode(pave_kernel::hash::encode(t))
}
fn dec<T: serde::de::DeserializeOwned>(v: &Value, k: &str) -> Result<T, String> {
    let b = hex::decode(v[k].as_str().ok_or(format!("missing {k}"))?).map_err(|e| format!("{k}: {e}"))?;
    ciborium::from_reader(b.as_slice()).map_err(|e| format!("{k}: {e}"))
}
fn hash(v: &Value, k: &str) -> Result<Hash, String> {
    let b = hex::decode(v[k].as_str().ok_or(format!("missing {k}"))?).map_err(|e| format!("{k}: {e}"))?;
    Ok(Hash(b.try_into().map_err(|_| format!("{k}: want 32 bytes"))?))
}
fn cred(v: &Value, k: &str) -> Result<Credential, String> {
    Ok(Credential(hex::decode(v[k].as_str().ok_or(format!("missing {k}"))?).map_err(|e| format!("{k}: {e}"))?))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str().ok_or(format!("missing {k}"))
}
fn manifest(v: &Value) -> Result<Manifest, String> {
    dec(v, "manifest")
}
fn kv(pairs: &[(&str, ciborium::Value)]) -> Params {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}
fn step(s: &Step) -> Value {
    match s {
        Step::Handoff { from, to } => json!({ "handoff": { "from": cx(from), "to": cx(to) } }),
        Step::Take { by } => json!({ "take": cx(by) }),
        Step::Retired { by } => json!({ "retired": cx(by) }),
        Step::Closed { by, .. } => json!({ "closed": cx(by) }),
    }
}
fn now() -> u64 {
    crate::bulletin::now()
}

/// Run `cmd` if it is one of these; None if it isn't.
pub fn command(n: &mut Node, cmd: &str, v: &Value) -> Option<Result<Value, String>> {
    let r = match cmd {
        "open_dispatch" => n.open_dispatch(v["label"].as_str().unwrap_or("dispatch")).map(|d| json!({ "dispatch": enc(&d), "id": hx(&d.id) })),
        "issue_badge" => (|| Ok(json!({ "badge": enc(&n.issue_badge(&hash(v, "dispatch")?, text(v, "courier")?, &cred(v, "key")?)?) })))(),
        "revoke_badge" => (|| {
            n.revoke_badge(&hash(v, "dispatch")?, text(v, "courier")?)?;
            Ok(json!({}))
        })(),
        "take_badge" => (|| {
            n.take_badge(&dec(v, "dispatch")?, dec(v, "badge")?)?;
            Ok(json!({}))
        })(),
        "present" => (|| Ok(json!({ "ticket": enc(&n.present(&cred(v, "key")?).ok_or("no ticket for that key")?) })))(),
        "learn_ticket" => (|| {
            let t: pave_protocol::SignedTicket = dec(v, "ticket")?;
            let badge = match v.get("dispatch") {
                Some(_) => dec::<crate::dispatch::Dispatch>(v, "dispatch")?.badge_of(n.view.scheme(), &t),
                None => None,
            };
            n.learn_ticket(t)?;
            Ok(json!({ "badge": badge }))
        })(),
        "name_dispatch" => (|| Ok(json!({ "manifest": enc(&n.name_dispatch(&hash(v, "parcel")?, dec(v, "dispatch")?)?) })))(),
        "name_about" => (|| Ok(json!({ "manifest": enc(&n.name_about(&hash(v, "parcel")?, hash(v, "about")?)?) })))(),
        "seal" => (|| Ok(json!({ "code": n.label_code(&hash(v, "parcel")?).ok_or("no label for that parcel")? })))(),
        "food_order" => (|| {
            let orders = Profile::from_json(ORDERS)?;
            let salt: [u8; 16] = rand::random();
            let salt = value(&serde_bytes::ByteBuf::from(salt.to_vec()));
            let address = text(v, "address")?;
            let commit = orders.receipt_of("address", &kv(&[("salt", salt.clone()), ("address", value(&address))]))?;
            let due = now() + v["due_in"].as_u64().unwrap_or(45 * 60);
            let order = crate::bulletin::content_hash(text(v, "order")?.as_bytes());
            let provider = match v.get("provider") {
                Some(_) => Some(cred(v, "provider")?),
                None => None,
            };
            let binding = orders.build("order", &kv(&[
                ("restaurant", value(&cred(v, "restaurant")?)),
                ("order", value(&order)),
                ("total", value(&v["total"].as_u64().unwrap_or(0))),
                ("delivery", value(&v["fee"].as_u64().unwrap_or(0))),
                ("to_cell", value(&v["cell"].as_str().unwrap_or(""))),
                ("address", value(&commit)),
                ("deliver_to", value(&cred(v, "deliver_to")?)),
                ("provider", value(&provider)),
                ("due", value(&due)),
            ]))?;
            let id = orders.hash("order", &binding)?;
            let paid = orders.receipt_of("paid", &kv(&[("order", binding.clone())]))?;
            let refund = orders.receipt_of("refund", &kv(&[("order", value(&id))]))?;
            Ok(json!({ "binding": enc(&binding), "order": hx(&id), "paid": hx(&paid), "refund": hx(&refund), "salt": enc(&salt), "due": due }))
        })(),
        "check_address" => (|| {
            let orders = Profile::from_json(ORDERS)?;
            let binding: ciborium::Value = dec(v, "binding")?;
            let salt: ciborium::Value = dec(v, "salt")?;
            let given = orders.receipt_of("address", &kv(&[("salt", salt), ("address", value(&text(v, "address")?))]))?;
            let committed = binding.as_map().and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("address"))).map(|(_, x)| x.clone());
            Ok(json!({ "matches": committed == Some(value(&given)) }))
        })(),
        "pay_to" => (|| Ok(json!({ "payment": hx(&n.pay_to(cred(v, "to")?, v["amount"].as_u64().unwrap_or(0), hash(v, "receipt")?)?) })))(),
        "received" => (|| Ok(json!({ "amount": n.received(&hash(v, "receipt")?) })))(),
        "act" => (|| {
            let food = Profile::from_json(FOOD)?;
            let m = manifest(v)?;
            let mut p = kv(&[("manifest", value(&m))]);
            if v.get("to").is_some() {
                p.insert("to".into(), value(&cred(v, "to")?));
            }
            let rec = n.act(&food, text(v, "action")?, &p)?;
            n.parcels.entry(m.parcel).or_insert(m);
            Ok(json!({ "record": hx(&rec.id()) }))
        })(),
        "manifest" => (|| {
            let m = manifest(v)?;
            Ok(json!({
                "parcel": hx(&m.parcel),
                "addressee": cx(&m.addressee),
                "dispatch": m.dispatch.as_ref().map(|d| json!({ "id": hx(&d.id), "label": d.label })),
                "provider": m.provider.as_ref().map(cx),
                "about": m.about.as_ref().map(hx),
            }))
        })(),
        "food_custody" => (|| {
            let c = n.custody(&manifest(v)?);
            Ok(json!({ "steps": c.steps.iter().map(step).collect::<Vec<_>>(), "holder": c.holder.as_ref().map(cx), "delivered": c.delivered }))
        })(),
        "offer_delivery" => (|| {
            let pickup_by = now().saturating_add_signed(v["pickup_in"].as_i64().unwrap_or(15 * 60));
            Ok(json!({ "job": hx(&n.offer_delivery(&manifest(v)?, v["pay"].as_u64().unwrap_or(0), pickup_by)?) }))
        })(),
        "show_known" => (|| {
            let job = hash(v, "job")?;
            let shown = n.show_known(job)?;
            let j = n.jobs().remove(&job).ok_or("no such job")?;
            let worker = j.replies.iter().map(|(c, _)| c).find(|c| n.mine.contains(*c)).ok_or("this wallet hasn't replied")?.clone();
            Ok(json!({ "shown": enc(&shown), "worker": cx(&worker), "key": cx(&shown.trade.key) }))
        })(),
        "accept_shown" => (|| Ok(json!({ "message": hx(&n.accept_shown(hash(v, "job")?, cred(v, "worker")?, dec(v, "shown")?)?) })))(),
        "assigned_courier" => (|| {
            let m = manifest(v)?;
            let job = n.delivery_job(&m);
            Ok(json!({ "job": job.as_ref().map(|(j, _)| hx(j)), "courier": job.and_then(|(_, k)| k).as_ref().map(cx) }))
        })(),
        "release_delivery" => (|| Ok(json!({ "message": hx(&n.release_delivery(&manifest(v)?)?) })))(),
        "pay_delivery" => (|| Ok(json!({ "payment": hx(&n.pay_delivery(&manifest(v)?, v["note"].as_str().unwrap_or(""))?) })))(),
        "note_delivered" => (|| Ok(json!({ "message": hx(&n.note_delivered(&manifest(v)?, hash(v, "order")?, text(v, "seal")?)?) })))(),
        "food_outcome" => (|| {
            let o = n.food_outcome(&manifest(v)?, hash(v, "order")?, v["due"].as_u64().ok_or("missing due")?);
            Ok(match o {
                Outcome::Pending => json!({ "outcome": "pending" }),
                Outcome::OnTime { at } => json!({ "outcome": "on time", "at": at }),
                Outcome::Late { at, by } => json!({ "outcome": "late", "at": at, "by": by }),
                Outcome::SealBroken { at } => json!({ "outcome": "seal broken", "at": at }),
            })
        })(),
        "vouch_delivery" => (|| Ok(json!({ "message": hx(&n.vouch_delivery(&manifest(v)?, v["note"].as_str().unwrap_or(""))?) })))(),
        "delivery_vouches" => (|| {
            let who = crate::board::contractor(&cred(v, "courier")?);
            let (people, vouches) = n.delivery_vouches(&who);
            Ok(json!({ "contractor": hx(&who), "people": people, "vouches": vouches.iter().map(|x| json!({ "parcel": hx(&x.parcel), "note": x.note })).collect::<Vec<_>>() }))
        })(),
        "refund" => (|| Ok(json!({ "payment": hx(&n.refund(&manifest(v)?, v["amount"].as_u64().unwrap_or(0), hash(v, "receipt")?)?) })))(),
        _ => return None,
    };
    Some(r)
}
