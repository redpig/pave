//! Commands for meeting in person over a link the app carries itself: what
//! this wallet has, a bundle for a peer, absorbing one, and the link
//! sessions (an invite shown or scanned, sealing, opening, QR frames). The
//! app moves the sealed bytes over whatever radio it has.

use crate::link::{frames, Frames, Invite, Link, Radio, Session, Side, FRAME_BYTES};
use crate::node::{Bundle, Have, Node};
use serde_json::{json, Value};

pub const HELP: &[&str] = &[
    "have (what this wallet has, for a meet over a link)",
    "bundle_for {have} (what the peer lacks)",
    "absorb {bundle}",
    "link_show {radios: [{wifi_aware: name} | {ble: uuid hex}], ttl} (an invite to show as a QR code)",
    "link_scan {code} (an invite scanned)",
    "link_seal {link, kind, body}",
    "link_open {link, sealed}",
    "link_frames {link, sealed} (QR codes to show in a loop)",
    "link_collect {link, frame} (a scanned frame; the sealed message once complete)",
];

fn bytes(v: &Value, k: &str) -> Result<Vec<u8>, String> {
    hex::decode(v[k].as_str().ok_or(format!("missing {k}"))?).map_err(|e| format!("{k}: {e}"))
}

fn open(n: &mut Node, inv: &Invite, side: Side) -> String {
    let token = hex::encode(inv.token);
    n.links.insert(token.clone(), Session { link: Link::new(inv, side), frames: Frames::new(inv.token) });
    token
}

fn with<T>(n: &mut Node, v: &Value, f: impl FnOnce(&mut Session) -> Result<T, String>) -> Result<T, String> {
    let id = v["link"].as_str().ok_or("missing link")?;
    f(n.links.get_mut(id).ok_or("no such link")?)
}

fn radio(r: &Value) -> Result<Radio, String> {
    if let Some(name) = r["wifi_aware"].as_str() {
        return Ok(Radio::WifiAware(name.into()));
    }
    if let Some(uuid) = r["ble"].as_str() {
        let b = hex::decode(uuid.replace('-', "")).map_err(|e| e.to_string())?;
        return Ok(Radio::Ble(b.try_into().map_err(|_| "a BLE service UUID is 16 bytes")?));
    }
    Err(format!("unknown radio {r}"))
}

fn radios(rs: &[Radio]) -> Vec<Value> {
    rs.iter()
        .map(|r| match r {
            Radio::WifiAware(n) => json!({ "wifi_aware": n }),
            Radio::Ble(u) => json!({ "ble": hex::encode(u) }),
        })
        .collect()
}

/// Run `cmd` if it is one of these; None if it isn't.
pub fn command(n: &mut Node, cmd: &str, v: &Value) -> Option<Result<Value, String>> {
    let r = match cmd {
        "have" => Ok(json!({ "have": hex::encode(pave_kernel::hash::encode(&n.have())) })),
        "bundle_for" => (|| {
            let have: Have = ciborium::from_reader(bytes(v, "have")?.as_slice()).map_err(|e| e.to_string())?;
            Ok(json!({ "bundle": hex::encode(pave_kernel::hash::encode(&n.bundle_for(&have))) }))
        })(),
        "absorb" => (|| {
            let b: Bundle = ciborium::from_reader(bytes(v, "bundle")?.as_slice()).map_err(|e| e.to_string())?;
            let new = n.absorb_bundle(&b);
            n.outbox.clear();
            Ok(json!({ "new_evidence": new.iter().map(super::hx).collect::<Vec<_>>() }))
        })(),
        "link_show" => (|| {
            let rs = v["radios"].as_array().map(|a| a.iter().map(radio).collect::<Result<Vec<_>, _>>()).transpose()?.unwrap_or_default();
            let inv = Invite::new(rs, v["ttl"].as_u64().unwrap_or(120));
            Ok(json!({ "link": open(n, &inv, Side::Shower), "code": inv.to_qr(), "expires": inv.expires }))
        })(),
        "link_scan" => (|| {
            let inv = Invite::from_qr(v["code"].as_str().ok_or("missing code")?)?;
            Ok(json!({ "link": open(n, &inv, Side::Scanner), "radios": radios(&inv.radios), "expires": inv.expires }))
        })(),
        "link_seal" => with(n, v, |s| Ok(json!({ "sealed": hex::encode(s.link.seal(v["kind"].as_str().unwrap_or(""), &bytes(v, "body")?)) }))),
        "link_open" => with(n, v, |s| {
            let (kind, body) = s.link.open(&bytes(v, "sealed")?)?;
            Ok(json!({ "kind": kind, "body": hex::encode(body) }))
        }),
        "link_frames" => with(n, v, |s| Ok(json!({ "frames": frames(s.link.token(), &bytes(v, "sealed")?, FRAME_BYTES) }))),
        "link_collect" => with(n, v, |s| {
            let got = s.frames.add(v["frame"].as_str().ok_or("missing frame")?)?;
            Ok(json!({ "sealed": got.map(hex::encode), "missing": s.frames.missing() }))
        }),
        _ => return None,
    };
    Some(r)
}
