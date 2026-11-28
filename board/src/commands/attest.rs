//! The town operator's attestation policy: which vendor roots and apps it
//! trusts, and which class each kind of attestation earns.

use crate::attest::{AndroidApp, Attested, Policy};
use crate::node::Node;
use serde_bytes::ByteBuf;
use serde_json::{json, Value};

pub const HELP: &[&str] = &[
    "attest_policy (the town's attestation policy)",
    "attest_policy {android_roots: [der hex], android_apps: [{package, signer_sha256}], allow_unlocked, apple_roots: [der hex], apple_app_ids: [TEAMID.bundle], allow_apple_development, earns: {android_tee|android_strongbox|apple_app_attest: class}} (operator: set it)",
];

fn kind(k: &str) -> Result<Attested, String> {
    match k {
        "android_tee" => Ok(Attested::AndroidTee),
        "android_strongbox" => Ok(Attested::AndroidStrongBox),
        "apple_app_attest" => Ok(Attested::AppleAppAttest),
        other => Err(format!("unknown attestation {other}")),
    }
}

fn name(a: &Attested) -> &'static str {
    match a {
        Attested::AndroidTee => "android_tee",
        Attested::AndroidStrongBox => "android_strongbox",
        Attested::AppleAppAttest => "apple_app_attest",
    }
}

fn ders(v: &Value, k: &str) -> Result<Vec<ByteBuf>, String> {
    v[k].as_array().map(|a| a.iter().map(|x| hex::decode(x.as_str().ok_or("expected hex")?).map(ByteBuf::from).map_err(|e| e.to_string())).collect()).unwrap_or(Ok(vec![]))
}

fn show(p: &Policy) -> Value {
    json!({
        "android_roots": p.android_roots.len(),
        "android_apps": p.android_apps.iter().map(|a| json!({ "package": a.package, "signer_sha256": hex::encode(&a.signer_sha256) })).collect::<Vec<_>>(),
        "allow_unlocked": p.allow_unlocked,
        "apple_roots": p.apple_roots.len(),
        "apple_app_ids": p.apple_app_ids,
        "allow_apple_development": p.allow_apple_development,
        "earns": p.earns.iter().map(|(a, c)| (name(a).to_string(), json!(c))).collect::<serde_json::Map<_, _>>(),
    })
}

/// Run `cmd` if it is one of these; None if it isn't.
pub fn command(n: &mut Node, cmd: &str, v: &Value) -> Option<Result<Value, String>> {
    if cmd != "attest_policy" {
        return None;
    }
    Some((|| {
        let op = n.operator.as_mut().ok_or("only the town operator has an attestation policy")?;
        if v.as_object().is_some_and(|o| o.keys().any(|k| k != "cmd")) {
            let apps = v["android_apps"].as_array().map(|a| a.iter().map(|x| Ok(AndroidApp {
                package: x["package"].as_str().ok_or("an app needs a package")?.into(),
                signer_sha256: ByteBuf::from(hex::decode(x["signer_sha256"].as_str().ok_or("an app needs signer_sha256")?).map_err(|e| e.to_string())?),
            })).collect::<Result<Vec<_>, String>>()).transpose()?.unwrap_or_default();
            let earns = v["earns"].as_object().map(|m| m.iter().map(|(k, c)| Ok((kind(k)?, c.as_str().ok_or("a class is a name")?.to_string()))).collect::<Result<_, String>>()).transpose()?.unwrap_or_default();
            op.attest = Policy {
                android_roots: ders(v, "android_roots")?,
                android_apps: apps,
                allow_unlocked: v["allow_unlocked"].as_bool().unwrap_or(false),
                apple_roots: ders(v, "apple_roots")?,
                apple_app_ids: v["apple_app_ids"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
                allow_apple_development: v["allow_apple_development"].as_bool().unwrap_or(false),
                earns,
            };
        }
        let shown = show(&op.attest);
        n.save()?;
        Ok(json!({ "policy": shown }))
    })())
}
