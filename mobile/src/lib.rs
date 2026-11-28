//! The pave wallet for phone apps, behind a small C interface.
//!
//! An app opens a wallet and sends it the same JSON commands `pave-node`
//! takes (`board/src/commands`): one object in, one out, binary values as
//! hex. Everything the wallet does, in person or online, goes through
//! [`pave_call`]; the app carries sealed bytes over its radios and shows
//! and scans QR codes.
//!
//! The wallet's state is sealed under a keystore. An app passes its
//! platform keystore (Android Keystore, the Secure Enclave) as callbacks,
//! so the platform key never leaves it; [`pave_open`] uses the software
//! keystore beside the state file, for tests and demos.
//!
//! Strings in and out are UTF-8 and NUL-terminated. Every string this
//! library returns is the caller's to free with [`pave_string_free`].
//! `include/pave.h` declares all of it.
//!
//! The same wallet is also offered through UniFFI (`src/pave.udl`), for
//! Kotlin and Swift apps without hand-written glue; see [`ffi`].

// UniFFI 0.25's generated scaffolding compares function pointers, which
// newer compilers warn about, and leaves blank lines after doc comments;
// it's the generator's code, not ours.
#![allow(unpredictable_function_pointer_comparisons, clippy::empty_line_after_doc_comments)]

use pave_board::commands::command;
use pave_board::node::{Enrollment, Node, PendingJoin};
use pave_board::vault::Keystore as VaultKeystore;
use serde_json::{json, Value};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::Path;
use std::sync::{Arc, Mutex};

mod ffi;
pub use ffi::*;
uniffi::include_scaffolding!("pave");

/// An attestation as the app hands it over: `{"android": {"chain": [hex]}}`
/// or `{"apple": {"object": hex, "key_id": hex}}`.
fn attestation(v: &Value) -> Result<pave_board::attest::Attestation, String> {
    let hexes = |x: &Value| -> Result<Vec<u8>, String> { hex::decode(x.as_str().ok_or("expected hex")?).map_err(|e| e.to_string()) };
    if let Some(a) = v.get("android") {
        let chain = a["chain"].as_array().ok_or("android needs a chain")?.iter().map(|c| hexes(c).map(serde_bytes::ByteBuf::from)).collect::<Result<_, _>>()?;
        Ok(pave_board::attest::Attestation::Android { chain })
    } else if let Some(a) = v.get("apple") {
        Ok(pave_board::attest::Attestation::Apple { object: serde_bytes::ByteBuf::from(hexes(&a["object"])?), key_id: serde_bytes::ByteBuf::from(hexes(&a["key_id"])?) })
    } else {
        Err("expected android or apple".into())
    }
}

/// An open wallet.
pub struct PaveWallet {
    node: Arc<Mutex<Node>>,
}

/// A join in progress: the key made on this device, waiting for the town's
/// answer, and the request. It lives only in memory.
pub struct PaveJoin {
    pending: PendingJoin,
    join: pave_board::node::Join,
}

fn request(join: &pave_board::node::Join) -> Value {
    json!({
        "ok": true,
        "request": hex::encode(pave_kernel::hash::encode(join)),
        "challenge": hex::encode(pave_board::attest::challenge(join)),
    })
}

/// The app's keystore. Each callback returns 0 on success, 1 if `out` is too
/// small (with the length needed in `*out_len`), anything else on failure.
/// `seal` seals under a fresh key, kept until `commit` retires the older
/// ones; `open` opens with any key not yet retired.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PaveKeystore {
    pub ctx: *mut c_void,
    pub seal: extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize, out: *mut u8, cap: usize, out_len: *mut usize) -> c_int,
    pub open: extern "C" fn(ctx: *mut c_void, sealed: *const u8, len: usize, out: *mut u8, cap: usize, out_len: *mut usize) -> c_int,
    pub commit: extern "C" fn(ctx: *mut c_void) -> c_int,
    /// Nonzero if an old copy of the state can't be opened after a commit.
    pub rollback_resistant: c_int,
}

struct Callbacks(PaveKeystore);

// The app promises its keystore may be called from any thread, one call at
// a time; the wallet serializes calls behind its lock.
unsafe impl Send for Callbacks {}

impl Callbacks {
    fn call(&self, f: extern "C" fn(*mut c_void, *const u8, usize, *mut u8, usize, *mut usize) -> c_int, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; data.len() + 256];
        loop {
            let mut len = 0usize;
            match f(self.0.ctx, data.as_ptr(), data.len(), out.as_mut_ptr(), out.len(), &mut len) {
                0 => {
                    out.truncate(len);
                    return Ok(out);
                }
                1 if len > out.len() => out.resize(len, 0),
                code => return Err(format!("keystore refused ({code})")),
            }
        }
    }
}

impl VaultKeystore for Callbacks {
    fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.call(self.0.seal, data)
    }
    fn commit(&mut self) -> Result<(), String> {
        match (self.0.commit)(self.0.ctx) {
            0 => Ok(()),
            code => Err(format!("keystore commit failed ({code})")),
        }
    }
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, String> {
        self.call(self.0.open, sealed)
    }
    fn rollback_resistant(&self) -> bool {
        self.0.rollback_resistant != 0
    }
}

fn out(v: Value) -> *mut c_char {
    CString::new(v.to_string()).expect("JSON has no NULs").into_raw()
}

fn fail(e: impl std::fmt::Display) -> *mut c_char {
    out(json!({ "ok": false, "error": e.to_string() }))
}

unsafe fn text<'a>(s: *const c_char) -> Result<&'a str, String> {
    if s.is_null() {
        return Err("null string".into());
    }
    CStr::from_ptr(s).to_str().map_err(|e| e.to_string())
}

unsafe fn set_err(err: *mut *mut c_char, e: String) {
    if !err.is_null() {
        *err = fail(e);
    }
}

fn wallet(n: Node) -> *mut PaveWallet {
    Box::into_raw(Box::new(PaveWallet { node: Arc::new(Mutex::new(n)) }))
}

/// This library's version.
#[no_mangle]
pub extern "C" fn pave_version() -> *mut c_char {
    out(json!({ "version": env!("CARGO_PKG_VERSION") }))
}

/// Open the wallet at `path`, sealed by the software keystore beside it.
/// Null on failure, with the error in `*err` if `err` isn't null.
///
/// # Safety
/// `path` is a NUL-terminated string; `err` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn pave_open(path: *const c_char, err: *mut *mut c_char) -> *mut PaveWallet {
    match text(path).and_then(|p| Node::load(Path::new(p))) {
        Ok(n) => wallet(n),
        Err(e) => {
            set_err(err, e);
            std::ptr::null_mut()
        }
    }
}

/// Open the wallet at `path`, sealed by the app's keystore.
///
/// # Safety
/// As [`pave_open`]; `ks`'s callbacks stay valid while the wallet is open.
#[no_mangle]
pub unsafe extern "C" fn pave_open_with(path: *const c_char, ks: PaveKeystore, err: *mut *mut c_char) -> *mut PaveWallet {
    match text(path).and_then(|p| Node::load_with(Path::new(p), Box::new(Callbacks(ks)))) {
        Ok(n) => wallet(n),
        Err(e) => {
            set_err(err, e);
            std::ptr::null_mut()
        }
    }
}

/// Start joining a town: make this device's keys and return the join
/// request to take to the town, `{"request": hex, "challenge": hex}`. For
/// a class that needs it, have the platform attest a hardware key with
/// `challenge` and add it with [`pave_join_attest`] before sending. The keys
/// stay in the returned handle, in memory, until [`pave_join_finish`].
///
/// # Safety
/// `request_out` is writable; free the string it gets.
#[no_mangle]
pub unsafe extern "C" fn pave_join_begin(request_out: *mut *mut c_char) -> *mut PaveJoin {
    let (pending, join) = PendingJoin::generate();
    if !request_out.is_null() {
        *request_out = out(request(&join));
    }
    Box::into_raw(Box::new(PaveJoin { pending, join }))
}

/// Add the platform's attestation to a join, returning the request to send
/// in its place. `json` is `{"android": {"chain": [hex, ...]}}`, the
/// attested key's certificate chain leaf first, or `{"apple": {"object":
/// hex, "key_id": hex}}`, App Attest's attestation object and key id.
///
/// # Safety
/// `join` came from [`pave_join_begin`] and isn't finished; `json` is
/// NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn pave_join_attest(join: *mut PaveJoin, json_in: *const c_char) -> *mut c_char {
    if join.is_null() {
        return fail("null join");
    }
    let r = (|| -> Result<Value, String> {
        let v: Value = serde_json::from_str(text(json_in)?).map_err(|e| format!("bad json: {e}"))?;
        (*join).join.attestation = Some(attestation(&v)?);
        Ok(request(&(*join).join))
    })();
    match r {
        Ok(v) => out(v),
        Err(e) => fail(e),
    }
}

/// Finish joining with the town's `reply` (hex), creating the wallet at
/// `path` sealed by the app's keystore. Consumes `join`, whatever happens.
///
/// # Safety
/// `join` came from [`pave_join_begin`] and isn't used again; strings are
/// NUL-terminated; `ks` as in [`pave_open_with`].
#[no_mangle]
pub unsafe extern "C" fn pave_join_finish(join: *mut PaveJoin, reply: *const c_char, name: *const c_char, path: *const c_char, ks: PaveKeystore, err: *mut *mut c_char) -> *mut PaveWallet {
    if join.is_null() {
        set_err(err, "null join".into());
        return std::ptr::null_mut();
    }
    let j = Box::from_raw(join);
    let r = (|| {
        let bytes = hex::decode(text(reply)?).map_err(|e| e.to_string())?;
        let e: Enrollment = ciborium::from_reader(bytes.as_slice()).map_err(|e| e.to_string())?;
        Node::finish_enrollment_with(j.pending, &e, text(name)?, Path::new(text(path)?), Box::new(Callbacks(ks)))
    })();
    match r {
        Ok(n) => wallet(n),
        Err(e) => {
            set_err(err, e);
            std::ptr::null_mut()
        }
    }
}

/// Run one JSON command, such as `{"cmd": "whoami"}`. Returns a JSON object
/// with `"ok": true` and the result, or `"ok": false` and an `"error"`. The
/// wallet saves after each command that changes it.
///
/// # Safety
/// `w` came from an open call and isn't closed; `json` is NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn pave_call(w: *mut PaveWallet, json_in: *const c_char) -> *mut c_char {
    if w.is_null() {
        return fail("null wallet");
    }
    let v: Value = match text(json_in).and_then(|t| serde_json::from_str(t).map_err(|e| format!("bad json: {e}"))) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let node = &(*w).node;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| command(node, &v))) {
        Ok(Ok(mut r)) => {
            r["ok"] = json!(true);
            out(r)
        }
        Ok(Err(e)) => fail(e),
        Err(_) => fail("the wallet panicked on that command"),
    }
}

/// Free a string this library returned.
///
/// # Safety
/// `s` came from this library and isn't freed twice.
#[no_mangle]
pub unsafe extern "C" fn pave_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Save and close a wallet.
///
/// # Safety
/// `w` came from an open call and isn't used again.
#[no_mangle]
pub unsafe extern "C" fn pave_close(w: *mut PaveWallet) {
    if !w.is_null() {
        let w = Box::from_raw(w);
        let _ = w.node.lock().map(|n| n.save());
    }
}
