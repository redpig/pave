//! The UniFFI interface (`pave.udl`): the same wallet as the C interface,
//! for Kotlin and Swift without hand-written glue.

use pave_board::commands::command;
use pave_board::node::{Enrollment, Join as JoinRequest, Node, PendingJoin};
use pave_board::vault::Keystore as VaultKeystore;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum PaveError {
    #[error("{message}")]
    Failed { message: String },
}

impl From<String> for PaveError {
    fn from(message: String) -> Self {
        PaveError::Failed { message }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PaveError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        PaveError::Failed { message: e.reason }
    }
}

/// The app's keystore, as UniFFI hands it over.
pub trait Keystore: Send + Sync {
    fn seal(&self, data: Vec<u8>) -> Result<Vec<u8>, PaveError>;
    fn open(&self, sealed: Vec<u8>) -> Result<Vec<u8>, PaveError>;
    fn commit(&self) -> Result<(), PaveError>;
    fn rollback_resistant(&self) -> bool;
}

struct AppKeystore(Box<dyn Keystore>);

impl VaultKeystore for AppKeystore {
    fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.0.seal(data.to_vec()).map_err(|e| e.to_string())
    }
    fn commit(&mut self) -> Result<(), String> {
        self.0.commit().map_err(|e| e.to_string())
    }
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, String> {
        self.0.open(sealed.to_vec()).map_err(|e| e.to_string())
    }
    fn rollback_resistant(&self) -> bool {
        self.0.rollback_resistant()
    }
}

pub fn version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

pub struct Join {
    state: Mutex<Option<(PendingJoin, JoinRequest)>>,
}

fn request(j: &JoinRequest) -> String {
    json!({
        "request": hex::encode(pave_kernel::hash::encode(j)),
        "challenge": hex::encode(pave_board::attest::challenge(j)),
    })
    .to_string()
}

impl Join {
    pub fn new() -> Self {
        Join {
            state: Mutex::new(Some(PendingJoin::generate())),
        }
    }

    pub fn request(&self) -> String {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .map(|(_, j)| request(j))
            .unwrap_or_else(|| json!({ "error": "this join is finished" }).to_string())
    }

    pub fn attest(&self, attestation_json: String) -> Result<String, PaveError> {
        let v: Value =
            serde_json::from_str(&attestation_json).map_err(|e| format!("bad json: {e}"))?;
        let a = crate::attestation(&v)?;
        let mut st = self.state.lock().unwrap();
        let (_, j) = st.as_mut().ok_or("this join is finished".to_string())?;
        j.attestation = Some(a);
        Ok(request(j))
    }

    pub fn finish(
        &self,
        reply_hex: String,
        name: String,
        path: String,
        keystore: Box<dyn Keystore>,
    ) -> Result<Arc<Wallet>, PaveError> {
        let (pending, _) = self
            .state
            .lock()
            .unwrap()
            .take()
            .ok_or("this join is finished".to_string())?;
        let bytes = hex::decode(reply_hex).map_err(|e| e.to_string())?;
        let e: Enrollment = ciborium::from_reader(bytes.as_slice()).map_err(|e| e.to_string())?;
        let n = Node::finish_enrollment_with(
            pending,
            &e,
            &name,
            Path::new(&path),
            Box::new(AppKeystore(keystore)),
        )?;
        Ok(Arc::new(Wallet {
            node: Arc::new(Mutex::new(n)),
        }))
    }
}

impl Default for Join {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Wallet {
    node: Arc<Mutex<Node>>,
}

impl Wallet {
    pub fn open(path: String, keystore: Box<dyn Keystore>) -> Result<Self, PaveError> {
        let n = Node::load_with(Path::new(&path), Box::new(AppKeystore(keystore)))?;
        Ok(Wallet {
            node: Arc::new(Mutex::new(n)),
        })
    }

    pub fn call(&self, json_in: String) -> String {
        let v: Value = match serde_json::from_str(&json_in) {
            Ok(v) => v,
            Err(e) => return json!({ "ok": false, "error": format!("bad json: {e}") }).to_string(),
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| command(&self.node, &v))) {
            Ok(Ok(mut r)) => {
                r["ok"] = json!(true);
                r.to_string()
            }
            Ok(Err(e)) => json!({ "ok": false, "error": e }).to_string(),
            Err(_) => {
                json!({ "ok": false, "error": "the wallet panicked on that command" }).to_string()
            }
        }
    }

    pub fn save(&self) -> Result<(), PaveError> {
        Ok(self.node.lock().unwrap().save()?)
    }
}
