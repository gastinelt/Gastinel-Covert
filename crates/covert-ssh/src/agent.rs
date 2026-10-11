//! OpenSSH Agent core request processing, identity tracking, and vault lock state machine.

use crate::keys::SshKeyEntry;
use crate::pipe::DEFAULT_SSH_PIPE_NAME;
use crate::protocol::{
    WireStream, SSH_AGENTC_REMOVE_ALL_IDENTITIES, SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENTC_SIGN_REQUEST, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_SIGN_RESPONSE, SSH_AGENT_SUCCESS,
};
use covert_core::models::{Category, Vault};
use covert_sentinel::{SecurityEvent, SecurityEventSink};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

/// Core OpenSSH Agent service coordinating keys and cryptographic requests.
#[derive(Debug)]
pub struct SshAgent {
    is_vault_unlocked: AtomicBool,
    keys: RwLock<Vec<SshKeyEntry>>,
    pipe_name: String,
}

impl Default for SshAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAgent {
    /// Create a new SshAgent defaulting to locked state and default named pipe.
    pub fn new() -> Self {
        Self {
            is_vault_unlocked: AtomicBool::new(false),
            keys: RwLock::new(Vec::new()),
            pipe_name: DEFAULT_SSH_PIPE_NAME.to_string(),
        }
    }

    /// Create agent with custom pipe name (useful for testing).
    pub fn with_pipe_name(pipe_name: impl Into<String>) -> Self {
        Self {
            is_vault_unlocked: AtomicBool::new(false),
            keys: RwLock::new(Vec::new()),
            pipe_name: pipe_name.into(),
        }
    }

    /// Check if the agent is in unlocked state.
    pub fn is_unlocked(&self) -> bool {
        self.is_vault_unlocked.load(Ordering::SeqCst)
    }

    /// Update unlock state.
    pub fn set_unlocked(&self, unlocked: bool) {
        self.is_vault_unlocked.store(unlocked, Ordering::SeqCst);
        if !unlocked {
            self.clear_keys();
        }
    }

    /// Populate agent keys from decrypted Vault SSH items.
    pub fn load_vault_keys(&self, vault: &Vault) {
        let mut key_entries = Vec::new();
        for item in vault.items_by_category(Category::SSH) {
            if let Some(ssh_data) = &item.ssh_data {
                key_entries.push(SshKeyEntry::from_ssh_data(ssh_data, &item.title));
            }
        }
        let mut keys_guard = self.keys.write().unwrap();
        *keys_guard = key_entries;
        self.is_vault_unlocked.store(true, Ordering::SeqCst);
    }

    /// Add an explicit key entry.
    pub fn add_key(&self, key: SshKeyEntry) {
        let mut keys_guard = self.keys.write().unwrap();
        keys_guard.push(key);
    }

    /// Clear all in-memory keys and drop credentials.
    pub fn clear_keys(&self) {
        let mut keys_guard = self.keys.write().unwrap();
        keys_guard.clear();
    }

    /// Lock agent and wipe all sensitive keys immediately.
    pub fn lock_and_zeroize(&self) {
        self.set_unlocked(false);
    }

    /// Process a raw OpenSSH Wire protocol request byte sequence and generate response.
    ///
    /// If the vault is locked, returns `SSH_AGENT_FAILURE` unconditionally.
    pub fn process_request(&self, request_bytes: &[u8]) -> Vec<u8> {
        if !self.is_unlocked() {
            return WireStream::encode_frame(SSH_AGENT_FAILURE, &[]);
        }

        let (msg_code, payload) = match WireStream::decode_frame(request_bytes) {
            Some(frame) => frame,
            None => return WireStream::encode_frame(SSH_AGENT_FAILURE, &[]),
        };

        match msg_code {
            SSH_AGENTC_REQUEST_IDENTITIES => self.handle_request_identities(),
            SSH_AGENTC_SIGN_REQUEST => self.handle_sign_request(payload),
            SSH_AGENTC_REMOVE_ALL_IDENTITIES => {
                self.clear_keys();
                WireStream::encode_frame(SSH_AGENT_SUCCESS, &[])
            }
            _ => WireStream::encode_frame(SSH_AGENT_FAILURE, &[]),
        }
    }

    fn handle_request_identities(&self) -> Vec<u8> {
        let keys_guard = self.keys.read().unwrap();
        let mut payload = Vec::new();

        WireStream::write_u32(&mut payload, keys_guard.len() as u32);
        for key in keys_guard.iter() {
            WireStream::write_string(&mut payload, &key.public_key_blob);
            WireStream::write_string(&mut payload, key.comment.as_bytes());
        }

        WireStream::encode_frame(SSH_AGENT_IDENTITIES_ANSWER, &payload)
    }

    fn handle_sign_request(&self, payload: &[u8]) -> Vec<u8> {
        let mut cursor = payload;

        let target_key_blob = match WireStream::read_string(&mut cursor) {
            Ok(b) => b,
            Err(_) => return WireStream::encode_frame(SSH_AGENT_FAILURE, &[]),
        };

        let data_to_sign = match WireStream::read_string(&mut cursor) {
            Ok(d) => d,
            Err(_) => return WireStream::encode_frame(SSH_AGENT_FAILURE, &[]),
        };

        let flags = WireStream::read_u32(&mut cursor).unwrap_or(0);

        let keys_guard = self.keys.read().unwrap();
        let key_opt = keys_guard
            .iter()
            .find(|k| k.public_key_blob == target_key_blob);

        match key_opt {
            Some(key) => match key.sign(data_to_sign, flags) {
                Ok(sig_blob) => WireStream::encode_frame(SSH_AGENT_SIGN_RESPONSE, &sig_blob),
                Err(_) => WireStream::encode_frame(SSH_AGENT_FAILURE, &[]),
            },
            None => WireStream::encode_frame(SSH_AGENT_FAILURE, &[]),
        }
    }

    /// Returns the named pipe path.
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }
}

/// Allows SshAgent to directly subscribe to covert-sentinel security events.
impl SecurityEventSink for SshAgent {
    fn on_security_alert(&self, _event: SecurityEvent) {
        self.lock_and_zeroize();
    }
}
