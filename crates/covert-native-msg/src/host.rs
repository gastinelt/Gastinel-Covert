//! Browser Extension Native Messaging Host wire protocol and domain-strict anti-phishing engine.

use crate::error::NativeMsgError;
use covert_core::models::{Category, Vault, VaultItem};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

/// Maximum allowed Native Messaging payload size (1 MB).
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Default whitelisted Gastinel Covert Chromium/Edge/Brave extension ID (32 lowercase letters).
pub const DEFAULT_EXTENSION_ID: &str = "gastinelcovertextensionidaaaaaaa";

/// Default whitelisted Native Messaging caller origin.
pub const DEFAULT_ALLOWED_ORIGIN: &str = "chrome-extension://gastinelcovertextensionidaaaaaaa/";

/// Official Native Messaging Host manifest identifier.
pub const DEFAULT_MANIFEST_NAME: &str = "com.gastinel.covert";

/// Native Messaging Host manifest file structure (`com.gastinel.covert.json`) enforcing
/// strict `allowed_origins` whitelisting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeMessagingManifest {
    pub name: String,
    pub description: String,
    pub path: String,
    pub r#type: String,
    pub allowed_origins: Vec<String>,
}

impl NativeMessagingManifest {
    /// Constructs a validated Native Messaging manifest with an explicit `allowed_origins` whitelist.
    pub fn new(host_exe_path: &str, allowed_origins: Vec<String>) -> Result<Self, NativeMsgError> {
        if host_exe_path.trim().is_empty() {
            return Err(NativeMsgError::InvalidManifest(
                "Host executable path cannot be empty".to_string(),
            ));
        }
        if allowed_origins.is_empty() {
            return Err(NativeMsgError::InvalidManifest(
                "allowed_origins whitelist cannot be empty".to_string(),
            ));
        }

        let mut normalized_origins = Vec::with_capacity(allowed_origins.len());
        for origin in allowed_origins {
            let norm = NativeMessagingHost::normalize_origin(&origin).ok_or_else(|| {
                NativeMsgError::InvalidManifest(format!(
                    "Invalid or unsafe extension origin in allowed_origins: {}",
                    origin
                ))
            })?;
            if !normalized_origins.contains(&norm) {
                normalized_origins.push(norm);
            }
        }

        Ok(Self {
            name: DEFAULT_MANIFEST_NAME.to_string(),
            description: "Gastinel Covert Zero-Trust Password Manager Native Messaging Host"
                .to_string(),
            path: host_exe_path.to_string(),
            r#type: "stdio".to_string(),
            allowed_origins: normalized_origins,
        })
    }

    /// Serializes the manifest to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, NativeMsgError> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Incoming query request from browser extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryMessage {
    pub r#type: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

/// Outgoing query response to browser extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryResponse {
    pub status: String,
    pub matches: Vec<MatchEntry>,
}

/// Credential match metadata returned to extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchEntry {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
}

/// Native Messaging Host state managing extension origin whitelisting, caller verification,
/// domain filtering, and stdio communication.
pub struct NativeMessagingHost {
    is_vault_unlocked: AtomicBool,
    vault: RwLock<Option<Vault>>,
    allowed_origins: RwLock<Vec<String>>,
    require_caller_auth: AtomicBool,
    caller_authorized: AtomicBool,
}

impl Default for NativeMessagingHost {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeMessagingHost {
    /// Create a new host instance in locked state with the default extension whitelist.
    pub fn new() -> Self {
        Self {
            is_vault_unlocked: AtomicBool::new(false),
            vault: RwLock::new(None),
            allowed_origins: RwLock::new(vec![DEFAULT_ALLOWED_ORIGIN.to_string()]),
            require_caller_auth: AtomicBool::new(false),
            caller_authorized: AtomicBool::new(false),
        }
    }

    /// Create a new host instance enforcing strict caller verification against the provided
    /// whitelist of extension IDs or `chrome-extension://<id>/` origins.
    pub fn with_allowed_origins(origins: Vec<String>) -> Result<Self, NativeMsgError> {
        let host = Self::new();
        host.set_allowed_origins(origins)?;
        host.require_caller_auth.store(true, Ordering::SeqCst);
        Ok(host)
    }

    /// Validates that an extension ID is a strict 32-character lowercase ASCII identifier
    /// without wildcards, path separators, or whitespace.
    pub fn is_valid_extension_id(id: &str) -> bool {
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    }

    /// Normalizes a raw extension ID or `chrome-extension://<id>/` URL into canonical
    /// `"chrome-extension://<id>/"` form, returning `None` if invalid or containing wildcards.
    pub fn normalize_origin(origin_or_id: &str) -> Option<String> {
        let trimmed = origin_or_id.trim();
        if trimmed.is_empty() || trimmed.contains('*') {
            return None;
        }
        let id = if let Some(rest) = trimmed.strip_prefix("chrome-extension://") {
            rest.strip_suffix('/').unwrap_or(rest)
        } else {
            trimmed
        };
        if Self::is_valid_extension_id(id) {
            Some(format!("chrome-extension://{}/", id))
        } else {
            None
        }
    }

    /// Returns the currently configured `allowed_origins` whitelist.
    pub fn allowed_origins(&self) -> Vec<String> {
        self.allowed_origins.read().unwrap().clone()
    }

    /// Replaces the `allowed_origins` whitelist after validating every entry.
    pub fn set_allowed_origins(&self, origins: Vec<String>) -> Result<(), NativeMsgError> {
        if origins.is_empty() {
            return Err(NativeMsgError::InvalidManifest(
                "allowed_origins whitelist cannot be empty".to_string(),
            ));
        }
        let mut normalized = Vec::with_capacity(origins.len());
        for orig in origins {
            let norm = Self::normalize_origin(&orig).ok_or_else(|| {
                NativeMsgError::InvalidManifest(format!("Invalid extension origin: {}", orig))
            })?;
            if !normalized.contains(&norm) {
                normalized.push(norm);
            }
        }
        let mut guard = self.allowed_origins.write().unwrap();
        *guard = normalized;
        self.caller_authorized.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Enables or disables mandatory session-level or per-message caller origin verification.
    pub fn set_require_caller_auth(&self, require: bool) {
        self.require_caller_auth.store(require, Ordering::SeqCst);
    }

    /// Checks whether a candidate extension ID or `chrome-extension://<id>/` origin is in the whitelist.
    pub fn is_origin_whitelisted(&self, origin_or_id: &str) -> bool {
        let norm = match Self::normalize_origin(origin_or_id) {
            Some(n) => n,
            None => return false,
        };
        let guard = self.allowed_origins.read().unwrap();
        guard.iter().any(|allowed| allowed == &norm)
    }

    /// Verifies the calling extension's origin (passed by the browser on the command line or handshake)
    /// against the `allowed_origins` whitelist.
    pub fn verify_caller(&self, caller_origin: &str) -> Result<(), NativeMsgError> {
        self.require_caller_auth.store(true, Ordering::SeqCst);
        if self.is_origin_whitelisted(caller_origin) {
            self.caller_authorized.store(true, Ordering::SeqCst);
            Ok(())
        } else {
            self.caller_authorized.store(false, Ordering::SeqCst);
            Err(NativeMsgError::UnauthorizedCaller(
                caller_origin.to_string(),
            ))
        }
    }

    /// Generates a validated `NativeMessagingManifest` (`allowed_origins`) for this host.
    pub fn generate_manifest(
        &self,
        host_exe_path: &str,
    ) -> Result<NativeMessagingManifest, NativeMsgError> {
        NativeMessagingManifest::new(host_exe_path, self.allowed_origins())
    }

    /// Update vault instance and unlock host.
    pub fn set_vault(&self, vault: Vault) {
        let mut guard = self.vault.write().unwrap();
        *guard = Some(vault);
        self.is_vault_unlocked.store(true, Ordering::SeqCst);
    }

    /// Clear vault and lock host.
    pub fn lock(&self) {
        self.is_vault_unlocked.store(false, Ordering::SeqCst);
        let mut guard = self.vault.write().unwrap();
        *guard = None;
    }

    /// Check if host is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.is_vault_unlocked.load(Ordering::SeqCst)
    }

    /// Encode a JSON string frame with 32-bit native-endian length prefix.
    pub fn encode_string_message(json_str: &str) -> Vec<u8> {
        let json_bytes = json_str.as_bytes();
        let len = json_bytes.len() as u32;
        let mut frame = Vec::with_capacity(4 + json_bytes.len());
        frame.extend_from_slice(&len.to_ne_bytes());
        frame.extend_from_slice(json_bytes);
        frame
    }

    /// Decode frame from 32-bit native-endian length prefix.
    pub fn decode_message(data: &[u8]) -> Option<&str> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return None;
        }
        std::str::from_utf8(&data[4..4 + len]).ok()
    }

    /// Read a single length-prefixed frame from an input stream.
    pub fn read_frame<R: Read>(reader: &mut R) -> Result<String, NativeMsgError> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let len = u32::from_ne_bytes(len_buf) as usize;

        if len > MAX_MESSAGE_SIZE {
            return Err(NativeMsgError::MessageTooLarge(len));
        }

        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload)?;

        String::from_utf8(payload)
            .map_err(|e| NativeMsgError::Framing(format!("Invalid UTF-8 payload: {}", e)))
    }

    /// Write a single length-prefixed frame to an output stream.
    pub fn write_frame<W: Write>(writer: &mut W, json_str: &str) -> Result<(), NativeMsgError> {
        let bytes = json_str.as_bytes();
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(NativeMsgError::MessageTooLarge(bytes.len()));
        }
        let len = bytes.len() as u32;
        writer.write_all(&len.to_ne_bytes())?;
        writer.write_all(bytes)?;
        writer.flush()?;
        Ok(())
    }

    /// Extract normalized domain/host from URL string.
    pub fn extract_host(url: &str) -> Option<String> {
        let clean = url.trim();
        let without_proto = if let Some(pos) = clean.find("://") {
            &clean[pos + 3..]
        } else {
            clean
        };

        // Split off path, query string, and fragment
        let authority = without_proto
            .split(|c| c == '/' || c == '?' || c == '#')
            .next()?;

        // Strip userinfo (e.g. "username:password@actual-host.com")
        let host_and_port = if let Some(at_pos) = authority.rfind('@') {
            &authority[at_pos + 1..]
        } else {
            authority
        };

        if host_and_port.is_empty() {
            return None;
        }

        // Handle IPv6 bracket notation [::1]:8080
        let host_str = if host_and_port.starts_with('[') {
            if let Some(end_bracket) = host_and_port.find(']') {
                &host_and_port[1..end_bracket]
            } else {
                return None;
            }
        } else {
            // Strip port number (e.g. "example.com:8080" -> "example.com")
            host_and_port.split(':').next()?
        };

        let trimmed_host = host_str.trim_end_matches('.');
        if trimmed_host.is_empty() {
            None
        } else {
            Some(trimmed_host.to_lowercase())
        }
    }

    /// Evaluate domain-strict matching rule.
    ///
    /// Rules:
    /// - Only matches items with Category::Web
    /// - Exact match between normalized domain names
    /// - Rejects substring matches (e.g. "evil-google.com" vs "google.com")
    /// - Rejects non-exact subdomain matches (e.g. "phish.bank.com" vs "bank.com") unless equal
    pub fn is_domain_match(item: &VaultItem, target_url: &str) -> bool {
        if item.category != Category::Web {
            return false;
        }
        let item_url = match &item.url {
            Some(u) => u,
            None => return false,
        };

        let target_host = match Self::extract_host(target_url) {
            Some(h) => h,
            None => return false,
        };
        let item_host = match Self::extract_host(item_url) {
            Some(h) => h,
            None => return false,
        };

        item_host == target_host
    }

    /// Process a raw JSON string query and generate JSON response string.
    ///
    /// Enforces caller verification:
    /// - Any `"origin"` or `"extension_id"` field in the payload must match `allowed_origins`.
    /// - When strict caller authentication is active (`with_allowed_origins`, `set_require_caller_auth(true)`,
    ///   or after `verify_caller`), unverified callers without a valid whitelisted origin are rejected.
    pub fn handle_json_message(&self, message_str: &str) -> String {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(message_str);
        let val = match parsed {
            Ok(v) => v,
            Err(e) => {
                return serde_json::json!({
                    "status": "error",
                    "message": format!("Invalid JSON: {}", e)
                })
                .to_string();
            }
        };

        let msg_origin = val
            .get("origin")
            .or_else(|| val.get("extension_id"))
            .and_then(|v| v.as_str());

        if let Some(candidate_origin) = msg_origin {
            if !self.is_origin_whitelisted(candidate_origin) {
                return serde_json::json!({
                    "status": "error",
                    "message": format!("Unauthorized caller origin: {}", candidate_origin)
                })
                .to_string();
            }
        } else if self.require_caller_auth.load(Ordering::SeqCst)
            && !self.caller_authorized.load(Ordering::SeqCst)
        {
            return serde_json::json!({
                "status": "error",
                "message": "Unauthorized caller: extension origin not verified"
            })
            .to_string();
        }

        let msg_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match msg_type {
            "query" => {
                let url = val.get("url").and_then(|v| v.as_str()).unwrap_or("");
                self.handle_query(url)
            }
            "status" => {
                serde_json::json!({
                    "status": "ok",
                    "unlocked": self.is_unlocked()
                })
                .to_string()
            }
            other => serde_json::json!({
                "status": "error",
                "message": format!("Unknown message type: {}", other)
            })
            .to_string(),
        }
    }

    fn handle_query(&self, target_url: &str) -> String {
        if !self.is_unlocked() {
            return serde_json::json!({
                "status": "locked",
                "matches": []
            })
            .to_string();
        }

        let guard = self.vault.read().unwrap();
        let vault = match guard.as_ref() {
            Some(v) => v,
            None => {
                return serde_json::json!({
                    "status": "locked",
                    "matches": []
                })
                .to_string();
            }
        };

        let mut matches = Vec::new();
        for item in vault.items_by_category(Category::Web) {
            if Self::is_domain_match(item, target_url) {
                matches.push(MatchEntry {
                    id: hex::encode(item.id),
                    title: item.title.clone(),
                    username: item.username.clone(),
                });
            }
        }

        let resp = QueryResponse {
            status: "ok".to_string(),
            matches,
        };

        serde_json::to_string(&resp).unwrap_or_else(|_| {
            serde_json::json!({ "status": "error", "message": "Serialization failure" }).to_string()
        })
    }

    /// Run stdio messaging loop after verifying `caller_origin` against the `allowed_origins` whitelist.
    pub fn run_stdio_loop_for_caller<R: Read, W: Write>(
        &self,
        caller_origin: &str,
        reader: R,
        writer: W,
    ) -> Result<(), NativeMsgError> {
        self.verify_caller(caller_origin)?;
        self.run_stdio_loop(reader, writer)
    }

    /// Run stdio messaging loop until EOF or IO error.
    pub fn run_stdio_loop<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<(), NativeMsgError> {
        loop {
            let msg = match Self::read_frame(&mut reader) {
                Ok(m) => m,
                Err(NativeMsgError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(e) => return Err(e),
            };

            let response = self.handle_json_message(&msg);
            Self::write_frame(&mut writer, &response)?;
        }
        Ok(())
    }
}

impl covert_sentinel::SecurityEventSink for NativeMessagingHost {
    fn on_security_alert(&self, _event: covert_sentinel::SecurityEvent) {
        self.lock();
    }
}

mod hex {
    pub fn encode(bytes: [u8; 16]) -> String {
        let mut s = String::with_capacity(32);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host() {
        assert_eq!(
            NativeMessagingHost::extract_host("https://google.com/path"),
            Some("google.com".to_string())
        );
        assert_eq!(
            NativeMessagingHost::extract_host("http://sub.domain.org:8080/foo"),
            Some("sub.domain.org".to_string())
        );
        assert_eq!(
            NativeMessagingHost::extract_host("https://UPPERCASE.COM/"),
            Some("uppercase.com".to_string())
        );
    }

    #[test]
    fn test_domain_strict_matching() {
        let item = VaultItem::new_credential(
            "Google Login",
            "user@gmail.com",
            "secret",
            Some("https://google.com/login".to_string()),
        );

        assert!(NativeMessagingHost::is_domain_match(&item, "https://google.com/other"));
        assert!(NativeMessagingHost::is_domain_match(&item, "http://google.com:443"));
        assert!(!NativeMessagingHost::is_domain_match(&item, "https://evil-google.com/login"));
        assert!(!NativeMessagingHost::is_domain_match(&item, "https://sub.google.com/"));
    }
}
