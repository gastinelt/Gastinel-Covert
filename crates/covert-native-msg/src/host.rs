//! Browser Extension Native Messaging Host wire protocol and domain-strict anti-phishing engine.

use crate::error::NativeMsgError;
use covert_core::models::{Category, Vault, VaultItem};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

/// Maximum allowed Native Messaging payload size (1 MB).
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Incoming query request from browser extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryMessage {
    pub r#type: String,
    pub url: String,
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

/// Native Messaging Host state managing domain filtering and stdio communication.
pub struct NativeMessagingHost {
    is_vault_unlocked: AtomicBool,
    vault: RwLock<Option<Vault>>,
}

impl Default for NativeMessagingHost {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeMessagingHost {
    /// Create a new host instance in locked state.
    pub fn new() -> Self {
        Self {
            is_vault_unlocked: AtomicBool::new(false),
            vault: RwLock::new(None),
        }
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
