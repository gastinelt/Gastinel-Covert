//! Browser extension native messaging host protocol and domain-strict matcher.

use covert_core::models::{Category, VaultItem};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryMessage {
    pub r#type: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryResponse {
    pub status: String,
    pub matches: Vec<MatchEntry>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchEntry {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
}

pub struct NativeMessagingHost;

impl NativeMessagingHost {
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

    /// Extract normalized domain/host from URL string.
    pub fn extract_host(url: &str) -> Option<String> {
        let clean = url.trim();
        let without_proto = if let Some(pos) = clean.find("://") {
            &clean[pos + 3..]
        } else {
            clean
        };
        let host_part = without_proto.split('/').next()?.split(':').next()?;
        if host_part.is_empty() {
            None
        } else {
            Some(host_part.to_lowercase())
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
}
