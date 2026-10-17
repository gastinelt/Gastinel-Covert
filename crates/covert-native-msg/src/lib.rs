//! Gastinel Covert Native Messaging Host (`covert-native-msg`).
//!
//! Provides:
//! - 32-bit native-endian length-prefixed JSON stdio wire protocol for Chrome/Firefox/Edge/Brave extensions.
//! - Domain-strict anti-phishing filter against Category::Web vault credentials.
//! - Strict vault lock state machine: returns `{"status": "locked", "matches": []}` when locked.

pub mod error;
pub mod host;

pub use error::NativeMsgError;
pub use host::{
    MatchEntry, NativeMessagingHost, NativeMessagingManifest, QueryMessage, QueryResponse,
    DEFAULT_ALLOWED_ORIGIN, DEFAULT_EXTENSION_ID, DEFAULT_MANIFEST_NAME, MAX_MESSAGE_SIZE,
};

