//! Gastinel Covert Native Messaging Host (`covert-native-msg`).
//!
//! Provides:
//! - 32-bit native-endian length-prefixed JSON stdio wire protocol for Chrome/Firefox/Edge/Brave extensions.
//! - Domain-strict anti-phishing filter against Category::Web vault credentials.
//! - Strict vault lock state machine: returns `{"status": "locked", "matches": []}` when locked.

// Parses untrusted length-prefixed frames from the browser; it must contain no `unsafe`.
#![forbid(unsafe_code)]

pub mod error;
pub mod host;

pub use error::NativeMsgError;
pub use host::{
    MatchEntry, NativeMessagingHost, QueryMessage, QueryResponse, MAX_MESSAGE_SIZE,
};
