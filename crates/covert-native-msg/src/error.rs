//! Error types for the covert-native-msg crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NativeMsgError {
    #[error("Framing error: {0}")]
    Framing(String),

    #[error("Message exceeds maximum allowed size ({0} > 1MB)")]
    MessageTooLarge(usize),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Host error: {0}")]
    Host(String),

    #[error("Unauthorized caller extension origin: {0}")]
    UnauthorizedCaller(String),

    #[error("Invalid Native Messaging manifest configuration: {0}")]
    InvalidManifest(String),
}
