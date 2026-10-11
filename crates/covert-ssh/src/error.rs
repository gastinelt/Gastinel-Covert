//! Error types for the covert-ssh crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SshAgentError {
    #[error("Named pipe error: {0}")]
    PipeError(String),

    #[error("Protocol wire format error: {0}")]
    ProtocolError(String),

    #[error("Key error: {0}")]
    KeyError(String),

    #[error("Vault is locked: SSH agent operations refused")]
    VaultLocked,

    #[error("Requested key not found in agent")]
    KeyNotFound,

    #[error("Signature error: {0}")]
    SignatureError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
