//! Error types for Gastinel Covert authentication, lockout, TOTP, and clipboard guard.

use std::time::Duration;
use thiserror::Error;

/// Top-level error type for `covert-auth`.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid master password or vault data corrupted")]
    InvalidMasterPassword,

    #[error("Invalid TOTP code")]
    InvalidTotpCode,

    #[error("TOTP code already used in this timestep (replay detected)")]
    TotpCodeReplayed,

    #[error("TOTP not configured in vault")]
    TotpNotConfigured,

    #[error("Lockout active: remaining {0:?}")]
    LockoutActive(Duration),

    #[error("Clock rollback detected: system time is earlier than last recorded event")]
    ClockRollbackDetected,

    #[error("Invalid Tier-2 master view password")]
    InvalidTier2Password,

    #[error("Tier-2 master view password not configured in vault")]
    Tier2NotConfigured,

    #[error("Emergency recovery code is invalid")]
    InvalidRecoveryCode,

    #[error("Emergency recovery code has already been consumed")]
    RecoveryCodeConsumed,

    #[error("Clipboard operation error: {0}")]
    Clipboard(String),

    #[error("Vault error: {0}")]
    Vault(#[from] covert_core::error::VaultError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] covert_core::error::CryptoError),

    #[error("Lockout error: {0}")]
    Lockout(#[from] LockoutError),

    #[error("TOTP error: {0}")]
    Totp(#[from] TotpError),

    #[error("Clipboard error: {0}")]
    ClipboardErr(#[from] ClipboardError),

    #[error("Storage error: {0}")]
    Storage(#[from] covert_storage::StorageError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors occurring during TOTP calculation or verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("Candidate code length does not match expected digits ({expected}, got {actual})")]
    InvalidLength { expected: u32, actual: usize },

    #[error("Candidate code contains non-numeric characters")]
    InvalidCharacters,

    #[error("Invalid Base32 secret string: {0}")]
    InvalidBase32(String),

    #[error("TOTP code does not match within drift window")]
    CodeMismatch,

    #[error("Replayed TOTP code within same timestep")]
    ReplayedCode,

    #[error("HMAC key or computation error")]
    HmacError,

    #[error("Unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Emergency recovery code is invalid or empty")]
    InvalidRecoveryCode,

    #[error("Emergency recovery code was not found or already consumed")]
    RecoveryCodeNotFound,
}

/// Errors occurring during rate limiting and lockout enforcement.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LockoutError {
    #[error("Clock rollback detected: system time is earlier than last recorded event")]
    ClockRollbackDetected,

    #[error("Authentication locked out: remaining {remaining_seconds} seconds")]
    LockedOut { remaining_seconds: u64 },

    #[error("I/O or serialization error operating on lockout record: {0}")]
    Io(String),
}

/// Errors occurring during Win32 clipboard manipulation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClipboardError {
    #[error("Failed to register clipboard format '{format_name}': Win32 error {code}")]
    RegisterFormatFailed { format_name: String, code: u32 },

    #[error("Failed to open clipboard: Win32 error {0}")]
    OpenFailed(u32),

    #[error("Failed to empty clipboard: Win32 error {0}")]
    EmptyFailed(u32),

    #[error("Failed to set clipboard data: Win32 error {0}")]
    SetDataFailed(u32),

    #[error("Global memory allocation failed: Win32 error {0}")]
    MemoryAllocationFailed(u32),

    #[error("Global memory lock failed")]
    MemoryLockFailed,

    #[error("Clipboard sequence number mismatch (external modification detected)")]
    SequenceMismatch,
}
