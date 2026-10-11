//! Error types for the `covert-storage` crate.

use std::path::PathBuf;

/// Result alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Errors occurring during atomic storage, path resolution, and camouflage management.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// A required system environment variable (such as `%LOCALAPPDATA%`) is not set.
    #[error("Required environment variable %{0}% is not set")]
    EnvironmentVariableMissing(&'static str),

    /// Failed to create the directory structure for the vault.
    #[error("Failed to create vault directory '{0}': {1}")]
    DirectoryCreationFailed(PathBuf, std::io::Error),

    /// Standard I/O error during file read or write.
    #[error("I/O error reading or writing vault file: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to explicitly flush hardware disk buffers via Win32 `FlushFileBuffers`.
    #[error("Win32 FlushFileBuffers failed: {0}")]
    FlushFailed(std::io::Error),

    /// Win32 `ReplaceFileW` failed during atomic substitution.
    #[error("Win32 ReplaceFileW failed with OS error code {code}: {message}")]
    AtomicReplaceFailed {
        /// Win32 OS error code (`GetLastError`).
        code: u32,
        /// Formatted OS error message.
        message: String,
    },

    /// Win32 `MoveFileExW` failed during atomic move/rename.
    #[error("Win32 MoveFileExW failed with OS error code {code}: {message}")]
    AtomicMoveFailed {
        /// Win32 OS error code (`GetLastError`).
        code: u32,
        /// Formatted OS error message.
        message: String,
    },

    /// Primary vault file does not exist at the designated path.
    #[error("Vault file not found at '{0}'")]
    VaultNotFound(PathBuf),

    /// Backup vault file does not exist at the designated path.
    #[error("Backup file not found at '{0}'")]
    BackupNotFound(PathBuf),

    /// Error originating from core cryptographic operations.
    #[error("Core cryptographic error: {0}")]
    Core(#[from] covert_core::VaultError),
}
