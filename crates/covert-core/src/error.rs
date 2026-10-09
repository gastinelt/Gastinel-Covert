//! Error types for covert-core.

use thiserror::Error;

/// High-level errors encountered when operating on a Vault.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Errors originating from binary header parsing, validation, or truncation.
    #[error("Header error: {0}")]
    Header(#[from] HeaderError),

    /// Errors originating from cryptographic operations (KDF, AEAD, MAC).
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    /// Errors during serialization or deserialization of vault payload.
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Errors specific to binary header parsing, bounds checking, and layout validation.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum HeaderError {
    /// The input buffer is shorter than the required 88-byte header.
    #[error("Truncated header: expected 88 bytes, found {actual}")]
    TruncatedHeader { actual: usize },

    /// The header magic bytes do not match b"GCOVERT1".
    #[error("Invalid magic identifier: expected b\"GCOVERT1\"")]
    InvalidMagic,

    /// The header format version is not supported.
    #[error("Unsupported format version: {0}")]
    UnsupportedVersion(u16),

    /// The KDF algorithm identifier is not recognized (expected 0x01 for Argon2id).
    #[error("Unsupported KDF algorithm: 0x{0:02X}")]
    UnsupportedKdfAlgo(u8),

    /// The cipher algorithm identifier is not recognized (expected 0x01 for XChaCha20-Poly1305).
    #[error("Unsupported cipher algorithm: 0x{0:02X}")]
    UnsupportedCipherAlgo(u8),

    /// Argon2 m_cost is outside the required safety bounds [65536, 1048576] KiB.
    #[error("Argon2 m_cost {0} out of valid bounds [65536, 1048576]")]
    MCostOutOfRange(u32),

    /// Argon2 t_cost is outside the required safety bounds [2, 15].
    #[error("Argon2 t_cost {0} out of valid bounds [2, 15]")]
    TCostOutOfRange(u32),

    /// Argon2 p_cost is outside the required safety bounds [1, 16].
    #[error("Argon2 p_cost {0} out of valid bounds [1, 16]")]
    PCostOutOfRange(u32),

    /// Ciphertext length exceeds maximum allowable safety limit (64 MiB).
    #[error("Ciphertext length {0} exceeds maximum allowable (64 MiB)")]
    CiphertextTooLarge(u64),

    /// Total file length does not equal expected 88 + ciphertext_len + 16.
    #[error("File length mismatch: expected {expected} bytes, found {actual} bytes")]
    PayloadLengthMismatch { expected: usize, actual: usize },
}

/// Errors specific to cryptographic operations.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum CryptoError {
    /// Argon2 parameter instantiation error.
    #[error("Invalid Argon2 parameters: {0}")]
    Argon2ParamsInvalid(String),

    /// Key derivation failed.
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Derived key length is invalid for the cipher.
    #[error("Invalid encryption key length")]
    InvalidKeyLength,

    /// AEAD encryption operation failed.
    #[error("Encryption failed")]
    EncryptionFailed,

    /// AEAD decryption failed (invalid password, tampered header AAD, or corrupted ciphertext/tag).
    #[error("Authentication failed: invalid password or tampered ciphertext/header")]
    AuthenticationFailed,
}
