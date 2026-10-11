//! Gastinel Covert Core Cryptographic Engine & Binary Vault Format.

// The cryptographic core handles attacker-controlled vault bytes; it must contain no `unsafe`.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod header;
pub mod models;

pub use error::{CryptoError, HeaderError, VaultError};
pub use header::{
    Argon2Params, Header, VaultHeader, CIPHER_ALGO_XCHACHA20_POLY1305, DEFAULT_M_COST,
    DEFAULT_P_COST, DEFAULT_T_COST, FORMAT_VERSION, HEADER_SIZE, KDF_ALGO_ARGON2ID, MAGIC,
    MAX_CIPHERTEXT_LEN, MAX_M_COST, MAX_P_COST, MAX_T_COST, MIN_M_COST, MIN_P_COST, MIN_T_COST,
    NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};
pub use models::{
    ApiKeyData, Category, SshKeyData, Vault, VaultItem, VaultMetadata, VaultSecurity,
};
pub use secrecy::{ExposeSecret, SecretString};

pub type Result<T> = std::result::Result<T, VaultError>;
