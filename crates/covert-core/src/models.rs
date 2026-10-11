//! Domain data structures for Gastinel Covert vaults.

use crate::crypto::{derive_key, encrypt_payload, decrypt_payload, generate_nonce, generate_salt};
use crate::error::VaultError;
use crate::header::{Argon2Params, VaultHeader, HEADER_SIZE};
use rand_core::{OsRng, RngCore};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Current vault schema version.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Supported secret categories in Gastinel Covert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    /// Web logins and browser credentials.
    Web,
    /// SSH private keys, certificates, and passphrases.
    SSH,
    /// API tokens, Bearer tokens, and secrets.
    ApiKey,
    /// Secure encrypted notes.
    Note,
    /// Raw unformatted secrets or binary blobs.
    RawSecret,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::Web => write!(f, "Web"),
            Category::SSH => write!(f, "SSH"),
            Category::ApiKey => write!(f, "ApiKey"),
            Category::Note => write!(f, "Note"),
            Category::RawSecret => write!(f, "RawSecret"),
        }
    }
}

impl Zeroize for Category {
    fn zeroize(&mut self) {
        *self = Category::Web;
    }
}

/// Metadata describing a vault (unencrypted when vault is unlocked in RAM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMetadata {
    /// Unique 16-byte identifier for the vault.
    pub vault_id: [u8; 16],
    /// Human-readable vault name.
    pub name: String,
    /// Vault schema version (currently 1).
    pub schema_version: u32,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
    /// Last modification timestamp (Unix epoch seconds).
    pub modified_at: u64,
}

impl VaultMetadata {
    /// Create new VaultMetadata with fresh random UUID bytes and current timestamp.
    pub fn new(name: impl Into<String>) -> Self {
        let mut vault_id = [0u8; 16];
        OsRng.fill_bytes(&mut vault_id);
        let now = current_timestamp();
        Self {
            vault_id,
            name: name.into(),
            schema_version: CURRENT_SCHEMA_VERSION,
            created_at: now,
            modified_at: now,
        }
    }
}

impl Zeroize for VaultMetadata {
    fn zeroize(&mut self) {
        self.vault_id.zeroize();
        self.name.zeroize();
        self.schema_version.zeroize();
        self.created_at.zeroize();
        self.modified_at.zeroize();
    }
}

/// Security section containing 2FA TOTP configuration, Tier-2 password hash, and lockout counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultSecurity {
    /// Base32 encoded TOTP secret (Aegis format).
    pub totp_secret: Option<String>,
    /// Number of TOTP digits (default 6).
    pub totp_digits: u32,
    /// TOTP time period in seconds (default 30).
    pub totp_period: u64,
    /// TOTP hash algorithm ("SHA1" or "SHA256").
    pub totp_algorithm: String,
    /// Single-use emergency recovery codes.
    pub recovery_codes: Vec<String>,
    /// Optional Argon2id password hash for Tier-2 plain-text reveal.
    pub master_view_password_hash: Option<String>,
    /// Number of consecutive failed authentication attempts.
    pub failed_attempts: u32,
    /// Lockout expiration timestamp (Unix epoch seconds), if locked.
    pub lockout_until: Option<u64>,
}

impl Default for VaultSecurity {
    fn default() -> Self {
        Self {
            totp_secret: None,
            totp_digits: 6,
            totp_period: 30,
            totp_algorithm: "SHA1".to_string(),
            recovery_codes: Vec::new(),
            master_view_password_hash: None,
            failed_attempts: 0,
            lockout_until: None,
        }
    }
}

/// Additional structured data for SSH key items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SshKeyData {
    pub key_type: String,
    pub public_key: String,
    pub private_key: String,
    pub passphrase: Option<String>,
    pub comment: Option<String>,
}

/// Additional structured data for API key items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ApiKeyData {
    pub service: String,
    pub token: String,
    pub expires_at: Option<u64>,
}

/// A single secret or credential item stored in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultItem {
    pub id: [u8; 16],
    pub category: Category,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub auto_type_sequence: Option<String>,
    pub ssh_data: Option<SshKeyData>,
    pub api_key_data: Option<ApiKeyData>,
    pub raw_data: Option<Vec<u8>>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl VaultItem {
    /// Create a general vault item with random ID and timestamps.
    pub fn new(category: Category, title: impl Into<String>) -> Self {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let now = current_timestamp();
        Self {
            id,
            category,
            title: title.into(),
            username: None,
            password: None,
            url: None,
            notes: None,
            tags: Vec::new(),
            auto_type_sequence: None,
            ssh_data: None,
            api_key_data: None,
            raw_data: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a web credential item.
    pub fn new_credential(
        title: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        url: Option<String>,
    ) -> Self {
        let mut item = Self::new(Category::Web, title);
        item.username = Some(username.into());
        item.password = Some(password.into());
        item.url = url;
        item
    }

    /// Create an SSH key item.
    pub fn new_ssh(
        title: impl Into<String>,
        key_type: impl Into<String>,
        public_key: impl Into<String>,
        private_key: impl Into<String>,
        passphrase: Option<String>,
        comment: Option<String>,
    ) -> Self {
        let mut item = Self::new(Category::SSH, title);
        item.ssh_data = Some(SshKeyData {
            key_type: key_type.into(),
            public_key: public_key.into(),
            private_key: private_key.into(),
            passphrase,
            comment,
        });
        item
    }

    /// Create an API key item.
    pub fn new_api_key(
        title: impl Into<String>,
        service: impl Into<String>,
        token: impl Into<String>,
        expires_at: Option<u64>,
    ) -> Self {
        let mut item = Self::new(Category::ApiKey, title);
        item.api_key_data = Some(ApiKeyData {
            service: service.into(),
            token: token.into(),
            expires_at,
        });
        item
    }

    /// Create an encrypted note item.
    pub fn new_note(title: impl Into<String>, content: impl Into<String>) -> Self {
        let mut item = Self::new(Category::Note, title);
        item.notes = Some(content.into());
        item
    }

    /// Create a raw secret item.
    pub fn new_raw_secret(title: impl Into<String>, raw_data: Vec<u8>) -> Self {
        let mut item = Self::new(Category::RawSecret, title);
        item.raw_data = Some(raw_data);
        item
    }
}

/// The main decrypted vault in-memory representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    pub metadata: VaultMetadata,
    pub security: VaultSecurity,
    pub items: Vec<VaultItem>,
}

impl Vault {
    /// Create a new empty Vault with default metadata and security settings.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            metadata: VaultMetadata::new(name),
            security: VaultSecurity::default(),
            items: Vec::new(),
        }
    }

    /// Add an item to the vault and update modification timestamp.
    pub fn add_item(&mut self, item: VaultItem) {
        self.metadata.modified_at = current_timestamp();
        self.items.push(item);
    }

    /// Retrieve an item reference by its 16-byte ID.
    pub fn get_item(&self, id: &[u8; 16]) -> Option<&VaultItem> {
        self.items.iter().find(|item| &item.id == id)
    }

    /// Retrieve a mutable item reference by its 16-byte ID.
    pub fn get_item_mut(&mut self, id: &[u8; 16]) -> Option<&mut VaultItem> {
        self.metadata.modified_at = current_timestamp();
        self.items.iter_mut().find(|item| &item.id == id)
    }

    /// Remove an item by ID, returning true if found and removed.
    pub fn remove_item(&mut self, id: &[u8; 16]) -> bool {
        let len_before = self.items.len();
        self.items.retain(|item| &item.id != id);
        if self.items.len() != len_before {
            self.metadata.modified_at = current_timestamp();
            true
        } else {
            false
        }
    }

    /// Filter items by category.
    pub fn items_by_category(&self, category: Category) -> Vec<&VaultItem> {
        self.items
            .iter()
            .filter(|item| item.category == category)
            .collect()
    }

    /// Encrypt this vault into the contiguous Gastinel Covert binary format:
    /// `[88 bytes Header] + [Ciphertext] + [16 bytes Poly1305 Tag]`.
    ///
    /// The entire 88-byte header is authenticated via AEAD AAD.
    pub fn encrypt(
        &self,
        master_password: &SecretString,
        params: Option<Argon2Params>,
    ) -> Result<Vec<u8>, VaultError> {
        let argon_params = params.unwrap_or_default();

        // Serialize payload into CBOR
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(self, &mut cbor_buf)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;
        let cbor_buf = Zeroizing::new(cbor_buf);

        let ciphertext_len = cbor_buf.len() as u64;

        // Generate CSPRNG salt and nonce
        let salt = generate_salt();
        let nonce = generate_nonce();

        // Construct 88-byte header
        let header = VaultHeader::new(salt, nonce, ciphertext_len, argon_params);
        let header_bytes = header.to_bytes();

        // Derive key using Argon2id
        let derived_key = derive_key(master_password, &salt, &argon_params)?;

        // Encrypt with XChaCha20-Poly1305 binding 88-byte header as AAD
        let ciphertext_and_tag = encrypt_payload(&derived_key, &nonce, &header_bytes, &cbor_buf)?;

        let mut out = Vec::with_capacity(HEADER_SIZE + ciphertext_and_tag.len());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&ciphertext_and_tag);

        Ok(out)
    }

    /// Decrypt a raw binary vault byte stream.
    ///
    /// Performs strict pre-allocation parameter bounds checking and size verification
    /// before any cryptographic allocation.
    pub fn decrypt(
        data: &[u8],
        master_password: &SecretString,
    ) -> Result<(Self, VaultHeader), VaultError> {
        // Validate header bounds and payload length
        let header = VaultHeader::validate_buffer(data)?;
        let argon_params = header.argon2_params()?;

        // Derive key using Argon2id
        let derived_key = derive_key(master_password, &header.salt, &argon_params)?;

        // Authenticated decryption
        let header_bytes = &data[..HEADER_SIZE];
        let ciphertext_and_tag = &data[HEADER_SIZE..];
        let decrypted_cbor =
            decrypt_payload(&derived_key, &header.nonce, header_bytes, ciphertext_and_tag)?;

        // Deserialize CBOR payload
        let vault: Vault = ciborium::from_reader(&decrypted_cbor[..])
            .map_err(|e| VaultError::Serialization(e.to_string()))?;

        Ok((vault, header))
    }

    /// Re-encrypt vault with a new master password, generating fresh CSPRNG salt and nonce.
    pub fn change_master_password(
        &mut self,
        _old_pw: &SecretString,
        new_pw: &SecretString,
        params: Option<Argon2Params>,
    ) -> Result<Vec<u8>, VaultError> {
        self.metadata.modified_at = current_timestamp();
        self.encrypt(new_pw, params)
    }

    /// Re-encrypt an existing encrypted vault file with a new master password.
    ///
    /// Safely unlocks with `old_pw`, then re-encrypts with `new_pw` using fresh CSPRNG salt and nonce.
    pub fn change_master_password_from_bytes(
        encrypted_data: &[u8],
        old_pw: &SecretString,
        new_pw: &SecretString,
        params: Option<Argon2Params>,
    ) -> Result<Vec<u8>, VaultError> {
        let (mut vault, _header) = Self::decrypt(encrypted_data, old_pw)?;
        vault.metadata.modified_at = current_timestamp();
        vault.encrypt(new_pw, params)
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
