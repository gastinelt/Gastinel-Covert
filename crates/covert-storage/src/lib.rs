//! Gastinel Covert Storage Engine: Camouflage Path Resolution & Win32 Atomic Replacement.
//!
//! Provides transactional, crash-resilient file persistence camouflaged as a
//! DirectX 12 ShaderCache pipeline binary (`dx12_pipeline.bin`), with automatic `.bak`
//! rotation, hardware buffer flushing via Win32 `FlushFileBuffers`, and atomic substitution
//! via Win32 `ReplaceFileW`.

pub mod atomic;
pub mod error;
pub mod paths;

use std::path::{Path, PathBuf};
use covert_core::header::{Argon2Params, VaultHeader};
use covert_core::models::Vault;
use covert_core::SecretString;

pub use atomic::{write_atomic, write_atomic_no_backup, write_atomic_rotate_backup};
pub use error::{Result, StorageError};
pub use paths::{
    default_camouflaged_path, derive_backup_path, derive_lock_path, derive_temp_path,
    VAULT_BACKUP_NAME, VAULT_DIR_DIRECTX, VAULT_DIR_SHADER_CACHE, VAULT_FILE_NAME,
    VAULT_LOCK_NAME, VAULT_TEMP_NAME,
};

/// High-level vault storage manager handling atomic reads, writes, and camouflage paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStorage {
    vault_path: PathBuf,
}

impl VaultStorage {
    /// Creates a new `VaultStorage` instance.
    ///
    /// If `path` is `Some(p)`, uses that path (useful for testing or custom locations).
    /// If `path` is `None`, resolves the default camouflaged path under `%LOCALAPPDATA%`.
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        let vault_path = match path {
            Some(p) => p,
            None => default_camouflaged_path()?,
        };
        Ok(Self { vault_path })
    }

    /// Creates a `VaultStorage` initialized to the default camouflaged location:
    /// `%LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.bin`.
    pub fn default_camouflaged() -> Result<Self> {
        Self::new(None)
    }

    /// Creates a `VaultStorage` bound to a specific custom path.
    pub fn from_path<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            vault_path: path.into(),
        }
    }

    /// Resolves the default camouflaged vault path on the system.
    pub fn default_camouflaged_path() -> Result<PathBuf> {
        paths::default_camouflaged_path()
    }

    /// Returns a reference to the primary vault file path.
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Returns the backup file path (`.bak`) in the same directory.
    pub fn backup_path(&self) -> PathBuf {
        derive_backup_path(&self.vault_path)
    }

    /// Returns the temporary file path (`.tmp`) in the same directory.
    pub fn temp_path(&self) -> PathBuf {
        derive_temp_path(&self.vault_path)
    }

    /// Returns the lockout record file path (`.lock`) in the same directory.
    pub fn lock_path(&self) -> PathBuf {
        derive_lock_path(&self.vault_path)
    }

    /// Returns true if the primary vault file exists on disk.
    pub fn exists(&self) -> bool {
        self.vault_path.exists()
    }

    /// Returns true if the backup vault file exists on disk.
    pub fn backup_exists(&self) -> bool {
        self.backup_path().exists()
    }

    /// Loads the raw unparsed encrypted bytes of the primary vault file.
    pub fn load_raw(&self) -> Result<Vec<u8>> {
        if !self.vault_path.exists() {
            return Err(StorageError::VaultNotFound(self.vault_path.clone()));
        }
        std::fs::read(&self.vault_path).map_err(StorageError::Io)
    }

    /// Loads the raw unparsed encrypted bytes of the backup vault file.
    pub fn load_raw_backup(&self) -> Result<Vec<u8>> {
        let b = self.backup_path();
        if !b.exists() {
            return Err(StorageError::BackupNotFound(b));
        }
        std::fs::read(&b).map_err(StorageError::Io)
    }

    /// Atomically saves raw encrypted bytes to the primary vault file.
    ///
    /// If a previous primary vault exists, it is automatically moved to `.bak`.
    pub fn save_atomic(&self, data: &[u8]) -> Result<()> {
        write_atomic(&self.vault_path, data)
    }

    /// Atomically saves raw encrypted bytes to the primary vault file and then
    /// atomically overwrites `.bak` with `data` so no residual backup encrypted
    /// with an older master password remains on disk.
    pub fn save_atomic_rotated(&self, data: &[u8]) -> Result<()> {
        write_atomic_rotate_backup(&self.vault_path, data)
    }

    /// Restores the primary vault file from the backup copy without modifying or
    /// overwriting the backup file itself.
    pub fn restore_from_backup(&self) -> Result<()> {
        let backup_p = self.backup_path();
        if !backup_p.exists() {
            return Err(StorageError::BackupNotFound(backup_p));
        }
        let data = std::fs::read(&backup_p)?;
        write_atomic_no_backup(&self.vault_path, &data)
    }

    /// Loads the raw encrypted vault file from disk and decrypts it with `covert-core`.
    pub fn load_vault(
        &self,
        master_password: &SecretString,
    ) -> Result<(Vault, VaultHeader)> {
        let raw_bytes = self.load_raw()?;
        let (vault, header) = Vault::decrypt(&raw_bytes, master_password)?;
        Ok((vault, header))
    }

    /// Loads the backup encrypted vault file from disk and decrypts it with `covert-core`.
    pub fn load_vault_from_backup(
        &self,
        master_password: &SecretString,
    ) -> Result<(Vault, VaultHeader)> {
        let raw_bytes = self.load_raw_backup()?;
        let (vault, header) = Vault::decrypt(&raw_bytes, master_password)?;
        Ok((vault, header))
    }

    /// Encrypts the provided `Vault` using `covert-core` and writes it atomically to disk.
    /// Also initializes the companion `.lock` file if it does not yet exist on disk.
    pub fn save_vault(
        &self,
        vault: &Vault,
        master_password: &SecretString,
        params: Option<Argon2Params>,
    ) -> Result<()> {
        let encrypted_bytes = vault.encrypt(master_password, params)?;
        self.save_atomic(&encrypted_bytes)?;
        self.ensure_lock_file_initialized()?;
        Ok(())
    }

    /// Rotates the master password of the vault and atomically updates both `.bin` and `.bak`
    /// so that neither file remains decryptable with `old_password`, without ever risking
    /// vault loss if the operation is interrupted.
    pub fn rotate_master_password(
        &self,
        vault: &mut Vault,
        old_password: &SecretString,
        new_password: &SecretString,
        params: Option<Argon2Params>,
    ) -> Result<()> {
        if self.exists() {
            let existing_raw = self.load_raw()?;
            let (_verified_vault, _header) = Vault::decrypt(&existing_raw, old_password)?;
        }
        let encrypted_bytes = vault.change_master_password(old_password, new_password, params)?;
        self.save_atomic_rotated(&encrypted_bytes)?;
        self.ensure_lock_file_initialized()?;
        Ok(())
    }

    /// Ensures the companion `.lock` file exists alongside the vault so that deleting `.lock`
    /// while `.bin` or `.bin.bak` is present can be reliably detected as tamper/bypass.
    fn ensure_lock_file_initialized(&self) -> Result<()> {
        // Canonical CBOR encoding of LockoutRecord::default() (5-field map with 0 values).
        const DEFAULT_LOCKOUT_CBOR: &[u8] = &[
            0xA5, 0x6F, b'f', b'a', b'i', b'l', b'e', b'd', b'_', b'a', b't', b't', b'e', b'm',
            b'p', b't', b's', 0x00, 0x74, b'c', b'o', b'n', b's', b'e', b'c', b'u', b't', b'i',
            b'v', b'e', b'_', b'l', b'o', b'c', b'k', b'o', b'u', b't', b's', 0x00, 0x70, b'l',
            b'o', b'c', b'k', b'e', b'd', b'_', b'u', b'n', b't', b'i', b'l', b'_', b'u', b't',
            b'c', 0x00, 0x6E, b'l', b'a', b's', b't', b'_', b'e', b'v', b'e', b'n', b't', b'_',
            b'u', b't', b'c', 0x00, 0x6E, b'l', b'a', b's', b't', b'_', b'b', b'o', b'o', b't',
            b'_', b't', b'i', b'c', b'k', 0x00,
        ];

        let lock_p = self.lock_path();
        if !lock_p.exists() {
            write_atomic_no_backup(&lock_p, DEFAULT_LOCKOUT_CBOR)?;
        }
        Ok(())
    }
}

impl AsRef<Path> for VaultStorage {
    fn as_ref(&self) -> &Path {
        &self.vault_path
    }
}
