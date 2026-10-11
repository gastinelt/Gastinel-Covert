//! Test sandbox environment providing isolated directory hierarchies and file management.

use covert_core::models::{Vault, VaultItem};
use rand_core::{OsRng, RngCore};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Sandboxed filesystem context for isolated opaque-box E2E tests.
pub struct TestSandbox {
    dir: PathBuf,
}

impl TestSandbox {
    /// Create a new uniquely named temporary sandbox directory.
    pub fn new() -> Self {
        let mut random_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut random_bytes);
        let dir_name = format!("covert_test_{:016x}", u64::from_le_bytes(random_bytes));
        let dir = std::env::temp_dir().join(dir_name);
        fs::create_dir_all(&dir).expect("Failed to create test sandbox directory");
        Self { dir }
    }

    /// Root directory path of this sandbox.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Primary camouflaged vault file path: `dx12_pipeline.bin`.
    pub fn vault_path(&self) -> PathBuf {
        self.dir.join("dx12_pipeline.bin")
    }

    /// Backup vault file path: `dx12_pipeline.bin.bak`.
    pub fn backup_path(&self) -> PathBuf {
        self.dir.join("dx12_pipeline.bin.bak")
    }

    /// Intermediate temporary file path: `dx12_pipeline.tmp`.
    pub fn temp_path(&self) -> PathBuf {
        self.dir.join("dx12_pipeline.tmp")
    }

    /// Persistent lockout record file path: `dx12_pipeline.lock`.
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join("dx12_pipeline.lock")
    }

    /// Execute atomic write sequence on the sandbox vault file:
    /// 1. Write payload to `dx12_pipeline.tmp`
    /// 2. Flush file buffers (`sync_all`)
    /// 3. If primary vault exists, copy/backup to `dx12_pipeline.bin.bak`
    /// 4. Atomically substitute `dx12_pipeline.tmp` to `dx12_pipeline.bin`
    pub fn write_vault_atomic(&self, data: &[u8]) -> std::io::Result<()> {
        let temp_p = self.temp_path();
        let primary_p = self.vault_path();
        let backup_p = self.backup_path();

        // 1. Write to temp file
        let mut f = File::create(&temp_p)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);

        // 2. Backup if primary exists
        if primary_p.exists() {
            fs::copy(&primary_p, &backup_p)?;
        }

        // 3. Atomic replacement within the same directory
        fs::rename(&temp_p, &primary_p)?;

        Ok(())
    }

    /// Build a populated standard Vault instance with diverse categories.
    pub fn create_sample_vault() -> Vault {
        let mut vault = Vault::new("Gastinel Personal Vault");

        // 1. Web credential
        vault.add_item(VaultItem::new_credential(
            "Google Workspace",
            "covert_user@gastinel.internal",
            "Super$ecurePass99!",
            Some("https://accounts.google.com".to_string()),
        ));

        // 2. SSH key entry
        vault.add_item(VaultItem::new_ssh(
            "Production Bastion Host",
            "ed25519",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyBlobProduction",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
            Some("ssh_bastion_pass".to_string()),
            Some("admin@bastion.internal".to_string()),
        ));

        // 3. API Key entry
        vault.add_item(VaultItem::new_api_key(
            "AWS Production Access Key",
            "aws.amazon.com",
            "AKIAIOSFODNN7EXAMPLE",
            Some(1893456000), // Year 2030
        ));

        // 4. Secure Note
        vault.add_item(VaultItem::new_note(
            "Disaster Recovery Procedure",
            "Cold storage backup is physically located at Vault Site Alpha.",
        ));

        // 5. Raw Secret
        vault.add_item(VaultItem::new_raw_secret(
            "Hardware Security Token Seed",
            vec![0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF],
        ));

        // 6. Security configuration
        vault.security.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string()); // Standard Base32 secret
        vault.security.totp_digits = 6;
        vault.security.totp_period = 30;
        vault.security.recovery_codes = vec![
            "RECV-0001-AAAA".to_string(),
            "RECV-0002-BBBB".to_string(),
            "RECV-0003-CCCC".to_string(),
            "RECV-0004-DDDD".to_string(),
            "RECV-0005-EEEE".to_string(),
            "RECV-0006-FFFF".to_string(),
            "RECV-0007-GGGG".to_string(),
            "RECV-0008-HHHH".to_string(),
            "RECV-0009-IIII".to_string(),
            "RECV-0010-JJJJ".to_string(),
        ];
        vault.security.master_view_password_hash = Some(
            "$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHQ$somehashvaluefortier2viewing".to_string(),
        );

        vault
    }
}

impl Drop for TestSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
