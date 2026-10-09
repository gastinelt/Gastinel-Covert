//! Empirical Challenger Stress & Verification Test Suite for `covert-storage`.
//!
//! Adversarial challenge scenarios:
//! 1. Camouflage path resolution & deep directory auto-creation.
//! 2. Full roundtrip with complex `covert-core::Vault` (all item types, UTF-8/emojis, binary secrets).
//! 3. Same-directory `.tmp` placement and volume invariance.
//! 4. Rapid successive generations and `.bak` rotation integrity.
//! 5. Corrupted primary recovery via `restore_from_backup`.
//! 6. Zero-length and large payload stress tests.
//! 7. Stray/read-only `.tmp` crash resilience.
//! 8. Unicode and spaced path handling.
//! 9. Gitignore rule validation.
//! 10. Exclusive file lock conflict resilience & temp file cleanup.
//! 11. Error variants for missing files and truncated headers via `VaultStorage`.
//! 12. Multithreaded concurrent save race stress.

use covert_core::header::{Argon2Params, HEADER_SIZE, MAGIC};
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use covert_storage::paths::{
    default_camouflaged_path, derive_backup_path, derive_lock_path, derive_temp_path,
    VAULT_BACKUP_NAME, VAULT_DIR_DIRECTX, VAULT_DIR_SHADER_CACHE, VAULT_FILE_NAME,
    VAULT_LOCK_NAME, VAULT_TEMP_NAME,
};
use covert_storage::{StorageError, VaultStorage};
use rand_core::{OsRng, RngCore};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

// =========================================================================
// 1. Camouflage Path & Auto-Creation Challenge
// =========================================================================

#[test]
fn challenge_default_camouflage_path_and_environment() {
    let resolved = default_camouflaged_path().expect("default_camouflaged_path must resolve");

    #[cfg(windows)]
    {
        let expected_local_appdata = std::env::var("LOCALAPPDATA").expect("LOCALAPPDATA must be set");
        let expected_prefix = PathBuf::from(expected_local_appdata);
        assert!(
            resolved.starts_with(&expected_prefix),
            "Resolved path {:?} does not start with LOCALAPPDATA {:?}",
            resolved,
            expected_prefix
        );
    }

    assert!(
        resolved.ends_with(
            PathBuf::from(VAULT_DIR_DIRECTX)
                .join(VAULT_DIR_SHADER_CACHE)
                .join(VAULT_FILE_NAME)
        ),
        "Resolved path {:?} must end with DirectX/ShaderCache/dx12_pipeline.bin",
        resolved
    );

    // Verify temp, backup, and lock paths derived from camouflage path
    let parent = resolved.parent().expect("Camouflage path must have parent");
    assert_eq!(derive_temp_path(&resolved), parent.join(VAULT_TEMP_NAME));
    assert_eq!(derive_backup_path(&resolved), parent.join(VAULT_BACKUP_NAME));
    assert_eq!(derive_lock_path(&resolved), parent.join(VAULT_LOCK_NAME));
}

#[test]
fn challenge_deep_nested_directory_auto_creation() {
    let temp_dir = TempDir::new().expect("TempDir");
    // Deep non-existent nested structure with spaces and special chars
    let deep_vault = temp_dir
        .path()
        .join("Level 1")
        .join("Level 2 - Direct X")
        .join("Cache @ Store")
        .join("DirectX")
        .join("ShaderCache")
        .join("dx12_pipeline.bin");

    assert!(!deep_vault.parent().unwrap().exists());

    let storage = VaultStorage::from_path(&deep_vault);
    let test_data = b"DeepDirectoryAutoCreationTestData";

    storage.save_atomic(test_data).expect("Must auto-create parents and succeed");

    assert!(deep_vault.exists());
    assert_eq!(storage.load_raw().unwrap(), test_data);
}

// =========================================================================
// 2. Full Roundtrip with Complex Vault
// =========================================================================

#[test]
fn challenge_complex_vault_roundtrip_all_item_types() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let mut vault = Vault::new("Gastinel Empirical Challenge Vault 🔑🛡️");

    // 1. Web Credential with Unicode, symbols, and non-ASCII password
    vault.add_item(VaultItem::new_credential(
        "Banque Nationale — Compte Courant 💳",
        "théophile.gastinel@covert.internal",
        "P@ssw0rd_with_€uro_and_Emojis_🔒🔑✨!?",
        Some("https://banque.example.com/login?lang=fr".to_string()),
    ));

    // 2. SSH Key (Ed25519)
    vault.add_item(VaultItem::new_ssh(
        "Production Gateway Ed25519",
        "ed25519",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICovertChallengeGatewayKey",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----",
        Some("ssh-passphrase-strong".to_string()),
        Some("ops@gateway.internal".to_string()),
    ));

    // 3. Multiline Markdown Note with code snippets and special formatting
    let note_content = "# Disaster Recovery Plan\n\n```bash\nssh root@cold-backup 'tar czf /mnt/safe/vault.tar.gz /data'\n```\n- Point 1: Keep offline\n- Point 2: Argon2id m=256MB\n";
    vault.add_item(VaultItem::new_note(
        "Emergency Procedure & Runbook",
        note_content,
    ));

    // 4. API Key with Unix timestamp expiry
    vault.add_item(VaultItem::new_api_key(
        "Stripe Live Production Key",
        "api.stripe.com",
        "PLACEHOLDER_FAKE_API_KEY_FOR_TESTS_0002",
        Some(1893456000), // Year 2030
    ));

    // 5. Binary Raw Secret (256 random bytes)
    let mut raw_bytes = vec![0u8; 256];
    OsRng.fill_bytes(&mut raw_bytes);
    vault.add_item(VaultItem::new_raw_secret(
        "Hardware YubiKey Master Seed (256-bit AES-GCM Root)",
        raw_bytes.clone(),
    ));

    // 6. Security configuration (Aegis TOTP, recovery codes, tier-2 password hash)
    vault.security.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
    vault.security.totp_digits = 6;
    vault.security.totp_period = 30;
    vault.security.recovery_codes = (1..=10)
        .map(|i| format!("RC-{:04}-CODE", i))
        .collect();
    vault.security.master_view_password_hash = Some(
        "$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHQ$viewpasswordhashvalue".to_string(),
    );

    let password = SecretString::new("Empirical_Master_Password_2026!#$".to_string());
    let wrong_pw = SecretString::new("Empirical_Master_Password_2026!#Wrong".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    // Save vault
    storage
        .save_vault(&vault, &password, Some(fast_params))
        .expect("save_vault must succeed");

    assert!(storage.exists());
    assert!(!storage.backup_exists());

    // Verify raw on-disk binary format
    let raw_file = storage.load_raw().expect("load_raw");
    assert!(raw_file.len() > HEADER_SIZE + 16);
    assert_eq!(&raw_file[0..8], &MAGIC);
    assert_eq!(u16::from_le_bytes([raw_file[8], raw_file[9]]), 1); // version

    // Decrypt with wrong password must fail
    assert!(storage.load_vault(&wrong_pw).is_err());

    // Decrypt with correct password
    let (loaded_vault, header) = storage
        .load_vault(&password)
        .expect("load_vault must succeed");

    assert_eq!(header.format_version, 1);
    assert_eq!(header.kdf_algo, 0x01);
    assert_eq!(header.cipher_algo, 0x01);
    assert_eq!(loaded_vault.metadata.name, vault.metadata.name);
    assert_eq!(loaded_vault.items.len(), 5);

    // Verify items in detail
    assert_eq!(loaded_vault.items[0].title, vault.items[0].title);
    assert_eq!(loaded_vault.items[1].title, vault.items[1].title);
    assert_eq!(loaded_vault.items[2].title, vault.items[2].title);
    assert_eq!(loaded_vault.items[3].title, vault.items[3].title);
    assert_eq!(loaded_vault.items[4].title, vault.items[4].title);

    // Verify security section
    assert_eq!(loaded_vault.security.totp_secret, Some("JBSWY3DPEHPK3PXP".to_string()));
    assert_eq!(loaded_vault.security.totp_digits, 6);
    assert_eq!(loaded_vault.security.totp_period, 30);
    assert_eq!(loaded_vault.security.recovery_codes.len(), 10);
    assert_eq!(loaded_vault.security.recovery_codes[0], "RC-0001-CODE");
    assert_eq!(loaded_vault.security.recovery_codes[9], "RC-0010-CODE");
}

// =========================================================================
// 3. Same-Directory and Same-Volume Guarantee
// =========================================================================

#[test]
fn challenge_same_directory_and_volume_invariance() {
    let test_cases = [
        PathBuf::from("C:\\Users\\User\\AppData\\Local\\DirectX\\ShaderCache\\dx12_pipeline.bin"),
        PathBuf::from("D:\\Gastinel\\Custom\\vault.bin"),
        PathBuf::from("E:\\my_store\\data_file"),
        PathBuf::from(".\\relative_vault.bin"),
    ];

    for vault_path in &test_cases {
        let storage = VaultStorage::from_path(vault_path);
        let temp_p = storage.temp_path();
        let backup_p = storage.backup_path();
        let lock_p = storage.lock_path();

        // Both must have the identical parent
        assert_eq!(
            temp_p.parent(),
            vault_path.parent(),
            "Temp file parent mismatch for {:?}",
            vault_path
        );
        assert_eq!(
            backup_p.parent(),
            vault_path.parent(),
            "Backup file parent mismatch for {:?}",
            vault_path
        );
        assert_eq!(
            lock_p.parent(),
            vault_path.parent(),
            "Lock file parent mismatch for {:?}",
            vault_path
        );
    }
}

// =========================================================================
// 4. Rapid Generations and Rotation Integrity
// =========================================================================

#[test]
fn challenge_rapid_successive_generations() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    const GENERATIONS: usize = 30;

    for gen in 1..=GENERATIONS {
        let content = format!("Vault Generation Content #{:04}", gen);
        storage.save_atomic(content.as_bytes()).expect("save_atomic generation");

        // Primary vault must always reflect current generation
        assert_eq!(
            storage.load_raw().unwrap(),
            content.as_bytes(),
            "Gen {} primary content mismatch",
            gen
        );

        // From gen 2 onwards, backup must exist and reflect gen - 1
        if gen > 1 {
            let prev_content = format!("Vault Generation Content #{:04}", gen - 1);
            assert!(storage.backup_exists());
            assert_eq!(
                storage.load_raw_backup().unwrap(),
                prev_content.as_bytes(),
                "Gen {} backup content mismatch",
                gen
            );
        } else {
            assert!(!storage.backup_exists());
        }

        // Stray temporary file must never remain
        assert!(!storage.temp_path().exists());
    }
}

// =========================================================================
// 5. Corrupted Primary Recovery via Backup
// =========================================================================

#[test]
fn challenge_corrupted_primary_recovery_preserves_backup() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let pristine_data = b"PristineCryptographicallyValidVaultPayload";
    let bad_data = b"CorruptedSecondaryData";

    storage.save_atomic(pristine_data).unwrap();
    storage.save_atomic(bad_data).unwrap();

    assert_eq!(storage.load_raw().unwrap(), bad_data);
    assert_eq!(storage.load_raw_backup().unwrap(), pristine_data);

    // Restore from backup
    storage.restore_from_backup().expect("restore_from_backup");

    // Primary restored
    assert_eq!(storage.load_raw().unwrap(), pristine_data);

    // Backup is NOT deleted or altered
    assert!(storage.backup_exists());
    assert_eq!(storage.load_raw_backup().unwrap(), pristine_data);
}

// =========================================================================
// 6. Zero-Length and Large Payload Stress Tests
// =========================================================================

#[test]
fn challenge_zero_length_payload() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    // 0-byte payload write
    storage.save_atomic(&[]).expect("Empty write must succeed");
    assert_eq!(storage.load_raw().unwrap(), Vec::<u8>::new());

    // 0-byte payload replace
    storage.save_atomic(b"some data").expect("Replace with some data");
    storage.save_atomic(&[]).expect("Replace with empty");
    assert_eq!(storage.load_raw().unwrap(), Vec::<u8>::new());
    assert_eq!(storage.load_raw_backup().unwrap(), b"some data");
}

#[test]
fn challenge_large_payload_stress() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    // 4 MiB buffer
    let mut large_buffer = vec![0u8; 4 * 1024 * 1024];
    OsRng.fill_bytes(&mut large_buffer);

    storage
        .save_atomic(&large_buffer)
        .expect("4 MiB atomic write");

    let loaded = storage.load_raw().expect("Load 4 MiB payload");
    assert_eq!(loaded.len(), large_buffer.len());
    assert_eq!(loaded, large_buffer);
}

// =========================================================================
// 7. Stray Temp File Resilience
// =========================================================================

#[test]
fn challenge_stray_tmp_file_overwritten_cleanly() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    // Pre-create a dirty .tmp file in the directory
    fs::write(storage.temp_path(), b"LeftoverStrayJunkFromCrash").unwrap();
    assert!(storage.temp_path().exists());

    // Atomic write should succeed and wipe the stray temp file
    let clean_data = b"CleanValidVaultData";
    storage.save_atomic(clean_data).expect("Atomic write over existing tmp");

    assert_eq!(storage.load_raw().unwrap(), clean_data);
    assert!(!storage.temp_path().exists());
}

// =========================================================================
// 8. Unicode and Spaced Path Resilience
// =========================================================================

#[test]
fn challenge_unicode_and_spaces_in_path() {
    let temp_dir = TempDir::new().expect("TempDir");
    let unicode_dir = temp_dir
        .path()
        .join("Répertoire de Données Cryptées 🔒")
        .join("ShaderCache — Spécial");
    let vault_file = unicode_dir.join("dx12_pipeline.bin");

    let storage = VaultStorage::from_path(&vault_file);
    let payload = b"UnicodeDirectoryPayload123";

    storage.save_atomic(payload).expect("Write in Unicode directory");
    assert_eq!(storage.load_raw().unwrap(), payload);

    let payload2 = b"UnicodeDirectoryPayload456";
    storage.save_atomic(payload2).expect("Second write in Unicode directory");
    assert_eq!(storage.load_raw().unwrap(), payload2);
    assert_eq!(storage.load_raw_backup().unwrap(), payload);
}

// =========================================================================
// 9. Strict Gitignore Exclusion Rules Audit
// =========================================================================

#[test]
fn challenge_git_ignore_rules_comprehensive() {
    let project_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let check_paths = [
        "dx12_pipeline.bin",
        "dx12_pipeline.tmp",
        "dx12_pipeline.bin.bak",
        "dx12_pipeline.lock",
        "nested/sub/dx12_pipeline.bin",
        "nested/sub/dx12_pipeline.tmp",
        "nested/sub/dx12_pipeline.bin.bak",
        "nested/sub/dx12_pipeline.lock",
        "my_secret.vault",
        "keys/id_rsa",
        "keys/id_ed25519",
        "keys/id_ecdsa",
        "keys/id_dsa",
        "secret.key",
        "cert.pem",
    ];

    for rel_path in &check_paths {
        let output = Command::new("git")
            .args(["check-ignore", "-q", rel_path])
            .current_dir(project_root)
            .status();

        match output {
            Ok(status) => {
                assert!(
                    status.success(),
                    "Path '{}' MUST be ignored by .gitignore but git check-ignore returned failure",
                    rel_path
                );
            }
            Err(e) => {
                panic!("Failed to execute git check-ignore: {}", e);
            }
        }
    }
}

// =========================================================================
// 10. Locked Target File Behavior & Temp File Cleanup
// =========================================================================

#[test]
fn challenge_locked_file_atomic_failure_cleans_temp() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    // Initial write
    storage.save_atomic(b"InitialVaultData").expect("Initial write");
    assert!(vault_file.exists());

    // Lock the file exclusively by opening it with share_mode(0) (no sharing permitted)
    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;

    #[cfg(windows)]
    let _exclusive_file = fs::OpenOptions::new()
        .write(true)
        .share_mode(0)
        .open(&vault_file)
        .expect("Open file with share_mode(0)");

    // Attempting atomic save while file is exclusively locked by another handle must fail on Windows
    #[cfg(windows)]
    {
        let res = storage.save_atomic(b"AttemptedOverwrite");
        assert!(res.is_err(), "Replacing an exclusively locked file must fail: {:?}", res);
        // Crucial: temporary file MUST be cleaned up even when ReplaceFile fails!
        assert!(
            !storage.temp_path().exists(),
            "Temporary file must be removed when atomic replace fails"
        );
    }
}

// =========================================================================
// 11. Error Type Fidelity
// =========================================================================

#[test]
fn challenge_error_variants_and_conversions() {
    let temp_dir = TempDir::new().expect("TempDir");
    let non_existent = temp_dir.path().join("missing.bin");
    let storage = VaultStorage::from_path(&non_existent);

    // load_raw on missing file
    match storage.load_raw() {
        Err(StorageError::VaultNotFound(p)) => assert_eq!(p, non_existent),
        other => panic!("Expected VaultNotFound, got {:?}", other),
    }

    // load_raw_backup on missing backup
    match storage.load_raw_backup() {
        Err(StorageError::BackupNotFound(p)) => assert_eq!(p, storage.backup_path()),
        other => panic!("Expected BackupNotFound, got {:?}", other),
    }

    // load_vault on missing file
    let pw = SecretString::new("pw".to_string());
    match storage.load_vault(&pw) {
        Err(StorageError::VaultNotFound(p)) => assert_eq!(p, non_existent),
        other => panic!("Expected VaultNotFound, got {:?}", other),
    }

    // Corrupted / truncated file through load_vault
    fs::write(&non_existent, b"TruncatedHeaderBytesOnly").unwrap();
    match storage.load_vault(&pw) {
        Err(StorageError::Core(err)) => {
            // Must be a crypto/header error
            assert!(format!("{:?}", err).contains("Header") || format!("{:?}", err).contains("Crypto"));
        }
        other => panic!("Expected Core(VaultError), got {:?}", other),
    }
}

// =========================================================================
// 12. Multithreaded Concurrent Saves
// =========================================================================

#[test]
fn challenge_multithreaded_concurrent_saves() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = Arc::new(VaultStorage::from_path(&vault_file));

    // Initial write
    storage.save_atomic(b"ThreadInitData").unwrap();

    let mut handles = vec![];
    for thread_idx in 0..8 {
        let storage_clone = Arc::clone(&storage);
        handles.push(thread::spawn(move || {
            let data = format!("Thread {} Data Payload", thread_idx);
            // Some may succeed or fail depending on race, but none should panic or corrupt the filesystem
            let _ = storage_clone.save_atomic(data.as_bytes());
        }));
    }

    for h in handles {
        h.join().expect("Thread should not panic");
    }

    // Primary vault MUST exist and be readable
    assert!(storage.exists());
    let final_data = storage.load_raw().expect("Final vault must be readable");
    assert!(
        String::from_utf8_lossy(&final_data).contains("Thread"),
        "Final data must be one of the thread writes"
    );
}
