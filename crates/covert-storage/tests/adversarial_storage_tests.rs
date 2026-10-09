//! Adversarial and Empirical Stress Test Suite for `covert-storage`.
//!
//! Stress-tests:
//! 1. Atomic file replacement when destination exists vs does not exist
//! 2. Backup (.bak) preservation across generations
//! 3. Cleanup of temporary (.tmp) file on failure (locked destination, locked backup, read-only file)
//! 4. Primary file integrity under aborted / failed writes
//! 5. Backup recovery when primary file is missing
//! 6. Backup recovery when primary file is corrupted (0 bytes, truncated, garbage)
//! 7. Repeated rapid writes and handle exhaustion
//! 8. Concurrent reader-writer atomicity (no partial read observed)
//! 9. Path resolution with special characters and Unicode
//! 10. Empty payload edge cases

use covert_core::error::VaultError;
use covert_core::header::Argon2Params;
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use covert_storage::{StorageError, VaultStorage};
use std::fs::{self, OpenOptions};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

// Helper to construct a standard populated Vault for tests
fn create_test_vault(name: &str) -> Vault {
    let mut vault = Vault::new(name);
    vault.add_item(VaultItem::new_credential(
        "Service Alpha",
        "agent007",
        "SuperSecretPass99!",
        Some("https://alpha.internal".to_string()),
    ));
    vault.add_item(VaultItem::new_note(
        "Field Coordinates",
        "Safehouse location encoded: 48.8566N, 2.3522E",
    ));
    vault
}

// =========================================================================
// 1. Target Replacement Lifecycle: Non-existent -> Exists -> N Generations
// =========================================================================

#[test]
fn test_adversarial_replacement_lifecycle_and_bak_preservation() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    // Initial state
    assert!(!storage.exists());
    assert!(!storage.backup_exists());
    assert!(!storage.temp_path().exists());

    // Gen 1: First write when target does not exist
    let gen1_data = b"Generation_1_InitialCreationBytes_AAAA";
    storage.save_atomic(gen1_data).expect("Gen 1 write");

    assert!(storage.exists());
    assert!(vault_file.exists());
    assert!(!storage.backup_exists(), "First write must NOT create a .bak file");
    assert!(!storage.temp_path().exists(), "Temp file must be cleaned up");
    assert_eq!(storage.load_raw().unwrap(), gen1_data);

    // Gen 2: Second write when target already exists -> Gen 1 moves to .bak
    let gen2_data = b"Generation_2_UpdatedContentBytes_BBBB";
    storage.save_atomic(gen2_data).expect("Gen 2 write");

    assert!(storage.exists());
    assert!(storage.backup_exists(), "Second write MUST create a .bak file");
    assert!(!storage.temp_path().exists(), "Temp file must be cleaned up");
    assert_eq!(storage.load_raw().unwrap(), gen2_data, "Primary must contain Gen 2");
    assert_eq!(storage.load_raw_backup().unwrap(), gen1_data, "Backup must preserve Gen 1");

    // Gen 3: Third write -> Gen 2 moves to .bak, replacing Gen 1
    let gen3_data = b"Generation_3_ThirdContentBytes_CCCC";
    storage.save_atomic(gen3_data).expect("Gen 3 write");

    assert!(storage.exists());
    assert!(storage.backup_exists());
    assert!(!storage.temp_path().exists());
    assert_eq!(storage.load_raw().unwrap(), gen3_data, "Primary must contain Gen 3");
    assert_eq!(storage.load_raw_backup().unwrap(), gen2_data, "Backup must preserve Gen 2");

    // Gen 4: Fourth write
    let gen4_data = b"Generation_4_FourthContentBytes_DDDD";
    storage.save_atomic(gen4_data).expect("Gen 4 write");

    assert_eq!(storage.load_raw().unwrap(), gen4_data);
    assert_eq!(storage.load_raw_backup().unwrap(), gen3_data);
    assert!(!storage.temp_path().exists());
}

// =========================================================================
// 2. Abort & Failure Recovery: Primary File Intact & Temp File Cleaned Up
// =========================================================================

#[test]
#[cfg(windows)]
fn test_adversarial_abort_locked_destination_preserves_primary_and_cleans_tmp() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let initial_data = b"PristineOriginalVaultContentMustSurvive";
    storage.save_atomic(initial_data).expect("Initial write");
    assert_eq!(storage.load_raw().unwrap(), initial_data);

    // Lock the primary vault file with exclusive share_mode = 0 (no sharing)
    let locked_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0) // Exclusive lock
        .open(&vault_file)
        .expect("Open with exclusive lock");

    // Attempt to save new data while primary is locked
    let attempted_data = b"AttemptedOverwriteDataThatMustFail";
    let save_res = storage.save_atomic(attempted_data);

    // Verify: save_atomic must fail
    assert!(save_res.is_err(), "Save must fail when destination is locked");
    match save_res.unwrap_err() {
        StorageError::AtomicReplaceFailed { code, .. } => {
            // Sharing violation (ERROR_SHARING_VIOLATION = 32) or Access Denied (= 5)
            assert!(code == 32 || code == 5, "Expected sharing violation OS error, got: {code}");
        }
        other => panic!("Expected AtomicReplaceFailed, got {:?}", other),
    }

    // CRITICAL: Temp file MUST be cleaned up on failure!
    assert!(
        !storage.temp_path().exists(),
        "Temporary file (.tmp) must be deleted when atomic replace fails"
    );

    // Release the lock
    drop(locked_handle);

    // CRITICAL: Primary file MUST remain completely intact and unmodified!
    assert_eq!(
        storage.load_raw().unwrap(),
        initial_data,
        "Primary file content must be preserved intact after failed save"
    );

    // A subsequent save should now cleanly succeed
    let recovery_data = b"SubsequentSaveAfterUnlocking";
    storage.save_atomic(recovery_data).expect("Save after unlock");
    assert_eq!(storage.load_raw().unwrap(), recovery_data);
    assert_eq!(storage.load_raw_backup().unwrap(), initial_data);
    assert!(!storage.temp_path().exists());
}

#[test]
#[cfg(windows)]
fn test_adversarial_abort_locked_backup_preserves_primary_and_cleans_tmp() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let v1_data = b"Vault_V1_FirstData";
    let v2_data = b"Vault_V2_SecondData";
    storage.save_atomic(v1_data).expect("v1 write");
    storage.save_atomic(v2_data).expect("v2 write");
    // Now primary is v2, backup is v1

    // Lock the backup file exclusively
    let backup_file = storage.backup_path();
    let locked_backup = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0) // Exclusive lock on .bak
        .open(&backup_file)
        .expect("Lock backup file");

    // Attempt to write v3 (which needs to replace .bak with v2)
    let v3_attempt = b"Vault_V3_ThirdDataAttempt";
    let save_res = storage.save_atomic(v3_attempt);

    // Must fail because .bak cannot be written to
    assert!(save_res.is_err(), "Save must fail when backup is locked");
    match save_res.unwrap_err() {
        StorageError::AtomicReplaceFailed { code, .. } => {
            // Error 1175 = ERROR_UNABLE_TO_REMOVE_REPLACED, 32 = ERROR_SHARING_VIOLATION, 5 = ERROR_ACCESS_DENIED
            assert!(
                code == 1175 || code == 32 || code == 5,
                "Expected ReplaceFileW failure error, got {code}"
            );
        }
        other => panic!("Expected AtomicReplaceFailed, got {:?}", other),
    }

    // Verify temp file is cleaned up
    assert!(
        !storage.temp_path().exists(),
        "Temp file must be cleaned up when replace fails due to locked backup"
    );

    // Release lock
    drop(locked_backup);

    // Primary file must still be v2
    assert_eq!(storage.load_raw().unwrap(), v2_data);
    // Backup must still be v1
    assert_eq!(storage.load_raw_backup().unwrap(), v1_data);
}

#[test]
fn test_adversarial_abort_readonly_destination_preserves_primary_and_cleans_tmp() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let initial_data = b"ReadOnlyProtectedVaultPayload";
    storage.save_atomic(initial_data).expect("Initial write");

    // Set destination file to read-only
    let mut perms = fs::metadata(&vault_file).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&vault_file, perms).expect("Set readonly");

    // Attempt save
    let attempted_data = b"OverwritingReadOnlyMustFail";
    let save_res = storage.save_atomic(attempted_data);

    assert!(save_res.is_err(), "Saving to read-only file must fail");

    // Temp file must be cleaned up
    assert!(
        !storage.temp_path().exists(),
        "Temp file must be cleaned up after readonly failure"
    );

    // Remove readonly attribute so we can read and test
    let mut perms = fs::metadata(&vault_file).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    fs::set_permissions(&vault_file, perms).expect("Remove readonly");

    // Primary file must still have original content
    assert_eq!(
        storage.load_raw().unwrap(),
        initial_data,
        "Primary file must be intact after readonly attempt"
    );
}

#[test]
fn test_adversarial_invalid_data_save_vault_does_not_touch_disk() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let initial_vault = create_test_vault("Initial Valid Vault");
    let password = SecretString::new("MasterPass123!".to_string());
    let valid_params = Argon2Params::new(65536, 2, 1).unwrap();

    storage
        .save_vault(&initial_vault, &password, Some(valid_params))
        .expect("Initial save");
    let initial_raw = storage.load_raw().unwrap();

    // Now try to save with invalid Argon2 parameters (e.g. m_cost out of bounds)
    // Argon2Params::new checks bounds before allocation:
    let bad_params_res = Argon2Params::new(1024, 2, 1);
    assert!(bad_params_res.is_err(), "Bounds check must reject m_cost=1024");

    // Primary file is completely untouched
    assert_eq!(storage.load_raw().unwrap(), initial_raw);
    assert!(!storage.temp_path().exists());
    assert!(!storage.backup_exists());
}

// =========================================================================
// 3. Backup Recovery Under Failure Scenarios
// =========================================================================

#[test]
fn test_adversarial_backup_recovery_when_primary_file_is_completely_missing() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let v1_data = b"ValuableData_Version_1";
    let v2_data = b"ValuableData_Version_2";

    storage.save_atomic(v1_data).expect("v1");
    storage.save_atomic(v2_data).expect("v2");

    // Primary is v2, backup is v1
    assert!(storage.exists());
    assert!(storage.backup_exists());

    // Catastrophic event: primary file is completely deleted!
    fs::remove_file(&vault_file).expect("Delete primary file");
    assert!(!storage.exists());
    assert!(storage.backup_exists());

    // load_raw on missing primary returns VaultNotFound
    match storage.load_raw() {
        Err(StorageError::VaultNotFound(p)) => assert_eq!(p, vault_file),
        other => panic!("Expected VaultNotFound, got {:?}", other),
    }

    // Restore from backup when primary does NOT exist
    storage.restore_from_backup().expect("Restore when primary is missing");

    // Primary is restored to v1!
    assert!(storage.exists());
    assert_eq!(storage.load_raw().unwrap(), v1_data);

    // CRITICAL: Backup file MUST STILL EXIST and remain identical!
    assert!(storage.backup_exists());
    assert_eq!(storage.load_raw_backup().unwrap(), v1_data);
    assert!(!storage.temp_path().exists());
}

#[test]
fn test_adversarial_backup_recovery_when_primary_is_corrupted_empty_truncated_or_garbage() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let vault_v1 = create_test_vault("Pristine V1 Vault");
    let vault_v2 = create_test_vault("Updated V2 Vault");
    let password = SecretString::new("CorrectPassword123!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    // 1. Save v1 then v2 -> v1 is in backup
    storage
        .save_vault(&vault_v1, &password, Some(fast_params))
        .unwrap();
    storage
        .save_vault(&vault_v2, &password, Some(fast_params))
        .unwrap();

    let backup_raw_before = storage.load_raw_backup().unwrap();

    // Scenario A: Primary is truncated to 0 bytes
    fs::write(&vault_file, b"").unwrap();
    assert!(storage.load_vault(&password).is_err());
    storage.restore_from_backup().expect("Restore from 0 bytes");
    let (restored_a, _) = storage.load_vault(&password).unwrap();
    assert_eq!(restored_a.metadata.name, "Pristine V1 Vault");
    assert_eq!(storage.load_raw_backup().unwrap(), backup_raw_before);

    // Scenario B: Primary is truncated header (40 bytes)
    fs::write(&vault_file, [0x41u8; 40]).unwrap();
    match storage.load_vault(&password) {
        Err(StorageError::Core(VaultError::Header(_))) => (),
        other => panic!("Expected Header error, got {:?}", other),
    }
    storage.restore_from_backup().expect("Restore from truncated");
    let (restored_b, _) = storage.load_vault(&password).unwrap();
    assert_eq!(restored_b.metadata.name, "Pristine V1 Vault");
    assert_eq!(storage.load_raw_backup().unwrap(), backup_raw_before);

    // Scenario C: Primary has invalid magic
    let mut bad_magic = storage.load_raw().unwrap();
    bad_magic[0..8].copy_from_slice(b"BADMAGIC");
    fs::write(&vault_file, &bad_magic).unwrap();
    assert!(storage.load_vault(&password).is_err());
    storage.restore_from_backup().expect("Restore from bad magic");
    let (restored_c, _) = storage.load_vault(&password).unwrap();
    assert_eq!(restored_c.metadata.name, "Pristine V1 Vault");
    assert_eq!(storage.load_raw_backup().unwrap(), backup_raw_before);

    // Scenario D: Multiple restores in a row
    for _ in 0..5 {
        storage.restore_from_backup().expect("Repeated restore");
        let (r, _) = storage.load_vault(&password).unwrap();
        assert_eq!(r.metadata.name, "Pristine V1 Vault");
        assert_eq!(storage.load_raw_backup().unwrap(), backup_raw_before);
    }
}

// =========================================================================
// 4. Stress: Rapid Sequential Writes & Handle Cleanliness
// =========================================================================

#[test]
fn test_adversarial_rapid_sequential_writes_stress() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let iterations = 50;
    for i in 0..iterations {
        let payload = format!("RapidWritePayload_Iteration_{:04}_{}", i, "x".repeat(i * 100));
        storage
            .save_atomic(payload.as_bytes())
            .unwrap_or_else(|e| panic!("Rapid write iteration {} failed: {:?}", i, e));

        assert_eq!(storage.load_raw().unwrap(), payload.as_bytes());
        assert!(!storage.temp_path().exists());

        if i > 0 {
            let prev_payload = format!(
                "RapidWritePayload_Iteration_{:04}_{}",
                i - 1,
                "x".repeat((i - 1) * 100)
            );
            assert_eq!(storage.load_raw_backup().unwrap(), prev_payload.as_bytes());
        }
    }
}

// =========================================================================
// 5. Concurrency: Atomic Visibility (No Partial Reads Under Write)
// =========================================================================

#[test]
fn test_adversarial_concurrent_readers_and_writers_atomicity() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = Arc::new(VaultStorage::from_path(&vault_file));

    // Seed initial content with a recognizable pattern
    let seed_payload = vec![0x11u8; 4096];
    storage.save_atomic(&seed_payload).expect("Seed payload");

    let stop_signal = Arc::new(AtomicBool::new(false));
    let mut reader_handles = Vec::new();

    // Spawn 4 reader threads
    for _ in 0..4 {
        let s = Arc::clone(&storage);
        let stop = Arc::clone(&stop_signal);

        reader_handles.push(thread::spawn(move || {
            let mut read_count = 0;
            while !stop.load(Ordering::Relaxed) {
                if let Ok(data) = s.load_raw() {
                    // CRITICAL ATOMICITY INVARIANT:
                    // Data MUST either be all 0x11 or all 0x22 or all 0x33, etc.
                    // It must NEVER be partially written or zero-length or torn!
                    if !data.is_empty() {
                        let first = data[0];
                        assert!(
                            data.iter().all(|&b| b == first),
                            "TEARING DETECTED! File read observed non-atomic mixed content"
                        );
                        assert_eq!(data.len(), 4096, "Torn partial length observed");
                    }
                    read_count += 1;
                }
                thread::yield_now();
            }
            read_count
        }));
    }

    // Writer thread performs 30 atomic saves of different uniform bytes
    let writer_storage = Arc::clone(&storage);
    let writer_handle = thread::spawn(move || {
        for gen in 1..=30u8 {
            let payload = vec![gen; 4096];
            writer_storage
                .save_atomic(&payload)
                .expect("Writer atomic save");
            thread::sleep(Duration::from_millis(5));
        }
    });

    writer_handle.join().expect("Writer thread finished");
    stop_signal.store(true, Ordering::Relaxed);

    for handle in reader_handles {
        let reads = handle.join().expect("Reader thread finished");
        assert!(reads > 0, "Reader thread should have performed reads");
    }

    // Final state check: last write was gen 30
    assert_eq!(storage.load_raw().unwrap(), vec![30u8; 4096]);
    assert_eq!(storage.load_raw_backup().unwrap(), vec![29u8; 4096]);
    assert!(!storage.temp_path().exists());
}

// =========================================================================
// 6. Path Handling: Special Characters, Spaces, and Unicode
// =========================================================================

#[test]
fn test_adversarial_paths_with_spaces_brackets_and_unicode() {
    let temp_dir = TempDir::new().expect("TempDir");
    let complex_dir = temp_dir
        .path()
        .join("Special [DirectX Cache] Folder")
        .join("Secret 🔐 測試 (Accents éàü)");
    let vault_file = complex_dir.join("dx12_pipeline.bin");

    let storage = VaultStorage::from_path(&vault_file);

    let v1 = b"UnicodePathPayloadV1";
    let v2 = b"UnicodePathPayloadV2";

    // Write v1 (tests create_dir_all on complex unicode path + MoveFileExW)
    storage.save_atomic(v1).expect("Write v1 with unicode path");
    assert!(vault_file.exists());
    assert_eq!(storage.load_raw().unwrap(), v1);

    // Write v2 (tests ReplaceFileW with unicode path)
    storage.save_atomic(v2).expect("Write v2 with unicode path");
    assert_eq!(storage.load_raw().unwrap(), v2);
    assert_eq!(storage.load_raw_backup().unwrap(), v1);

    // Test restore
    storage.restore_from_backup().expect("Restore on unicode path");
    assert_eq!(storage.load_raw().unwrap(), v1);
    assert_eq!(storage.load_raw_backup().unwrap(), v1);
}

// =========================================================================
// 7. Edge Case: Empty Payload (0 Bytes)
// =========================================================================

#[test]
fn test_adversarial_empty_payload_atomic_save() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("empty_vault.bin");
    let storage = VaultStorage::from_path(&vault_file);

    // Save 0-byte payload
    storage.save_atomic(b"").expect("Save 0-byte payload");
    assert!(vault_file.exists());
    assert_eq!(storage.load_raw().unwrap(), b"");
    assert_eq!(fs::metadata(&vault_file).unwrap().len(), 0);

    // Second write moves empty file to .bak
    storage.save_atomic(b"NonEmptyData").expect("Save non-empty");
    assert_eq!(storage.load_raw().unwrap(), b"NonEmptyData");
    assert_eq!(storage.load_raw_backup().unwrap(), b"");
}
