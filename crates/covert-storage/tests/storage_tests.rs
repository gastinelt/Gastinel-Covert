//! Comprehensive unit and integration test suite for `covert-storage`.

use covert_core::header::Argon2Params;
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use covert_storage::paths::{
    default_camouflaged_path, derive_backup_path, derive_lock_path, derive_temp_path,
    VAULT_BACKUP_NAME, VAULT_DIR_DIRECTX, VAULT_DIR_SHADER_CACHE, VAULT_FILE_NAME,
    VAULT_LOCK_NAME, VAULT_TEMP_NAME,
};
use covert_storage::{StorageError, VaultStorage};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_default_camouflaged_path_resolution() {
    let path = default_camouflaged_path().expect("Default path must resolve");
    assert!(
        path.ends_with(
            PathBuf::from(VAULT_DIR_DIRECTX)
                .join(VAULT_DIR_SHADER_CACHE)
                .join(VAULT_FILE_NAME)
        ),
        "Default path must end with DirectX/ShaderCache/dx12_pipeline.bin, got: {:?}",
        path
    );

    let storage = VaultStorage::default_camouflaged().expect("VaultStorage::default_camouflaged");
    assert_eq!(storage.vault_path(), path.as_path());
    assert_eq!(
        storage.temp_path(),
        path.parent().unwrap().join(VAULT_TEMP_NAME)
    );
    assert_eq!(
        storage.backup_path(),
        path.parent().unwrap().join(VAULT_BACKUP_NAME)
    );
    assert_eq!(
        storage.lock_path(),
        path.parent().unwrap().join(VAULT_LOCK_NAME)
    );
}

#[test]
fn test_path_derivation_logic() {
    // 1. Standard camouflaged filename
    let p1 = PathBuf::from("C:\\AppData\\DirectX\\ShaderCache\\dx12_pipeline.bin");
    assert_eq!(
        derive_temp_path(&p1),
        PathBuf::from("C:\\AppData\\DirectX\\ShaderCache\\dx12_pipeline.tmp")
    );
    assert_eq!(
        derive_backup_path(&p1),
        PathBuf::from("C:\\AppData\\DirectX\\ShaderCache\\dx12_pipeline.bin.bak")
    );
    assert_eq!(
        derive_lock_path(&p1),
        PathBuf::from("C:\\AppData\\DirectX\\ShaderCache\\dx12_pipeline.lock")
    );

    // 2. Custom filename with .bin extension
    let p2 = PathBuf::from("D:\\custom\\storage\\my_vault.bin");
    assert_eq!(
        derive_temp_path(&p2),
        PathBuf::from("D:\\custom\\storage\\my_vault.tmp")
    );
    assert_eq!(
        derive_backup_path(&p2),
        PathBuf::from("D:\\custom\\storage\\my_vault.bin.bak")
    );
    assert_eq!(
        derive_lock_path(&p2),
        PathBuf::from("D:\\custom\\storage\\my_vault.lock")
    );

    // 3. Custom filename without extension
    let p3 = PathBuf::from("E:\\test_dir\\vault_blob");
    assert_eq!(
        derive_temp_path(&p3),
        PathBuf::from("E:\\test_dir\\vault_blob.tmp")
    );
    assert_eq!(
        derive_backup_path(&p3),
        PathBuf::from("E:\\test_dir\\vault_blob.bak")
    );
    assert_eq!(
        derive_lock_path(&p3),
        PathBuf::from("E:\\test_dir\\vault_blob.lock")
    );
}

#[test]
fn test_first_time_file_creation_when_dest_does_not_exist() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    assert!(!storage.exists());
    assert!(!storage.backup_exists());

    let payload = b"FirstEverVaultPayloadInitialBytes";
    storage.save_atomic(payload).expect("Initial save_atomic");

    assert!(storage.exists());
    assert!(vault_file.exists());
    // Initial creation MUST NOT create a backup file
    assert!(!storage.backup_exists());
    assert!(!storage.temp_path().exists());

    let loaded = storage.load_raw().expect("load_raw");
    assert_eq!(loaded, payload);
}

#[test]
fn test_nested_directory_auto_creation() {
    let temp_dir = TempDir::new().expect("TempDir");
    let nested_dir = temp_dir
        .path()
        .join("Deep")
        .join("Sub")
        .join("Folder")
        .join("DirectX")
        .join("ShaderCache");
    let vault_file = nested_dir.join("dx12_pipeline.bin");

    assert!(!nested_dir.exists());

    let storage = VaultStorage::from_path(&vault_file);
    storage
        .save_atomic(b"NestedDirPayload")
        .expect("Save in non-existent directory tree");

    assert!(nested_dir.exists());
    assert!(vault_file.exists());
    let loaded = storage.load_raw().expect("load_raw");
    assert_eq!(loaded, b"NestedDirPayload");
}

#[test]
fn test_atomic_write_creates_bak_copy_of_prior_vault() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let v1_data = b"VaultGenerationAlphaContent111";
    let v2_data = b"VaultGenerationBetaContent222";
    let v3_data = b"VaultGenerationGammaContent333";

    // Gen 1: First write
    storage.save_atomic(v1_data).expect("v1 write");
    assert!(storage.exists());
    assert!(!storage.backup_exists());
    assert_eq!(storage.load_raw().unwrap(), v1_data);

    // Gen 2: Second write -> prior vault (v1) moves to .bak
    storage.save_atomic(v2_data).expect("v2 write");
    assert!(storage.exists());
    assert!(storage.backup_exists());
    assert!(!storage.temp_path().exists());
    assert_eq!(storage.load_raw().unwrap(), v2_data);
    assert_eq!(storage.load_raw_backup().unwrap(), v1_data);

    // Gen 3: Third write -> prior vault (v2) moves to .bak
    storage.save_atomic(v3_data).expect("v3 write");
    assert!(storage.exists());
    assert!(storage.backup_exists());
    assert!(!storage.temp_path().exists());
    assert_eq!(storage.load_raw().unwrap(), v3_data);
    assert_eq!(storage.load_raw_backup().unwrap(), v2_data);
}

#[test]
fn test_temporary_file_written_in_exact_same_directory() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let temp_path = storage.temp_path();
    assert_eq!(
        temp_path.parent(),
        vault_file.parent(),
        "Temporary file must reside in the exact same parent directory"
    );
    assert_eq!(
        storage.backup_path().parent(),
        vault_file.parent(),
        "Backup file must reside in the exact same parent directory"
    );
    assert_eq!(
        storage.lock_path().parent(),
        vault_file.parent(),
        "Lock file must reside in the exact same parent directory"
    );
}

#[test]
fn test_crash_resilience_unaffected_by_stray_tmp_file() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let legitimate_data = b"LegitimateUncorruptedVaultContent";
    storage.save_atomic(legitimate_data).expect("Initial write");

    // Simulate an interrupted write / crash that leaves a partial .tmp file
    let simulated_tmp = storage.temp_path();
    fs::write(&simulated_tmp, b"InterruptedCorruptedJunkData").expect("Write stray tmp");

    // Primary vault MUST remain completely untouched and valid
    assert_eq!(storage.load_raw().unwrap(), legitimate_data);

    // A subsequent atomic save must cleanly succeed and overwrite/remove the temp file
    let next_data = b"NextLegitimateVaultContentAfterCrash";
    storage.save_atomic(next_data).expect("Save after crash");

    assert_eq!(storage.load_raw().unwrap(), next_data);
    assert_eq!(storage.load_raw_backup().unwrap(), legitimate_data);
    assert!(!simulated_tmp.exists());
}

#[test]
fn test_load_raw_non_existent_returns_not_found() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("non_existent_vault.bin");
    let storage = VaultStorage::from_path(&vault_file);

    match storage.load_raw() {
        Err(StorageError::VaultNotFound(p)) => assert_eq!(p, vault_file),
        other => panic!("Expected VaultNotFound, got {:?}", other),
    }

    match storage.load_raw_backup() {
        Err(StorageError::BackupNotFound(p)) => assert_eq!(p, storage.backup_path()),
        other => panic!("Expected BackupNotFound, got {:?}", other),
    }
}

#[test]
fn test_recovery_from_backup() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let good_data = b"VerifiedGoodVaultDataVersion1";
    let bad_data = b"CorruptedOverwrittenVaultDataVersion2";

    // 1. Write good version
    storage.save_atomic(good_data).expect("Save good version");

    // 2. Overwrite with bad version -> good version is now in .bak
    storage.save_atomic(bad_data).expect("Save bad version");
    assert_eq!(storage.load_raw().unwrap(), bad_data);
    assert_eq!(storage.load_raw_backup().unwrap(), good_data);

    // 3. Restore from backup
    storage.restore_from_backup().expect("restore_from_backup");

    // Primary vault is now restored to good_data!
    assert_eq!(storage.load_raw().unwrap(), good_data);
    // Crucially: .bak remains preserved and untouched!
    assert_eq!(storage.load_raw_backup().unwrap(), good_data);
}

#[test]
fn test_restore_from_backup_when_no_backup_returns_error() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    storage.save_atomic(b"SingleVersion").unwrap();
    assert!(!storage.backup_exists());

    match storage.restore_from_backup() {
        Err(StorageError::BackupNotFound(p)) => assert_eq!(p, storage.backup_path()),
        other => panic!("Expected BackupNotFound, got {:?}", other),
    }
}

#[test]
fn test_full_roundtrip_save_and_load_with_covert_core_vault() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let mut vault = Vault::new("Gastinel Storage Test Vault");
    vault.add_item(VaultItem::new_credential(
        "GitHub",
        "octocat",
        "SuperSecretToken99!",
        Some("https://github.com".to_string()),
    ));
    vault.add_item(VaultItem::new_ssh(
        "Personal SSH Key",
        "ed25519",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGastinelKeyBlob",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nFakePrivKey\n-----END OPENSSH PRIVATE KEY-----",
        None,
        Some("user@machine".to_string()),
    ));
    vault.add_item(VaultItem::new_note(
        "Secure Recovery Note",
        "Emergency seed phrase stored safely.",
    ));
    vault.add_item(VaultItem::new_api_key(
        "Anthropic API",
        "api.anthropic.com",
        "sk-ant-test-key-1234567890",
        Some(1893456000),
    ));

    let password = SecretString::new("CorrectMasterPassword!@#".to_string());
    let wrong_password = SecretString::new("WrongMasterPassword!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    // 1. Save vault using covert-storage
    storage
        .save_vault(&vault, &password, Some(fast_params))
        .expect("save_vault must succeed");

    assert!(storage.exists());
    assert!(!storage.backup_exists());

    // 2. Load vault with wrong password must fail with crypto error
    let fail_res = storage.load_vault(&wrong_password);
    assert!(fail_res.is_err(), "Wrong password must fail decryption");

    // 3. Load vault with correct password must restore exact vault structure
    let (restored_vault, header) = storage
        .load_vault(&password)
        .expect("load_vault must succeed with correct password");

    assert_eq!(restored_vault.metadata.name, "Gastinel Storage Test Vault");
    assert_eq!(restored_vault.items.len(), 4);
    assert_eq!(restored_vault.items[0].title, "GitHub");
    assert_eq!(restored_vault.items[1].title, "Personal SSH Key");
    assert_eq!(restored_vault.items[2].title, "Secure Recovery Note");
    assert_eq!(restored_vault.items[3].title, "Anthropic API");
    assert_eq!(header.format_version, 1);
    assert_eq!(header.kdf_algo, 0x01);
    assert_eq!(header.cipher_algo, 0x01);

    // 4. Update vault and save again -> creates .bak
    let mut updated_vault = restored_vault;
    updated_vault.add_item(VaultItem::new_raw_secret(
        "Hardware Token Seed",
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    ));

    storage
        .save_vault(&updated_vault, &password, Some(fast_params))
        .expect("Second save_vault");

    assert!(storage.backup_exists());

    // 5. Verify backup can be decrypted and contains 4 items
    let (backup_vault, _) = storage
        .load_vault_from_backup(&password)
        .expect("load_vault_from_backup");
    assert_eq!(backup_vault.items.len(), 4);

    // 6. Verify primary vault contains 5 items
    let (current_vault, _) = storage
        .load_vault(&password)
        .expect("load_vault after update");
    assert_eq!(current_vault.items.len(), 5);
    assert_eq!(current_vault.items[4].title, "Hardware Token Seed");

    // 7. Simulate primary file corruption, then restore from backup
    let primary_path = storage.vault_path().to_path_buf();
    fs::write(&primary_path, b"TamperedGarbageBytesReplacingVault").unwrap();

    // Primary vault load now fails
    assert!(storage.load_vault(&password).is_err());

    // Restore from backup
    storage
        .restore_from_backup()
        .expect("Restore after corruption");

    // Primary vault now successfully loads and has 4 items
    let (recovered_vault, _) = storage
        .load_vault(&password)
        .expect("load_vault after recovery");
    assert_eq!(recovered_vault.items.len(), 4);
}

#[test]
fn test_master_password_rotation_updates_backup_and_invalidates_old_password() {
    let temp_dir = TempDir::new().expect("TempDir");
    let vault_file = temp_dir.path().join("dx12_pipeline.bin");
    let storage = VaultStorage::from_path(&vault_file);

    let old_pw = SecretString::new("CompromisedOldPassword123!".to_string());
    let new_pw = SecretString::new("RotatedNewPassword456!".to_string());
    let wrong_pw = SecretString::new("WrongOldPassword999!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    let mut vault = Vault::new("Rotation Test Vault");
    vault.add_item(VaultItem::new_credential(
        "Forgejo",
        "theo",
        "InitialSecretPass!",
        Some("https://git.gastinel.me".to_string()),
    ));

    // 1. Initial save (.bin encrypted with old_pw)
    storage
        .save_vault(&vault, &old_pw, Some(fast_params))
        .expect("Initial save_vault");

    // 2. Second save so .bak also exists and is encrypted with old_pw
    vault.add_item(VaultItem::new_note("Second Item", "Before rotation"));
    storage
        .save_vault(&vault, &old_pw, Some(fast_params))
        .expect("Second save_vault");
    assert!(storage.exists());
    assert!(storage.backup_exists());
    assert!(storage.load_vault(&old_pw).is_ok());
    assert!(storage.load_vault_from_backup(&old_pw).is_ok());

    // 3. Attempting rotation with wrong old password must fail and leave files intact
    assert!(storage
        .rotate_master_password(&mut vault, &wrong_pw, &new_pw, Some(fast_params))
        .is_err());
    assert!(storage.load_vault(&old_pw).is_ok());
    assert!(storage.load_vault_from_backup(&old_pw).is_ok());

    // 4. Rotate master password with valid old_pw -> new_pw
    storage
        .rotate_master_password(&mut vault, &old_pw, &new_pw, Some(fast_params))
        .expect("rotate_master_password must succeed");

    assert!(storage.exists());
    assert!(storage.backup_exists());
    assert!(!storage.temp_path().exists());

    // 5. Old password MUST NOT decrypt either .bin or .bak
    assert!(
        storage.load_vault(&old_pw).is_err(),
        "Old password must not open primary .bin after rotation"
    );
    assert!(
        storage.load_vault_from_backup(&old_pw).is_err(),
        "Old password must not open backup .bak after rotation"
    );
    let raw_bin = storage.load_raw().expect("load_raw");
    let raw_bak = storage.load_raw_backup().expect("load_raw_backup");
    assert!(Vault::decrypt(&raw_bin, &old_pw).is_err());
    assert!(Vault::decrypt(&raw_bak, &old_pw).is_err());

    // 6. New password MUST decrypt both .bin and .bak with all items intact
    let (loaded_bin, _) = storage
        .load_vault(&new_pw)
        .expect("New password must decrypt primary .bin");
    let (loaded_bak, _) = storage
        .load_vault_from_backup(&new_pw)
        .expect("New password must decrypt backup .bak");
    assert_eq!(loaded_bin.items.len(), 2);
    assert_eq!(loaded_bak.items.len(), 2);
    assert_eq!(loaded_bin.items[0].title, "Forgejo");
    assert_eq!(loaded_bak.items[1].title, "Second Item");
}

