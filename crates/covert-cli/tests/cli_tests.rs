//! Integration tests for covert-cli commands.
//!
//! Les secrets ne peuvent plus etre passes en argument : les tests utilisent la
//! voie non-interactive par variables d'environnement (COVERT_PASSWORD,
//! COVERT_TIER2_PASSWORD, COVERT_TOTP, COVERT_RECOVERY_CODE), reservee a
//! l'automatisation. Comme ces variables sont globales au processus, un mutex
//! serialise les tests entre eux et nettoie l'environnement avant chaque test.

use covert_cli::args::{
    AddArgs, AutotypeArgs, BackupArgs, ChangeMasterArgs, DaemonArgs, DeleteArgs, EditArgs,
    ExportArgs, GetArgs, ImportArgs, InitArgs, UnlockArgs,
};
use covert_cli::commands::{
    execute_add, execute_autotype, execute_backup, execute_change_master, execute_delete,
    execute_edit, execute_export, execute_get, execute_import, execute_init, execute_unlock,
};
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use covert_storage::VaultStorage;
use std::fs;
use std::sync::{Mutex, MutexGuard, OnceLock};

const SECRET_ENV_VARS: [&str; 7] = [
    "COVERT_PASSWORD",
    "COVERT_NEW_PASSWORD",
    "COVERT_ITEM_SECRET",
    "COVERT_EXPORT_PASSWORD",
    "COVERT_TIER2_PASSWORD",
    "COVERT_TOTP",
    "COVERT_RECOVERY_CODE",
];

/// Verrouille l'acces aux variables d'environnement de secrets et les remet a
/// zero. Le garde reste detenu pour toute la duree du test, ce qui serialise
/// les tests qui manipulent ces variables globales.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_secret_env();
    guard
}

fn clear_secret_env() {
    for var in SECRET_ENV_VARS {
        std::env::remove_var(var);
    }
}

#[test]
fn test_cli_init_and_unlock_lifecycle() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!("covert_cli_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_vault.bin");

    // 1. Init without TOTP
    std::env::set_var("COVERT_PASSWORD", "TestMasterPassword123!");
    let init_args = InitArgs {
        name: "CLI Test Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        setup_tier2: false,
    };
    execute_init(init_args).expect("execute_init");
    assert!(vault_path.exists());

    // 2. Unlock with correct password
    std::env::set_var("COVERT_PASSWORD", "TestMasterPassword123!");
    let unlock_args = UnlockArgs {
        path: Some(vault_path.clone()),
    };
    execute_unlock(unlock_args).expect("execute_unlock");

    // 3. Unlock with wrong password fails
    std::env::set_var("COVERT_PASSWORD", "WrongPassword!");
    let wrong_unlock = UnlockArgs {
        path: Some(vault_path.clone()),
    };
    assert!(execute_unlock(wrong_unlock).is_err());

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_init_totp_and_get() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!("covert_cli_totp_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_totp_vault.bin");

    // 1. Init with TOTP
    std::env::set_var("COVERT_PASSWORD", "SuperSecretPassword!");
    let init_args = InitArgs {
        name: "2FA Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: true,
        setup_tier2: false,
    };
    execute_init(init_args).expect("execute_init with totp");

    // Load created vault to inspect TOTP secret and recovery codes
    let storage = VaultStorage::from_path(&vault_path);
    let sec_pw = SecretString::from("SuperSecretPassword!".to_string());
    let (mut vault, _) = storage.load_vault(&sec_pw).expect("load vault");
    let recovery_code = vault.security.recovery_codes[0].clone();

    // Add a credential item
    vault.add_item(VaultItem::new_credential(
        "AWS Console",
        "cloud_admin",
        "hunter2",
        Some("https://aws.amazon.com".to_string()),
    ));
    storage.save_vault(&vault, &sec_pw, None).expect("save vault with item");

    // 2. Unlock using recovery code (should consume it)
    std::env::set_var("COVERT_PASSWORD", "SuperSecretPassword!");
    std::env::set_var("COVERT_RECOVERY_CODE", &recovery_code);
    let unlock_rec = UnlockArgs {
        path: Some(vault_path.clone()),
    };
    execute_unlock(unlock_rec).expect("execute_unlock with recovery code");

    // 3. Re-using same recovery code fails
    std::env::set_var("COVERT_PASSWORD", "SuperSecretPassword!");
    std::env::set_var("COVERT_RECOVERY_CODE", &recovery_code);
    let reuse_rec = UnlockArgs {
        path: Some(vault_path.clone()),
    };
    assert!(execute_unlock(reuse_rec).is_err());

    // 4. Query with get command (using a fresh recovery code)
    let (vault2, _) = storage.load_vault(&sec_pw).expect("load updated vault");
    let recovery_code2 = vault2.security.recovery_codes[0].clone();

    std::env::set_var("COVERT_PASSWORD", "SuperSecretPassword!");
    std::env::set_var("COVERT_RECOVERY_CODE", &recovery_code2);
    let get_args = GetArgs {
        query: Some("AWS".to_string()),
        reveal: false,
        json: true,
        path: Some(vault_path.clone()),
    };
    execute_get(get_args).expect("execute_get");

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_autotype_simulated() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!("covert_cli_autotype_sim_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_autotype_vault.bin");

    let storage = VaultStorage::from_path(&vault_path);
    let sec_pw = SecretString::from("MasterPass!".to_string());

    let mut vault = Vault::new("Autotype Vault");
    let mut item = VaultItem::new_credential(
        "GitHub",
        "octocat",
        "github_secret",
        Some("https://github.com".to_string()),
    );
    item.auto_type_sequence = Some("{USERNAME}{TAB}{PASSWORD}".to_string());
    vault.add_item(item);
    storage.save_vault(&vault, &sec_pw, None).expect("save vault");

    // Simulated mode uniquement : aucun SendInput reel, tout reste en memoire.
    std::env::set_var("COVERT_PASSWORD", "MasterPass!");
    let autotype_sim = AutotypeArgs {
        query: "GitHub".to_string(),
        sequence: None,
        delay: 0,
        simulated: true,
        path: Some(vault_path.clone()),
    };
    execute_autotype(autotype_sim).expect("execute_autotype simulated");

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
#[ignore = "injecte de vraies frappes clavier / manipule la fenetre au premier plan ; lancer volontairement avec: cargo test -- --ignored"]
fn test_cli_autotype_production() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!("covert_cli_autotype_prod_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_autotype_vault.bin");

    let storage = VaultStorage::from_path(&vault_path);
    let sec_pw = SecretString::from("MasterPass!".to_string());

    let mut vault = Vault::new("Autotype Vault");
    let mut item = VaultItem::new_credential(
        "GitHub",
        "octocat",
        "github_secret",
        Some("https://github.com".to_string()),
    );
    item.auto_type_sequence = Some("{USERNAME}{TAB}{PASSWORD}".to_string());
    vault.add_item(item);
    storage.save_vault(&vault, &sec_pw, None).expect("save vault");

    // Production mode : injecte de VRAIES frappes via Win32 SendInput dans la
    // fenetre au premier plan. Ignore par defaut pour ne pas polluer le poste.
    std::env::set_var("COVERT_PASSWORD", "MasterPass!");
    let autotype_prod = AutotypeArgs {
        query: "GitHub".to_string(),
        sequence: None,
        delay: 0,
        simulated: false,
        path: Some(vault_path.clone()),
    };
    execute_autotype(autotype_prod).expect("execute_autotype prod");

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_daemon_options_parsing() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!("covert_cli_daemon_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_daemon_vault.bin");

    let storage = VaultStorage::from_path(&vault_path);
    let sec_pw = SecretString::from("MasterPass!".to_string());
    let vault = Vault::new("Daemon Vault");
    storage.save_vault(&vault, &sec_pw, None).expect("save vault");

    let daemon_args = DaemonArgs {
        unlock: false,
        pipe: Some(format!(r"\\.\pipe\test-pipe-{}", std::process::id())),
        native_msg: false,
        no_sentinel: true,
        path: Some(vault_path.clone()),
    };

    assert!(daemon_args.no_sentinel);
    assert!(!daemon_args.unlock);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_tier2_password_reveal() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!("covert_cli_tier2_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_tier2_vault.bin");

    // Init vault with Tier-2 password (fourni via COVERT_TIER2_PASSWORD)
    std::env::set_var("COVERT_PASSWORD", "Master123!");
    std::env::set_var("COVERT_TIER2_PASSWORD", "ViewSecret456!");
    let init_args = InitArgs {
        name: "Tier2 Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        setup_tier2: true,
    };
    execute_init(init_args).expect("execute_init with tier2");
    clear_secret_env();

    // Add secret credential
    let storage = VaultStorage::from_path(&vault_path);
    let sec_pw = SecretString::from("Master123!".to_string());
    let (mut vault, _) = storage.load_vault(&sec_pw).expect("load vault");
    vault.add_item(VaultItem::new_credential(
        "Banking",
        "user_bank",
        "super_sensitive_bank_pin",
        Some("https://bank.com".to_string()),
    ));
    storage.save_vault(&vault, &sec_pw, None).expect("save vault");

    // 1. Get with incorrect Tier-2 password fails
    std::env::set_var("COVERT_PASSWORD", "Master123!");
    std::env::set_var("COVERT_TIER2_PASSWORD", "WrongT2!");
    let get_wrong_t2 = GetArgs {
        query: Some("Banking".to_string()),
        reveal: true,
        json: true,
        path: Some(vault_path.clone()),
    };
    assert!(execute_get(get_wrong_t2).is_err());

    // 2. Get with correct Tier-2 password succeeds
    std::env::set_var("COVERT_PASSWORD", "Master123!");
    std::env::set_var("COVERT_TIER2_PASSWORD", "ViewSecret456!");
    let get_correct_t2 = GetArgs {
        query: Some("Banking".to_string()),
        reveal: true,
        json: true,
        path: Some(vault_path.clone()),
    };
    execute_get(get_correct_t2).expect("execute_get with correct tier2");

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_add_command() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!("covert_cli_add_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_add_vault.bin");

    std::env::set_var("COVERT_PASSWORD", "MasterAddPass123!");
    execute_init(InitArgs {
        name: "Add Test Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        setup_tier2: false,
    })
    .expect("init");

    // Add Web item
    std::env::set_var("COVERT_ITEM_SECRET", "WebSecretPass99!");
    execute_add(AddArgs {
        title: "Forgejo".to_string(),
        category: "web".to_string(),
        username: Some("theo".to_string()),
        url: Some("https://git.gastinel.me".to_string()),
        service: None,
        key_type: None,
        public_key: None,
        comment: None,
        notes: Some("Depot interne".to_string()),
        tags: vec!["git".to_string(), "dev".to_string()],
        sequence: None,
        path: Some(vault_path.clone()),
    })
    .expect("execute_add web");

    // Add ApiKey item
    std::env::set_var("COVERT_ITEM_SECRET", "tok_test_abc123");
    execute_add(AddArgs {
        title: "Infomaniak DNS".to_string(),
        category: "apikey".to_string(),
        username: None,
        url: None,
        service: Some("api.infomaniak.com".to_string()),
        key_type: None,
        public_key: None,
        comment: None,
        notes: None,
        tags: vec!["dns".to_string()],
        sequence: None,
        path: Some(vault_path.clone()),
    })
    .expect("execute_add apikey");

    let storage = VaultStorage::from_path(&vault_path);
    let (vault, _) = storage
        .load_vault(&SecretString::from("MasterAddPass123!".to_string()))
        .expect("load_vault");
    assert_eq!(vault.items.len(), 2);
    assert_eq!(vault.items[0].title, "Forgejo");
    assert_eq!(vault.items[0].username.as_deref(), Some("theo"));
    assert_eq!(vault.items[0].password.as_deref(), Some("WebSecretPass99!"));
    assert_eq!(vault.items[1].title, "Infomaniak DNS");
    assert_eq!(
        vault.items[1].api_key_data.as_ref().unwrap().token,
        "tok_test_abc123"
    );

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_edit_command() {
    let _guard = env_lock();

    let temp_dir =
        std::env::temp_dir().join(format!("covert_cli_edit_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_edit_vault.bin");

    std::env::set_var("COVERT_PASSWORD", "MasterEditPass123!");
    execute_init(InitArgs {
        name: "Edit Test Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        setup_tier2: false,
    })
    .expect("init");

    std::env::set_var("COVERT_ITEM_SECRET", "InitialSecret111!");
    execute_add(AddArgs {
        title: "Old Title".to_string(),
        category: "web".to_string(),
        username: Some("old_user".to_string()),
        url: Some("https://old.example.com".to_string()),
        service: None,
        key_type: None,
        public_key: None,
        comment: None,
        notes: None,
        tags: vec!["v1".to_string()],
        sequence: None,
        path: Some(vault_path.clone()),
    })
    .expect("add");

    // Edit metadata and rotate secret
    std::env::set_var("COVERT_ITEM_SECRET", "RotatedSecret222!");
    execute_edit(EditArgs {
        query: "Old Title".to_string(),
        title: Some("New Title".to_string()),
        username: Some("new_user".to_string()),
        url: Some("https://new.example.com".to_string()),
        notes: Some("Updated note".to_string()),
        service: None,
        tags: vec!["v2".to_string()],
        sequence: Some("{USERNAME}{ENTER}".to_string()),
        rotate_secret: true,
        path: Some(vault_path.clone()),
    })
    .expect("execute_edit");

    let storage = VaultStorage::from_path(&vault_path);
    let (vault, _) = storage
        .load_vault(&SecretString::from("MasterEditPass123!".to_string()))
        .expect("load_vault");
    assert_eq!(vault.items.len(), 1);
    assert_eq!(vault.items[0].title, "New Title");
    assert_eq!(vault.items[0].username.as_deref(), Some("new_user"));
    assert_eq!(vault.items[0].url.as_deref(), Some("https://new.example.com"));
    assert_eq!(vault.items[0].password.as_deref(), Some("RotatedSecret222!"));
    assert_eq!(vault.items[0].tags, vec!["v2".to_string()]);

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_delete_command() {
    let _guard = env_lock();

    let temp_dir =
        std::env::temp_dir().join(format!("covert_cli_delete_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_delete_vault.bin");

    std::env::set_var("COVERT_PASSWORD", "MasterDelPass123!");
    execute_init(InitArgs {
        name: "Delete Test Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        setup_tier2: false,
    })
    .expect("init");

    std::env::set_var("COVERT_ITEM_SECRET", "TempPass!");
    execute_add(AddArgs {
        title: "Disposable Account".to_string(),
        category: "web".to_string(),
        username: Some("temp".to_string()),
        url: None,
        service: None,
        key_type: None,
        public_key: None,
        comment: None,
        notes: None,
        tags: Vec::new(),
        sequence: None,
        path: Some(vault_path.clone()),
    })
    .expect("add");

    execute_delete(DeleteArgs {
        query: "Disposable Account".to_string(),
        path: Some(vault_path.clone()),
    })
    .expect("execute_delete");

    // Deleting again must fail
    assert!(execute_delete(DeleteArgs {
        query: "Disposable Account".to_string(),
        path: Some(vault_path.clone()),
    })
    .is_err());

    let storage = VaultStorage::from_path(&vault_path);
    let (vault, _) = storage
        .load_vault(&SecretString::from("MasterDelPass123!".to_string()))
        .expect("load_vault");
    assert!(vault.items.is_empty());

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_change_master_command() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!(
        "covert_cli_change_master_test_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_change_master.bin");

    std::env::set_var("COVERT_PASSWORD", "OldMasterPass111!");
    execute_init(InitArgs {
        name: "ChangeMaster Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        setup_tier2: false,
    })
    .expect("init");

    std::env::set_var("COVERT_ITEM_SECRET", "ItemSecret!");
    execute_add(AddArgs {
        title: "KeepMe".to_string(),
        category: "web".to_string(),
        username: Some("theo".to_string()),
        url: None,
        service: None,
        key_type: None,
        public_key: None,
        comment: None,
        notes: None,
        tags: Vec::new(),
        sequence: None,
        path: Some(vault_path.clone()),
    })
    .expect("add");

    // Rotate master password via CLI command
    std::env::set_var("COVERT_PASSWORD", "OldMasterPass111!");
    std::env::set_var("COVERT_NEW_PASSWORD", "NewMasterPass222!");
    execute_change_master(ChangeMasterArgs {
        path: Some(vault_path.clone()),
    })
    .expect("execute_change_master");

    let storage = VaultStorage::from_path(&vault_path);
    let old_sec = SecretString::from("OldMasterPass111!".to_string());
    let new_sec = SecretString::from("NewMasterPass222!".to_string());

    // Old password opens NEITHER .bin NOR .bak
    assert!(storage.load_vault(&old_sec).is_err());
    assert!(storage.load_vault_from_backup(&old_sec).is_err());

    // New password opens BOTH .bin and .bak
    let (v_bin, _) = storage.load_vault(&new_sec).expect("load .bin with new pw");
    let (v_bak, _) = storage
        .load_vault_from_backup(&new_sec)
        .expect("load .bak with new pw");
    assert_eq!(v_bin.items.len(), 1);
    assert_eq!(v_bak.items.len(), 1);

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_export_and_import_integrity_verification() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!(
        "covert_cli_export_import_test_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("source_vault.bin");
    let export_path = temp_dir.join("vault_export.covert");
    let restored_vault_path = temp_dir.join("restored_vault.bin");

    std::env::set_var("COVERT_PASSWORD", "SourceMasterPass123!");
    execute_init(InitArgs {
        name: "Export Source Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        setup_tier2: false,
    })
    .expect("init");

    std::env::set_var("COVERT_ITEM_SECRET", "ExportedItemSecret99!");
    execute_add(AddArgs {
        title: "Critical Server".to_string(),
        category: "web".to_string(),
        username: Some("root".to_string()),
        url: Some("https://cornaf.internal".to_string()),
        service: None,
        key_type: None,
        public_key: None,
        comment: None,
        notes: None,
        tags: Vec::new(),
        sequence: None,
        path: Some(vault_path.clone()),
    })
    .expect("add");

    // 1. Export with same password as master password MUST be rejected
    std::env::set_var("COVERT_PASSWORD", "SourceMasterPass123!");
    std::env::set_var("COVERT_EXPORT_PASSWORD", "SourceMasterPass123!");
    assert!(execute_export(ExportArgs {
        output: export_path.clone(),
        path: Some(vault_path.clone()),
    })
    .is_err());

    // 2. Export with a separate export password succeeds
    std::env::set_var("COVERT_EXPORT_PASSWORD", "SeparateExportPass789!");
    execute_export(ExportArgs {
        output: export_path.clone(),
        path: Some(vault_path.clone()),
    })
    .expect("execute_export");
    assert!(export_path.exists());

    // 3. Tamper with the exported file (1 bit flip in ciphertext) -> import MUST be refused
    let orig_bytes = fs::read(&export_path).unwrap();
    let tampered_path = temp_dir.join("tampered_export.covert");
    let mut tampered = orig_bytes.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    fs::write(&tampered_path, &tampered).unwrap();

    std::env::set_var("COVERT_EXPORT_PASSWORD", "SeparateExportPass789!");
    std::env::set_var("COVERT_PASSWORD", "RestoredMasterPass456!");
    assert!(
        execute_import(ImportArgs {
            input: tampered_path,
            path: Some(restored_vault_path.clone()),
        })
        .is_err(),
        "Modified export file must be refused by import"
    );
    assert!(!restored_vault_path.exists());

    // 4. Import untampered export file succeeds
    execute_import(ImportArgs {
        input: export_path,
        path: Some(restored_vault_path.clone()),
    })
    .expect("execute_import valid");

    let restored_storage = VaultStorage::from_path(&restored_vault_path);
    let (restored_vault, _) = restored_storage
        .load_vault(&SecretString::from("RestoredMasterPass456!".to_string()))
        .expect("load restored vault");
    assert_eq!(restored_vault.items.len(), 1);
    assert_eq!(restored_vault.items[0].title, "Critical Server");
    assert_eq!(
        restored_vault.items[0].password.as_deref(),
        Some("ExportedItemSecret99!")
    );

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_backup_command() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!(
        "covert_cli_backup_test_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("main_vault.bin");
    let backup_dir = temp_dir.join("backups");

    std::env::set_var("COVERT_PASSWORD", "BackupMasterPass123!");
    execute_init(InitArgs {
        name: "Backup Test Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        setup_tier2: false,
    })
    .expect("init");

    let created_backup = execute_backup(BackupArgs {
        output_dir: backup_dir.clone(),
        path: Some(vault_path.clone()),
    })
    .expect("execute_backup");

    assert!(created_backup.exists());
    let fname = created_backup.file_name().unwrap().to_str().unwrap();
    assert!(fname.starts_with("covert-backup-"));
    assert!(fname.ends_with(".bin"));

    let backup_storage = VaultStorage::from_path(&created_backup);
    let (backed_up_vault, _) = backup_storage
        .load_vault(&SecretString::from("BackupMasterPass123!".to_string()))
        .expect("Backup file must decrypt with master password");
    assert_eq!(backed_up_vault.metadata.name, "Backup Test Vault");

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_full_crud_lifecycle_create_add_edit_delete_export_import_backup() {
    let _guard = env_lock();

    let temp_dir = std::env::temp_dir().join(format!(
        "covert_cli_full_cycle_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("cycle_vault.bin");
    let export_path = temp_dir.join("cycle_export.covert");
    let backup_dir = temp_dir.join("cycle_backups");

    // 1. Create (init)
    std::env::set_var("COVERT_PASSWORD", "CycleMasterPass1!");
    execute_init(InitArgs {
        name: "Cycle Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        setup_tier2: false,
    })
    .expect("1. init");

    // 2. Add two items
    std::env::set_var("COVERT_ITEM_SECRET", "AlphaSecret1!");
    execute_add(AddArgs {
        title: "Service Alpha".to_string(),
        category: "web".to_string(),
        username: Some("alpha_user".to_string()),
        url: Some("https://alpha.local".to_string()),
        service: None,
        key_type: None,
        public_key: None,
        comment: None,
        notes: None,
        tags: vec!["prod".to_string()],
        sequence: None,
        path: Some(vault_path.clone()),
    })
    .expect("2a. add alpha");

    std::env::set_var("COVERT_ITEM_SECRET", "BetaSecret2!");
    execute_add(AddArgs {
        title: "Service Beta".to_string(),
        category: "web".to_string(),
        username: Some("beta_user".to_string()),
        url: Some("https://beta.local".to_string()),
        service: None,
        key_type: None,
        public_key: None,
        comment: None,
        notes: None,
        tags: vec!["staging".to_string()],
        sequence: None,
        path: Some(vault_path.clone()),
    })
    .expect("2b. add beta");

    // 3. Edit Service Alpha
    std::env::set_var("COVERT_ITEM_SECRET", "AlphaSecretUpdated!");
    execute_edit(EditArgs {
        query: "Service Alpha".to_string(),
        title: None,
        username: Some("alpha_admin".to_string()),
        url: None,
        notes: Some("Edited in full cycle".to_string()),
        service: None,
        tags: Vec::new(),
        sequence: None,
        rotate_secret: true,
        path: Some(vault_path.clone()),
    })
    .expect("3. edit alpha");

    // 4. Export with separate password (while both items exist)
    std::env::set_var("COVERT_EXPORT_PASSWORD", "SeparateCycleExportPass9!");
    execute_export(ExportArgs {
        output: export_path.clone(),
        path: Some(vault_path.clone()),
    })
    .expect("4. export");

    // 5. Delete Service Beta
    clear_secret_env();
    std::env::set_var("COVERT_PASSWORD", "CycleMasterPass1!");
    execute_delete(DeleteArgs {
        query: "Service Beta".to_string(),
        path: Some(vault_path.clone()),
    })
    .expect("5. delete beta");

    let storage = VaultStorage::from_path(&vault_path);
    let (v_after_del, _) = storage
        .load_vault(&SecretString::from("CycleMasterPass1!".to_string()))
        .unwrap();
    assert_eq!(v_after_del.items.len(), 1);

    // 6. Import from export (restores Service Beta into existing vault)
    std::env::set_var("COVERT_EXPORT_PASSWORD", "SeparateCycleExportPass9!");
    execute_import(ImportArgs {
        input: export_path,
        path: Some(vault_path.clone()),
    })
    .expect("6. import");

    let (v_after_imp, _) = storage
        .load_vault(&SecretString::from("CycleMasterPass1!".to_string()))
        .unwrap();
    assert_eq!(v_after_imp.items.len(), 2);

    // 7. Backup to dated file
    let backup_file = execute_backup(BackupArgs {
        output_dir: backup_dir,
        path: Some(vault_path.clone()),
    })
    .expect("7. backup");
    assert!(backup_file.exists());

    clear_secret_env();
    let _ = fs::remove_dir_all(&temp_dir);
}

