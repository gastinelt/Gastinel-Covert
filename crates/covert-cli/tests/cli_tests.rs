//! Integration tests for covert-cli commands.

use covert_cli::args::{AutotypeArgs, DaemonArgs, GetArgs, InitArgs, UnlockArgs};
use covert_cli::commands::{
    execute_autotype, execute_get, execute_init, execute_unlock,
};
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use covert_storage::VaultStorage;
use std::fs;

#[test]
fn test_cli_init_and_unlock_lifecycle() {
    let temp_dir = std::env::temp_dir().join(format!("covert_cli_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_vault.bin");

    // 1. Init without TOTP
    let init_args = InitArgs {
        password: Some("TestMasterPassword123!".to_string()),
        name: "CLI Test Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        tier2_password: None,
    };
    execute_init(init_args).expect("execute_init");
    assert!(vault_path.exists());

    // 2. Unlock with correct password
    let unlock_args = UnlockArgs {
        password: Some("TestMasterPassword123!".to_string()),
        totp: None,
        recovery_code: None,
        path: Some(vault_path.clone()),
    };
    execute_unlock(unlock_args).expect("execute_unlock");

    // 3. Unlock with wrong password fails
    let wrong_unlock = UnlockArgs {
        password: Some("WrongPassword!".to_string()),
        totp: None,
        recovery_code: None,
        path: Some(vault_path.clone()),
    };
    assert!(execute_unlock(wrong_unlock).is_err());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_init_totp_and_get() {
    let temp_dir = std::env::temp_dir().join(format!("covert_cli_totp_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_totp_vault.bin");

    // 1. Init with TOTP
    let init_args = InitArgs {
        password: Some("SuperSecretPassword!".to_string()),
        name: "2FA Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: true,
        tier2_password: None,
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
    let unlock_rec = UnlockArgs {
        password: Some("SuperSecretPassword!".to_string()),
        totp: None,
        recovery_code: Some(recovery_code.clone()),
        path: Some(vault_path.clone()),
    };
    execute_unlock(unlock_rec).expect("execute_unlock with recovery code");

    // 3. Re-using same recovery code fails
    let reuse_rec = UnlockArgs {
        password: Some("SuperSecretPassword!".to_string()),
        totp: None,
        recovery_code: Some(recovery_code),
        path: Some(vault_path.clone()),
    };
    assert!(execute_unlock(reuse_rec).is_err());

    // 4. Query with get command (using a fresh recovery code)
    let (vault2, _) = storage.load_vault(&sec_pw).expect("load updated vault");
    let recovery_code2 = vault2.security.recovery_codes[0].clone();

    let get_args = GetArgs {
        query: Some("AWS".to_string()),
        password: Some("SuperSecretPassword!".to_string()),
        totp: None,
        recovery_code: Some(recovery_code2),
        tier2: None,
        json: true,
        path: Some(vault_path.clone()),
    };
    execute_get(get_args).expect("execute_get");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_autotype() {
    let temp_dir = std::env::temp_dir().join(format!("covert_cli_autotype_test_{}", std::process::id()));
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

    // 1. Simulated mode
    let autotype_sim = AutotypeArgs {
        query: "GitHub".to_string(),
        password: Some("MasterPass!".to_string()),
        totp: None,
        sequence: None,
        delay: 0,
        simulated: true,
        path: Some(vault_path.clone()),
    };
    execute_autotype(autotype_sim).expect("execute_autotype simulated");

    // 2. Production mode (Windows-only: gracefully succeeds or warns in non-interactive
    //    sessions). Off-Windows there is no Win32 SendInput backend — direct injection returns
    //    an explicit "Windows only" error — so this path is exercised on Windows targets only.
    #[cfg(windows)]
    {
        let autotype_prod = AutotypeArgs {
            query: "GitHub".to_string(),
            password: Some("MasterPass!".to_string()),
            totp: None,
            sequence: None,
            delay: 0,
            simulated: false,
            path: Some(vault_path.clone()),
        };
        execute_autotype(autotype_prod).expect("execute_autotype prod");
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_daemon_options_parsing() {
    let temp_dir = std::env::temp_dir().join(format!("covert_cli_daemon_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_daemon_vault.bin");

    let storage = VaultStorage::from_path(&vault_path);
    let sec_pw = SecretString::from("MasterPass!".to_string());
    let vault = Vault::new("Daemon Vault");
    storage.save_vault(&vault, &sec_pw, None).expect("save vault");

    let daemon_args = DaemonArgs {
        password: Some("MasterPass!".to_string()),
        totp: None,
        pipe: Some(format!(r"\\.\pipe\test-pipe-{}", std::process::id())),
        native_msg: false,
        no_sentinel: true,
        path: Some(vault_path.clone()),
    };

    assert!(daemon_args.no_sentinel);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_tier2_password_reveal() {
    let temp_dir = std::env::temp_dir().join(format!("covert_cli_tier2_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();
    let vault_path = temp_dir.join("test_tier2_vault.bin");

    // Init vault with Tier-2 password
    let init_args = InitArgs {
        password: Some("Master123!".to_string()),
        name: "Tier2 Vault".to_string(),
        path: Some(vault_path.clone()),
        setup_totp: false,
        tier2_password: Some("ViewSecret456!".to_string()),
    };
    execute_init(init_args).expect("execute_init with tier2");

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
    let get_wrong_t2 = GetArgs {
        query: Some("Banking".to_string()),
        password: Some("Master123!".to_string()),
        totp: None,
        recovery_code: None,
        tier2: Some("WrongT2!".to_string()),
        json: true,
        path: Some(vault_path.clone()),
    };
    assert!(execute_get(get_wrong_t2).is_err());

    // 2. Get with correct Tier-2 password succeeds
    let get_correct_t2 = GetArgs {
        query: Some("Banking".to_string()),
        password: Some("Master123!".to_string()),
        totp: None,
        recovery_code: None,
        tier2: Some("ViewSecret456!".to_string()),
        json: true,
        path: Some(vault_path.clone()),
    };
    execute_get(get_correct_t2).expect("execute_get with correct tier2");

    let _ = fs::remove_dir_all(&temp_dir);
}
