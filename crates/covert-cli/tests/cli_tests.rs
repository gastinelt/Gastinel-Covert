//! Integration tests for covert-cli commands.
//!
//! Les secrets ne peuvent plus etre passes en argument : les tests utilisent la
//! voie non-interactive par variables d'environnement (COVERT_PASSWORD,
//! COVERT_TIER2_PASSWORD, COVERT_TOTP, COVERT_RECOVERY_CODE), reservee a
//! l'automatisation. Comme ces variables sont globales au processus, un mutex
//! serialise les tests entre eux et nettoie l'environnement avant chaque test.

use covert_cli::args::{AutotypeArgs, DaemonArgs, GetArgs, InitArgs, UnlockArgs};
use covert_cli::commands::{
    execute_autotype, execute_get, execute_init, execute_unlock,
};
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use covert_storage::VaultStorage;
use std::fs;
use std::sync::{Mutex, MutexGuard, OnceLock};

const SECRET_ENV_VARS: [&str; 4] = [
    "COVERT_PASSWORD",
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
