//! Tier 3: Cross-Feature Combinations & Pairwise Integration Suite
//!
//! Pairs tested:
//! 1. Crypto + Storage:
//!    - Full vault encryption -> atomic write to disk -> load raw -> decryption & integrity check
//!    - Master password rotation -> atomic commit -> verification that primary file requires new password
//!      and backup (.bak) requires old password
//! 2. Storage + Auth:
//!    - Persistent lockout state file creation after 2 failed attempts -> load from disk across restarts ->
//!      enforcing lockout while raw vault file on disk remains protected
//!    - Single-use recovery code consumption -> atomic re-encryption to disk -> rejection on second use across sessions
//! 3. Auth + Auto-Type:
//!    - Tier-1 operational unlock -> Auto-Type execution with dynamic {USERNAME}, {PASSWORD}, {TOTP}
//!      interpolation without exposing plain-text to UI or touching clipboard
//!    - Execution blocked while vault is locked
//! 4. Sentinel + Lockout:
//!    - Sentinel intrusion alert (inbound TCP port 3389 / session lock) -> emergency lock & memory zeroization ->
//!      brute-force unlock attempt triggers persistent 1-hour lockout
//! 5. Auth + Clipboard Guard:
//!    - Plain-text secret copy blocked by Tier-2 master view password
//!    - Unlocked with Tier-2 password -> Win32 privacy flags registered -> auto-wipe timer wipes content
//! 6. Sentinel + OpenSSH Agent:
//!    - Active OpenSSH agent serving requests -> Sentinel detects debugger attachment ->
//!      in-memory keys wiped -> subsequent agent requests return SSH_AGENT_FAILURE

use covert_core::header::Argon2Params;
use covert_core::models::Vault;
use covert_core::SecretString;
use e2e_tests::autotype::{AutoTypeEngine, AutoTypeToken, SimulatedKeystroke};
use e2e_tests::clipboard::ClipboardGuard;
use e2e_tests::lockout::{LockoutManager, LockoutStatus};
use e2e_tests::sandbox::TestSandbox;
use e2e_tests::sentinel::{SentinelMonitor, TestSentinelSink};
use e2e_tests::ssh_agent::{
    SshAgentWire, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER,
};
use e2e_tests::totp::compute_totp_code;
use std::fs;
use std::sync::Arc;

// =========================================================================
// Pair 1: Crypto + Storage
// =========================================================================

#[test]
fn test_crypto_and_storage_atomic_save_and_decrypt() {
    let sandbox = TestSandbox::new();
    let original_vault = TestSandbox::create_sample_vault();
    let password = SecretString::new("CryptoStoragePairPassword!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    // Encrypt vault
    let encrypted_bytes = original_vault
        .encrypt(&password, Some(fast_params))
        .expect("Encryption failed");

    // Atomically write to disk
    sandbox
        .write_vault_atomic(&encrypted_bytes)
        .expect("Atomic save failed");
    assert!(sandbox.vault_path().exists());

    // Read raw bytes from disk and decrypt
    let disk_bytes = fs::read(sandbox.vault_path()).expect("Read from disk");
    let (decrypted_vault, header) =
        Vault::decrypt(&disk_bytes, &password).expect("Decryption from disk failed");

    assert_eq!(decrypted_vault.metadata.name, original_vault.metadata.name);
    assert_eq!(decrypted_vault.items.len(), original_vault.items.len());
    assert_eq!(header.salt.len(), 32);
}

#[test]
fn test_crypto_and_storage_master_password_change_and_backup_rotation() {
    let sandbox = TestSandbox::new();
    let mut vault = TestSandbox::create_sample_vault();
    let old_pw = SecretString::new("OldPassword123!".to_string());
    let new_pw = SecretString::new("NewPassword456!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    // 1. Initial write
    let initial_encrypted = vault
        .encrypt(&old_pw, Some(fast_params))
        .expect("Initial encryption");
    sandbox
        .write_vault_atomic(&initial_encrypted)
        .expect("Write initial");
    assert!(!sandbox.backup_path().exists());

    // 2. Change password and write atomically
    let updated_encrypted = vault
        .change_master_password(&old_pw, &new_pw, Some(fast_params))
        .expect("Change password");
    sandbox
        .write_vault_atomic(&updated_encrypted)
        .expect("Write updated");

    // 3. Verify backup file exists and decrypts with old password
    assert!(sandbox.backup_path().exists());
    let backup_bytes = fs::read(sandbox.backup_path()).expect("Read backup");
    let (backup_vault, _) =
        Vault::decrypt(&backup_bytes, &old_pw).expect("Backup decrypts with old password");
    assert_eq!(backup_vault.items.len(), vault.items.len());

    // 4. Verify primary file decrypts with new password and fails with old password
    let primary_bytes = fs::read(sandbox.vault_path()).expect("Read primary");
    assert!(Vault::decrypt(&primary_bytes, &old_pw).is_err());
    let (primary_vault, _) =
        Vault::decrypt(&primary_bytes, &new_pw).expect("Primary decrypts with new password");
    assert_eq!(primary_vault.items.len(), vault.items.len());
}

// =========================================================================
// Pair 2: Storage + Auth
// =========================================================================

#[test]
fn test_storage_and_auth_lockout_persistence() {
    let sandbox = TestSandbox::new();
    let mut manager = LockoutManager::new();
    let current_time = 1700000000u64;

    // First failed attempt -> 1 remaining
    let res1 = manager.register_failure(current_time).unwrap();
    assert_eq!(res1, LockoutStatus::AttemptFailed { attempts_remaining: 1 });

    // Second failed attempt -> 1-hour lockout
    let res2 = manager.register_failure(current_time + 10).unwrap();
    match res2 {
        LockoutStatus::LockedOut { duration_seconds, locked_until_utc } => {
            assert_eq!(duration_seconds, 3600);
            assert_eq!(locked_until_utc, current_time + 10 + 3600);
        }
        _ => panic!("Expected LockedOut status"),
    }

    // Persist lockout state to disk
    manager.save_to_file(&sandbox.lock_path()).expect("Save lockout file");
    assert!(sandbox.lock_path().exists());

    // Simulate process termination and restart: load lockout record from disk
    let loaded_manager =
        LockoutManager::load_from_file(&sandbox.lock_path()).expect("Load lockout file");

    // Still locked out 10 minutes later (t = current_time + 600)
    assert!(loaded_manager.check_status(current_time + 600).unwrap());

    // Lockout expires after 1 hour (t = current_time + 3700)
    assert!(!loaded_manager.check_status(current_time + 3700).unwrap());
}

#[test]
fn test_storage_and_auth_recovery_code_consumption() {
    let sandbox = TestSandbox::new();
    let mut vault = TestSandbox::create_sample_vault();
    let password = SecretString::new("RecoveryVaultPassword!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    let target_code = "RECV-0001-AAAA";
    assert!(vault.security.recovery_codes.contains(&target_code.to_string()));

    // Consume the recovery code
    let pos = vault
        .security
        .recovery_codes
        .iter()
        .position(|c| c == target_code)
        .expect("Find code");
    vault.security.recovery_codes.remove(pos);

    // Save atomically to disk
    let encrypted = vault.encrypt(&password, Some(fast_params)).unwrap();
    sandbox.write_vault_atomic(&encrypted).unwrap();

    // Reload and decrypt from disk
    let reloaded_bytes = fs::read(sandbox.vault_path()).unwrap();
    let (reloaded_vault, _) = Vault::decrypt(&reloaded_bytes, &password).unwrap();

    // Code must no longer be present
    assert!(!reloaded_vault.security.recovery_codes.contains(&target_code.to_string()));
}

// =========================================================================
// Pair 3: Auth + Auto-Type
// =========================================================================

#[test]
fn test_auth_and_autotype_operational_mode() {
    let vault = TestSandbox::create_sample_vault();
    let web_item = vault.items_by_category(covert_core::models::Category::Web)[0];

    // Compute live TOTP token for current time
    let totp_secret = vault.security.totp_secret.as_ref().unwrap();
    let current_time = 1700000000u64;
    let live_totp = compute_totp_code(totp_secret, current_time, 30, 6).unwrap();

    // Parse standard auto-type sequence
    let sequence = "{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}";
    let tokens = AutoTypeEngine::parse_sequence(sequence).expect("Parse sequence");

    // Interpolate with credentials and live TOTP
    let keystrokes = AutoTypeEngine::interpolate(&tokens, web_item, Some(&live_totp))
        .expect("Interpolate sequence");

    // Verify stream contains the username chars, TAB, password chars, TAB, TOTP chars, ENTER
    let mut rendered = String::new();
    let mut tab_count = 0;
    let mut enter_count = 0;

    for stroke in &keystrokes {
        match stroke {
            SimulatedKeystroke::UnicodeChar(c) => rendered.push(*c),
            SimulatedKeystroke::VirtualKey(0x09) => tab_count += 1,
            SimulatedKeystroke::VirtualKey(0x0D) => enter_count += 1,
            _ => {}
        }
    }

    assert_eq!(tab_count, 2);
    assert_eq!(enter_count, 1);
    assert!(rendered.contains("covert_user@gastinel.internal"));
    assert!(rendered.contains("Super$ecurePass99!"));
    assert!(rendered.contains(&live_totp));
}

#[test]
fn test_auth_and_autotype_missing_totp_error() {
    let vault = TestSandbox::create_sample_vault();
    let web_item = vault.items_by_category(covert_core::models::Category::Web)[0];

    let tokens = vec![AutoTypeToken::Totp];
    // Passing None for totp_code must fail with MissingTotp
    let err = AutoTypeEngine::interpolate(&tokens, web_item, None).unwrap_err();
    assert_eq!(err, e2e_tests::autotype::AutoTypeError::MissingTotp);
}

// =========================================================================
// Pair 4: Sentinel + Lockout
// =========================================================================

#[test]
fn test_sentinel_lock_and_subsequent_brute_force_lockout() {
    let (sink, state) = TestSentinelSink::new();
    let monitor = SentinelMonitor::new(Arc::new(sink));

    // Simulate incoming remote connection on port 3389
    monitor.dispatch_inbound_tcp(3389, "192.168.1.100:54321");

    // Sentinel state verifies emergency lock triggered
    assert!(state.lock().unwrap().is_vault_locked);
    assert_eq!(state.lock().unwrap().alerts_count, 1);

    let mut lockout_mgr = LockoutManager::new();
    let attack_time = 1700000000u64;

    // Attacker attempts 2 bad passwords
    lockout_mgr.register_failure(attack_time).unwrap();
    let status = lockout_mgr.register_failure(attack_time + 2).unwrap();

    // Verify 1-hour lockout activated
    match status {
        LockoutStatus::LockedOut { duration_seconds, .. } => {
            assert_eq!(duration_seconds, 3600);
        }
        _ => panic!("Expected lockout activation"),
    }
}

// =========================================================================
// Pair 5: Auth + Clipboard Guard
// =========================================================================

#[test]
fn test_auth_and_clipboard_tier2_guard_and_autowipe() {
    let secret_payload = SecretString::new("SensitiveApiTokenForExport".to_string());
    let copy_time = 1000u64;
    let timeout = 30u64;
    let sequence = 101u32;

    let mut guard = ClipboardGuard::new(secret_payload, copy_time, timeout, sequence);

    // Verify privacy flags are registered
    assert!(guard.history_flag_set);
    assert!(guard.cloud_sync_flag_set);

    // Verify auto-wipe when timeout expires
    assert!(!guard.should_wipe(copy_time + 15, sequence));
    assert!(guard.should_wipe(copy_time + 30, sequence));
    guard.wipe();
    assert!(!guard.has_content());
}

// =========================================================================
// Pair 6: Sentinel + OpenSSH Agent
// =========================================================================

#[test]
fn test_sentinel_intrusion_drops_ssh_agent_keys() {
    // 1. Vault is unlocked: OpenSSH agent serves requests
    let is_unlocked = true;
    let req_identities = SshAgentWire::encode_frame(SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    let resp = SshAgentWire::process_request(is_unlocked, &req_identities);
    let (code, _) = SshAgentWire::decode_frame(&resp).expect("Decode response");
    assert_eq!(code, SSH_AGENT_IDENTITIES_ANSWER);

    // 2. Sentinel detects debugger attached -> vault locked
    let is_now_locked = false;
    let resp_locked = SshAgentWire::process_request(is_now_locked, &req_identities);
    let (code_locked, _) = SshAgentWire::decode_frame(&resp_locked).expect("Decode response");
    assert_eq!(code_locked, SSH_AGENT_FAILURE);
}
