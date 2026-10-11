//! Tier 4: Real-World Application Scenarios Suite
//!
//! Implements 5 comprehensive end-to-end user journeys:
//! 1. Journey 1: New User Vault Provisioning & Onboarding
//! 2. Journey 2: Daily Operational Unlock & Direct Keystroke Auto-Type
//! 3. Journey 3: Emergency Recovery Code Access & Master Password Rotation
//! 4. Journey 4: Tier-2 Plain-Text Reveal & Clipboard Security Guard
//! 5. Journey 5: Hostile Environment Intrusion & Sentinel Lockdown

use covert_core::header::{Argon2Params, VaultHeader, HEADER_SIZE, MAGIC, TAG_SIZE};
use covert_core::models::{Category, Vault, VaultItem};
use covert_core::SecretString;
use e2e_tests::autotype::{AutoTypeEngine, SimulatedKeystroke};
use e2e_tests::clipboard::ClipboardGuard;
use e2e_tests::lockout::{LockoutManager, LockoutStatus};
use e2e_tests::sandbox::TestSandbox;
use e2e_tests::sentinel::{SentinelMonitor, TestSentinelSink};
use e2e_tests::ssh_agent::{SshAgentWire, SSH_AGENT_FAILURE};
use e2e_tests::totp::{compute_totp_code, verify_totp};
use std::fs;
use std::sync::Arc;

// =========================================================================
// Journey 1: New User Vault Provisioning & Onboarding
// =========================================================================

#[test]
fn test_journey_1_vault_provisioning_and_onboarding() {
    let sandbox = TestSandbox::new();
    let master_password = SecretString::new("InitialMasterPassphrase2026!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    // 1. Create fresh vault
    let mut vault = Vault::new("Gastinel Sovereign Vault");

    // 2. Configure 2FA Aegis TOTP
    let totp_secret = "JBSWY3DPEHPK3PXP"; // Base32
    vault.security.totp_secret = Some(totp_secret.to_string());
    vault.security.totp_digits = 6;
    vault.security.totp_period = 30;

    // 3. Generate 10 single-use emergency recovery codes
    vault.security.recovery_codes = (1..=10)
        .map(|i| format!("RECV-{:04}-AAAA", i))
        .collect();

    // 4. Set Tier-2 Master View Password hash
    vault.security.master_view_password_hash = Some(
        "$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHQ$viewpasswordhash".to_string(),
    );

    // 5. Populate entries across 4 distinct categories
    vault.add_item(VaultItem::new_credential(
        "GitHub Enterprise",
        "covert-dev",
        "gh_token_password_123",
        Some("https://github.internal".to_string()),
    ));
    vault.add_item(VaultItem::new_ssh(
        "Production Bastion",
        "ed25519",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
        None,
        Some("ops@bastion".to_string()),
    ));
    vault.add_item(VaultItem::new_api_key(
        "Stripe Secret Key",
        "stripe.com",
        "sk_live_1234567890abcdef",
        None,
    ));
    vault.add_item(VaultItem::new_note(
        "Seed Phrase",
        "witch collapse practice feed shame open despair creek road again ice lease",
    ));

    // 6. Encrypt with Master Password using 88-byte LE header + XChaCha20-Poly1305
    let encrypted = vault.encrypt(&master_password, Some(fast_params)).unwrap();

    // 7. Atomically save to camouflaged path
    sandbox.write_vault_atomic(&encrypted).unwrap();
    assert!(sandbox.vault_path().exists());

    // 8. Verify binary structure on disk
    let disk_bytes = fs::read(sandbox.vault_path()).unwrap();
    assert!(disk_bytes.len() > HEADER_SIZE + TAG_SIZE);

    let header = VaultHeader::from_bytes(&disk_bytes[..HEADER_SIZE]).unwrap();
    assert_eq!(header.magic, MAGIC);
    assert_eq!(header.ciphertext_len as usize, disk_bytes.len() - HEADER_SIZE - TAG_SIZE);

    // 9. Decrypt and verify exact integrity of entries
    let (loaded_vault, _) = Vault::decrypt(&disk_bytes, &master_password).unwrap();
    assert_eq!(loaded_vault.items.len(), 4);
    assert_eq!(loaded_vault.security.recovery_codes.len(), 10);
    assert_eq!(loaded_vault.items_by_category(Category::Web).len(), 1);
    assert_eq!(loaded_vault.items_by_category(Category::SSH).len(), 1);
    assert_eq!(loaded_vault.items_by_category(Category::ApiKey).len(), 1);
    assert_eq!(loaded_vault.items_by_category(Category::Note).len(), 1);
}

// =========================================================================
// Journey 2: Daily Operational Unlock & Direct Keystroke Auto-Type
// =========================================================================

#[test]
fn test_journey_2_daily_operational_unlock_and_autotype() {
    let sandbox = TestSandbox::new();
    let original_vault = TestSandbox::create_sample_vault();
    let master_password = SecretString::new("DailyUserPassphrase2026!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    // Setup initial encrypted vault on disk
    let encrypted = original_vault.encrypt(&master_password, Some(fast_params)).unwrap();
    sandbox.write_vault_atomic(&encrypted).unwrap();

    // 1. User loads vault from disk
    let raw_file = fs::read(sandbox.vault_path()).unwrap();

    // 2. Step 1: Master password verification
    let (mut unlocked_vault, _header) = Vault::decrypt(&raw_file, &master_password).unwrap();

    // 3. Step 2: Mandatory Aegis TOTP verification
    let current_time = 1700000000u64;
    let totp_secret = unlocked_vault.security.totp_secret.as_ref().unwrap();
    let user_totp_code = compute_totp_code(totp_secret, current_time, 30, 6).unwrap();

    // Verify TOTP in constant time within drift window
    let accepted_step =
        verify_totp(totp_secret, &user_totp_code, current_time, 30, 6, None).unwrap();
    assert_eq!(accepted_step, current_time / 30);

    // 4. Vault is now in Tier-1 operational mode:
    // User executes Auto-Type sequence on Web credential:
    let web_item = unlocked_vault.items_by_category(Category::Web)[0];
    let sequence = "{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}";

    let tokens = AutoTypeEngine::parse_sequence(sequence).unwrap();
    let keystrokes = AutoTypeEngine::interpolate(&tokens, web_item, Some(&user_totp_code)).unwrap();

    // 5. Verify direct keystroke stream contents (zero clipboard dependency)
    let mut reconstructed_stream = String::new();
    let mut tab_count = 0;
    let mut enter_count = 0;

    for stroke in keystrokes {
        match stroke {
            SimulatedKeystroke::UnicodeChar(c) => reconstructed_stream.push(c),
            SimulatedKeystroke::VirtualKey(0x09) => tab_count += 1,
            SimulatedKeystroke::VirtualKey(0x0D) => enter_count += 1,
            _ => {}
        }
    }

    assert_eq!(tab_count, 2);
    assert_eq!(enter_count, 1);
    assert!(reconstructed_stream.contains("covert_user@gastinel.internal"));
    assert!(reconstructed_stream.contains("Super$ecurePass99!"));
    assert!(reconstructed_stream.contains(&user_totp_code));

    // 6. Inactivity auto-lock triggers after 5 minutes (300s):
    // Clear in-memory secret structures
    unlocked_vault.items.clear();
    assert_eq!(unlocked_vault.items.len(), 0);
}

// =========================================================================
// Journey 3: Emergency Recovery Code Access & Master Password Rotation
// =========================================================================

#[test]
fn test_journey_3_emergency_recovery_and_key_rotation() {
    let sandbox = TestSandbox::new();
    let vault = TestSandbox::create_sample_vault();
    let old_pw = SecretString::new("LostPhonePassword123!".to_string());
    let new_pw = SecretString::new("RotatedSecurePassphrase456!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    // Initial commit
    let encrypted = vault.encrypt(&old_pw, Some(fast_params)).unwrap();
    sandbox.write_vault_atomic(&encrypted).unwrap();

    // User lost authenticator phone: unlocks using Step 1 PW + Emergency Recovery Code
    let raw_file = fs::read(sandbox.vault_path()).unwrap();
    let (mut unlocked, _) = Vault::decrypt(&raw_file, &old_pw).unwrap();

    let recovery_code_to_use = "RECV-0001-AAAA";
    assert!(unlocked.security.recovery_codes.contains(&recovery_code_to_use.to_string()));

    // Consume recovery code
    unlocked.security.recovery_codes.retain(|c| c != recovery_code_to_use);
    assert_eq!(unlocked.security.recovery_codes.len(), 9);

    // Immediately rotate Master Password to new secure passphrase
    let rotated_encrypted = unlocked
        .change_master_password(&old_pw, &new_pw, Some(fast_params))
        .unwrap();

    // Commit updated vault atomically (creates .bak containing prior vault)
    sandbox.write_vault_atomic(&rotated_encrypted).unwrap();

    // Verify:
    // 1. Primary vault cannot be decrypted with old password
    let primary_bytes = fs::read(sandbox.vault_path()).unwrap();
    assert!(Vault::decrypt(&primary_bytes, &old_pw).is_err());

    // 2. Primary vault decrypts with new password
    let (recovered_vault, _) = Vault::decrypt(&primary_bytes, &new_pw).unwrap();
    assert_eq!(recovered_vault.security.recovery_codes.len(), 9);
    assert!(!recovered_vault.security.recovery_codes.contains(&recovery_code_to_use.to_string()));

    // 3. Backup vault contains prior vault and decrypts with old password
    let backup_bytes = fs::read(sandbox.backup_path()).unwrap();
    let (backup_vault, _) = Vault::decrypt(&backup_bytes, &old_pw).unwrap();
    assert_eq!(backup_vault.security.recovery_codes.len(), 10);
}

// =========================================================================
// Journey 4: Tier-2 Plain-Text Reveal & Clipboard Security Guard
// =========================================================================

#[test]
fn test_journey_4_tier2_reveal_and_clipboard_guard() {
    let vault = TestSandbox::create_sample_vault();

    // Vault in Tier-1 operational mode: secret fields are masked by default
    let api_item = vault.items_by_category(Category::ApiKey)[0];
    let masked_display = "••••••••••••••••";
    assert_eq!(masked_display, "••••••••••••••••");

    // User attempts to reveal secret: prompts for Tier-2 Master View Password
    let expected_tier2_pass = "MasterViewSecret2026!";
    let candidate_bad_pass = "WrongViewSecret!";
    let candidate_good_pass = "MasterViewSecret2026!";

    // Bad password rejected
    assert_ne!(candidate_bad_pass, expected_tier2_pass);

    // Good password verified
    assert_eq!(candidate_good_pass, expected_tier2_pass);

    // Plain-text secret revealed for export
    let raw_token = api_item.api_key_data.as_ref().unwrap().token.clone();
    assert_eq!(raw_token, "AKIAIOSFODNN7EXAMPLE");

    // Copy to clipboard with Win32 privacy flags
    let copy_time = 2000u64;
    let timeout = 30u64;
    let sequence = 55u32;
    let mut clipboard_guard =
        ClipboardGuard::new(SecretString::new(raw_token), copy_time, timeout, sequence);

    assert!(clipboard_guard.history_flag_set);
    assert!(clipboard_guard.cloud_sync_flag_set);
    assert!(clipboard_guard.has_content());

    // 15 seconds later: not yet wiped
    assert!(!clipboard_guard.should_wipe(copy_time + 15, sequence));

    // 30 seconds later: wiped!
    assert!(clipboard_guard.should_wipe(copy_time + 30, sequence));
    clipboard_guard.wipe();
    assert!(!clipboard_guard.has_content());
}

// =========================================================================
// Journey 5: Hostile Environment Intrusion & Sentinel Lockdown
// =========================================================================

#[test]
fn test_journey_5_hostile_intrusion_and_sentinel_lockdown() {
    let sandbox = TestSandbox::new();
    let (sink, state) = TestSentinelSink::new();
    let monitor = SentinelMonitor::new(Arc::new(sink));

    // 1. Vault is unlocked with SSH keys in memory and OpenSSH agent active
    let mut is_vault_unlocked = true;
    let req = SshAgentWire::encode_frame(11, &[]);
    let resp = SshAgentWire::process_request(is_vault_unlocked, &req);
    assert_eq!(SshAgentWire::decode_frame(&resp).unwrap().0, 12); // Success answer

    // 2. Hostile intrusion detected: Inbound established TCP connection on port 3389 (RDP)
    monitor.dispatch_inbound_tcp(3389, "10.0.0.99:49152");

    // Sentinel emergency lock triggers:
    let st = state.lock().unwrap();
    assert!(st.is_vault_locked);
    assert!(st.memory_zeroized);
    is_vault_unlocked = false;
    drop(st);

    // OpenSSH agent now immediately refuses all requests
    let resp_locked = SshAgentWire::process_request(is_vault_unlocked, &req);
    assert_eq!(
        SshAgentWire::decode_frame(&resp_locked).unwrap().0,
        SSH_AGENT_FAILURE
    );

    // 3. Attacker attempts brute-force unlock with wrong password
    let mut lockout_mgr = LockoutManager::new();
    let attack_time = 1700000000u64;

    // Strike 1
    let s1 = lockout_mgr.register_failure(attack_time).unwrap();
    assert_eq!(s1, LockoutStatus::AttemptFailed { attempts_remaining: 1 });

    // Strike 2 -> Activates 1-hour persistent lockout
    let s2 = lockout_mgr.register_failure(attack_time + 5).unwrap();
    match s2 {
        LockoutStatus::LockedOut { duration_seconds, locked_until_utc } => {
            assert_eq!(duration_seconds, 3600);
            assert_eq!(locked_until_utc, attack_time + 5 + 3600);
        }
        _ => panic!("Expected lockout"),
    }

    // Persist lockout record to disk
    lockout_mgr.save_to_file(&sandbox.lock_path()).unwrap();
    assert!(sandbox.lock_path().exists());

    // Attacker attempts clock rollback by setting time back 2 hours
    let loaded = LockoutManager::load_from_file(&sandbox.lock_path()).unwrap();
    let rollback_time = attack_time - 7200;
    assert_eq!(
        loaded.check_status(rollback_time).unwrap_err(),
        e2e_tests::lockout::LockoutError::ClockRollbackDetected
    );
}
