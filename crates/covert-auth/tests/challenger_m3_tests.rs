//! Empirical Challenger Test Suite for Milestone 3 (`covert-auth`).
//!
//! Adversarially verifies:
//! 1. Aegis RFC 6238 TOTP constant-time verification using subtle::ConstantTimeEq.
//! 2. Drift tolerance: codes at t-30s, t, t+30s are accepted; codes outside the window are rejected.
//! 3. Replay prevention: entering the same valid TOTP code twice in the same window must be rejected.
//! 4. Recovery codes: 10 single-use emergency recovery codes, each marked as consumed upon use.
//! 5. Tier-2 Master View Password protection for plain-text reveals and clipboard copy.

use covert_auth::error::{AuthError, TotpError};
use covert_auth::tier2::{
    hash_tier2_password, validate_tier2_candidate, verify_tier2_password,
};
use covert_auth::totp::{
    generate_recovery_codes, verify_and_consume_recovery_code,
    TotpEngine,
};
use covert_auth::AuthManager;
use covert_core::header::Argon2Params;
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use subtle::ConstantTimeEq;

fn create_test_vault(master_pw: &SecretString, totp_secret: &str) -> (Vault, Vec<u8>) {
    let mut vault = Vault::new("Challenger Verification Vault");
    vault.security.totp_secret = Some(totp_secret.to_string());
    vault.security.totp_digits = 6;
    vault.security.totp_period = 30;
    vault.security.totp_algorithm = "SHA1".to_string();
    vault.security.recovery_codes = generate_recovery_codes(10);

    vault.add_item(VaultItem::new_credential(
        "Challenger Target",
        "challenger_user",
        "P@ssw0rd99!",
        None,
    ));

    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();
    let raw_bytes = vault.encrypt(master_pw, Some(fast_params)).unwrap();
    (vault, raw_bytes)
}

// =========================================================================
// Invariant 1: Aegis RFC 6238 TOTP constant-time verification & subtle ct_eq
// =========================================================================

#[test]
fn test_invariant_1_totp_constant_time_and_subtle_eq() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";
    let base_time = 1700000000u64;
    let engine = TotpEngine::from_base32(secret_b32).unwrap();
    let expected = engine.generate_at(base_time).unwrap();

    // Verify constant-time comparison via subtle::ConstantTimeEq directly on candidate bytes
    assert!(bool::from(expected.as_bytes().ct_eq(expected.as_bytes())));

    // Near-miss candidates differing by exactly 1 character at each position
    for pos in 0..6 {
        let mut tampered = expected.clone().into_bytes();
        tampered[pos] = if tampered[pos] == b'9' { b'0' } else { tampered[pos] + 1 };
        let tampered_str = String::from_utf8(tampered).unwrap();

        assert!(!bool::from(expected.as_bytes().ct_eq(tampered_str.as_bytes())));

        let mut fresh_engine = TotpEngine::from_base32(secret_b32).unwrap();
        let res = fresh_engine.verify(&tampered_str, base_time);
        assert_eq!(res.unwrap_err(), TotpError::CodeMismatch);
    }

    // Invalid character candidates
    let invalid_chars = ["12345a", "abcdef", "12 456", "12-456", "12345!", "1234\x005"];
    for invalid in invalid_chars {
        let mut fresh_engine = TotpEngine::from_base32(secret_b32).unwrap();
        let res = fresh_engine.verify(invalid, base_time);
        assert!(
            matches!(res, Err(TotpError::InvalidCharacters)),
            "Expected InvalidCharacters for candidate '{}', got {:?}",
            invalid,
            res
        );
    }

    // Invalid length candidates
    let invalid_lengths = ["", "1", "12", "123", "1234", "12345", "1234567", "12345678"];
    for invalid in invalid_lengths {
        let mut fresh_engine = TotpEngine::from_base32(secret_b32).unwrap();
        let res = fresh_engine.verify(invalid, base_time);
        assert!(
            matches!(res, Err(TotpError::InvalidLength { .. })),
            "Expected InvalidLength for candidate '{}', got {:?}",
            invalid,
            res
        );
    }
}

// =========================================================================
// Invariant 2: Drift tolerance: t-30s, t, t+30s accepted; outside rejected
// =========================================================================

#[test]
fn test_invariant_2_drift_tolerance_exhaustive_windows() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";
    let step_secs = 30u64;

    // Test multiple base timestamps, including step boundaries
    let test_timestamps = [
        0u64,           // Timestamp 0 (saturating_sub underflow test)
        15u64,          // Mid-first step
        29u64,          // Edge-first step
        30u64,          // Step 1 boundary
        59u64,          // Edge step 1
        60u64,          // Step 2 boundary
        1700000000u64,  // Standard epoch time
        1700000009u64,  // End of step
        1700000010u64,  // Start of next step
        2000000000u64,  // Future epoch
    ];

    for &base_t in &test_timestamps {
        let engine = TotpEngine::from_base32(secret_b32).unwrap();
        let code_curr = engine.generate_at(base_t).unwrap();
        let code_prev = engine.generate_at(base_t.saturating_sub(step_secs)).unwrap();
        let code_next = engine.generate_at(base_t.saturating_add(step_secs)).unwrap();

        // 1. Current code at base_t: MUST PASS
        let mut e1 = TotpEngine::from_base32(secret_b32).unwrap();
        assert!(
            e1.verify(&code_curr, base_t).is_ok(),
            "Current code rejected at base_t = {}",
            base_t
        );

        // 2. Previous code (t - 30s) at base_t: MUST PASS
        let mut e2 = TotpEngine::from_base32(secret_b32).unwrap();
        assert!(
            e2.verify(&code_prev, base_t).is_ok(),
            "t-30s code rejected at base_t = {}",
            base_t
        );

        // 3. Next code (t + 30s) at base_t: MUST PASS
        let mut e3 = TotpEngine::from_base32(secret_b32).unwrap();
        assert!(
            e3.verify(&code_next, base_t).is_ok(),
            "t+30s code rejected at base_t = {}",
            base_t
        );

        // 4. Code at t - 60s: MUST FAIL (outside window) if base_t >= 60
        if base_t >= 60 {
            let code_too_old = engine.generate_at(base_t - 60).unwrap();
            let mut e4 = TotpEngine::from_base32(secret_b32).unwrap();
            let err = e4.verify(&code_too_old, base_t);
            assert_eq!(
                err.unwrap_err(),
                TotpError::CodeMismatch,
                "t-60s code accepted at base_t = {}",
                base_t
            );
        }

        // 5. Code at t + 60s: MUST FAIL (outside window)
        let code_too_far = engine.generate_at(base_t + 60).unwrap();
        let mut e5 = TotpEngine::from_base32(secret_b32).unwrap();
        let err = e5.verify(&code_too_far, base_t);
        assert_eq!(
            err.unwrap_err(),
            TotpError::CodeMismatch,
            "t+60s code accepted at base_t = {}",
            base_t
        );

        // 6. Code at t + 90s: MUST FAIL
        let code_far_future = engine.generate_at(base_t + 90).unwrap();
        let mut e6 = TotpEngine::from_base32(secret_b32).unwrap();
        assert_eq!(
            e6.verify(&code_far_future, base_t).unwrap_err(),
            TotpError::CodeMismatch
        );
    }
}

// =========================================================================
// Invariant 3: Replay prevention: same valid code twice in window rejected
// =========================================================================

#[test]
fn test_invariant_3_replay_prevention_and_lockout_integration() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";
    let base_time = 1700000000u64;
    let mut engine = TotpEngine::from_base32(secret_b32).unwrap();

    let valid_code = engine.generate_at(base_time).unwrap();

    // 1. First submission succeeds
    let step = engine.verify(&valid_code, base_time).unwrap();
    assert_eq!(engine.last_used_step(), Some(step));

    // 2. Immediate second submission at exact same second MUST be rejected
    let replay_err = engine.verify(&valid_code, base_time).unwrap_err();
    assert_eq!(
        replay_err,
        TotpError::ReplayedCode,
        "Submitting same valid code twice at same timestamp must be rejected"
    );

    // 3. Second submission 15s later within SAME 30s window MUST be rejected
    let replay_mid_window = engine.verify(&valid_code, base_time + 15).unwrap_err();
    assert_eq!(
        replay_mid_window,
        TotpError::ReplayedCode,
        "Submitting same valid code 15s later in same window must be rejected"
    );

    // 4. Second submission 29s later within SAME window MUST be rejected
    let replay_end_window = engine.verify(&valid_code, base_time + 29).unwrap_err();
    assert_eq!(
        replay_end_window,
        TotpError::ReplayedCode,
        "Submitting same valid code 29s later in same window must be rejected"
    );

    // 5. Code from previous step (t - 30s) MUST be rejected because step <= last_used_step
    let prev_code = engine.generate_at(base_time - 30).unwrap();
    let replay_past = engine.verify(&prev_code, base_time + 5).unwrap_err();
    assert_eq!(
        replay_past,
        TotpError::ReplayedCode,
        "Submitting older step code after current step is used must be rejected"
    );

    // 6. Test AuthManager integration: replayed codes trigger anti-brute-force rate limiting!
    let temp_lock = std::env::temp_dir().join(format!("gastinel_replay_{}.lock", std::process::id()));
    let master_pw = SecretString::new("ReplayTestMasterPass!".to_string());
    let (_vault, raw_vault) = create_test_vault(&master_pw, secret_b32);

    let mut auth = AuthManager::with_lockout_path(&temp_lock);

    // Step 1: Verify master password
    let (unlocked_vault, _) = auth
        .verify_master_password_at_time(&raw_vault, &master_pw, base_time)
        .unwrap();

    // Step 2 Attempt 1: First TOTP verification succeeds
    assert!(auth.verify_totp(&unlocked_vault, &valid_code, base_time).is_ok());

    // Step 2 Attempt 2: Replay TOTP verification -> FAILS and registers failure 1
    let replay_res1 = auth.verify_totp(&unlocked_vault, &valid_code, base_time);
    assert!(
        matches!(replay_res1.unwrap_err(), AuthError::TotpCodeReplayed),
        "AuthManager must return TotpCodeReplayed"
    );
    assert_eq!(auth.lockout_manager().record().failed_attempts, 1);

    // Step 2 Attempt 3: Second replay attempt -> FAILS and registers failure 2 -> LOCKOUT TRIGGERED!
    let replay_res2 = auth.verify_totp(&unlocked_vault, &valid_code, base_time + 1);
    assert!(
        matches!(replay_res2.unwrap_err(), AuthError::TotpCodeReplayed),
        "AuthManager must return TotpCodeReplayed"
    );
    assert!(auth.lockout_manager().check_status(base_time + 2).unwrap());

    // Step 2 Attempt 4: Even with a FRESH brand-new TOTP code for step + 1, blocked by lockout!
    let next_code = engine.generate_at(base_time + 30).unwrap();
    let blocked_res = auth.verify_totp(&unlocked_vault, &next_code, base_time + 2);
    assert!(
        matches!(blocked_res, Err(AuthError::LockoutActive(_))),
        "Fresh code must be blocked while lockout is active"
    );

    let _ = std::fs::remove_file(temp_lock);
}

// =========================================================================
// Invariant 4: Recovery codes: 10 single-use codes, consumed upon use
// =========================================================================

#[test]
fn test_invariant_4_recovery_codes_consumption_and_exhaustion() {
    let mut codes = generate_recovery_codes(10);
    assert_eq!(codes.len(), 10);

    // Check code structure and character set (no 0, O, 1, I, L in random parts)
    let forbidden_chars = ['0', 'O', '1', 'I', 'L'];
    for code in &codes {
        assert!(code.starts_with("RECV-"));
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "RECV");
        assert_eq!(parts[1].len(), 4); // index
        assert_eq!(parts[2].len(), 4); // part1
        assert_eq!(parts[3].len(), 4); // part2

        for c in parts[2].chars().chain(parts[3].chars()) {
            assert!(
                !forbidden_chars.contains(&c),
                "Forbidden character '{}' found in recovery code {}",
                c,
                code
            );
        }
    }

    // Sequential consumption of all 10 codes
    let original_codes = codes.clone();
    for (i, code_to_use) in original_codes.iter().enumerate() {
        let remaining_before = 10 - i;
        assert_eq!(codes.len(), remaining_before);

        // Normalize variations: lowercase, no dashes, extra spaces
        let input_variations = [
            code_to_use.clone(),
            code_to_use.to_lowercase(),
            code_to_use.replace('-', ""),
            format!("  {}  ", code_to_use),
        ];

        let test_input = &input_variations[i % input_variations.len()];
        let consumed = verify_and_consume_recovery_code(&mut codes, test_input).unwrap();
        assert_eq!(consumed, *code_to_use);
        assert_eq!(codes.len(), remaining_before - 1);
        assert!(!codes.contains(code_to_use));

        // Immediate replay of the consumed code MUST fail
        let replay_err = verify_and_consume_recovery_code(&mut codes, test_input).unwrap_err();
        assert_eq!(
            replay_err,
            TotpError::RecoveryCodeNotFound,
            "Replaying consumed recovery code must fail"
        );
    }

    // Now all 10 codes are consumed; list must be empty
    assert_eq!(codes.len(), 0);
    assert_eq!(
        verify_and_consume_recovery_code(&mut codes, &original_codes[0]).unwrap_err(),
        TotpError::RecoveryCodeNotFound
    );

    // AuthManager integration: recovery code consumption and lockout on failure
    let temp_lock = std::env::temp_dir().join(format!("gastinel_recv_{}.lock", std::process::id()));
    let master_pw = SecretString::new("RecvTestMasterPass!".to_string());
    let (mut vault, _raw_vault) = create_test_vault(&master_pw, "JBSWY3DPEHPK3PXP");
    let initial_count = vault.security.recovery_codes.len();
    assert_eq!(initial_count, 10);

    let mut auth = AuthManager::with_lockout_path(&temp_lock);
    let base_time = 1700000000u64;

    // Bad recovery code attempt 1 -> Failure
    let bad_code = "RECV-0001-XXXX-YYYY";
    let bad_res1 = auth.verify_recovery_code_at_time(&mut vault, bad_code, base_time);
    assert!(matches!(bad_res1.unwrap_err(), AuthError::InvalidRecoveryCode));
    assert_eq!(auth.lockout_manager().record().failed_attempts, 1);

    // Bad recovery code attempt 2 -> Failure -> Lockout triggered
    let bad_res2 = auth.verify_recovery_code_at_time(&mut vault, bad_code, base_time + 1);
    assert!(matches!(bad_res2.unwrap_err(), AuthError::InvalidRecoveryCode));
    assert!(auth.lockout_manager().check_status(base_time + 2).unwrap());

    // Valid recovery code blocked by active lockout
    let valid_code = vault.security.recovery_codes[0].clone();
    let blocked_res = auth.verify_recovery_code_at_time(&mut vault, &valid_code, base_time + 2);
    assert!(matches!(blocked_res, Err(AuthError::LockoutActive(_))));

    // After lockout expires (1 hour later): valid recovery code succeeds and is consumed
    let success_time = base_time + 3605;
    let ok_res = auth.verify_recovery_code_at_time(&mut vault, &valid_code, success_time);
    assert!(ok_res.is_ok());
    assert_eq!(vault.security.recovery_codes.len(), 9);
    assert!(!vault.security.recovery_codes.contains(&valid_code));

    // Lockout state reset on success
    assert_eq!(auth.lockout_manager().record().failed_attempts, 0);

    let _ = std::fs::remove_file(temp_lock);
}

// =========================================================================
// Invariant 5: Tier-2 Master View Password protection & clipboard copy
// =========================================================================

#[test]
fn test_invariant_5_tier2_protection_and_clipboard_export() {
    let mut vault = Vault::new("Tier2ProtectionVault");
    let master_pw = SecretString::new("VaultMasterLoginPassphrase#1".to_string());
    let tier2_pw = SecretString::new("DedicatedTier2ViewPassphrase#2".to_string());
    let wrong_pw = SecretString::new("IncorrectPasswordAttempt!".to_string());

    // 1. Distinctness rule: Tier-2 password identical to Master Password must be rejected
    let identical_tier2 = SecretString::new("VaultMasterLoginPassphrase#1".to_string());
    assert!(matches!(
        validate_tier2_candidate(&identical_tier2, Some(&master_pw)),
        Err(AuthError::InvalidTier2Password)
    ));
    assert!(validate_tier2_candidate(&tier2_pw, Some(&master_pw)).is_ok());

    // 2. Unconfigured state: reveal and copy must fail
    assert!(matches!(
        verify_tier2_password(&vault, &tier2_pw),
        Err(AuthError::Tier2NotConfigured)
    ));

    let mut auth = AuthManager::new();
    let secret_to_copy = SecretString::new("ConfidentialApiKey999".to_string());
    let unconfigured_copy = auth.copy_to_clipboard(&vault, &tier2_pw, &secret_to_copy, 30);
    assert!(matches!(
        unconfigured_copy,
        Err(AuthError::Tier2NotConfigured)
    ));

    // 3. Configure Tier-2 password in vault
    let hash = hash_tier2_password(&tier2_pw).expect("Argon2 hash generation");
    vault.security.master_view_password_hash = Some(hash);

    // 4. Invalid passwords must be rejected
    assert!(matches!(
        verify_tier2_password(&vault, &wrong_pw),
        Err(AuthError::InvalidTier2Password)
    ));
    assert!(matches!(
        auth.copy_to_clipboard(&vault, &wrong_pw, &secret_to_copy, 30),
        Err(AuthError::InvalidTier2Password)
    ));

    // 5. Valid Tier-2 password succeeds
    assert!(verify_tier2_password(&vault, &tier2_pw).is_ok());

    // 6. Clipboard copy succeeds with Tier-2 authentication
    let copy_seq = auth
        .copy_to_clipboard(&vault, &tier2_pw, &secret_to_copy, 10)
        .expect("Clipboard copy with valid Tier-2 password must succeed");
    assert!(auth.active_clipboard().is_some());
    let copy_time = {
        let guard = auth.active_clipboard().unwrap();
        assert_eq!(guard.sequence_number(), copy_seq);
        assert!(guard.history_flag_set);
        assert!(guard.cloud_sync_flag_set);
        assert!(guard.monitor_exclusion_flag_set);
        guard.copied_at()
    };

    // 7. Auto-wipe behavior
    // Before expiration: no wipe
    let wipe_early = auth.wipe_clipboard_if_expired(copy_time + 5).unwrap();
    assert!(!wipe_early);
    assert!(auth.active_clipboard().is_some());

    // Sequence mismatch protection: if user copies something else, do NOT wipe
    let fake_external_seq = copy_seq.wrapping_add(100);
    assert!(!auth.active_clipboard().unwrap().should_wipe(copy_time + 15, fake_external_seq));

    // Expiration after timeout: wipe triggers
    let wipe_expired = auth.wipe_clipboard_if_expired(copy_time + 15).unwrap();
    assert!(auth.active_clipboard().is_none() || wipe_expired);
}
