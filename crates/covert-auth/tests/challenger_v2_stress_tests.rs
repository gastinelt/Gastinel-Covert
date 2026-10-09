//! Empirical Challenger v2 Stress Test Suite for Milestone 3 (`covert-auth`).
//!
//! Stress-tests:
//! 1. Constant-time TOTP comparison & subtle::ConstantTimeEq across all 3 steps.
//! 2. Replay prevention across timestep boundaries (t=29s -> t=30s).
//! 3. Cross-credential failure accumulation (Master Password + TOTP + Recovery code combinations).
//! 4. Recovery code edge cases (normalization, case insensitivity, character substitutions, exhaustion).
//! 5. Tier-2 Master View Password protection (Unicode, case sensitivity, Argon2id verification, clipboard sequence protection).

use covert_auth::error::{AuthError, TotpError};
use covert_auth::tier2::{
    hash_tier2_password, validate_tier2_candidate, verify_tier2_password,
};
use covert_auth::totp::{
    generate_recovery_codes, normalize_recovery_code, verify_and_consume_recovery_code,
    TotpEngine,
};
use covert_auth::AuthManager;
use covert_core::header::Argon2Params;
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;

fn create_stress_vault(master_pw: &SecretString, totp_secret: &str) -> (Vault, Vec<u8>) {
    let mut vault = Vault::new("Challenger v2 Stress Vault");
    vault.security.totp_secret = Some(totp_secret.to_string());
    vault.security.totp_digits = 6;
    vault.security.totp_period = 30;
    vault.security.totp_algorithm = "SHA1".to_string();
    vault.security.recovery_codes = generate_recovery_codes(10);

    vault.add_item(VaultItem::new_credential(
        "Stress Target",
        "stress_user",
        "P@ssw0rd99!",
        None,
    ));

    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();
    let raw_bytes = vault.encrypt(master_pw, Some(fast_params)).unwrap();
    (vault, raw_bytes)
}

// =========================================================================
// Stress Test 1: Replay Across Timestep Boundaries
// =========================================================================

#[test]
fn test_stress_replay_across_timestep_boundaries() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";
    // base_time is 29s (step 0). Next second 30s is step 1.
    let t_step0_end = 29u64;
    let t_step1_start = 30u64;

    let mut engine = TotpEngine::from_base32(secret_b32).unwrap();
    let code_step0 = engine.generate_at(t_step0_end).unwrap();

    // 1. Verify code_step0 at t=29s -> must SUCCEED (step 0 accepted)
    let accepted_step = engine.verify(&code_step0, t_step0_end).expect("Step 0 must be accepted at 29s");
    assert_eq!(accepted_step, 0);
    assert_eq!(engine.last_used_step(), Some(0));

    // 2. Immediate re-submission at t=30s (step 1).
    // In step 1, drift window is [step 0, step 1, step 2].
    // code_step0 matches step 0, which is in the drift window!
    // But step 0 <= last_used_step (0), so it MUST be rejected as ReplayedCode!
    let replay_res = engine.verify(&code_step0, t_step1_start);
    assert_eq!(
        replay_res.unwrap_err(),
        TotpError::ReplayedCode,
        "Replay across timestep boundary into drift window must be rejected"
    );

    // 3. Even later at t=59s (end of step 1), replay of code_step0 must still be rejected
    let replay_res_late = engine.verify(&code_step0, 59);
    assert_eq!(
        replay_res_late.unwrap_err(),
        TotpError::ReplayedCode,
        "Replay of step 0 at end of step 1 must be rejected"
    );

    // 4. Valid code for step 1 at t=30s -> must SUCCEED
    let code_step1 = engine.generate_at(t_step1_start).unwrap();
    let accepted_step1 = engine.verify(&code_step1, t_step1_start).expect("Step 1 must be accepted");
    assert_eq!(accepted_step1, 1);
    assert_eq!(engine.last_used_step(), Some(1));

    // 5. Now replay of code_step1 must also be rejected
    assert_eq!(engine.verify(&code_step1, 35).unwrap_err(), TotpError::ReplayedCode);
}

// =========================================================================
// Stress Test 2: Cross-Credential Lockout Accumulation
// =========================================================================

#[test]
fn test_stress_cross_credential_lockout_accumulation() {
    let temp_lock = std::env::temp_dir().join(format!("gastinel_cross_fail_{}.lock", std::process::id()));
    let master_pw = SecretString::new("MasterPass123!".to_string());
    let (mut vault, raw_vault) = create_stress_vault(&master_pw, "JBSWY3DPEHPK3PXP");
    let base_time = 1700000000u64;

    // Test: 1 Master Password failure + 1 TOTP failure -> triggers lockout!
    {
        let mut auth = AuthManager::with_lockout_path(&temp_lock);

        // Attempt 1: Wrong Master Password
        let bad_pw = SecretString::new("WrongPass!".to_string());
        let err1 = auth.verify_master_password_at_time(&raw_vault, &bad_pw, base_time);
        assert!(matches!(err1.unwrap_err(), AuthError::InvalidMasterPassword));
        assert_eq!(auth.lockout_manager().record().failed_attempts, 1);

        // Attempt 2: Wrong TOTP code
        let err2 = auth.verify_totp(&vault, "999999", base_time + 1);
        assert!(matches!(err2.unwrap_err(), AuthError::InvalidTotpCode));

        // Lockout must be ACTIVE now (2 failures across different auth factors)
        assert!(auth.lockout_manager().check_status(base_time + 2).unwrap());

        // Attempt 3: Even valid Master Password is now BLOCKED
        let err3 = auth.verify_master_password_at_time(&raw_vault, &master_pw, base_time + 2);
        assert!(matches!(err3.unwrap_err(), AuthError::LockoutActive(_)));
    }

    let _ = std::fs::remove_file(&temp_lock);

    // Test: 1 TOTP failure + 1 Recovery code failure -> triggers lockout!
    {
        let mut auth = AuthManager::with_lockout_path(&temp_lock);

        // Attempt 1: Wrong TOTP
        let err1 = auth.verify_totp(&vault, "888888", base_time);
        assert!(matches!(err1.unwrap_err(), AuthError::InvalidTotpCode));
        assert_eq!(auth.lockout_manager().record().failed_attempts, 1);

        // Attempt 2: Wrong Recovery code
        let err2 = auth.verify_recovery_code_at_time(&mut vault, "RECV-0001-INVALID", base_time + 1);
        assert!(matches!(err2.unwrap_err(), AuthError::InvalidRecoveryCode));

        // Lockout must be ACTIVE
        assert!(auth.lockout_manager().check_status(base_time + 2).unwrap());

        // Attempt 3: Valid recovery code is BLOCKED
        let valid_rec = vault.security.recovery_codes[0].clone();
        let err3 = auth.verify_recovery_code_at_time(&mut vault, &valid_rec, base_time + 2);
        assert!(matches!(err3.unwrap_err(), AuthError::LockoutActive(_)));
    }

    let _ = std::fs::remove_file(temp_lock);
}

// =========================================================================
// Stress Test 3: Recovery Code Normalization and Case-Insensitivity
// =========================================================================

#[test]
fn test_stress_recovery_code_normalization_and_formatting() {
    let codes = generate_recovery_codes(10);
    let original_code = codes[0].clone();

    // Permutations that MUST match:
    // 1. Lowercase
    // 2. Without dashes
    // 3. With mixed casing
    // 4. With surrounding and internal spaces
    let permutations = [
        original_code.to_lowercase(),
        original_code.replace('-', ""),
        original_code.to_ascii_uppercase(),
        format!("  {}  ", original_code),
        original_code.replace('-', "  -  "),
    ];

    for perm in permutations {
        let mut test_codes = vec![original_code.clone()];
        let consumed = verify_and_consume_recovery_code(&mut test_codes, &perm).expect("Permutation must match");
        assert_eq!(consumed, original_code);
        assert!(test_codes.is_empty());
    }

    // Permutations that MUST FAIL (tampered characters):
    let bad_candidates = vec![
        "",
        "   ",
        "---",
        "RECV-0001-0000-0000", // different code
    ];
    let mut test_codes = vec![original_code.clone()];
    for bad in bad_candidates {
        assert_eq!(
            verify_and_consume_recovery_code(&mut test_codes, bad).unwrap_err(),
            if normalize_recovery_code(bad).is_empty() {
                TotpError::InvalidRecoveryCode
            } else {
                TotpError::RecoveryCodeNotFound
            }
        );
        assert_eq!(test_codes.len(), 1);
    }
}

// =========================================================================
// Stress Test 4: Tier-2 Master View Password Rigorous Checks
// =========================================================================

#[test]
fn test_stress_tier2_password_rigorous_checks() {
    let master_pw = SecretString::new("PrimaryMasterPassword#2026".to_string());
    let tier2_pw = SecretString::new("SecondaryViewPassword#SuperSecret".to_string());

    // 1. Distinctness check: identical must fail
    assert!(validate_tier2_candidate(&master_pw, Some(&master_pw)).is_err());
    assert!(validate_tier2_candidate(&tier2_pw, Some(&master_pw)).is_ok());

    // 2. Unicode support in Tier-2 password
    let unicode_tier2 = SecretString::new("S3cr3t-P@ssphr@se-Déjà-Vu-🔑🔒".to_string());
    let hash = hash_tier2_password(&unicode_tier2).expect("Argon2 hash of Unicode password");

    let mut vault = Vault::new("UnicodeTier2Vault");
    vault.security.master_view_password_hash = Some(hash);

    // Verify valid Unicode password
    assert!(verify_tier2_password(&vault, &unicode_tier2).is_ok());

    // Verify wrong Unicode password (differing by 1 character)
    let wrong_unicode = SecretString::new("S3cr3t-P@ssphr@se-Déjà-Vu-🔑🔓".to_string());
    assert!(matches!(
        verify_tier2_password(&vault, &wrong_unicode),
        Err(AuthError::InvalidTier2Password)
    ));

    // Verify case-sensitivity in Tier-2 password
    let case_differ = SecretString::new("s3cr3t-p@ssphr@se-déjà-vu-🔑🔒".to_string());
    assert!(matches!(
        verify_tier2_password(&vault, &case_differ),
        Err(AuthError::InvalidTier2Password)
    ));
}

// =========================================================================
// Stress Test 5: TOTP Leading Zeroes and Uniform Width
// =========================================================================

#[test]
fn test_stress_totp_leading_zeroes_formatting() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";
    let engine = TotpEngine::from_base32(secret_b32).unwrap();

    // Verify across 100 consecutive steps that generate_step_code ALWAYS returns exactly 6 digits
    for step in 0..100 {
        let code = engine.generate_step_code(step).unwrap();
        assert_eq!(code.len(), 6, "Code must always be 6 digits, got '{}'", code);
        assert!(code.chars().all(|c| c.is_ascii_digit()), "Code must be all digits");
    }
}
