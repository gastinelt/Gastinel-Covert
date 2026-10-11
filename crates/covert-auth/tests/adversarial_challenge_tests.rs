//! Adversarial Challenge Test Suite for covert-auth.
//!
//! Evaluates the 5 critical security requirements:
//! 1. Lockout behavior: exactly 2 failed attempts must trigger 1-hour lockout; repeat failures trigger exponential backoff.
//! 2. Clock rollback attacks: simulated clock set back in time leaves lockout strictly enforced.
//! 3. TOTP drift bounds: t-30s, t, t+30s accepted; t-60s and t+60s rejected.
//! 4. TOTP replay prevention: submitting same valid code twice in same window rejected on second use.
//! 5. Recovery codes: each single-use emergency recovery code consumed on use, rejected on reuse.
//! 6. Session persistence: lockout state persisted across process restart.

use covert_auth::error::{AuthError, LockoutError, TotpError};
use covert_auth::lockout::{LockoutManager, LockoutStatus, BASE_LOCKOUT_SECONDS, MAX_BACKOFF_SHIFT};
use covert_auth::totp::{
    generate_recovery_codes, verify_and_consume_recovery_code, TotpEngine,
};
use covert_auth::AuthManager;
use covert_core::header::Argon2Params;
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use std::fs;

fn create_challenge_vault(
    master_pw: &SecretString,
    totp_secret: &str,
) -> (Vault, Vec<u8>) {
    let mut vault = Vault::new("Adversarial Challenge Vault");
    vault.security.totp_secret = Some(totp_secret.to_string());
    vault.security.totp_digits = 6;
    vault.security.totp_period = 30;
    vault.security.totp_algorithm = "SHA1".to_string();
    vault.security.recovery_codes = generate_recovery_codes(10);

    vault.add_item(VaultItem::new_credential(
        "Adversarial Target",
        "challenger_user",
        "P@ssw0rd99!",
        None,
    ));

    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();
    let raw_bytes = vault.encrypt(master_pw, Some(fast_params)).unwrap();
    (vault, raw_bytes)
}

// =========================================================================
// Challenge 1: Lockout Behavior & Exponential Backoff
// =========================================================================

#[test]
fn challenge_1_lockout_exact_threshold_and_exponential_backoff() {
    let mut manager = LockoutManager::new();
    let current_time = 1700000000u64;

    // 1. Initial state: zero failures, allowed
    assert_eq!(manager.record().failed_attempts, 0);
    assert!(!manager.check_status(current_time).unwrap());
    assert!(manager.check_lockout(current_time).is_ok());

    // 2. Failure 1: remaining = 1, NOT locked out
    let res1 = manager.register_failure(current_time).unwrap();
    assert_eq!(res1, LockoutStatus::AttemptFailed { attempts_remaining: 1 });
    assert_eq!(manager.record().failed_attempts, 1);
    assert!(!manager.check_status(current_time).unwrap(), "1 failure must not lock out");

    // 3. Failure 2: triggers EXACTLY 1-hour (3600s) lockout
    let res2 = manager.register_failure(current_time + 5).unwrap();
    match res2 {
        LockoutStatus::LockedOut { duration_seconds, locked_until_utc } => {
            assert_eq!(duration_seconds, BASE_LOCKOUT_SECONDS, "1st lockout must be 3600s");
            assert_eq!(locked_until_utc, current_time + 5 + 3600);
        }
        _ => panic!("2nd failure must trigger LockedOut"),
    }
    assert!(manager.check_status(current_time + 6).unwrap());
    assert!(manager.check_lockout(current_time + 6).is_err());

    // 4. Repeat failures after lockout expiry trigger exponential backoff
    let mut sim_time = current_time + 5 + 3601; // after 1st lockout
    assert!(!manager.check_status(sim_time).unwrap(), "Lockout should have expired");

    // Lockout 2: 2 failures -> 7200s (3600 * 2^1)
    manager.register_failure(sim_time).unwrap();
    let res_lock2 = manager.register_failure(sim_time + 1).unwrap();
    match res_lock2 {
        LockoutStatus::LockedOut { duration_seconds, .. } => {
            assert_eq!(duration_seconds, 7200, "2nd lockout must be 7200s (2 hours)");
        }
        _ => panic!("Expected 2nd lockout"),
    }

    // Lockout 3: 2 failures -> 14400s (3600 * 2^2)
    sim_time += 7202;
    manager.register_failure(sim_time).unwrap();
    let res_lock3 = manager.register_failure(sim_time + 1).unwrap();
    match res_lock3 {
        LockoutStatus::LockedOut { duration_seconds, .. } => {
            assert_eq!(duration_seconds, 14400, "3rd lockout must be 14400s (4 hours)");
        }
        _ => panic!("Expected 3rd lockout"),
    }

    // Lockout 4: 2 failures -> 28800s (3600 * 2^3)
    sim_time += 14402;
    manager.register_failure(sim_time).unwrap();
    let res_lock4 = manager.register_failure(sim_time + 1).unwrap();
    match res_lock4 {
        LockoutStatus::LockedOut { duration_seconds, .. } => {
            assert_eq!(duration_seconds, 28800, "4th lockout must be 28800s (8 hours)");
        }
        _ => panic!("Expected 4th lockout"),
    }

    // Verify backoff cap shift prevents arithmetic overflow
    assert_eq!(MAX_BACKOFF_SHIFT, 10);
    let max_duration = BASE_LOCKOUT_SECONDS * (1u64 << MAX_BACKOFF_SHIFT);
    assert_eq!(max_duration, 3600 * 1024); // 3,686,400s (~42.6 days)
}

// =========================================================================
// Challenge 2: Clock Rollback Attacks
// =========================================================================

#[test]
fn challenge_2_clock_rollback_attacks_enforce_lockout() {
    let mut manager = LockoutManager::new();
    let event_time = 1700000000u64;

    // Trigger lockout at event_time
    manager.register_failure(event_time).unwrap();
    manager.register_failure(event_time + 10).unwrap();
    let locked_time = event_time + 10;
    assert!(manager.check_status(locked_time + 1).unwrap());

    // Attack 1: Roll clock back 100 seconds before last event
    let rollback_100s = locked_time - 100;
    assert_eq!(
        manager.check_status(rollback_100s),
        Err(LockoutError::ClockRollbackDetected),
        "check_status must detect rollback"
    );
    assert_eq!(
        manager.check_lockout(rollback_100s),
        Err(LockoutError::ClockRollbackDetected),
        "check_lockout must reject rolled-back clock"
    );

    // Attack 2: Attempt to register failure at rolled-back time
    assert_eq!(
        manager.register_failure(rollback_100s),
        Err(LockoutError::ClockRollbackDetected),
        "register_failure must reject rolled-back time"
    );

    // Attack 3: Roll clock back to epoch 0
    assert_eq!(
        manager.check_status(0),
        Err(LockoutError::ClockRollbackDetected),
        "Epoch 0 clock rollback must be detected"
    );

    // Attack 4: Roll clock back by 1 second
    assert_eq!(
        manager.check_status(locked_time - 1),
        Err(LockoutError::ClockRollbackDetected),
        "1-second clock rollback must be detected"
    );

    // Verify AuthManager enforces rollback protection across all auth operations
    let master_pw = SecretString::new("Passphrase2026!".to_string());
    let (_, raw_vault) = create_challenge_vault(&master_pw, "JBSWY3DPEHPK3PXP");

    let temp_lock = std::env::temp_dir().join(format!("gastinel_rollback_{}.lock", std::process::id()));
    let mut auth = AuthManager::with_lockout_path(&temp_lock);

    // 2 failed attempts in AuthManager
    let bad_pw = SecretString::new("WrongPass!".to_string());
    auth.verify_master_password_at_time(&raw_vault, &bad_pw, event_time).unwrap_err();
    auth.verify_master_password_at_time(&raw_vault, &bad_pw, event_time + 5).unwrap_err();

    // Verify AuthManager blocks master password verification under clock rollback
    let rollback_res =
        auth.verify_master_password_at_time(&raw_vault, &master_pw, event_time - 50);
    assert!(
        matches!(rollback_res, Err(AuthError::Lockout(LockoutError::ClockRollbackDetected))),
        "AuthManager must block unlock under clock rollback"
    );

    let _ = fs::remove_file(temp_lock);
}

// =========================================================================
// Challenge 3: TOTP Drift Bounds (t-30s, t, t+30s accepted; t-60s, t+60s rejected)
// =========================================================================

#[test]
fn challenge_3_totp_drift_tolerance_strict_bounds() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";
    let base_time = 1700000000u64; // step = 56666666
    let step_secs = 30u64;

    let engine = TotpEngine::from_base32(secret_b32).unwrap();

    let code_t_minus_60 = engine.generate_at(base_time - step_secs * 2).unwrap();
    let code_t_minus_30 = engine.generate_at(base_time - step_secs).unwrap();
    let code_t = engine.generate_at(base_time).unwrap();
    let code_t_plus_30 = engine.generate_at(base_time + step_secs).unwrap();
    let code_t_plus_60 = engine.generate_at(base_time + step_secs * 2).unwrap();

    // 1. Code at t must be ACCEPTED at t
    let mut e1 = TotpEngine::from_base32(secret_b32).unwrap();
    assert!(e1.verify(&code_t, base_time).is_ok(), "t code must be accepted at t");

    // 2. Code at t-30s must be ACCEPTED at t (lower drift boundary)
    let mut e2 = TotpEngine::from_base32(secret_b32).unwrap();
    assert!(e2.verify(&code_t_minus_30, base_time).is_ok(), "t-30s code must be accepted at t");

    // 3. Code at t+30s must be ACCEPTED at t (upper drift boundary)
    let mut e3 = TotpEngine::from_base32(secret_b32).unwrap();
    assert!(e3.verify(&code_t_plus_30, base_time).is_ok(), "t+30s code must be accepted at t");

    // 4. Code at t-60s must be STRICTLY REJECTED at t
    let mut e4 = TotpEngine::from_base32(secret_b32).unwrap();
    let err_minus_60 = e4.verify(&code_t_minus_60, base_time).unwrap_err();
    assert_eq!(err_minus_60, TotpError::CodeMismatch, "t-60s code must be rejected");

    // 5. Code at t+60s must be STRICTLY REJECTED at t
    let mut e5 = TotpEngine::from_base32(secret_b32).unwrap();
    let err_plus_60 = e5.verify(&code_t_plus_60, base_time).unwrap_err();
    assert_eq!(err_plus_60, TotpError::CodeMismatch, "t+60s code must be rejected");

    // 6. Test boundary precision at window transitions:
    // Window boundaries for base_time = 1700000000:
    // step = 1700000000 / 30 = 56666666. Step span: [1699999980, 1700000009]
    let t_start = 1699999980u64;
    let t_end = 1700000009u64;

    let code_start = engine.generate_at(t_start).unwrap();
    let code_end = engine.generate_at(t_end).unwrap();
    assert_eq!(code_start, code_end, "Codes across same step must be identical");

    let mut e_boundary = TotpEngine::from_base32(secret_b32).unwrap();
    assert!(e_boundary.verify(&code_start, t_end).is_ok());
}

// =========================================================================
// Challenge 4: TOTP Replay Prevention
// =========================================================================

#[test]
fn challenge_4_totp_replay_prevention_same_window_and_backward() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";
    let base_time = 1700000000u64;
    let mut engine = TotpEngine::from_base32(secret_b32).unwrap();

    let valid_code = engine.generate_at(base_time).unwrap();

    // 1st submission: Accepted
    let step = engine.verify(&valid_code, base_time).expect("First use must succeed");
    assert_eq!(engine.last_used_step(), Some(step));

    // 2nd submission at exact same time: Rejected with ReplayedCode
    let replay_same_time = engine.verify(&valid_code, base_time);
    assert_eq!(
        replay_same_time.unwrap_err(),
        TotpError::ReplayedCode,
        "Replay at exact same time must fail"
    );

    // 3rd submission 10s later within same 30s window: Rejected with ReplayedCode
    let replay_later_in_window = engine.verify(&valid_code, base_time + 10);
    assert_eq!(
        replay_later_in_window.unwrap_err(),
        TotpError::ReplayedCode,
        "Replay 10s later in same window must fail"
    );

    // 4th submission of previous step (t-30s) after current step consumed: Rejected
    let older_code = engine.generate_at(base_time - 30).unwrap();
    let replay_older = engine.verify(&older_code, base_time + 5);
    assert_eq!(
        replay_older.unwrap_err(),
        TotpError::ReplayedCode,
        "Past step code after newer step consumed must fail"
    );

    // 5th submission of next step (t+30s): Accepted!
    let next_code = engine.generate_at(base_time + 30).unwrap();
    let next_step = engine.verify(&next_code, base_time + 30).expect("Next step must succeed");
    assert_eq!(next_step, step + 1);
    assert_eq!(engine.last_used_step(), Some(next_step));
}

// =========================================================================
// Challenge 5: Single-Use Emergency Recovery Codes
// =========================================================================

#[test]
fn challenge_5_recovery_codes_single_use_and_exhaustion() {
    let mut codes = generate_recovery_codes(10);
    assert_eq!(codes.len(), 10);

    // All 10 codes must be unique
    let mut deduped = codes.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(deduped.len(), 10, "All recovery codes must be unique");

    // 1. Consume code #0
    let target = codes[0].clone();
    let consumed = verify_and_consume_recovery_code(&mut codes, &target).unwrap();
    assert_eq!(consumed, target);
    assert_eq!(codes.len(), 9);
    assert!(!codes.contains(&target), "Consumed code must be removed from pool");

    // 2. Re-use of consumed code must be REJECTED
    let reuse_err = verify_and_consume_recovery_code(&mut codes, &target).unwrap_err();
    assert_eq!(
        reuse_err,
        TotpError::RecoveryCodeNotFound,
        "Re-use of consumed recovery code must fail"
    );
    assert_eq!(codes.len(), 9);

    // 3. Consume remaining 9 codes one by one
    while !codes.is_empty() {
        let code = codes[0].clone();
        let res = verify_and_consume_recovery_code(&mut codes, &code);
        assert!(res.is_ok(), "Each remaining code must succeed once");
    }

    // 4. Exhausted pool: all codes consumed, any attempt fails
    assert_eq!(codes.len(), 0);
    let empty_err = verify_and_consume_recovery_code(&mut codes, &target).unwrap_err();
    assert_eq!(empty_err, TotpError::RecoveryCodeNotFound);
}

// =========================================================================
// Challenge 6: Lockout Persistence Across Process Sessions
// =========================================================================

#[test]
fn challenge_6_lockout_persistence_across_sessions() {
    let temp_lock = std::env::temp_dir().join(format!("gastinel_sess_test_{}.lock", std::process::id()));
    let master_pw = SecretString::new("SessionPass2026!".to_string());
    let (_, raw_vault) = create_challenge_vault(&master_pw, "JBSWY3DPEHPK3PXP");
    let base_time = 1700000000u64;

    // --- Session 1 ---
    {
        let mut auth1 = AuthManager::with_lockout_path(&temp_lock);
        let bad_pw = SecretString::new("WrongPass!".to_string());

        // 1st failure
        auth1.verify_master_password_at_time(&raw_vault, &bad_pw, base_time).unwrap_err();
        // 2nd failure -> triggers 1-hour lockout and saves to disk
        auth1.verify_master_password_at_time(&raw_vault, &bad_pw, base_time + 5).unwrap_err();

        assert!(auth1.lockout_manager().check_status(base_time + 10).unwrap());
        assert!(temp_lock.exists(), "Lockout file must be created on disk");
    } // auth1 dropped (session 1 ends)

    // --- Session 2 (New Process / Restart) ---
    {
        // When a new AuthManager is created with the same lock path:
        let mut auth2 = AuthManager::with_lockout_path(&temp_lock);

        // Verification of Requirement R3:
        // "Anti-brute-force rate limiting: 2 maximum failed attempts -> 1-hour lockout with exponential backoff on repeat failures, persisted across sessions."
        let is_locked = auth2.lockout_manager().check_status(base_time + 100).unwrap();
        assert!(
            is_locked,
            "CRITICAL BUG: Session 2 did not load persisted lockout from disk! Lockout was bypassed by restarting AuthManager."
        );

        // Authentication rejection check
        let bad_pw = SecretString::new("AnotherWrong!".to_string());
        let res = auth2.verify_master_password_at_time(&raw_vault, &bad_pw, base_time + 100);
        assert!(
            matches!(res, Err(AuthError::LockoutActive(_))),
            "Session 2 must strictly reject authentication attempts while locked out"
        );
    }

    let _ = fs::remove_file(temp_lock);
}

// =========================================================================
// Challenge 7: Monotonic Tick Verification & Clock Fast-Forward Defense
// =========================================================================

#[test]
fn challenge_7_monotonic_tick_verification_and_clock_tampering() {
    let mut manager = LockoutManager::new();
    let base_utc = 1700000000u64;
    let base_tick = 500_000u64; // 500s uptime in ms

    // Simulate 2 failures triggering a 1-hour lockout
    manager.register_failure(base_utc).unwrap();
    let mut record = manager.record().clone();
    record.last_boot_tick = base_tick;
    manager = LockoutManager::from_record(record);

    let res = manager.register_failure(base_utc + 5).unwrap();
    match res {
        LockoutStatus::LockedOut { duration_seconds, locked_until_utc } => {
            assert_eq!(duration_seconds, 3600);
            assert_eq!(locked_until_utc, base_utc + 5 + 3600);
        }
        _ => panic!("Expected LockedOut"),
    }

    let locked_time_utc = base_utc + 5;
    let locked_tick = base_tick + 5_000;
    let mut record = manager.record().clone();
    record.last_boot_tick = locked_tick;
    manager = LockoutManager::from_record(record);

    // Scenario 1: Normal active lockout (10s later, ticks and UTC agree)
    let status_normal = manager.check_status_monotonic(locked_time_utc + 10, locked_tick + 10_000);
    assert_eq!(status_normal, Ok(true), "Active lockout must return Ok(true)");

    // Scenario 2: Clock Fast-Forward Attack (UTC jumped 3601s, but monotonic tick only advanced 10s)
    let fast_forward_utc = locked_time_utc + 3601;
    let fake_elapsed_tick = locked_tick + 10_000; // only 10 seconds of physical time passed!
    let tamper_res = manager.check_status_monotonic(fast_forward_utc, fake_elapsed_tick);
    assert_eq!(
        tamper_res,
        Err(LockoutError::ClockRollbackDetected),
        "Fast-forward attack must be detected and rejected via monotonic ticks"
    );

    // Scenario 3: Legitimate Expiration (both UTC and monotonic tick advanced >= 3600s)
    let legit_utc = locked_time_utc + 3601;
    let legit_tick = locked_tick + 3601 * 1000; // 3601s in ms
    let legit_res = manager.check_status_monotonic(legit_utc, legit_tick);
    assert_eq!(
        legit_res,
        Ok(false),
        "Legitimate expiration with verified monotonic ticks must return Ok(false)"
    );

    // Scenario 4: System Reboot during active lockout (tick resets to low value)
    let reboot_tick = 2_000u64; // system just booted, tick < last_boot_tick
    let reboot_utc = locked_time_utc + 100; // still within 1 hour
    let reboot_res = manager.check_status_monotonic(reboot_utc, reboot_tick);
    assert_eq!(
        reboot_res,
        Ok(true),
        "Active lockout must remain enforced across reboot"
    );

    // Scenario 5: System Reboot after lockout expiration (tick < last_boot_tick, but UTC expired)
    let reboot_expired_utc = locked_time_utc + 3601;
    let reboot_expired_res = manager.check_status_monotonic(reboot_expired_utc, reboot_tick);
    assert_eq!(
        reboot_expired_res,
        Ok(false),
        "Expired lockout after reboot must return Ok(false)"
    );

    // Scenario 6: AuthManager integration - rejecting clock fast-forward attack
    let temp_lock = std::env::temp_dir().join(format!("gastinel_auth_tick_{}.lock", std::process::id()));
    let master_pw = SecretString::new("Passphrase2026!".to_string());
    let (_, raw_vault) = create_challenge_vault(&master_pw, "JBSWY3DPEHPK3PXP");
    let mut auth = AuthManager::with_lockout_path(&temp_lock);
    let bad_pw = SecretString::new("WrongPass!".to_string());

    auth.verify_master_password_at_time_and_tick(&raw_vault, &bad_pw, locked_time_utc, Some(locked_tick)).unwrap_err();
    auth.verify_master_password_at_time_and_tick(&raw_vault, &bad_pw, locked_time_utc + 1, Some(locked_tick + 1000)).unwrap_err();

    let res_auth_attack = auth.verify_master_password_at_time_and_tick(
        &raw_vault,
        &master_pw,
        fast_forward_utc,
        Some(fake_elapsed_tick),
    );
    assert!(
        matches!(res_auth_attack, Err(AuthError::Lockout(LockoutError::ClockRollbackDetected))),
        "AuthManager must reject clock fast-forward attack via monotonic tick validation"
    );
    let _ = fs::remove_file(temp_lock);
}
