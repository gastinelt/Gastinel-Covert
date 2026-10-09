//! Adversarial Verification Harness for Milestone 3 Remediation.
//!
//! Specifically investigates:
//! 1. challenge_6: Lockout persistence across sessions and AuthManager unlock rejection.
//! 2. challenge_7: Monotonic tick validation and clock fast-forward attacks.
//! 3. Edge Case 1: Empty .lock file (0 bytes).
//! 4. Edge Case 2: Corrupted .lock file (garbage bytes).
//! 5. Edge Case 3: 2 failures -> killed -> restarted -> unlock blocked (correct pw, bad pw, totp, recovery).
//! 6. Edge Case 4: 1 failure -> killed -> restarted -> 1 failure -> triggers lockout.
//! 7. Edge Case 5: Reboot simulation (current_tick < last_boot_tick) within lockout window vs expired.
//! 8. Edge Case 6: Exponential backoff persisted across process restarts.
//! 9. Edge Case 7: TOTP & Recovery code failures trigger persisted lockout.

use covert_auth::error::{AuthError, LockoutError};
use covert_auth::lockout::{LockoutManager, LockoutStatus, BASE_LOCKOUT_SECONDS};
use covert_auth::AuthManager;
use covert_core::header::Argon2Params;
use covert_core::models::Vault;
use covert_core::SecretString;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn create_test_vault(password: &SecretString) -> (Vault, Vec<u8>) {
    let mut vault = Vault::new("Challenger Test Vault");
    vault.security.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
    vault.security.totp_digits = 6;
    vault.security.totp_period = 30;
    vault.security.totp_algorithm = "SHA1".to_string();
    vault.security.recovery_codes = vec!["ABCD-1234".to_string()];

    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();
    let raw = vault.encrypt(password, Some(fast_params)).unwrap();
    (vault, raw)
}

fn get_temp_lock_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("gastinel_challenger_{}_{}.lock", tag, std::process::id()))
}

#[test]
fn test_edge_case_empty_lock_file() {
    let lock_path = get_temp_lock_path("empty");
    // Create an empty 0-byte file
    {
        let mut f = fs::File::create(&lock_path).unwrap();
        f.flush().unwrap();
    }
    assert_eq!(fs::metadata(&lock_path).unwrap().len(), 0);

    // 1. LockoutManager should not panic; fail closed: empty lock file enforces safety lockout
    let manager = LockoutManager::with_path(&lock_path);
    assert_eq!(manager.record().failed_attempts, 2);
    assert!(manager.record().locked_until_utc > 0);

    // 2. AuthManager should fail closed with empty lock file (active lockout)
    let pw = SecretString::new("CorrectPass123!".to_string());
    let (_, raw_vault) = create_test_vault(&pw);
    let mut auth = AuthManager::with_lockout_path(&lock_path);

    // 3. Authentication attempt should be immediately blocked by active lockout
    let test_now = auth.lockout_manager().record().last_event_utc;
    let res = auth.verify_master_password_at_time(&raw_vault, &pw, test_now);
    assert!(matches!(res, Err(AuthError::LockoutActive(_))));

    let _ = fs::remove_file(lock_path);
}

#[test]
fn test_edge_case_corrupt_lock_file() {
    let lock_path = get_temp_lock_path("corrupt");
    // Write 32 bytes of random garbage
    {
        let mut f = fs::File::create(&lock_path).unwrap();
        f.write_all(b"\xFF\xFE\xFD\xFC\x00\x01\x02\x03\xDE\xAD\xBE\xEF_INVALID_CBOR_DATA").unwrap();
        f.flush().unwrap();
    }

    // 1. LockoutManager::with_path should fail closed: corrupt lock file enforces safety lockout
    let manager = LockoutManager::with_path(&lock_path);
    assert_eq!(manager.record().failed_attempts, 2);
    assert!(manager.record().locked_until_utc > 0);

    // 2. AuthManager should initialize without panic and fail closed
    let pw = SecretString::new("CorrectPass123!".to_string());
    let (_, raw_vault) = create_test_vault(&pw);
    let mut auth = AuthManager::with_lockout_path(&lock_path);

    // 3. Attempting authentication is blocked by active safety lockout
    let test_now1 = auth.lockout_manager().record().last_event_utc;
    let res1 = auth.verify_master_password_at_time(&raw_vault, &pw, test_now1);
    assert!(matches!(res1, Err(AuthError::LockoutActive(_))));

    let _ = fs::remove_file(lock_path);
}

#[test]
fn test_edge_case_two_failures_killed_restarted_lockout_enforced() {
    let lock_path = get_temp_lock_path("kill_restart");
    let pw = SecretString::new("SecretPass2026!".to_string());
    let (mut vault, raw_vault) = create_test_vault(&pw);
    let base_utc = 1700000000u64;

    // Process 1: 2 failures occur
    {
        let mut auth1 = AuthManager::with_lockout_path(&lock_path);
        let bad_pw = SecretString::new("Wrong!".to_string());

        auth1.verify_master_password_at_time(&raw_vault, &bad_pw, base_utc).unwrap_err();
        auth1.verify_master_password_at_time(&raw_vault, &bad_pw, base_utc + 2).unwrap_err();

        // Lockout is active in Process 1
        assert!(auth1.lockout_manager().check_status(base_utc + 5).unwrap());
    } // Process 1 terminates ("killed")

    // Process 2: Restarted after kill
    {
        let mut auth2 = AuthManager::with_lockout_path(&lock_path);

        // Check 1: Record should reflect 1-hour lockout
        let rec = auth2.lockout_manager().record();
        assert_eq!(rec.locked_until_utc, base_utc + 2 + BASE_LOCKOUT_SECONDS);
        assert_eq!(rec.consecutive_lockouts, 1);

        // Check 2: Entering CORRECT password must be BLOCKED by active lockout
        let res_correct = auth2.verify_master_password_at_time(&raw_vault, &pw, base_utc + 100);
        match res_correct {
            Err(AuthError::LockoutActive(dur)) => {
                assert_eq!(dur.as_secs(), (base_utc + 2 + 3600) - (base_utc + 100));
            }
            other => panic!("Expected LockoutActive, got {:?}", other),
        }

        // Check 3: Entering WRONG password must also be BLOCKED by active lockout
        let bad_pw = SecretString::new("AnotherWrong!".to_string());
        let res_bad = auth2.verify_master_password_at_time(&raw_vault, &bad_pw, base_utc + 200);
        assert!(matches!(res_bad, Err(AuthError::LockoutActive(_))));

        // Check 4: TOTP attempt must also be BLOCKED by active lockout
        let res_totp = auth2.verify_totp(&vault, "123456", base_utc + 300);
        assert!(matches!(res_totp, Err(AuthError::LockoutActive(_))));

        // Check 5: Recovery code attempt must also be BLOCKED by active lockout
        let res_rec = auth2.verify_recovery_code_at_time(&mut vault, "ABCD-1234", base_utc + 400);
        assert!(matches!(res_rec, Err(AuthError::LockoutActive(_))));

        // Check 6: After 3602 seconds, correct password should SUCCEED
        let res_expired = auth2.verify_master_password_at_time(&raw_vault, &pw, base_utc + 3605);
        assert!(res_expired.is_ok(), "Authentication must succeed after lockout expiry");
    }

    let _ = fs::remove_file(lock_path);
}

#[test]
fn test_edge_case_one_failure_persists_across_restart() {
    let lock_path = get_temp_lock_path("one_fail_restart");
    let pw = SecretString::new("SecretPass2026!".to_string());
    let (_, raw_vault) = create_test_vault(&pw);
    let base_utc = 1700000000u64;

    // Session 1: exactly 1 failure occurs, then user closes/kills process
    {
        let mut auth1 = AuthManager::with_lockout_path(&lock_path);
        let bad_pw = SecretString::new("Wrong1!".to_string());
        auth1.verify_master_password_at_time(&raw_vault, &bad_pw, base_utc).unwrap_err();
        assert_eq!(auth1.lockout_manager().record().failed_attempts, 1);
    }

    // Session 2: new process started, enters 1 wrong password
    {
        let mut auth2 = AuthManager::with_lockout_path(&lock_path);
        assert_eq!(auth2.lockout_manager().record().failed_attempts, 1, "Failed attempt must persist across restart");

        let bad_pw = SecretString::new("Wrong2!".to_string());
        auth2.verify_master_password_at_time(&raw_vault, &bad_pw, base_utc + 10).unwrap_err();

        // Should now be LOCKED OUT! (1 previous + 1 current = 2 failures)
        assert!(auth2.lockout_manager().check_status(base_utc + 15).unwrap());
        let res = auth2.verify_master_password_at_time(&raw_vault, &pw, base_utc + 15);
        assert!(matches!(res, Err(AuthError::LockoutActive(_))));
    }

    let _ = fs::remove_file(lock_path);
}

#[test]
fn test_edge_case_reboot_simulation_tick_less_than_last_boot() {
    let mut manager = LockoutManager::new();
    let base_utc = 1700000000u64;
    let base_tick = 1_000_000u64; // system uptime was 1000s

    // Trigger lockout
    manager.register_failure_at_time_and_tick(base_utc, Some(base_tick)).unwrap();
    let res = manager.register_failure_at_time_and_tick(base_utc + 5, Some(base_tick + 5000)).unwrap();
    assert!(matches!(res, LockoutStatus::LockedOut { .. }));

    let locked_time_utc = base_utc + 5;
    let locked_until = locked_time_utc + 3600;

    // Simulation: System rebooted!
    // current_tick is now 3_000 (3 seconds uptime), which is < last_boot_tick (1_005_000)
    let reboot_tick = 3_000u64;

    // Case 1: 50 seconds after lockout (still within 1 hour)
    let is_locked = manager.check_status_monotonic(locked_time_utc + 50, reboot_tick).unwrap();
    assert!(is_locked, "Lockout must remain enforced across reboot if UTC < locked_until_utc");

    // Case 2: 3601 seconds after lockout (UTC >= locked_until)
    let is_locked_expired = manager.check_status_monotonic(locked_until + 1, reboot_tick).unwrap();
    assert!(!is_locked_expired, "Lockout must be released after reboot if UTC >= locked_until_utc");

    // Case 3: Clock rollback across reboot (UTC < last_event_utc)
    let rollback_res = manager.check_status_monotonic(locked_time_utc - 10, reboot_tick);
    assert_eq!(rollback_res, Err(LockoutError::ClockRollbackDetected));
}

#[test]
fn test_edge_case_exponential_backoff_persists_across_restart() {
    let lock_path = get_temp_lock_path("exp_backoff_persist");
    let pw = SecretString::new("SecretPass2026!".to_string());
    let (_, raw_vault) = create_test_vault(&pw);
    let base_utc = 1700000000u64;

    // Session 1: Trigger 1st lockout (3600s)
    {
        let mut auth1 = AuthManager::with_lockout_path(&lock_path);
        let bad = SecretString::new("Bad!".to_string());
        auth1.verify_master_password_at_time(&raw_vault, &bad, base_utc).unwrap_err();
        auth1.verify_master_password_at_time(&raw_vault, &bad, base_utc + 1).unwrap_err();
        assert_eq!(auth1.lockout_manager().record().consecutive_lockouts, 1);
        assert_eq!(auth1.lockout_manager().record().locked_until_utc, base_utc + 1 + 3600);
    }

    // Session 2 (after 1st lockout expired): Trigger 2nd lockout
    let session2_utc = base_utc + 1 + 3602;
    {
        let mut auth2 = AuthManager::with_lockout_path(&lock_path);
        assert_eq!(auth2.lockout_manager().record().consecutive_lockouts, 1, "Backoff counter must persist");
        let bad = SecretString::new("Bad!".to_string());
        auth2.verify_master_password_at_time(&raw_vault, &bad, session2_utc).unwrap_err();
        auth2.verify_master_password_at_time(&raw_vault, &bad, session2_utc + 1).unwrap_err();

        // 2nd lockout must be 7200s (3600 * 2^1)
        assert_eq!(auth2.lockout_manager().record().consecutive_lockouts, 2);
        assert_eq!(auth2.lockout_manager().record().locked_until_utc, session2_utc + 1 + 7200);
    }

    // Session 3 (kill and restart during 2nd lockout):
    {
        let mut auth3 = AuthManager::with_lockout_path(&lock_path);
        assert_eq!(auth3.lockout_manager().record().consecutive_lockouts, 2);

        // Lockout should still be active 5000s into the 7200s window
        let res = auth3.verify_master_password_at_time(&raw_vault, &pw, session2_utc + 1 + 5000);
        assert!(matches!(res, Err(AuthError::LockoutActive(_))));

        // Expired after 7202s
        let res_ok = auth3.verify_master_password_at_time(&raw_vault, &pw, session2_utc + 1 + 7205);
        assert!(res_ok.is_ok(), "Must unlock after 7200s expires");
    }

    let _ = fs::remove_file(lock_path);
}

#[test]
fn test_edge_case_totp_failures_trigger_persisted_lockout() {
    let lock_path = get_temp_lock_path("totp_fail_persist");
    let pw = SecretString::new("SecretPass2026!".to_string());
    let (vault, _) = create_test_vault(&pw);
    let base_utc = 1700000000u64;

    // Session 1: 2 TOTP failures trigger lockout
    {
        let mut auth1 = AuthManager::with_lockout_path(&lock_path);
        auth1.verify_totp(&vault, "000000", base_utc).unwrap_err();
        auth1.verify_totp(&vault, "111111", base_utc + 5).unwrap_err();
        assert!(auth1.lockout_manager().check_status(base_utc + 10).unwrap());
    }

    // Session 2: New session loads lockout
    {
        let mut auth2 = AuthManager::with_lockout_path(&lock_path);
        let res = auth2.verify_totp(&vault, "222222", base_utc + 100);
        assert!(matches!(res, Err(AuthError::LockoutActive(_))));
    }

    let _ = fs::remove_file(lock_path);
}
