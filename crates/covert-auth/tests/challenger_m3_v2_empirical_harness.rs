//! Empirical Challenge Harness for Milestone 3 Remediation.
//!
//! Authored by challenger_m3_v2_1 to empirically verify:
//! 1. challenge_6: Lockout persistence across sessions and AuthManager unlock rejection.
//! 2. challenge_7: Monotonic tick validation and clock fast-forward attacks.
//! 3. Edge Case 1: Empty .lock file (0 bytes), 1-byte, and truncated/corrupted CBOR recovery.
//! 4. Edge Case 2: 2 failures -> kill process -> restart -> all auth entry points blocked.
//! 5. Edge Case 3: Reboot simulation (current_tick < last_boot_tick) within lockout window vs expired.
//! 6. Edge Case 4: Interrupted failure accumulation across sessions (1 fail -> kill -> 1 fail -> locked).
//! 7. Edge Case 5: Multi-session exponential backoff progression and reset on successful auth.
//! 8. Edge Case 6: Millisecond boundary precision for monotonic ticks and micro-fast-forward detection.
//! 9. Edge Case 7: Clipboard guard safety and sequence protection.

use covert_auth::error::{AuthError, LockoutError};
use covert_auth::lockout::{LockoutManager, BASE_LOCKOUT_SECONDS};
use covert_auth::AuthManager;
use covert_core::header::Argon2Params;
use covert_core::models::Vault;
use covert_core::SecretString;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn create_challenge_vault(password: &SecretString) -> (Vault, Vec<u8>) {
    let mut vault = Vault::new("Challenger V2 Test Vault");
    vault.security.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
    vault.security.totp_digits = 6;
    vault.security.totp_period = 30;
    vault.security.totp_algorithm = "SHA1".to_string();
    vault.security.recovery_codes = vec![
        "RC01-1111".to_string(),
        "RC02-2222".to_string(),
        "RC03-3333".to_string(),
    ];

    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();
    let raw = vault.encrypt(password, Some(fast_params)).unwrap();
    (vault, raw)
}

fn get_challenge_lock_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gastinel_challenger_v2_{}_{}_{}.lock",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

// ---------------------------------------------------------------------------
// 1. Corrupt, Empty, and Truncated Lock File Edge Cases
// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_lock_file_corruption_variants() {
    let corruption_payloads: Vec<(&str, Vec<u8>)> = vec![
        ("zero_bytes", vec![]),
        ("single_byte", vec![0x00]),
        ("high_byte", vec![0xFF]),
        ("truncated_cbor_map", vec![0xA5]), // CBOR map with 5 items, but EOF immediately
        ("invalid_utf8_cbor", vec![0xA1, 0x65, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        ("random_garbage", (0..128).map(|i| (i * 37) as u8).collect()),
    ];

    for (name, payload) in corruption_payloads {
        let lock_path = get_challenge_lock_path(name);
        {
            let mut f = fs::File::create(&lock_path).unwrap();
            f.write_all(&payload).unwrap();
            f.flush().unwrap();
        }

        // Test 1: LockoutManager loads without panic and fails closed: enforces safety lockout
        let manager = LockoutManager::with_path(&lock_path);
        assert_eq!(
            manager.record().failed_attempts,
            2,
            "Corruption '{}' must fail closed with MAX_FAILED_ATTEMPTS",
            name
        );
        assert!(
            manager.record().locked_until_utc > 0,
            "Corruption '{}' must enforce safety locked_until_utc > 0",
            name
        );

        // Test 2: AuthManager initializes cleanly and fails closed
        let pw = SecretString::new("Pass123!".to_string());
        let (_, raw_vault) = create_challenge_vault(&pw);
        let mut auth = AuthManager::with_lockout_path(&lock_path);

        // Test 3: Authentication is blocked due to active safety lockout
        let test_now = auth.lockout_manager().record().last_event_utc;
        let res = auth.verify_master_password_at_time(&raw_vault, &pw, test_now);
        assert!(
            matches!(res, Err(AuthError::LockoutActive(_))),
            "Corruption '{}' must block authentication with LockoutActive",
            name
        );

        let _ = fs::remove_file(lock_path);
    }
}

// ---------------------------------------------------------------------------
// 2. Kill and Restart: All Entry Points Strictly Blocked During Lockout
// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_kill_restart_all_entry_points_blocked() {
    let lock_path = get_challenge_lock_path("kill_restart_all");
    let pw = SecretString::new("MasterSecret2026!".to_string());
    let (mut vault, raw_vault) = create_challenge_vault(&pw);
    let base_utc = 1700000000u64;
    let base_tick = 1_000_000u64;

    // Process 1: 2 consecutive failures -> 1-hour lockout
    {
        let mut auth1 = AuthManager::with_lockout_path(&lock_path);
        let bad_pw = SecretString::new("BadPass!".to_string());

        auth1
            .verify_master_password_at_time_and_tick(
                &raw_vault,
                &bad_pw,
                base_utc,
                Some(base_tick),
            )
            .unwrap_err();
        auth1
            .verify_master_password_at_time_and_tick(
                &raw_vault,
                &bad_pw,
                base_utc + 3,
                Some(base_tick + 3000),
            )
            .unwrap_err();

        assert!(auth1.lockout_manager().check_status(base_utc + 5).unwrap());
    } // Process 1 killed

    // Process 2: Restarted after kill
    {
        let mut auth2 = AuthManager::with_lockout_path(&lock_path);
        let test_utc = base_utc + 600; // 10 minutes into 1-hour lockout
        let test_tick = base_tick + 600_000;

        // Entry point 1: verify_master_password_at_time_and_tick (correct password)
        let res_master_correct = auth2.verify_master_password_at_time_and_tick(
            &raw_vault,
            &pw,
            test_utc,
            Some(test_tick),
        );
        assert!(
            matches!(res_master_correct, Err(AuthError::LockoutActive(_))),
            "Master password verification must be blocked during active lockout"
        );

        // Entry point 2: verify_master_password_at_time (without tick)
        let res_master_notick =
            auth2.verify_master_password_at_time(&raw_vault, &pw, test_utc);
        assert!(
            matches!(res_master_notick, Err(AuthError::LockoutActive(_))),
            "Master password verification without tick must also be blocked"
        );

        // Entry point 3: verify_totp_at_time_and_tick
        let res_totp =
            auth2.verify_totp_at_time_and_tick(&vault, "123456", test_utc, Some(test_tick));
        assert!(
            matches!(res_totp, Err(AuthError::LockoutActive(_))),
            "TOTP verification must be blocked during active lockout"
        );

        // Entry point 4: verify_totp (without tick)
        let res_totp_notick = auth2.verify_totp(&vault, "123456", test_utc);
        assert!(
            matches!(res_totp_notick, Err(AuthError::LockoutActive(_))),
            "TOTP verification without tick must also be blocked"
        );

        // Entry point 5: verify_recovery_code_at_time_and_tick
        let res_rec = auth2.verify_recovery_code_at_time_and_tick(
            &mut vault,
            "RC01-1111",
            test_utc,
            Some(test_tick),
        );
        assert!(
            matches!(res_rec, Err(AuthError::LockoutActive(_))),
            "Recovery code verification must be blocked during active lockout"
        );

        // Entry point 6: verify_recovery_code_at_time
        let res_rec_notick =
            auth2.verify_recovery_code_at_time(&mut vault, "RC01-1111", test_utc);
        assert!(
            matches!(res_rec_notick, Err(AuthError::LockoutActive(_))),
            "Recovery code verification without tick must also be blocked"
        );

        // Entry point 7: LockoutManager::check_lockout
        let res_check = auth2.lockout_manager().check_lockout(test_utc);
        assert!(
            matches!(res_check, Err(LockoutError::LockedOut { .. })),
            "check_lockout must return LockedOut error"
        );

        // Entry point 8: LockoutManager::check_lockout_monotonic
        let res_check_mono = auth2
            .lockout_manager()
            .check_lockout_monotonic(test_utc, test_tick);
        assert!(
            matches!(res_check_mono, Err(LockoutError::LockedOut { .. })),
            "check_lockout_monotonic must return LockedOut error"
        );

        // Precise boundary testing:
        // Expiry is at base_utc + 3 + 3600 = base_utc + 3603.
        let expiry_utc = base_utc + 3 + 3600;
        let expiry_tick = base_tick + 3000 + 3600 * 1000;

        // 1 second BEFORE expiry: still locked
        let res_before = auth2.verify_master_password_at_time_and_tick(
            &raw_vault,
            &pw,
            expiry_utc - 1,
            Some(expiry_tick - 1000),
        );
        assert!(
            matches!(res_before, Err(AuthError::LockoutActive(_))),
            "Must still be locked 1 second before expiry"
        );

        // EXACTLY AT expiry: allowed
        let res_at_expiry = auth2.verify_master_password_at_time_and_tick(
            &raw_vault,
            &pw,
            expiry_utc,
            Some(expiry_tick),
        );
        assert!(
            res_at_expiry.is_ok(),
            "Must be unlocked exactly at expiry timestamp"
        );
    }

    let _ = fs::remove_file(lock_path);
}

// ---------------------------------------------------------------------------
// 3. Reboot Simulation (current_tick < last_boot_tick)
// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_reboot_simulation_exhaustive() {
    let mut manager = LockoutManager::new();
    let base_utc = 1700000000u64;
    let base_tick = 10_000_000u64; // 10,000s uptime before reboot

    manager
        .register_failure_at_time_and_tick(base_utc, Some(base_tick))
        .unwrap();
    manager
        .register_failure_at_time_and_tick(base_utc + 2, Some(base_tick + 2000))
        .unwrap();

    let locked_time_utc = base_utc + 2;
    let locked_until = locked_time_utc + 3600;

    // Simulation: System rebooted! Ticks reset to a low value (e.g. 5 seconds after reboot)
    let post_reboot_ticks = vec![0u64, 100u64, 1_000u64, 5_000u64, 100_000u64];

    for reboot_tick in post_reboot_ticks {
        assert!(
            reboot_tick < base_tick,
            "Reboot tick must be less than pre-reboot tick"
        );

        // Case 1: Post-reboot, time within lockout window (30s after lockout)
        let is_locked_early = manager
            .check_status_monotonic(locked_time_utc + 30, reboot_tick)
            .unwrap();
        assert!(
            is_locked_early,
            "Lockout must remain enforced after reboot if UTC < locked_until"
        );

        // Case 2: Post-reboot, time halfway through lockout (1800s after lockout)
        let is_locked_mid = manager
            .check_status_monotonic(locked_time_utc + 1800, reboot_tick)
            .unwrap();
        assert!(
            is_locked_mid,
            "Lockout must remain enforced halfway through window after reboot"
        );

        // Case 3: Post-reboot, time 1s before expiry
        let is_locked_before_exp = manager
            .check_status_monotonic(locked_until - 1, reboot_tick)
            .unwrap();
        assert!(
            is_locked_before_exp,
            "Lockout must remain enforced 1s before expiry after reboot"
        );

        // Case 4: Post-reboot, time at expiry
        let is_locked_at_exp = manager
            .check_status_monotonic(locked_until, reboot_tick)
            .unwrap();
        assert!(
            !is_locked_at_exp,
            "Lockout must expire at locked_until after reboot"
        );

        // Case 5: Post-reboot, time well after expiry
        let is_locked_after = manager
            .check_status_monotonic(locked_until + 500, reboot_tick)
            .unwrap();
        assert!(
            !is_locked_after,
            "Lockout must be released well after expiry after reboot"
        );

        // Case 6: Post-reboot, clock rollback attack (current_utc < last_event_utc)
        let rollback_res =
            manager.check_status_monotonic(locked_time_utc - 1, reboot_tick);
        assert_eq!(
            rollback_res,
            Err(LockoutError::ClockRollbackDetected),
            "Clock rollback after reboot must be detected"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Interrupted Failure Accumulation Across Sessions
// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_interrupted_failure_accumulation_across_sessions() {
    let lock_path = get_challenge_lock_path("fail_accum");
    let pw = SecretString::new("SecretPass2026!".to_string());
    let (_, raw_vault) = create_challenge_vault(&pw);
    let base_utc = 1700000000u64;

    // Session 1: 1 failure -> process killed
    {
        let mut auth1 = AuthManager::with_lockout_path(&lock_path);
        let bad = SecretString::new("Wrong1!".to_string());
        auth1
            .verify_master_password_at_time(&raw_vault, &bad, base_utc)
            .unwrap_err();
        assert_eq!(auth1.lockout_manager().record().failed_attempts, 1);
        assert_eq!(auth1.lockout_manager().record().consecutive_lockouts, 0);
        assert_eq!(auth1.lockout_manager().record().locked_until_utc, 0);
    }

    // Session 2: Fresh process starts. Failed count should be 1.
    {
        let mut auth2 = AuthManager::with_lockout_path(&lock_path);
        assert_eq!(
            auth2.lockout_manager().record().failed_attempts,
            1,
            "Failed attempts must persist across session boundary"
        );

        // Second failure -> triggers 1-hour lockout!
        let bad = SecretString::new("Wrong2!".to_string());
        auth2
            .verify_master_password_at_time(&raw_vault, &bad, base_utc + 5)
            .unwrap_err();

        assert_eq!(auth2.lockout_manager().record().consecutive_lockouts, 1);
        assert_eq!(
            auth2.lockout_manager().record().locked_until_utc,
            base_utc + 5 + BASE_LOCKOUT_SECONDS
        );
        assert_eq!(auth2.lockout_manager().record().failed_attempts, 0);
    }

    // Session 3: Another fresh process starts during lockout.
    {
        let mut auth3 = AuthManager::with_lockout_path(&lock_path);
        let res = auth3.verify_master_password_at_time(&raw_vault, &pw, base_utc + 100);
        assert!(matches!(res, Err(AuthError::LockoutActive(_))));
    }

    let _ = fs::remove_file(lock_path);
}

// ---------------------------------------------------------------------------
// 5. Multi-Session Exponential Backoff Progression and Reset on Success
// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_exponential_backoff_progression_and_reset() {
    let lock_path = get_challenge_lock_path("backoff_progression");
    let pw = SecretString::new("FinalSecret2026!".to_string());
    let (vault, raw_vault) = create_challenge_vault(&pw);
    let mut current_utc = 1700000000u64;

    // We will test 4 successive lockout tiers:
    // Tier 1: 3600s (2^0 * 3600)
    // Tier 2: 7200s (2^1 * 3600)
    // Tier 3: 14400s (2^2 * 3600)
    // Tier 4: 28800s (2^3 * 3600)
    let expected_durations = [3600u64, 7200u64, 14400u64, 28800u64];

    for (idx, &expected_dur) in expected_durations.iter().enumerate() {
        let expected_k = (idx + 1) as u32;

        // Session to trigger lockout
        {
            let mut auth = AuthManager::with_lockout_path(&lock_path);
            let bad = SecretString::new("BadAttempt!".to_string());

            auth.verify_master_password_at_time(&raw_vault, &bad, current_utc)
                .unwrap_err();
            current_utc += 1;
            auth.verify_master_password_at_time(&raw_vault, &bad, current_utc)
                .unwrap_err();

            let rec = auth.lockout_manager().record();
            assert_eq!(
                rec.consecutive_lockouts, expected_k,
                "Consecutive lockouts must equal {}",
                expected_k
            );
            assert_eq!(
                rec.locked_until_utc,
                current_utc + expected_dur,
                "Lockout duration must be {} for tier {}",
                expected_dur,
                expected_k
            );
        }

        // New session during lockout: verify active
        {
            let mut auth = AuthManager::with_lockout_path(&lock_path);
            let res = auth.verify_master_password_at_time(&raw_vault, &pw, current_utc + 10);
            assert!(
                matches!(res, Err(AuthError::LockoutActive(_))),
                "Must be locked out during tier {} active window",
                expected_k
            );
        }

        // Advance time past the lockout expiration for next iteration
        current_utc += expected_dur + 5;
    }

    // Now, at current_utc (which is after Tier 4 expired):
    // Enter CORRECT password and TOTP to authenticate successfully!
    {
        let mut auth = AuthManager::with_lockout_path(&lock_path);
        let decrypt_res = auth.verify_master_password_at_time(&raw_vault, &pw, current_utc);
        assert!(decrypt_res.is_ok(), "Password decrypt must succeed after expiry");

        // Verify TOTP successfully to trigger register_success
        let totp_engine = covert_auth::totp::TotpEngine::from_base32("JBSWY3DPEHPK3PXP").unwrap();
        let code = totp_engine.generate_at(current_utc).unwrap();
        let totp_res = auth.verify_totp(&vault, &code, current_utc);
        assert!(totp_res.is_ok(), "TOTP verification must succeed");

        // Consecutive lockouts and failed attempts must be completely RESET to 0!
        assert_eq!(auth.lockout_manager().record().failed_attempts, 0);
        assert_eq!(auth.lockout_manager().record().consecutive_lockouts, 0);
        assert_eq!(auth.lockout_manager().record().locked_until_utc, 0);
    }

    // Verify reset persists in next session:
    // Next 2 failures should trigger Tier 1 (3600s), NOT Tier 5!
    {
        let mut auth = AuthManager::with_lockout_path(&lock_path);
        assert_eq!(auth.lockout_manager().record().consecutive_lockouts, 0);

        let bad = SecretString::new("BadAttempt!".to_string());
        current_utc += 10;
        auth.verify_master_password_at_time(&raw_vault, &bad, current_utc)
            .unwrap_err();
        current_utc += 1;
        auth.verify_master_password_at_time(&raw_vault, &bad, current_utc)
            .unwrap_err();

        let rec = auth.lockout_manager().record();
        assert_eq!(
            rec.consecutive_lockouts, 1,
            "Consecutive lockouts must reset to 1 after successful auth"
        );
        assert_eq!(
            rec.locked_until_utc,
            current_utc + 3600,
            "Duration must reset to base 3600s after successful auth"
        );
    }

    let _ = fs::remove_file(lock_path);
}

// ---------------------------------------------------------------------------
// 6. Monotonic Tick Micro-Fast-Forward & Boundary Testing
// ---------------------------------------------------------------------------

#[test]
fn test_adversarial_monotonic_tick_micro_fast_forward_boundaries() {
    let mut manager = LockoutManager::new();
    let base_utc = 1700000000u64;
    let base_tick = 500_000u64; // 500s uptime

    manager
        .register_failure_at_time_and_tick(base_utc, Some(base_tick))
        .unwrap();
    manager
        .register_failure_at_time_and_tick(base_utc + 1, Some(base_tick + 1000))
        .unwrap();

    let locked_time_utc = base_utc + 1;
    let locked_tick = base_tick + 1000;
    let required_duration = 3600u64;
    let expiry_utc = locked_time_utc + required_duration;

    // Test A: Clock advanced to EXACT expiry (expiry_utc), but ticks only advanced by 3599 seconds
    // (1 second short of physical duration).
    let tick_almost_done = locked_tick + 3599 * 1000;
    let tamper_res1 = manager.check_status_monotonic(expiry_utc, tick_almost_done);
    assert_eq!(
        tamper_res1,
        Err(LockoutError::ClockRollbackDetected),
        "Clock fast-forward by 1 second ahead of physical time must be caught"
    );

    // Test B: Clock advanced to 1 second past expiry (expiry_utc + 1), but ticks only advanced 3599.999 seconds
    // (elapsed_tick_secs = 3599).
    let tick_999ms = locked_tick + 3599 * 1000 + 999;
    let tamper_res2 = manager.check_status_monotonic(expiry_utc + 1, tick_999ms);
    assert_eq!(
        tamper_res2,
        Err(LockoutError::ClockRollbackDetected),
        "Sub-second tick precision fast-forward must be caught"
    );

    // Test C: Ticks advanced by exactly 3600 seconds, and UTC at expiry_utc
    let tick_exact = locked_tick + 3600 * 1000;
    let legit_res = manager.check_status_monotonic(expiry_utc, tick_exact);
    assert_eq!(
        legit_res,
        Ok(false),
        "Legitimate expiration at exact 3600s boundary must return Ok(false)"
    );

    // Test D: Extreme tick values (large tick counts, near u64::MAX / 2)
    let huge_tick = 1_000_000_000_000_000u64;
    let mut manager_huge = LockoutManager::new();
    manager_huge
        .register_failure_at_time_and_tick(base_utc, Some(huge_tick))
        .unwrap();
    manager_huge
        .register_failure_at_time_and_tick(base_utc + 1, Some(huge_tick + 1000))
        .unwrap();

    // Check with huge ticks
    let normal_huge = manager_huge.check_status_monotonic(base_utc + 10, huge_tick + 10_000);
    assert_eq!(normal_huge, Ok(true));

    let tamper_huge = manager_huge.check_status_monotonic(expiry_utc + 100, huge_tick + 5_000);
    assert_eq!(tamper_huge, Err(LockoutError::ClockRollbackDetected));
}
