//! Adversarial Round 2 Challenge Test Suite
//!
//! Specifically validates:
//! 1. Fail-closed lock file behavior on corrupt and empty files.
//! 2. AuthManager rejection of all unlock attempts with `AuthError::LockoutActive(_)`.
//! 3. Expiration behavior of fail-closed lockouts after physical duration elapses.
//! 4. Atomic write resilience of `save_to_file` without zero-byte artifacts.
//! 5. Error propagation when lock file save fails.

use covert_auth::error::AuthError;
use covert_auth::lockout::{LockoutManager, LockoutRecord, BASE_LOCKOUT_SECONDS, MAX_FAILED_ATTEMPTS};
use covert_auth::AuthManager;
use covert_core::header::Argon2Params;
use covert_core::models::Vault;
use covert_core::SecretString;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_temp_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gastinel_r2_chal_{}_{}_{}.lock",
        label,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn create_vault_and_raw(password: &SecretString) -> (Vault, Vec<u8>) {
    let mut vault = Vault::new("Challenger R2 Vault");
    vault.security.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
    vault.security.totp_digits = 6;
    vault.security.totp_period = 30;
    vault.security.totp_algorithm = "SHA1".to_string();
    vault.security.recovery_codes = vec!["RECO-1111".to_string(), "RECO-2222".to_string()];

    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();
    let raw = vault.encrypt(password, Some(fast_params)).unwrap();
    (vault, raw)
}

#[test]
fn test_challenge_empty_lock_file_fail_closed_and_all_unlock_rejected() {
    let path = test_temp_path("empty_fail_closed");
    // Create empty 0-byte file
    {
        let mut f = fs::File::create(&path).unwrap();
        f.flush().unwrap();
    }
    assert_eq!(fs::metadata(&path).unwrap().len(), 0);

    // 1. LockoutManager::with_path must fail closed
    let manager = LockoutManager::with_path(&path);
    assert_eq!(
        manager.record().failed_attempts,
        MAX_FAILED_ATTEMPTS,
        "Empty file must enforce MAX_FAILED_ATTEMPTS == 2"
    );
    assert!(
        manager.record().locked_until_utc > 0,
        "Empty file must enforce locked_until_utc > 0"
    );

    // 2. AuthManager must reject ALL unlock entry points with AuthError::LockoutActive
    let pw = SecretString::new("Passphrase123!".to_string());
    let (mut vault, raw_vault) = create_vault_and_raw(&pw);
    let mut auth = AuthManager::with_lockout_path(&path);

    let now_utc = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Master password entry point (correct password)
    let res_pw_correct = auth.verify_master_password_at_time(&raw_vault, &pw, now_utc);
    assert!(
        matches!(res_pw_correct, Err(AuthError::LockoutActive(_))),
        "Must reject correct master password during fail-closed lockout"
    );

    // Master password entry point (wrong password)
    let bad_pw = SecretString::new("WrongPass!".to_string());
    let res_pw_wrong = auth.verify_master_password_at_time(&raw_vault, &bad_pw, now_utc);
    assert!(
        matches!(res_pw_wrong, Err(AuthError::LockoutActive(_))),
        "Must reject wrong master password during fail-closed lockout"
    );

    // TOTP entry point
    let res_totp = auth.verify_totp(&vault, "123456", now_utc);
    assert!(
        matches!(res_totp, Err(AuthError::LockoutActive(_))),
        "Must reject TOTP verification during fail-closed lockout"
    );

    // Recovery code entry point
    let res_recovery = auth.verify_recovery_code_at_time(&mut vault, "RECO-1111", now_utc);
    assert!(
        matches!(res_recovery, Err(AuthError::LockoutActive(_))),
        "Must reject recovery code verification during fail-closed lockout"
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn test_challenge_corrupted_lock_file_fail_closed_and_all_unlock_rejected() {
    let corrupt_payloads = [
        ("garbage_bytes", b"\xDE\xAD\xBE\xEF\x00\xFF\xAA\x55".to_vec()),
        ("single_zero", vec![0x00]),
        ("single_ff", vec![0xFF]),
        ("invalid_cbor_type", vec![0x05]), // CBOR positive int 5
        ("cbor_text_string", vec![0x64, b't', b'e', b'x', b't']), // CBOR text "text"
        ("cbor_empty_array", vec![0x80]), // CBOR empty array []
        ("cbor_empty_map", vec![0xA0]),   // CBOR empty map {} (missing fields)
        ("truncated_cbor", vec![0xA5, 0x64]), // CBOR map truncated midway
    ];

    let pw = SecretString::new("CorrectMasterPass2026!".to_string());
    let (mut vault, raw_vault) = create_vault_and_raw(&pw);

    for (name, payload) in corrupt_payloads {
        let path = test_temp_path(name);
        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(&payload).unwrap();
            f.flush().unwrap();
        }

        // 1. LockoutManager::with_path must fail closed
        let manager = LockoutManager::with_path(&path);
        assert_eq!(
            manager.record().failed_attempts,
            MAX_FAILED_ATTEMPTS,
            "Payload '{}' must enforce failed_attempts == 2",
            name
        );
        assert!(
            manager.record().locked_until_utc > 0,
            "Payload '{}' must enforce locked_until_utc > 0",
            name
        );

        // 2. AuthManager must reject ALL unlock entry points with AuthError::LockoutActive
        let mut auth = AuthManager::with_lockout_path(&path);
        let now_utc = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let res_master = auth.verify_master_password_at_time(&raw_vault, &pw, now_utc);
        assert!(
            matches!(res_master, Err(AuthError::LockoutActive(_))),
            "Payload '{}' must reject master password with LockoutActive",
            name
        );

        let res_totp = auth.verify_totp(&vault, "123456", now_utc);
        assert!(
            matches!(res_totp, Err(AuthError::LockoutActive(_))),
            "Payload '{}' must reject TOTP with LockoutActive",
            name
        );

        let res_recovery = auth.verify_recovery_code_at_time(&mut vault, "RECO-1111", now_utc);
        assert!(
            matches!(res_recovery, Err(AuthError::LockoutActive(_))),
            "Payload '{}' must reject recovery code with LockoutActive",
            name
        );

        let _ = fs::remove_file(&path);
    }
}

#[test]
fn test_challenge_atomic_write_resilience_and_no_zero_byte_files() {
    let path = test_temp_path("atomic_write");

    let manager = LockoutManager::from_record_and_path(
        LockoutRecord {
            failed_attempts: 1,
            consecutive_lockouts: 0,
            locked_until_utc: 0,
            last_event_utc: 1700000000,
            last_boot_tick: 500000,
        },
        &path,
    );

    // Initial save: file must exist and be non-empty valid CBOR
    manager.save_to_file(&path).unwrap();
    assert!(path.exists());
    let len1 = fs::metadata(&path).unwrap().len();
    assert!(len1 > 0, "Saved lock file must never be 0 bytes");

    // Temp file should not linger
    let temp_path = path.with_extension("tmp");
    assert!(!temp_path.exists(), "Temporary file must not linger after save");

    // Overwrite with updated record
    let updated_record = LockoutRecord {
        failed_attempts: 2,
        consecutive_lockouts: 1,
        locked_until_utc: 1700003600,
        last_event_utc: 1700000001,
        last_boot_tick: 501000,
    };
    let manager2 = LockoutManager::from_record_and_path(updated_record.clone(), &path);
    manager2.save_to_file(&path).unwrap();

    let len2 = fs::metadata(&path).unwrap().len();
    assert!(len2 > 0, "Updated lock file must not be 0 bytes");
    assert!(!temp_path.exists(), "Temporary file must not linger after overwrite");

    // Verify written content is correctly reloadable
    let loaded = LockoutManager::load_from_file(&path).unwrap();
    assert_eq!(loaded.record(), &updated_record);

    // Rapid successive atomic saves (stress test)
    for i in 0..50 {
        let rec = LockoutRecord {
            failed_attempts: (i % 3),
            consecutive_lockouts: i,
            locked_until_utc: 1700000000 + (i as u64) * 3600,
            last_event_utc: 1700000000 + (i as u64),
            last_boot_tick: 600000 + (i as u64) * 1000,
        };
        let m = LockoutManager::from_record_and_path(rec.clone(), &path);
        m.save_to_file(&path).unwrap();

        let meta = fs::metadata(&path).unwrap();
        assert!(meta.len() > 0, "Iteration {} resulted in 0-byte file", i);

        let reloaded = LockoutManager::load_from_file(&path).unwrap();
        assert_eq!(reloaded.record(), &rec, "Iteration {} data mismatch", i);
    }

    let _ = fs::remove_file(&path);
}

#[test]
fn test_challenge_lockout_expiration_after_corrupted_file() {
    // When a lock file is corrupted, the system enforces a safety lockout for BASE_LOCKOUT_SECONDS (1 hour).
    // AFTER 1 hour of real time and monotonic ticks have passed (3601 seconds),
    // does the lockout correctly expire and permit authentication,
    // OR does check_status_monotonic falsely trigger ClockRollbackDetected due to last_event_utc == 0?

    let path = test_temp_path("corrupt_expiry");
    // Write corrupt data
    {
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"CORRUPTED_CBOR_PAYLOAD").unwrap();
        f.flush().unwrap();
    }

    let manager = LockoutManager::with_path(&path);
    let record = manager.record();
    let initial_locked_until = record.locked_until_utc;
    let initial_boot_tick = record.last_boot_tick;

    println!(
        "Corrupt file initial state: locked_until_utc={}, last_event_utc={}, last_boot_tick={}",
        record.locked_until_utc, record.last_event_utc, record.last_boot_tick
    );

    // 1. During the 1-hour lockout window (e.g. 500 seconds later)
    let mid_utc = initial_locked_until.saturating_sub(BASE_LOCKOUT_SECONDS).saturating_add(500);
    let mid_tick = initial_boot_tick + 500_000;
    let mid_status = manager.check_status_monotonic(mid_utc, mid_tick);
    assert_eq!(
        mid_status,
        Ok(true),
        "During lockout window, check_status_monotonic must return Ok(true) (locked)"
    );

    // 2. AFTER the 1-hour lockout window (e.g. 3601 seconds after creation, 1 second past locked_until_utc)
    let post_utc = initial_locked_until + 1;
    let post_tick = initial_boot_tick + (BASE_LOCKOUT_SECONDS + 1) * 1000;

    let post_status = manager.check_status_monotonic(post_utc, post_tick);
    println!(
        "Post-expiry check: post_utc={}, post_tick={}, result={:?}",
        post_utc, post_tick, post_status
    );

    // The lockout duration (1 hour) has physically elapsed.
    // The user should now be unlocked (Ok(false)).
    // If it returns Err(LockoutError::ClockRollbackDetected), the user is permanently locked out!
    assert_eq!(
        post_status,
        Ok(false),
        "After 1 hour of real time and monotonic ticks, lockout MUST expire to Ok(false), not ClockRollbackDetected!"
    );

    // Also verify AuthManager unlock after 1 hour has elapsed
    let pw = SecretString::new("CorrectMasterPass2026!".to_string());
    let (_, raw_vault) = create_vault_and_raw(&pw);
    let mut auth = AuthManager::with_lockout_path(&path);
    let auth_res = auth.verify_master_password_at_time_and_tick(&raw_vault, &pw, post_utc, Some(post_tick));
    assert!(
        auth_res.is_ok(),
        "After 1 hour of real time and monotonic ticks, AuthManager must allow unlock, but got: {:?}",
        auth_res
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn test_challenge_lockout_expiration_after_empty_file() {
    let path = test_temp_path("empty_expiry");
    // Write 0-byte file
    {
        let mut f = fs::File::create(&path).unwrap();
        f.flush().unwrap();
    }

    let manager = LockoutManager::with_path(&path);
    let record = manager.record();
    let initial_locked_until = record.locked_until_utc;
    let initial_boot_tick = record.last_boot_tick;

    // After 1-hour lockout duration expires
    let post_utc = initial_locked_until + 1;
    let post_tick = initial_boot_tick + (BASE_LOCKOUT_SECONDS + 1) * 1000;

    let post_status = manager.check_status_monotonic(post_utc, post_tick);
    assert_eq!(
        post_status,
        Ok(false),
        "After 1 hour of real time and monotonic ticks, empty file lockout MUST expire to Ok(false), not ClockRollbackDetected!"
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn test_challenge_save_failure_error_propagation() {
    // Point lockout path to an impossible file (e.g. inside a file treated as directory)
    let temp_file = test_temp_path("save_err_parent");
    {
        let mut f = fs::File::create(&temp_file).unwrap();
        f.write_all(b"not a directory").unwrap();
    }
    let impossible_path = temp_file.join("sub_dir").join("file.lock");

    let mut auth = AuthManager::with_lockout_path(&impossible_path);
    let pw = SecretString::new("CorrectMasterPass2026!".to_string());
    let (_, raw_vault) = create_vault_and_raw(&pw);
    let bad_pw = SecretString::new("WrongPass!".to_string());

    // When verification fails, it registers failure and attempts to save.
    // If save fails, it should propagate the LockoutError rather than silently discarding it.
    let res = auth.verify_master_password_at_time(&raw_vault, &bad_pw, 1700000000);
    assert!(
        matches!(res, Err(AuthError::Lockout(_))),
        "Failed save must bubble up as AuthError::Lockout, but got: {:?}",
        res
    );

    let _ = fs::remove_file(&temp_file);
}

#[test]
fn test_challenge_corrupt_file_unlock_flow_after_expiry() {
    let path = test_temp_path("flow_broken");
    {
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"CORRUPTED_FILE").unwrap();
        f.flush().unwrap();
    }

    let pw = SecretString::new("MasterKey2026!".to_string());
    let (_, raw_vault) = create_vault_and_raw(&pw);

    // Initial load from corrupt file
    let mut auth = AuthManager::with_lockout_path(&path);
    let init_record = auth.lockout_manager().record().clone();
    let locked_until = init_record.locked_until_utc;
    let boot_tick = init_record.last_boot_tick;

    // Simulate waiting full 1 hour + 1 second in physical time & UTC
    let post_utc = locked_until + 1;
    let post_tick = boot_tick + (BASE_LOCKOUT_SECONDS + 1) * 1000;

    // The user now tries to unlock with correct master password
    let res = auth.verify_master_password_at_time_and_tick(&raw_vault, &pw, post_utc, Some(post_tick));

    // Desired: res should be Ok((vault, header)) because lockout duration expired.
    // Actual bug: res is Err(AuthError::Lockout(LockoutError::ClockRollbackDetected))
    println!("Auth result post-expiry on corrupt file: {:?}", res);
    assert!(
        res.is_ok(),
        "User must be allowed to decrypt vault after 1-hour fail-closed lockout expires! Got: {:?}",
        res
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn test_challenge_corrupt_file_restart_after_lockout_duration_resets_timer() {
    let path = test_temp_path("corrupt_restart_reset");
    {
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(b"CORRUPTED_CBOR_PAYLOAD").unwrap();
        f.flush().unwrap();
    }

    // Process 1 starts and encounters corrupt file
    let initial_locked_until = {
        let auth1 = AuthManager::with_lockout_path(&path);
        // Lockout was enforced
        assert_eq!(auth1.lockout_manager().record().failed_attempts, 2);
        auth1.lockout_manager().record().locked_until_utc
    }; // Process 1 exits

    // Process 2 starts (simulating app restart after waiting)
    let auth2 = AuthManager::with_lockout_path(&path);
    let record2 = auth2.lockout_manager().record();

    println!(
        "Process 2 restart: locked_until_utc={}, expected expiry was {}",
        record2.locked_until_utc, initial_locked_until
    );

    // If the fail-closed state was persisted, locked_until_utc matches initial_locked_until,
    // rather than resetting to a fresh 1-hour lockout every time the app opens!
    assert_eq!(
        record2.locked_until_utc, initial_locked_until,
        "Corrupt file fail-closed lockout must persist its initial locked_until timestamp across process restarts, rather than resetting to a fresh 1-hour lockout every time the app opens!"
    );

    // Verify corrupt file on disk was replaced with valid CBOR
    assert!(
        LockoutManager::load_from_file(&path).is_ok(),
        "Corrupt file must be replaced on disk with valid persisted lockout record"
    );

    let _ = fs::remove_file(&path);
}


