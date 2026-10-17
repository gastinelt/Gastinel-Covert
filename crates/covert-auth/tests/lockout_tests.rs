use covert_auth::error::LockoutError;
use covert_auth::lockout::{LockoutManager, LockoutStatus, BASE_LOCKOUT_SECONDS};
use std::fs;

#[test]
fn test_lockout_two_failures_triggers_one_hour() {
    let mut manager = LockoutManager::new();
    let current_time = 1700000000u64;

    // Initially allowed
    assert!(!manager.check_status(current_time).unwrap());
    assert!(manager.check_lockout(current_time).is_ok());

    // 1st failed attempt -> 1 attempt remaining, still not locked out
    let res1 = manager.register_failure(current_time).unwrap();
    assert_eq!(res1, LockoutStatus::AttemptFailed { attempts_remaining: 1 });
    assert!(!manager.check_status(current_time).unwrap());
    assert!(manager.check_lockout(current_time).is_ok());

    // 2nd failed attempt -> triggers 1-hour lockout (3600s)
    let res2 = manager.register_failure(current_time + 10).unwrap();
    match res2 {
        LockoutStatus::LockedOut { duration_seconds, locked_until_utc } => {
            assert_eq!(duration_seconds, BASE_LOCKOUT_SECONDS);
            assert_eq!(locked_until_utc, current_time + 10 + 3600);
        }
        _ => panic!("Expected LockedOut status on 2nd failure"),
    }

    // Now locked out: check_status returns true
    assert!(manager.check_status(current_time + 15).unwrap());

    // check_lockout returns LockedOut error with remaining seconds
    match manager.check_lockout(current_time + 15).unwrap_err() {
        LockoutError::LockedOut { remaining_seconds } => {
            assert_eq!(remaining_seconds, 3600 - 5);
        }
        err => panic!("Unexpected error: {:?}", err),
    }

    // Still locked out 30 minutes later (t = 1800)
    assert!(manager.check_status(current_time + 10 + 1800).unwrap());

    // Lockout expires after 1 hour (t = 3601)
    assert!(!manager.check_status(current_time + 10 + 3601).unwrap());
    assert!(manager.check_lockout(current_time + 10 + 3601).is_ok());
}

#[test]
fn test_lockout_exponential_backoff_on_repeat_failures() {
    let mut manager = LockoutManager::new();
    let mut current_time = 1700000000u64;

    // Lockout 1: 2 failures -> 3600s (1h)
    manager.register_failure(current_time).unwrap();
    let res1 = manager.register_failure(current_time + 1).unwrap();
    match res1 {
        LockoutStatus::LockedOut { duration_seconds, .. } => {
            assert_eq!(duration_seconds, 3600);
        }
        _ => panic!("Expected 1st lockout"),
    }

    // Fast-forward past 1st lockout
    current_time += 3601;
    assert!(!manager.check_status(current_time).unwrap());

    // Lockout 2: 2 more failures -> 7200s (2h)
    manager.register_failure(current_time).unwrap();
    let res2 = manager.register_failure(current_time + 1).unwrap();
    match res2 {
        LockoutStatus::LockedOut { duration_seconds, .. } => {
            assert_eq!(duration_seconds, 7200, "2nd lockout should be 7200s (2 hours)");
        }
        _ => panic!("Expected 2nd lockout"),
    }

    // Fast-forward past 2nd lockout
    current_time += 7202;
    assert!(!manager.check_status(current_time).unwrap());

    // Lockout 3: 2 more failures -> 14400s (4h)
    manager.register_failure(current_time).unwrap();
    let res3 = manager.register_failure(current_time + 1).unwrap();
    match res3 {
        LockoutStatus::LockedOut { duration_seconds, .. } => {
            assert_eq!(duration_seconds, 14400, "3rd lockout should be 14400s (4 hours)");
        }
        _ => panic!("Expected 3rd lockout"),
    }

    // Fast-forward past 3rd lockout
    current_time += 14402;
    assert!(!manager.check_status(current_time).unwrap());

    // Lockout 4: 2 more failures -> 28800s (8h)
    manager.register_failure(current_time).unwrap();
    let res4 = manager.register_failure(current_time + 1).unwrap();
    match res4 {
        LockoutStatus::LockedOut { duration_seconds, .. } => {
            assert_eq!(duration_seconds, 28800, "4th lockout should be 28800s (8 hours)");
        }
        _ => panic!("Expected 4th lockout"),
    }
}

#[test]
fn test_lockout_success_resets_counters() {
    let mut manager = LockoutManager::new();
    let current_time = 1700000000u64;

    // 1 failure
    manager.register_failure(current_time).unwrap();
    assert_eq!(manager.record().failed_attempts, 1);

    // Successful authentication
    manager.register_success(current_time + 5);
    assert_eq!(manager.record().failed_attempts, 0);
    assert_eq!(manager.record().consecutive_lockouts, 0);
    assert_eq!(manager.record().locked_until_utc, 0);

    // Another failure after success: still needs 2 failures to lock out
    let res = manager.register_failure(current_time + 10).unwrap();
    assert_eq!(res, LockoutStatus::AttemptFailed { attempts_remaining: 1 });
}

#[test]
fn test_lockout_clock_rollback_detection() {
    let mut manager = LockoutManager::new();
    let current_time = 1700000000u64;

    manager.register_failure(current_time).unwrap();

    // System clock rolled back by 100 seconds
    let rollback_time = current_time - 100;

    let check_res = manager.check_status(rollback_time);
    assert_eq!(check_res.unwrap_err(), LockoutError::ClockRollbackDetected);

    let fail_res = manager.register_failure(rollback_time);
    assert_eq!(fail_res.unwrap_err(), LockoutError::ClockRollbackDetected);
}

#[test]
fn test_lockout_file_persistence() {
    let temp_dir = std::env::temp_dir().join(format!("gastinel_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let lock_file = temp_dir.join("dx12_pipeline.lock");

    let mut manager = LockoutManager::with_path(&lock_file);
    let current_time = 1700000000u64;

    manager.register_failure(current_time).unwrap();
    manager.register_failure(current_time + 5).unwrap();
    assert!(manager.check_status(current_time + 6).unwrap());

    // Save to disk
    manager.save().expect("Save to file failed");
    assert!(lock_file.exists());

    // Reload in brand new LockoutManager instance
    let reloaded = LockoutManager::load_from_file(&lock_file).expect("Load failed");
    assert_eq!(reloaded.record().consecutive_lockouts, 1);
    assert!(reloaded.check_status(current_time + 6).unwrap());

    // Cleanup
    let _ = fs::remove_file(lock_file);
    let _ = fs::remove_dir(temp_dir);
}

#[test]
fn test_lockout_deletion_mid_session_fails_closed() {
    let temp_dir = std::env::temp_dir().join(format!(
        "gastinel_test_del_mid_{}",
        std::process::id()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    let lock_file = temp_dir.join("dx12_pipeline.lock");
    let _ = fs::remove_file(&lock_file);

    let mut manager = LockoutManager::with_path(&lock_file);
    let current_time = 1700000000u64;

    // 1st failed attempt persisted to disk
    let res1 = manager.register_failure(current_time).unwrap();
    assert_eq!(res1, LockoutStatus::AttemptFailed { attempts_remaining: 1 });
    manager.save().expect("Save after 1st failure");
    assert!(lock_file.exists());

    // Attacker deletes the .lock file to try to reset failed_attempts to 0
    fs::remove_file(&lock_file).expect("Delete .lock file");
    assert!(!lock_file.exists());

    // Next attempt immediately detects deletion and fails closed with 1-hour lockout
    let res2 = manager.register_failure(current_time + 5).unwrap();
    match res2 {
        LockoutStatus::LockedOut {
            duration_seconds,
            locked_until_utc,
        } => {
            assert_eq!(duration_seconds, BASE_LOCKOUT_SECONDS);
            assert_eq!(locked_until_utc, current_time + 5 + BASE_LOCKOUT_SECONDS);
        }
        other => panic!("Expected LockedOut after .lock deletion, got: {:?}", other),
    }
    assert!(
        lock_file.exists(),
        ".lock file must be recreated on fail-closed lockout"
    );

    let _ = fs::remove_file(&lock_file);
    let _ = fs::remove_dir(&temp_dir);
}

#[test]
fn test_lockout_deletion_across_restarts_with_companion_vault_fails_closed() {
    let temp_dir = std::env::temp_dir().join(format!(
        "gastinel_test_del_restart_{}",
        std::process::id()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    let vault_file = temp_dir.join("dx12_pipeline.bin");
    let lock_file = temp_dir.join("dx12_pipeline.lock");

    // Create a vault via VaultStorage::save_vault (which also initializes .lock)
    let storage = covert_storage::VaultStorage::from_path(&vault_file);
    let vault = covert_core::models::Vault::new("Lockout Companion Test");
    let pw = covert_core::SecretString::new("MasterPass123!".to_string());
    let fast_params = covert_core::header::Argon2Params::new(65536, 2, 1).unwrap();
    storage
        .save_vault(&vault, &pw, Some(fast_params))
        .expect("save_vault");

    assert!(vault_file.exists());
    assert!(
        lock_file.exists(),
        "VaultStorage::save_vault must initialize companion .lock file"
    );

    // Normal load succeeds and is not locked out
    let initial_mgr = LockoutManager::with_path(&lock_file);
    assert_eq!(initial_mgr.record().failed_attempts, 0);
    assert_eq!(initial_mgr.record().locked_until_utc, 0);

    // Attacker deletes .lock while .bin remains on disk
    fs::remove_file(&lock_file).expect("Delete .lock");
    assert!(!lock_file.exists());

    // New LockoutManager::with_path sees missing .lock alongside existing .bin and fails closed
    let restarted_mgr = LockoutManager::with_path(&lock_file);
    assert_eq!(restarted_mgr.record(). consecutive_lockouts, 1);
    assert!(restarted_mgr.record().locked_until_utc > 0);
    assert!(restarted_mgr.check_status_current().unwrap());
    assert!(
        lock_file.exists(),
        "Fail-closed startup must recreate .lock on disk"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

