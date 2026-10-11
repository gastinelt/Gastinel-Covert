use covert_auth::error::AuthError;
use covert_auth::tier2::hash_tier2_password;
use covert_auth::totp::{compute_totp_code, generate_recovery_codes};
use covert_auth::AuthManager;
use covert_core::header::Argon2Params;
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use std::fs;

fn create_test_vault(
    master_pw: &SecretString,
    view_pw: &SecretString,
    totp_secret: &str,
) -> (Vault, Vec<u8>) {
    let mut vault = Vault::new("Test Auth Vault");
    vault.security.totp_secret = Some(totp_secret.to_string());
    vault.security.totp_digits = 6;
    vault.security.totp_period = 30;
    vault.security.totp_algorithm = "SHA1".to_string();
    vault.security.recovery_codes = generate_recovery_codes(10);

    let view_hash = hash_tier2_password(view_pw).unwrap();
    vault.security.master_view_password_hash = Some(view_hash);

    vault.add_item(VaultItem::new_credential(
        "Secure Portal",
        "covert_agent",
        "UltraSecretP@ss99!",
        Some("https://secure.internal".to_string()),
    ));

    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();
    let raw_bytes = vault.encrypt(master_pw, Some(fast_params)).unwrap();

    (vault, raw_bytes)
}

#[test]
fn test_auth_manager_two_step_unlock_flow() {
    let master_pw = SecretString::new("MasterSecretPassphrase2026!".to_string());
    let view_pw = SecretString::new("ViewPasswordSecondary2026!".to_string());
    let totp_secret = "JBSWY3DPEHPK3PXP";

    let (mut initial_vault, raw_vault) =
        create_test_vault(&master_pw, &view_pw, totp_secret);

    let temp_lock = std::env::temp_dir().join(format!("gastinel_auth_test_{}.lock", std::process::id()));
    let mut auth = AuthManager::with_lockout_path(&temp_lock);
    let current_time = 1700000000u64;

    // 1. Step 1: Master password verification
    let (decrypted_vault, header) = auth
        .verify_master_password_at_time(&raw_vault, &master_pw, current_time)
        .expect("Master password verification failed");

    assert_eq!(decrypted_vault.metadata.name, initial_vault.metadata.name);
    assert_eq!(header.salt.len(), 32);

    // 2. Step 2: Aegis TOTP verification
    let valid_totp = compute_totp_code(totp_secret, current_time, 30, 6).unwrap();

    // Wrong TOTP code fails
    let err_totp = auth.verify_totp(&decrypted_vault, "999999", current_time);
    assert!(matches!(err_totp, Err(AuthError::InvalidTotpCode)));
    assert_eq!(auth.lockout_manager().record().failed_attempts, 1);

    // Correct TOTP code succeeds and resets failed attempts
    auth.verify_totp(&decrypted_vault, &valid_totp, current_time)
        .expect("TOTP verification failed");
    assert_eq!(auth.lockout_manager().record().failed_attempts, 0);

    // Replay of same TOTP code in same window is rejected
    let replay_err = auth.verify_totp(&decrypted_vault, &valid_totp, current_time + 5);
    assert!(matches!(replay_err, Err(AuthError::TotpCodeReplayed)));

    // 3. Alternative Step 2: Emergency Recovery Code
    let recovery_code = initial_vault.security.recovery_codes[0].clone();
    auth.verify_recovery_code_at_time(&mut initial_vault, &recovery_code, current_time + 10)
        .expect("Recovery code verification failed");
    assert_eq!(initial_vault.security.recovery_codes.len(), 9);

    // Re-use of consumed recovery code fails
    let reuse_err =
        auth.verify_recovery_code_at_time(&mut initial_vault, &recovery_code, current_time + 10);
    assert!(matches!(reuse_err, Err(AuthError::InvalidRecoveryCode)));

    // 4. Tier 2: Master View Password verification
    auth.verify_tier2_password(&decrypted_vault, &view_pw)
        .expect("Tier 2 verification failed");

    let wrong_view_pw = SecretString::new("WrongViewPassword!".to_string());
    let err_view = auth.verify_tier2_password(&decrypted_vault, &wrong_view_pw);
    assert!(matches!(err_view, Err(AuthError::InvalidTier2Password)));

    let _ = fs::remove_file(temp_lock);
}

#[test]
fn test_auth_manager_brute_force_lockout_activation() {
    let master_pw = SecretString::new("CorrectMasterPass123!".to_string());
    let view_pw = SecretString::new("CorrectViewPass123!".to_string());
    let (_, raw_vault) = create_test_vault(&master_pw, &view_pw, "JBSWY3DPEHPK3PXP");

    let temp_lock = std::env::temp_dir().join(format!("gastinel_lockout_test_{}.lock", std::process::id()));
    let mut auth = AuthManager::with_lockout_path(&temp_lock);
    let current_time = 1700000000u64;

    let bad_pw = SecretString::new("BadPassword123!".to_string());

    // 1st failed attempt
    let res1 = auth.verify_master_password_at_time(&raw_vault, &bad_pw, current_time);
    assert!(matches!(res1, Err(AuthError::InvalidMasterPassword)));
    assert_eq!(auth.lockout_manager().record().failed_attempts, 1);

    // 2nd failed attempt -> triggers 1-hour lockout!
    let res2 = auth.verify_master_password_at_time(&raw_vault, &bad_pw, current_time + 5);
    assert!(matches!(res2, Err(AuthError::InvalidMasterPassword)));
    assert!(auth.lockout_manager().record().locked_until_utc > current_time);

    // 3rd attempt with CORRECT password while locked out -> rejected with LockoutActive
    let res3 = auth.verify_master_password_at_time(&raw_vault, &master_pw, current_time + 10);
    match res3 {
        Err(AuthError::LockoutActive(rem)) => {
            assert!(rem.as_secs() > 3500);
        }
        other => panic!("Expected LockoutActive, got: {:?}", other),
    }

    // After 1 hour (3601s later), correct password unlocks
    let res4 = auth.verify_master_password_at_time(&raw_vault, &master_pw, current_time + 3606);
    assert!(res4.is_ok());

    let _ = fs::remove_file(temp_lock);
}
