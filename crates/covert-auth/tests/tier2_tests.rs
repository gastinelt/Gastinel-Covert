use covert_auth::error::AuthError;
use covert_auth::tier2::{
    hash_tier2_password, validate_tier2_candidate, verify_tier2_password, Tier2Session,
};
use covert_core::models::Vault;
use covert_core::SecretString;

#[test]
fn test_tier2_hash_and_verify() {
    let mut vault = Vault::new("Test Vault");
    let view_pw = SecretString::new("MyLongMasterViewSecret2026!".to_string());

    // Hash password and store in vault
    let hash = hash_tier2_password(&view_pw).expect("Hashing failed");
    assert!(hash.starts_with("$argon2id$"));
    vault.security.master_view_password_hash = Some(hash);

    // Verify correct password
    assert!(verify_tier2_password(&vault, &view_pw).is_ok());

    // Verify wrong password fails
    let wrong_pw = SecretString::new("WrongPassword123!".to_string());
    assert!(matches!(
        verify_tier2_password(&vault, &wrong_pw),
        Err(AuthError::InvalidTier2Password)
    ));
}

#[test]
fn test_tier2_unconfigured_error() {
    let vault = Vault::new("Empty Vault");
    let pw = SecretString::new("AnyPassword123!".to_string());

    // master_view_password_hash is None
    assert!(matches!(
        verify_tier2_password(&vault, &pw),
        Err(AuthError::Tier2NotConfigured)
    ));
}

#[test]
fn test_tier2_must_not_equal_master_password() {
    let master_pw = SecretString::new("SharedSecretPassphrase123!".to_string());
    let same_view_pw = SecretString::new("SharedSecretPassphrase123!".to_string());
    let different_view_pw = SecretString::new("UniqueViewPassphrase456!".to_string());

    // Candidate identical to Master Password must be rejected
    let res_same = validate_tier2_candidate(&same_view_pw, Some(&master_pw));
    assert!(matches!(res_same, Err(AuthError::InvalidTier2Password)));

    // Distinct candidate is accepted
    let res_diff = validate_tier2_candidate(&different_view_pw, Some(&master_pw));
    assert!(res_diff.is_ok());

    // Empty password rejected
    let empty_pw = SecretString::new("   ".to_string());
    assert!(matches!(
        validate_tier2_candidate(&empty_pw, None),
        Err(AuthError::InvalidTier2Password)
    ));
}

#[test]
fn test_tier2_ephemeral_session_grant() {
    let start_time = 1000u64;
    let ttl = 60u64;
    let session = Tier2Session::grant(start_time, ttl);

    // Active immediately
    assert!(session.is_valid(start_time));
    assert_eq!(session.remaining_seconds(start_time), 60);

    // Active after 30 seconds
    assert!(session.is_valid(start_time + 30));
    assert_eq!(session.remaining_seconds(start_time + 30), 30);

    // Boundary: expired at exactly start_time + 60
    assert!(!session.is_valid(start_time + 60));
    assert_eq!(session.remaining_seconds(start_time + 60), 0);

    // Past expiration
    assert!(!session.is_valid(start_time + 100));

    // Manual revocation
    let mut active_session = Tier2Session::grant(start_time, ttl);
    assert!(active_session.is_valid(start_time + 5));
    active_session.revoke();
    assert!(!active_session.is_valid(start_time + 5));
}
