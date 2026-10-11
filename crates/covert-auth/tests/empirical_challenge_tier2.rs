//! Empirical Challenge Test Suite for Tier-2 Master View Password Protection (`covert-auth`).
//!
//! Rigorously verifies:
//! 1. Plain-text secrets cannot be viewed or copied without providing the secondary long view password.
//! 2. Unconfigured Tier-2 protection blocks all plain-text access and clipboard exports.
//! 3. Invalid, truncated, near-miss, and empty passwords are fundamentally rejected.
//! 4. Tier-2 password must strictly be distinct from Master Password.
//! 5. Ephemeral session grant expiration and revocation boundaries.
//! 6. Clipboard sequence retention and auto-wipe integrity without touching external user clipboard.

use covert_auth::{
    clear_clipboard_if_sequence_matches, get_clipboard_sequence_number, hash_tier2_password,
    validate_tier2_candidate, verify_tier2_password, AuthError, AuthManager, ClipboardGuard,
    Tier2Session, CF_CAN_INCLUDE_IN_CLIPBOARD_HISTORY, CF_CAN_UPLOAD_TO_CLOUD_CLIPBOARD,
    CF_EXCLUDE_CLIPBOARD_MONITOR,
};
use covert_core::models::Vault;
use covert_core::SecretString;

#[test]
fn test_challenge_plain_text_secrets_blocked_when_unconfigured() {
    let vault = Vault::new("UnconfiguredTier2Vault");
    assert!(vault.security.master_view_password_hash.is_none());

    let candidate = SecretString::new("AnyRandomAttemptPassword123!".to_string());

    // 1. Direct verify_tier2_password must fail with Tier2NotConfigured
    let err = verify_tier2_password(&vault, &candidate);
    assert!(
        matches!(err, Err(AuthError::Tier2NotConfigured)),
        "Expected Err(Tier2NotConfigured), got {:?}",
        err
    );

    // 2. AuthManager::verify_tier2_password must fail with Tier2NotConfigured
    let mut auth_mgr = AuthManager::new();
    let err2 = auth_mgr.verify_tier2_password(&vault, &candidate);
    assert!(
        matches!(err2, Err(AuthError::Tier2NotConfigured)),
        "Expected Err(Tier2NotConfigured), got {:?}",
        err2
    );

    // 3. Attempting to copy to clipboard must be fundamentally blocked
    let secret = SecretString::new("SensitiveApiKeySecretToProtect".to_string());
    let initial_seq = get_clipboard_sequence_number();

    let copy_err = auth_mgr.copy_to_clipboard(&vault, &candidate, &secret, 30);
    assert!(
        matches!(copy_err, Err(AuthError::Tier2NotConfigured)),
        "Expected Err(Tier2NotConfigured), got {:?}",
        copy_err
    );

    // Verify clipboard was never touched
    let post_seq = get_clipboard_sequence_number();
    assert_eq!(
        initial_seq, post_seq,
        "Clipboard sequence must not change when Tier 2 copy is blocked"
    );
    assert!(auth_mgr.active_clipboard().is_none());
}

#[test]
fn test_challenge_plain_text_secrets_blocked_with_invalid_passwords() {
    let mut vault = Vault::new("ConfiguredTier2Vault");
    let valid_pw = SecretString::new("CorrectLongSecondaryViewPassword#2026!".to_string());
    let hash = hash_tier2_password(&valid_pw).expect("hash_tier2_password must succeed");
    vault.security.master_view_password_hash = Some(hash);

    let initial_seq = get_clipboard_sequence_number();
    let secret = SecretString::new("SuperSecretTokenThatMustRemainHidden".to_string());
    let mut auth_mgr = AuthManager::new();

    let invalid_attempts = [
        ("WrongPasswordEntirely!", "Wrong password"),
        ("", "Empty password"),
        ("   ", "Whitespace-only password"),
        ("CorrectLongSecondaryViewPassword#2026", "Truncated by one char"),
        ("CorrectLongSecondaryViewPassword#2026?", "Near-miss single char changed"),
        ("correctlongsecondaryviewpassword#2026!", "Lowercase variant"),
        ("CorrectLongSecondaryViewPassword#2026! ", "Trailing space"),
        (" CorrectLongSecondaryViewPassword#2026!", "Leading space"),
    ];

    for (candidate_str, desc) in invalid_attempts {
        let candidate = SecretString::new(candidate_str.to_string());

        // 1. Direct verification fails
        let err = verify_tier2_password(&vault, &candidate);
        assert!(
            matches!(err, Err(AuthError::InvalidTier2Password)),
            "{} must be rejected with InvalidTier2Password, got {:?}",
            desc,
            err
        );

        // 2. Clipboard copy fails
        let copy_err = auth_mgr.copy_to_clipboard(&vault, &candidate, &secret, 30);
        assert!(
            matches!(copy_err, Err(AuthError::InvalidTier2Password)),
            "Clipboard copy with {} must be rejected, got {:?}",
            desc,
            copy_err
        );

        // 3. Clipboard sequence is strictly unchanged
        let cur_seq = get_clipboard_sequence_number();
        assert_eq!(
            initial_seq, cur_seq,
            "Clipboard sequence altered during rejected attempt: {}",
            desc
        );
        assert!(auth_mgr.active_clipboard().is_none());
    }

    // Now verify the correct password succeeds
    let copy_ok = auth_mgr.copy_to_clipboard(&vault, &valid_pw, &secret, 30);
    assert!(copy_ok.is_ok(), "Correct Tier-2 password must authorize clipboard copy");
    assert!(auth_mgr.active_clipboard().is_some());
}

#[test]
fn test_challenge_tier2_distinctness_from_master_password() {
    let master_pw = SecretString::new("MasterPassphraseForVaultLogin123!".to_string());

    // Identical password must be rejected
    let identical_tier2 = SecretString::new("MasterPassphraseForVaultLogin123!".to_string());
    let res = validate_tier2_candidate(&identical_tier2, Some(&master_pw));
    assert!(
        matches!(res, Err(AuthError::InvalidTier2Password)),
        "Tier-2 password identical to Master Password must be rejected"
    );

    // Distinct password must be accepted
    let distinct_tier2 = SecretString::new("SecondaryViewPassphraseDifferent456!".to_string());
    let res2 = validate_tier2_candidate(&distinct_tier2, Some(&master_pw));
    assert!(res2.is_ok(), "Distinct Tier-2 password must be accepted");
}

#[test]
fn test_challenge_ephemeral_session_boundaries_and_revocation() {
    let now = 1_700_000_000u64;
    let ttl = 60u64;

    let session = Tier2Session::grant(now, ttl);

    // Initial grant: valid, 60s remaining
    assert!(session.is_valid(now));
    assert_eq!(session.remaining_seconds(now), 60);

    // Boundary at t + 30s: valid, 30s remaining
    assert!(session.is_valid(now + 30));
    assert_eq!(session.remaining_seconds(now + 30), 30);

    // Boundary at t + 59s: valid, 1s remaining
    assert!(session.is_valid(now + 59));
    assert_eq!(session.remaining_seconds(now + 59), 1);

    // Exact expiration at t + 60s: EXPIRED
    assert!(!session.is_valid(now + 60));
    assert_eq!(session.remaining_seconds(now + 60), 0);

    // Post-expiration at t + 61s: EXPIRED
    assert!(!session.is_valid(now + 61));
    assert_eq!(session.remaining_seconds(now + 61), 0);

    // Revocation: an active session revoked immediately becomes invalid
    let mut session2 = Tier2Session::grant(now, ttl);
    assert!(session2.is_valid(now + 10));
    session2.revoke();
    assert!(!session2.is_valid(now + 10));
    assert_eq!(session2.remaining_seconds(now + 10), 0);
}

#[test]
fn test_challenge_clipboard_preserves_external_user_content() {
    let secret = SecretString::new("SecretPayloadToWipe".to_string());
    let copied_at = 1000u64;
    let timeout = 30u64;
    let sequence = 42u32;

    let guard = ClipboardGuard::new(secret, copied_at, timeout, sequence);

    // 1. Should not wipe before timeout
    assert!(!guard.should_wipe(copied_at + 15, sequence));

    // 2. Should wipe after timeout IF sequence matches
    assert!(guard.should_wipe(copied_at + 30, sequence));

    // 3. Should NEVER wipe if user copied something else (sequence changed)
    let user_external_seq = 43u32;
    assert!(
        !guard.should_wipe(copied_at + 35, user_external_seq),
        "Auto-wipe must NOT trigger when sequence has changed, preserving external clipboard content"
    );

    // 4. clear_clipboard_if_sequence_matches refuses to clear if sequence differs
    let wiped = clear_clipboard_if_sequence_matches(99999).unwrap();
    assert!(!wiped, "clear_clipboard_if_sequence_matches must return false when sequence does not match");
}

#[test]
fn test_challenge_tampered_tier2_argon2_hash_fails_safely() {
    let mut vault = Vault::new("CorruptedHashVault");
    vault.security.master_view_password_hash = Some("NotAValidArgon2PHCHashString".to_string());

    let candidate = SecretString::new("AttemptPassword123!".to_string());
    let res = verify_tier2_password(&vault, &candidate);
    assert!(
        matches!(res, Err(AuthError::InvalidTier2Password)),
        "Corrupted Argon2 hash string must be rejected safely without panic, got {:?}",
        res
    );
}

#[test]
fn test_challenge_clipboard_privacy_flag_names() {
    assert_eq!(
        CF_CAN_INCLUDE_IN_CLIPBOARD_HISTORY,
        "CanIncludeInClipboardHistory"
    );
    assert_eq!(
        CF_CAN_UPLOAD_TO_CLOUD_CLIPBOARD,
        "CanUploadToCloudClipboard"
    );
    assert_eq!(
        CF_EXCLUDE_CLIPBOARD_MONITOR,
        "ExcludeClipboardContentFromMonitorProcessing"
    );
}
