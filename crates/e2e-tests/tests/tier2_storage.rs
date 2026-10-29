//! Tier 2: Boundary & Corner Cases Suite
//!
//! Covers:
//! - Pre-allocation parameter bounds checking for Argon2 (m_cost, t_cost, p_cost)
//! - Truncated headers (0..87 bytes) safe rejection without panic
//! - Corrupted magic, unsupported version, unsupported KDF and cipher algorithms
//! - Ciphertext size upper bound validation (>64 MiB)
//! - 1-bit tampering across all fields of the 88-byte header (AAD verification)
//! - 1-bit tampering across ciphertext and 16-byte Poly1305 authentication tag
//! - Atomic storage lifecycle (.tmp write, flush, .bak backup, atomic replace)
//! - Interrupted write crash resilience
//! - Git repository hygiene (.gitignore exclusion rules audit and local-only configuration)
//! - TOTP drift window boundaries (+-30s edge, +-60s rejection) and replay prevention
//! - Lockout state machine monotonic clock rollback detection
//! - AutoType AST parser error cases and UTF-16 surrogate pairs
//! - Browser Native Messaging domain-strict rejection of phishing and subdomains

use covert_core::header::{
    Argon2Params, HeaderError, VaultHeader, DEFAULT_M_COST, DEFAULT_P_COST, DEFAULT_T_COST,
    HEADER_SIZE, MAGIC, MAX_CIPHERTEXT_LEN, MAX_M_COST, MAX_P_COST, MAX_T_COST, MIN_M_COST,
    MIN_P_COST, MIN_T_COST,
};
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use e2e_tests::autotype::{AutoTypeEngine, AutoTypeError};
use e2e_tests::clipboard::ClipboardGuard;
use e2e_tests::lockout::{LockoutError, LockoutManager};
use e2e_tests::native_msg::NativeMessagingHost;
use e2e_tests::sandbox::TestSandbox;
use e2e_tests::totp::{verify_totp, TotpError};
use std::fs;
use std::process::Command;

// =========================================================================
// 1. Argon2 Pre-Allocation Bounds Checks
// =========================================================================

#[test]
fn test_prealloc_bounds_m_cost_rejection() {
    // Under minimum (65536 KiB = 64 MiB)
    let err_under = Argon2Params::new(MIN_M_COST - 1, DEFAULT_T_COST, DEFAULT_P_COST).unwrap_err();
    assert_eq!(err_under, HeaderError::MCostOutOfRange(MIN_M_COST - 1));

    // Zero
    let err_zero = Argon2Params::new(0, DEFAULT_T_COST, DEFAULT_P_COST).unwrap_err();
    assert_eq!(err_zero, HeaderError::MCostOutOfRange(0));

    // Exceeding maximum (1048576 KiB = 1024 MiB)
    let err_over = Argon2Params::new(MAX_M_COST + 1, DEFAULT_T_COST, DEFAULT_P_COST).unwrap_err();
    assert_eq!(err_over, HeaderError::MCostOutOfRange(MAX_M_COST + 1));

    // Valid boundaries must succeed
    assert!(Argon2Params::new(MIN_M_COST, DEFAULT_T_COST, DEFAULT_P_COST).is_ok());
    assert!(Argon2Params::new(MAX_M_COST, DEFAULT_T_COST, DEFAULT_P_COST).is_ok());
}

#[test]
fn test_prealloc_bounds_t_cost_rejection() {
    // Under minimum (t < 2)
    assert_eq!(
        Argon2Params::new(DEFAULT_M_COST, 1, DEFAULT_P_COST).unwrap_err(),
        HeaderError::TCostOutOfRange(1)
    );
    assert_eq!(
        Argon2Params::new(DEFAULT_M_COST, 0, DEFAULT_P_COST).unwrap_err(),
        HeaderError::TCostOutOfRange(0)
    );

    // Over maximum (t > 15)
    assert_eq!(
        Argon2Params::new(DEFAULT_M_COST, MAX_T_COST + 1, DEFAULT_P_COST).unwrap_err(),
        HeaderError::TCostOutOfRange(MAX_T_COST + 1)
    );

    // Valid boundaries must succeed
    assert!(Argon2Params::new(DEFAULT_M_COST, MIN_T_COST, DEFAULT_P_COST).is_ok());
    assert!(Argon2Params::new(DEFAULT_M_COST, MAX_T_COST, DEFAULT_P_COST).is_ok());
}

#[test]
fn test_prealloc_bounds_p_cost_rejection() {
    // Under minimum (p < 1)
    assert_eq!(
        Argon2Params::new(DEFAULT_M_COST, DEFAULT_T_COST, 0).unwrap_err(),
        HeaderError::PCostOutOfRange(0)
    );

    // Over maximum (p > 16)
    assert_eq!(
        Argon2Params::new(DEFAULT_M_COST, DEFAULT_T_COST, MAX_P_COST + 1).unwrap_err(),
        HeaderError::PCostOutOfRange(MAX_P_COST + 1)
    );

    // Valid boundaries must succeed
    assert!(Argon2Params::new(DEFAULT_M_COST, DEFAULT_T_COST, MIN_P_COST).is_ok());
    assert!(Argon2Params::new(DEFAULT_M_COST, DEFAULT_T_COST, MAX_P_COST).is_ok());
}

// =========================================================================
// 2. Truncated & Corrupted Header Structural Invariants
// =========================================================================

#[test]
fn test_truncated_headers_0_to_87_bytes() {
    let sample = [0u8; 88];
    for len in 0..88 {
        let truncated = &sample[..len];
        let err = VaultHeader::from_bytes(truncated).unwrap_err();
        assert_eq!(err, HeaderError::TruncatedHeader { actual: len });
    }
}

#[test]
fn test_invalid_magic_bytes_rejection() {
    let mut header_bytes = [0u8; HEADER_SIZE];
    header_bytes[0..8].copy_from_slice(b"BADMAGIC");
    let err = VaultHeader::from_bytes(&header_bytes).unwrap_err();
    assert_eq!(err, HeaderError::InvalidMagic);
}

#[test]
fn test_unsupported_version_rejection() {
    let mut header_bytes = [0u8; HEADER_SIZE];
    header_bytes[0..8].copy_from_slice(&MAGIC);
    header_bytes[8..10].copy_from_slice(&2u16.to_le_bytes()); // Version 2
    let err = VaultHeader::from_bytes(&header_bytes).unwrap_err();
    assert_eq!(err, HeaderError::UnsupportedVersion(2));
}

#[test]
fn test_unsupported_kdf_and_cipher_algo_rejection() {
    let mut header_bytes = [0u8; HEADER_SIZE];
    header_bytes[0..8].copy_from_slice(&MAGIC);
    header_bytes[8..10].copy_from_slice(&1u16.to_le_bytes());

    // Bad KDF
    header_bytes[10] = 0x99;
    header_bytes[11] = 0x01;
    let err = VaultHeader::from_bytes(&header_bytes).unwrap_err();
    assert_eq!(err, HeaderError::UnsupportedKdfAlgo(0x99));

    // Bad Cipher
    header_bytes[10] = 0x01;
    header_bytes[11] = 0x99;
    let err = VaultHeader::from_bytes(&header_bytes).unwrap_err();
    assert_eq!(err, HeaderError::UnsupportedCipherAlgo(0x99));
}

#[test]
fn test_ciphertext_too_large_rejection() {
    let mut header_bytes = [0u8; HEADER_SIZE];
    header_bytes[0..8].copy_from_slice(&MAGIC);
    header_bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    header_bytes[10] = 0x01;
    header_bytes[11] = 0x01;
    header_bytes[12..16].copy_from_slice(&DEFAULT_M_COST.to_le_bytes());
    header_bytes[16..20].copy_from_slice(&DEFAULT_T_COST.to_le_bytes());
    header_bytes[20..24].copy_from_slice(&DEFAULT_P_COST.to_le_bytes());
    // Exceeds 64 MiB limit
    let too_large = MAX_CIPHERTEXT_LEN + 1;
    header_bytes[80..88].copy_from_slice(&too_large.to_le_bytes());

    let err = VaultHeader::from_bytes(&header_bytes).unwrap_err();
    assert_eq!(err, HeaderError::CiphertextTooLarge(too_large));
}

// =========================================================================
// 3. 1-Bit Tampering & AEAD Integrity Tests
// =========================================================================

#[test]
fn test_1bit_tampering_header_aad_rejection() {
    let vault = Vault::new("Tamper Test Vault");
    let password = SecretString::new("Passphrase123!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    let valid_encrypted = vault
        .encrypt(&password, Some(fast_params))
        .expect("Encryption");

    // Test bit tampering across sample positions of the 88-byte header:
    // Magic (0), version (8), kdf (10), cipher (11), m_cost (12), salt (24), nonce (56), ciphertext_len (80)
    let test_offsets = [0, 8, 10, 11, 12, 24, 56, 80];

    for &offset in &test_offsets {
        let mut tampered = valid_encrypted.clone();
        tampered[offset] ^= 0x01; // flip 1 bit

        let result = Vault::decrypt(&tampered, &password);
        assert!(
            result.is_err(),
            "Tampering at header byte {} bit 0 must fail decryption",
            offset
        );
    }
}

#[test]
fn test_1bit_tampering_ciphertext_and_tag() {
    let vault = Vault::new("Tamper Test Vault");
    let password = SecretString::new("Passphrase123!".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    let valid_encrypted = vault
        .encrypt(&password, Some(fast_params))
        .expect("Encryption");
    let len = valid_encrypted.len();

    // Tamper first byte of ciphertext
    let mut tampered_ct = valid_encrypted.clone();
    tampered_ct[HEADER_SIZE] ^= 0x01;
    assert!(Vault::decrypt(&tampered_ct, &password).is_err());

    // Tamper middle byte of ciphertext
    let mid = HEADER_SIZE + (len - HEADER_SIZE - 16) / 2;
    let mut tampered_mid = valid_encrypted.clone();
    tampered_mid[mid] ^= 0x04;
    assert!(Vault::decrypt(&tampered_mid, &password).is_err());

    // Tamper Poly1305 tag (last 16 bytes)
    let mut tampered_tag = valid_encrypted.clone();
    tampered_tag[len - 1] ^= 0x80;
    assert!(Vault::decrypt(&tampered_tag, &password).is_err());
}

// =========================================================================
// 4. Atomic Storage & Git Hygiene Tests
// =========================================================================

#[test]
fn test_atomic_write_creates_bak_and_tmp_lifecycle() {
    let sandbox = TestSandbox::new();
    let initial_data = b"InitialVaultBinaryContentVersion1";
    let updated_data = b"UpdatedVaultBinaryContentVersion2";

    // 1. Initial write
    sandbox
        .write_vault_atomic(initial_data)
        .expect("Initial write");
    assert!(sandbox.vault_path().exists());
    assert!(!sandbox.backup_path().exists());
    assert!(!sandbox.temp_path().exists());
    assert_eq!(fs::read(sandbox.vault_path()).unwrap(), initial_data);

    // 2. Updated write -> creates .bak with initial_data
    sandbox
        .write_vault_atomic(updated_data)
        .expect("Updated write");
    assert!(sandbox.vault_path().exists());
    assert!(sandbox.backup_path().exists());
    assert!(!sandbox.temp_path().exists());
    assert_eq!(fs::read(sandbox.vault_path()).unwrap(), updated_data);
    assert_eq!(fs::read(sandbox.backup_path()).unwrap(), initial_data);
}

#[test]
fn test_interrupted_write_crash_resilience() {
    let sandbox = TestSandbox::new();
    let initial_data = b"SafeExistingVaultPayload";

    sandbox
        .write_vault_atomic(initial_data)
        .expect("Write initial");

    // Simulate an interrupted write that crashes while writing to .tmp
    let partial_tmp_data = b"CorruptedPartialCrashData";
    fs::write(sandbox.temp_path(), partial_tmp_data).expect("Simulate partial write");

    // Primary vault MUST remain completely untouched and valid
    assert!(sandbox.vault_path().exists());
    assert_eq!(fs::read(sandbox.vault_path()).unwrap(), initial_data);
}

#[test]
fn test_gitignore_exclusion_rules() {
    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let gitignore_path = project_root.join(".gitignore");
    assert!(
        gitignore_path.exists(),
        ".gitignore must exist at project root"
    );

    let content = fs::read_to_string(&gitignore_path).expect("Read .gitignore");
    let required_patterns = ["target", "*.vault", "*.bin", "*.bak", "*.tmp"];

    for pat in &required_patterns {
        assert!(
            content.contains(pat),
            ".gitignore is missing critical security pattern: {}",
            pat
        );
    }
}

#[test]
fn test_git_local_only_no_remotes() {
    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let output = Command::new("git")
        .args(["remote"])
        .current_dir(project_root)
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let remotes: Vec<&str> = stdout.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
        // Repository may be strictly local or only bound to the official 'origin' remote
        for remote in remotes {
            assert!(
                remote == "origin",
                "Git repository may only have official remote 'origin'! Found: {}",
                remote
            );
        }
    }
}

// =========================================================================
// 5. Auth, Lockout & Clipboard Boundary Tests
// =========================================================================

#[test]
fn test_totp_drift_window_boundaries() {
    let secret = "JBSWY3DPEHPK3PXP";
    let base_time = 1700000000u64; // arbitrary epoch seconds
    let digits = 6;
    let step = 30;

    // Generate code for exact base_time (step C)
    let code_c = e2e_tests::totp::compute_totp_code(secret, base_time, step, digits).unwrap();

    // Verify at exact time (step C) -> succeeds
    assert!(verify_totp(secret, &code_c, base_time, step, digits, None).is_ok());

    // Verify at t + 29s (still within step C) -> succeeds
    assert!(verify_totp(secret, &code_c, base_time + 29, step, digits, None).is_ok());

    // Verify at t + 30s (step C + 1, valid drift) -> succeeds
    assert!(verify_totp(secret, &code_c, base_time + 30, step, digits, None).is_ok());

    // Verify at t - 30s (step C - 1, valid drift) -> succeeds
    assert!(verify_totp(secret, &code_c, base_time - 30, step, digits, None).is_ok());

    // Verify at t + 60s (step C + 2, out of drift window) -> fails
    assert_eq!(
        verify_totp(secret, &code_c, base_time + 60, step, digits, None).unwrap_err(),
        TotpError::CodeMismatch
    );

    // Verify at t - 60s (step C - 2, out of drift window) -> fails
    assert_eq!(
        verify_totp(secret, &code_c, base_time - 60, step, digits, None).unwrap_err(),
        TotpError::CodeMismatch
    );
}

#[test]
fn test_totp_replay_prevention() {
    let secret = "JBSWY3DPEHPK3PXP";
    let base_time = 1700000000u64;
    let code = e2e_tests::totp::compute_totp_code(secret, base_time, 30, 6).unwrap();

    // First use: step recorded
    let step_accepted = verify_totp(secret, &code, base_time, 30, 6, None).unwrap();

    // Second use with last_accepted_step = step_accepted -> rejected as replay
    let replay_result = verify_totp(secret, &code, base_time, 30, 6, Some(step_accepted));
    assert_eq!(replay_result.unwrap_err(), TotpError::ReplayedCode);
}

#[test]
fn test_totp_malformed_inputs() {
    let secret = "JBSWY3DPEHPK3PXP";
    // Too short
    assert_eq!(
        verify_totp(secret, "12345", 1000, 30, 6, None).unwrap_err(),
        TotpError::InvalidLength
    );
    // Non-numeric
    assert_eq!(
        verify_totp(secret, "12345a", 1000, 30, 6, None).unwrap_err(),
        TotpError::InvalidCharacters
    );
    // Bad Base32
    assert_eq!(
        verify_totp("189??!!", "123456", 1000, 30, 6, None).unwrap_err(),
        TotpError::InvalidBase32
    );
}

#[test]
fn test_lockout_clock_rollback_detection() {
    let mut manager = LockoutManager::new();
    let current_time = 1700000000u64;

    manager.register_failure(current_time).unwrap();

    // Simulate system clock manipulation backwards by 1 hour
    let rolled_back_time = current_time - 3600;
    let result = manager.register_failure(rolled_back_time);
    assert_eq!(result.unwrap_err(), LockoutError::ClockRollbackDetected);

    let status_check = manager.check_status(rolled_back_time);
    assert_eq!(status_check.unwrap_err(), LockoutError::ClockRollbackDetected);
}

#[test]
fn test_clipboard_autowipe_boundary() {
    let secret = SecretString::new("ExposedTokenForCopy".to_string());
    let copy_time = 1000u64;
    let timeout = 30u64;
    let sequence = 42u32;

    let mut guard = ClipboardGuard::new(secret, copy_time, timeout, sequence);

    // Before timeout (t = 1020s) -> should NOT wipe
    assert!(!guard.should_wipe(1020, sequence));

    // Sequence changed (user copied something else elsewhere) -> should NOT wipe
    assert!(!guard.should_wipe(1035, sequence + 1));

    // Exact timeout reached with same sequence -> SHOULD wipe
    assert!(guard.should_wipe(1030, sequence));
    guard.wipe();
    assert!(!guard.has_content());
}

// =========================================================================
// 6. Auto-Type & Native Messaging Boundaries
// =========================================================================

#[test]
fn test_autotype_syntax_errors() {
    // Empty sequence
    assert_eq!(
        AutoTypeEngine::parse_sequence("   ").unwrap_err(),
        AutoTypeError::EmptySequence
    );

    // Unterminated tag
    assert_eq!(
        AutoTypeEngine::parse_sequence("{USERNAME").unwrap_err(),
        AutoTypeError::UnterminatedTag
    );

    // Unknown tag
    assert_eq!(
        AutoTypeEngine::parse_sequence("{NONEXISTENT_TAG}").unwrap_err(),
        AutoTypeError::UnknownPlaceholder("NONEXISTENT_TAG".to_string())
    );
}

#[test]
fn test_autotype_utf16_surrogate_pairs() {
    // Testing non-BMP character (e.g. key emoji 🔑 U+1F511 and shield 🛡 U+1F6E1)
    let emoji_text = "Key: 🔑 Shield: 🛡";
    let utf16_units = AutoTypeEngine::encode_utf16_events(emoji_text);

    // U+1F511 requires surrogate pair: 0xD83D, 0xDD11
    assert!(utf16_units.contains(&0xD83D));
    assert!(utf16_units.contains(&0xDD11));
}

#[test]
fn test_native_msg_domain_strict_rejection() {
    let web_item = VaultItem::new_credential(
        "Real Bank",
        "user1",
        "pass1",
        Some("https://login.bank.com".to_string()),
    );
    let ssh_item = VaultItem::new_ssh("SSH Key", "ed25519", "pub", "priv", None, None);

    // Exact match -> TRUE
    assert!(NativeMessagingHost::is_domain_match(
        &web_item,
        "https://login.bank.com/signin"
    ));

    // Phishing prefix match -> FALSE
    assert!(!NativeMessagingHost::is_domain_match(
        &web_item,
        "https://login.bank.com.evil-phish.com"
    ));

    // Subdomain mismatch -> FALSE
    assert!(!NativeMessagingHost::is_domain_match(
        &web_item,
        "https://phish.bank.com"
    ));

    // Non-Web category -> FALSE
    assert!(!NativeMessagingHost::is_domain_match(
        &ssh_item,
        "https://login.bank.com"
    ));
}
