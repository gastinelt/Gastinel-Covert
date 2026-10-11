//! Integration tests for Vault encryption, decryption, tampering resilience, and domain models.

use covert_core::crypto::{generate_nonce, generate_salt};
use covert_core::error::{CryptoError, HeaderError, VaultError};
use covert_core::header::{Argon2Params, MIN_M_COST, MIN_P_COST, MIN_T_COST};
use covert_core::models::{Category, Vault, VaultItem};
use secrecy::SecretString;
use std::collections::HashSet;

fn fast_test_params() -> Argon2Params {
    // Smallest valid parameters strictly within the safety bounds to keep unit tests fast
    Argon2Params::new(MIN_M_COST, MIN_T_COST, MIN_P_COST)
        .expect("MIN bounds are valid")
}

fn create_sample_vault() -> Vault {
    let mut vault = Vault::new("Personal Confidential Vault");

    // Configure Security
    vault.security.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
    vault.security.totp_digits = 6;
    vault.security.totp_period = 30;
    vault.security.totp_algorithm = "SHA1".to_string();
    vault.security.recovery_codes = vec![
        "RC-1011-2022".to_string(),
        "RC-3033-4044".to_string(),
        "RC-5055-6066".to_string(),
    ];

    // Add Credential (Web)
    let cred = VaultItem::new_credential(
        "GitHub Primary Account",
        "octocat",
        "ghp_SecretTokenPassphrase9988!",
        Some("https://github.com/login".to_string()),
    );
    vault.add_item(cred);

    // Add SSH Key
    let ssh = VaultItem::new_ssh(
        "Production Server Bastion",
        "ed25519",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@gastinel",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE...\n-----END OPENSSH PRIVATE KEY-----",
        Some("ssh-key-passphrase-77".to_string()),
        Some("admin@bastion.internal".to_string()),
    );
    vault.add_item(ssh);

    // Add API Key
    let api = VaultItem::new_api_key(
        "Stripe Live Secret Key",
        "Stripe",
        "PLACEHOLDER_FAKE_API_KEY_FOR_TESTS_0001",
        Some(1893456000), // 2030-01-01
    );
    vault.add_item(api);

    // Add Note
    let note = VaultItem::new_note(
        "Emergency Disaster Recovery Instructions",
        "Step 1: Contact security lead.\nStep 2: Revoke primary credentials.",
    );
    vault.add_item(note);

    // Add Raw Secret
    let raw = VaultItem::new_raw_secret(
        "Cryptographic Seed Bytes",
        vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
    );
    vault.add_item(raw);

    vault
}

#[test]
fn test_roundtrip_cbor_encrypt_decrypt() {
    let original_vault = create_sample_vault();
    let master_password = SecretString::new("SuperStrongMasterPassword_2026!".to_string());

    let encrypted = original_vault
        .encrypt(&master_password, Some(fast_test_params()))
        .expect("vault encryption succeeds");

    assert!(encrypted.len() > 88 + 16, "encrypted payload contains header, ciphertext, and tag");

    let (decrypted_vault, header) =
        Vault::decrypt(&encrypted, &master_password).expect("vault decryption succeeds");

    // Verify header properties
    assert_eq!(&header.magic, b"GCOVERT1");
    assert_eq!(header.format_version, 1);
    assert_eq!(header.argon2_m_cost, MIN_M_COST);

    // Verify restored vault fidelity
    assert_eq!(decrypted_vault.metadata.name, original_vault.metadata.name);
    assert_eq!(decrypted_vault.metadata.vault_id, original_vault.metadata.vault_id);
    assert_eq!(decrypted_vault.security, original_vault.security);
    assert_eq!(decrypted_vault.items.len(), original_vault.items.len());

    // Verify each category item
    let web_items = decrypted_vault.items_by_category(Category::Web);
    assert_eq!(web_items.len(), 1);
    assert_eq!(web_items[0].username, Some("octocat".to_string()));
    assert_eq!(web_items[0].password, Some("ghp_SecretTokenPassphrase9988!".to_string()));

    let ssh_items = decrypted_vault.items_by_category(Category::SSH);
    assert_eq!(ssh_items.len(), 1);
    let ssh_data = ssh_items[0].ssh_data.as_ref().unwrap();
    assert_eq!(ssh_data.key_type, "ed25519");
    assert!(ssh_data.private_key.contains("BEGIN OPENSSH PRIVATE KEY"));

    let api_items = decrypted_vault.items_by_category(Category::ApiKey);
    assert_eq!(api_items.len(), 1);
    assert_eq!(api_items[0].api_key_data.as_ref().unwrap().service, "Stripe");

    let note_items = decrypted_vault.items_by_category(Category::Note);
    assert_eq!(note_items.len(), 1);
    assert_eq!(note_items[0].title, "Emergency Disaster Recovery Instructions");
    assert!(note_items[0].notes.as_ref().unwrap().contains("Contact security lead"));

    let raw_items = decrypted_vault.items_by_category(Category::RawSecret);
    assert_eq!(raw_items.len(), 1);
    assert_eq!(
        raw_items[0].raw_data,
        Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
    );
}

#[test]
fn test_invalid_master_password_rejected_safely() {
    let vault = create_sample_vault();
    let correct_pw = SecretString::new("RightPassword_1234!".to_string());
    let wrong_pw = SecretString::new("IncorrectPassword_9999?".to_string());

    let encrypted = vault
        .encrypt(&correct_pw, Some(fast_test_params()))
        .expect("encryption succeeds");

    let result = Vault::decrypt(&encrypted, &wrong_pw);
    match result {
        Err(VaultError::Crypto(CryptoError::AuthenticationFailed)) => {
            // Expected safe failure
        }
        other => panic!("Expected CryptoError::AuthenticationFailed, got: {:?}", other),
    }
}

#[test]
fn test_1bit_tampering_header_full_matrix() {
    let vault = create_sample_vault();
    let password = SecretString::new("TamperTestPassword_1!".to_string());
    let encrypted = vault
        .encrypt(&password, Some(fast_test_params()))
        .expect("encryption succeeds");

    // 1. Verify that 1-bit tampering in EVERY SINGLE ONE of the 88 header bytes causes failure
    let mut tested_bytes = 0;
    for byte_idx in 0..88 {
        let mut tampered = encrypted.clone();
        tampered[byte_idx] ^= 0x01; // flip bit 0

        let result = Vault::decrypt(&tampered, &password);
        assert!(
            result.is_err(),
            "1-bit header tampering at byte {} must be rejected, but succeeded!",
            byte_idx
        );
        tested_bytes += 1;
    }
    assert_eq!(tested_bytes, 88, "All 88 header bytes tested with 1-bit tampering");

    // 2. Full 8-bit exhaustive matrix for header structural fields (magic, version, algorithms, bounds, length)
    for byte_idx in (0..24).chain(80..88) {
        for bit_idx in 0..8 {
            let mut tampered = encrypted.clone();
            tampered[byte_idx] ^= 1 << bit_idx;

            let result = Vault::decrypt(&tampered, &password);
            assert!(
                result.is_err(),
                "Exhaustive header tampering at byte {}, bit {} must be rejected!",
                byte_idx,
                bit_idx
            );
        }
    }
}



#[test]
fn test_1bit_tampering_ciphertext_and_tag() {
    let vault = create_sample_vault();
    let password = SecretString::new("CiphertextTamperTest_2!".to_string());
    let encrypted = vault
        .encrypt(&password, Some(fast_test_params()))
        .expect("encryption succeeds");

    // Ciphertext segment: bytes 88 .. (len - 16)
    // Tag segment: bytes (len - 16) .. len
    let total_len = encrypted.len();
    let ciphertext_start = 88;
    let tag_start = total_len - 16;

    // Test multiple bit mutations in ciphertext
    for offset in [ciphertext_start, ciphertext_start + 1, tag_start - 1] {
        for bit in 0..8 {
            let mut tampered = encrypted.clone();
            tampered[offset] ^= 1 << bit;

            let result = Vault::decrypt(&tampered, &password);
            match result {
                Err(VaultError::Crypto(CryptoError::AuthenticationFailed)) => (),
                other => panic!(
                    "Expected AuthenticationFailed for ciphertext tamper at {}, bit {}, got: {:?}",
                    offset, bit, other
                ),
            }
        }
    }

    // Test multiple bit mutations in tag
    for offset in [tag_start, tag_start + 7, total_len - 1] {
        for bit in 0..8 {
            let mut tampered = encrypted.clone();
            tampered[offset] ^= 1 << bit;

            let result = Vault::decrypt(&tampered, &password);
            match result {
                Err(VaultError::Crypto(CryptoError::AuthenticationFailed)) => (),
                other => panic!(
                    "Expected AuthenticationFailed for tag tamper at {}, bit {}, got: {:?}",
                    offset, bit, other
                ),
            }
        }
    }
}

#[test]
fn test_nonce_and_salt_uniqueness_across_1000_cycles() {
    let mut salts = HashSet::with_capacity(1000);
    let mut nonces = HashSet::with_capacity(1000);

    for _ in 0..1000 {
        let salt = generate_salt();
        let nonce = generate_nonce();

        assert!(salts.insert(salt), "Duplicate salt generated by OsRng!");
        assert!(nonces.insert(nonce), "Duplicate nonce generated by OsRng!");
    }

    assert_eq!(salts.len(), 1000);
    assert_eq!(nonces.len(), 1000);
}

#[test]
fn test_master_password_change_routine() {
    let vault = create_sample_vault();
    let old_pw = SecretString::new("OldInitialPassword_2026!".to_string());
    let new_pw = SecretString::new("NewStrongerPassword_2027#".to_string());
    let wrong_pw = SecretString::new("CompletelyWrongOldPassword!".to_string());

    let encrypted = vault
        .encrypt(&old_pw, Some(fast_test_params()))
        .expect("initial encryption succeeds");

    // Attempting password change with wrong old password must fail
    let bad_change = Vault::change_master_password_from_bytes(
        &encrypted,
        &wrong_pw,
        &new_pw,
        Some(fast_test_params()),
    );
    assert!(
        matches!(bad_change, Err(VaultError::Crypto(CryptoError::AuthenticationFailed))),
        "Password change with wrong old password must fail"
    );

    // Legitimate password change
    let re_encrypted = Vault::change_master_password_from_bytes(
        &encrypted,
        &old_pw,
        &new_pw,
        Some(fast_test_params()),
    ).expect("password change succeeds");

    // Old password must now fail
    let decrypt_old = Vault::decrypt(&re_encrypted, &old_pw);
    assert!(
        matches!(decrypt_old, Err(VaultError::Crypto(CryptoError::AuthenticationFailed))),
        "Decrypting re-encrypted vault with old password must fail"
    );

    // New password must succeed and restore exact data
    let (restored, _header) =
        Vault::decrypt(&re_encrypted, &new_pw).expect("decrypting with new password succeeds");
    assert_eq!(restored.items.len(), vault.items.len());
    assert_eq!(restored.metadata.name, vault.metadata.name);
}

#[test]
fn test_hardcoded_bounds_check_rejects_before_allocation() {
    // Rejects m_cost < 64 MiB
    let low_m_res = Argon2Params::new(65_535, 4, 4);
    assert_eq!(low_m_res, Err(HeaderError::MCostOutOfRange(65_535)));

    // Rejects m_cost > 1024 MiB
    let high_m_res = Argon2Params::new(1_048_577, 4, 4);
    assert_eq!(high_m_res, Err(HeaderError::MCostOutOfRange(1_048_577)));

    // Injected in header: Vault::decrypt rejects before Argon2 execution
    let vault = create_sample_vault();
    let password = SecretString::new("BoundsPassword_123".to_string());
    let mut encrypted = vault
        .encrypt(&password, Some(fast_test_params()))
        .expect("encryption succeeds");

    // Tamper m_cost to 1024 (below 65536)
    encrypted[12..16].copy_from_slice(&1024u32.to_le_bytes());
    let decrypt_res = Vault::decrypt(&encrypted, &password);
    assert_eq!(
        decrypt_res.unwrap_err().to_string(),
        VaultError::Header(HeaderError::MCostOutOfRange(1024)).to_string()
    );
}
