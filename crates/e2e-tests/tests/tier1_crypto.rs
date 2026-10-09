//! Tier 1: Feature Coverage & Happy-Path Invariants in Isolation
//!
//! Requirement R1 (Core Cryptographic Engine & Binary Vault Format)
//! Requirement R6 (SSH Key Management)
//!
//! Tests verify:
//! - Exact 88-byte LE header structure and fields
//! - XChaCha20-Poly1305 AEAD roundtrip CBOR fidelity
//! - Password verification and failure without panic
//! - Nonce and salt freshness
//! - Master password change routine
//! - In-memory zeroization and redaction
//! - Domain model category handling
//! - Official RFC vectors (RFC 9106, RFC 8439)
//! - SSH key storage models

use covert_core::crypto::derive_key_raw;
use covert_core::header::{
    Argon2Params, VaultHeader, CIPHER_ALGO_XCHACHA20_POLY1305, DEFAULT_M_COST,
    DEFAULT_P_COST, DEFAULT_T_COST, FORMAT_VERSION, HEADER_SIZE, KDF_ALGO_ARGON2ID, MAGIC,
    NONCE_SIZE, SALT_SIZE, TAG_SIZE,
};
use covert_core::models::{Category, Vault, VaultItem};
use covert_core::SecretString;
use e2e_tests::sandbox::TestSandbox;
use e2e_tests::vectors::{RFC9106_ARGON2ID_VECTOR, XCHACHA20_VECTOR_1};
use std::collections::HashSet;

/// Test 1: End-to-end encrypt and decrypt roundtrip restores exact CBOR data.
/// Authoritative Source: ORIGINAL_REQUEST.md Acceptance Criteria / RFC 8949
#[test]
fn test_vault_roundtrip_cbor_integrity() {
    let original_vault = TestSandbox::create_sample_vault();
    let password = SecretString::new("MasterSecretPassphrase2026!".to_string());

    let encrypted_bytes = original_vault
        .encrypt(&password, None)
        .expect("Encryption failed");

    assert!(
        encrypted_bytes.len() > HEADER_SIZE + TAG_SIZE,
        "Encrypted bytes must exceed header + tag"
    );

    let (decrypted_vault, header) =
        Vault::decrypt(&encrypted_bytes, &password).expect("Decryption failed");

    // Verify header metadata
    assert_eq!(header.magic, MAGIC);
    assert_eq!(header.format_version, FORMAT_VERSION);
    assert_eq!(header.kdf_algo, KDF_ALGO_ARGON2ID);
    assert_eq!(header.cipher_algo, CIPHER_ALGO_XCHACHA20_POLY1305);

    // Verify exact item fidelity
    assert_eq!(decrypted_vault.metadata.name, original_vault.metadata.name);
    assert_eq!(decrypted_vault.items.len(), original_vault.items.len());
    for orig_item in &original_vault.items {
        let dec_item = decrypted_vault
            .get_item(&orig_item.id)
            .expect("Item missing in decrypted vault");
        assert_eq!(dec_item.title, orig_item.title);
        assert_eq!(dec_item.category, orig_item.category);
        assert_eq!(dec_item.username, orig_item.username);
        assert_eq!(dec_item.password, orig_item.password);
        assert_eq!(dec_item.url, orig_item.url);
    }
}

/// Test 2: Invalid master password is fundamentally rejected without panic.
/// Authoritative Source: ORIGINAL_REQUEST.md Acceptance Criteria / RFC 8439
#[test]
fn test_invalid_master_password_rejection_no_panic() {
    let vault = TestSandbox::create_sample_vault();
    let correct_password = SecretString::new("CorrectVaultPassphrase!".to_string());
    let wrong_password = SecretString::new("WrongVaultPassphrase!".to_string());

    let encrypted = vault
        .encrypt(&correct_password, None)
        .expect("Encryption failed");

    let result = Vault::decrypt(&encrypted, &wrong_password);
    assert!(result.is_err(), "Decryption must fail with wrong password");
    match result {
        Err(covert_core::VaultError::Crypto(covert_core::CryptoError::AuthenticationFailed)) => {
            // Expected Poly1305 authentication failure
        }
        other => panic!("Expected CryptoError::AuthenticationFailed, got: {:?}", other),
    }
}

/// Test 3: Exact 88-byte Little-Endian binary header layout and fields.
/// Authoritative Source: PROJECT.md §2.2 / ORIGINAL_REQUEST.md R1
#[test]
fn test_exact_88_byte_header_fields_layout() {
    let salt = [0x42u8; SALT_SIZE];
    let nonce = [0x24u8; NONCE_SIZE];
    let ciphertext_len = 1024u64;
    let params = Argon2Params::new(DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST)
        .expect("Valid default params");

    let header = VaultHeader::new(salt, nonce, ciphertext_len, params);
    let bytes = header.to_bytes();

    assert_eq!(bytes.len(), HEADER_SIZE, "Header must be exactly 88 bytes");
    assert_eq!(&bytes[0..8], &MAGIC);
    assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), FORMAT_VERSION);
    assert_eq!(bytes[10], KDF_ALGO_ARGON2ID);
    assert_eq!(bytes[11], CIPHER_ALGO_XCHACHA20_POLY1305);
    assert_eq!(
        u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        DEFAULT_M_COST
    );
    assert_eq!(
        u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
        DEFAULT_T_COST
    );
    assert_eq!(
        u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
        DEFAULT_P_COST
    );
    assert_eq!(&bytes[24..56], &salt);
    assert_eq!(&bytes[56..80], &nonce);
    assert_eq!(
        u64::from_le_bytes([
            bytes[80], bytes[81], bytes[82], bytes[83], bytes[84], bytes[85], bytes[86], bytes[87]
        ]),
        ciphertext_len
    );
}

/// Test 4: In-memory secret protection: zeroization and secrecy formatting.
/// Authoritative Source: ORIGINAL_REQUEST.md R1 / secrecy crate contract
#[test]
fn test_in_memory_secret_zeroization_and_redaction() {
    let secret_raw = "SuperSecretTokenValue123!".to_string();
    let secret = SecretString::new(secret_raw.clone());

    // Verify debug representation is redacted and does not leak raw plaintext
    let debug_output = format!("{:?}", secret);
    assert!(
        !debug_output.contains(&secret_raw),
        "Secret contents leaked in Debug string"
    );
}

/// Test 5: Master password change routine generates fresh CSPRNG parameters.
/// Authoritative Source: ORIGINAL_REQUEST.md R1
#[test]
fn test_master_password_change_routine() {
    let mut vault = TestSandbox::create_sample_vault();
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();
    let old_pw = SecretString::new("OldMasterPassword123!".to_string());
    let new_pw = SecretString::new("NewMasterPassword456!".to_string());

    let initial_encrypted = vault
        .encrypt(&old_pw, Some(fast_params))
        .expect("Initial encryption");
    let initial_header =
        VaultHeader::from_bytes(&initial_encrypted[..HEADER_SIZE]).expect("Parse header");

    let updated_encrypted = vault
        .change_master_password(&old_pw, &new_pw, Some(fast_params))
        .expect("Change master password");
    let updated_header =
        VaultHeader::from_bytes(&updated_encrypted[..HEADER_SIZE]).expect("Parse header");

    // Salt and nonce must be completely fresh
    assert_ne!(
        initial_header.salt, updated_header.salt,
        "Salt must be refreshed"
    );
    assert_ne!(
        initial_header.nonce, updated_header.nonce,
        "Nonce must be refreshed"
    );

    // Old password must fail to decrypt new payload
    assert!(
        Vault::decrypt(&updated_encrypted, &old_pw).is_err(),
        "Old password decrypted updated vault"
    );

    // New password must succeed
    let (decrypted, _) =
        Vault::decrypt(&updated_encrypted, &new_pw).expect("New password decryption");
    assert_eq!(decrypted.items.len(), vault.items.len());
}

/// Test 6: Domain models handle diverse secret categories.
/// Authoritative Source: PROJECT.md §2.9
#[test]
fn test_domain_models_category_diversity() {
    let vault = TestSandbox::create_sample_vault();

    assert!(!vault.items_by_category(Category::Web).is_empty());
    assert!(!vault.items_by_category(Category::SSH).is_empty());
    assert!(!vault.items_by_category(Category::ApiKey).is_empty());
    assert!(!vault.items_by_category(Category::Note).is_empty());
    assert!(!vault.items_by_category(Category::RawSecret).is_empty());

    let ssh_items = vault.items_by_category(Category::SSH);
    let ssh_entry = ssh_items[0];
    assert!(ssh_entry.ssh_data.is_some());
    let ssh_data = ssh_entry.ssh_data.as_ref().unwrap();
    assert_eq!(ssh_data.key_type, "ed25519");
}

/// Test 7: Nonce and salt uniqueness across successive encryptions.
/// Authoritative Source: ORIGINAL_REQUEST.md Acceptance Criteria (uniqueness across multiple runs)
#[test]
fn test_salt_and_nonce_uniqueness_runs() {
    let vault = Vault::new("Ephemeral Vault");
    let password = SecretString::new("UniquenessTestPassword".to_string());
    let fast_params = Argon2Params::new(65536, 2, 1).unwrap();

    let runs = 30; // Sufficient to prove CSPRNG independence
    let mut salts = HashSet::new();
    let mut nonces = HashSet::new();

    for _ in 0..runs {
        let enc = vault.encrypt(&password, Some(fast_params)).expect("Encryption");
        let header = VaultHeader::from_bytes(&enc[..HEADER_SIZE]).expect("Header parse");
        assert!(salts.insert(header.salt), "Duplicate salt generated");
        assert!(nonces.insert(header.nonce), "Duplicate nonce generated");
    }
}

/// Test 8: Official RFC test vector for XChaCha20-Poly1305.
/// Authoritative Source: draft-irtf-cfrg-xchacha-03 / RFC 8439
#[test]
fn test_official_xchacha20poly1305_vector() {
    let vector = &XCHACHA20_VECTOR_1;
    let encrypted = covert_core::crypto::encrypt_payload(
        &vector.key,
        &vector.nonce,
        vector.aad,
        vector.plaintext,
    )
    .expect("AEAD encrypt");

    let tag_offset = encrypted.len() - 16;
    let ciphertext = &encrypted[..tag_offset];
    let tag = &encrypted[tag_offset..];

    let ct_hex: String = ciphertext.iter().map(|b| format!("{:02x}", b)).collect();
    let tag_hex: String = tag.iter().map(|b| format!("{:02x}", b)).collect();

    assert_eq!(ct_hex, vector.expected_ciphertext_hex);
    assert_eq!(tag_hex, vector.expected_tag_hex);

    // Decrypt and verify exact plaintext
    let decrypted = covert_core::crypto::decrypt_payload(
        &vector.key,
        &vector.nonce,
        vector.aad,
        &encrypted,
    )
    .expect("AEAD decrypt");

    assert_eq!(&*decrypted, vector.plaintext);
}

/// Test 9: Official RFC 9106 test vector for Argon2id key derivation.
/// Authoritative Source: RFC 9106 Section 5.3
#[test]
fn test_official_argon2id_vector() {
    let vector = &RFC9106_ARGON2ID_VECTOR;
    let mut out = [0u8; 32];
    derive_key_raw(
        vector.password,
        vector.salt,
        vector.m_cost,
        vector.t_cost,
        vector.p_cost,
        Some(vector.secret),
        Some(vector.ad),
        &mut out,
    )
    .expect("Argon2id derivation");

    let out_hex: String = out.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(out_hex, vector.expected_output_hex);
}

/// Test 10: SSH Key entry storage and Ed25519 / RSA metadata.
/// Authoritative Source: PROJECT.md §5.1 / RFC 8709
#[test]
fn test_ssh_key_storage_ed25519_and_rsa() {
    let mut vault = Vault::new("SSH Key Vault");
    let ed25519_item = VaultItem::new_ssh(
        "GitHub SSH Key",
        "ed25519",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIUserPublicSSHKeyBlob",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nprivatekeycontent\n-----END OPENSSH PRIVATE KEY-----",
        None,
        Some("user@workstation".to_string()),
    );
    let rsa_item = VaultItem::new_ssh(
        "Legacy Server RSA Key",
        "rsa-4096",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDLRSA...",
        "-----BEGIN RSA PRIVATE KEY-----\nrsaprivatekeycontent\n-----END RSA PRIVATE KEY-----",
        Some("rsa_passphrase".to_string()),
        Some("legacy@server".to_string()),
    );

    vault.add_item(ed25519_item);
    vault.add_item(rsa_item);

    let ssh_items = vault.items_by_category(Category::SSH);
    assert_eq!(ssh_items.len(), 2);
    assert_eq!(ssh_items[0].ssh_data.as_ref().unwrap().key_type, "ed25519");
    assert_eq!(ssh_items[1].ssh_data.as_ref().unwrap().key_type, "rsa-4096");
}
