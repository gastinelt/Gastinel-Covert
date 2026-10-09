//! Adversarial and Boundary Stress Test Suite for Milestone 1 (`covert-core`).
//!
//! Evaluates:
//! 1. Truncated vault files (0, 1, 10, 87, 88, 103 bytes, and all intermediate lengths)
//! 2. Mutated header fields (magic, version, kdf_algo, cipher_algo, ciphertext_len)
//! 3. Out-of-bounds KDF parameters (m_cost = 0, 65535, 1048577, 4GB; t_cost = 0, 1, 16; p_cost = 0, 17)
//! 4. 1-bit bitflips in header (704 bits), ciphertext, and Poly1305 tag (128 bits)
//! 5. Ciphertext length spoofing and integer overflow resistance
//! 6. Corrupted CBOR payload handling post-AEAD
//! 7. Extreme and Unicode password handling
//! 8. Primitive edge cases (empty or short buffers to decrypt_payload)

use covert_core::crypto::{decrypt_payload, encrypt_payload};
use covert_core::error::{CryptoError, HeaderError, VaultError};
use covert_core::header::{
    Argon2Params, VaultHeader, DEFAULT_M_COST, DEFAULT_P_COST, DEFAULT_T_COST, HEADER_SIZE,
    MAX_CIPHERTEXT_LEN, MAX_M_COST, MAX_P_COST, MAX_T_COST, MIN_M_COST, MIN_P_COST, MIN_T_COST,
    TAG_SIZE,
};
use covert_core::models::{Vault, VaultItem};
use secrecy::SecretString;

fn fast_test_params() -> Argon2Params {
    Argon2Params::new(MIN_M_COST, MIN_T_COST, MIN_P_COST).expect("Valid test params")
}

fn create_test_vault() -> Vault {
    let mut vault = Vault::new("Adversarial Test Vault");
    vault.security.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
    vault.security.recovery_codes = vec!["RC-1111-2222".to_string(), "RC-3333-4444".to_string()];

    let cred = VaultItem::new_credential(
        "Admin Portal",
        "admin@covert.internal",
        "P@ssw0rd_Empirical_2026!",
        Some("https://admin.covert.internal".to_string()),
    );
    vault.add_item(cred);

    let note = VaultItem::new_note("Adversarial Notes", "Testing boundary conditions");
    vault.add_item(note);

    vault
}

// ============================================================================
// Scenario 1: Truncated Vault Files (0, 1, 10, 87, 88, 103 bytes)
// ============================================================================
#[test]
fn test_adversarial_truncation_specific_and_all_bytes() {
    let vault = create_test_vault();
    let password = SecretString::new("TruncationTestPassword123!".to_string());
    let encrypted = vault
        .encrypt(&password, Some(fast_test_params()))
        .expect("encryption succeeds");

    assert!(
        encrypted.len() >= 104,
        "Valid encrypted vault must be at least 88 + 0 + 16 = 104 bytes"
    );

    // Explicit targets requested in dispatch: 0, 1, 10, 87, 88, 103
    let specific_targets = [0, 1, 10, 87, 88, 103];

    for &len in &specific_targets {
        let truncated = &encrypted[..len];

        // 1. Test VaultHeader::from_bytes
        if len < HEADER_SIZE {
            let res = VaultHeader::from_bytes(truncated);
            assert_eq!(
                res,
                Err(HeaderError::TruncatedHeader { actual: len }),
                "VaultHeader::from_bytes at len {} must return TruncatedHeader",
                len
            );
        }

        // 2. Test VaultHeader::validate_buffer
        let val_res = VaultHeader::validate_buffer(truncated);
        assert!(
            val_res.is_err(),
            "VaultHeader::validate_buffer at len {} must fail",
            len
        );
        if len < HEADER_SIZE {
            assert_eq!(
                val_res,
                Err(HeaderError::TruncatedHeader { actual: len }),
                "validate_buffer at len {} must return TruncatedHeader",
                len
            );
        } else {
            // len is 88 or 103: header parses, but buffer length is less than expected (88 + ciphertext_len + 16)
            match val_res {
                Err(HeaderError::PayloadLengthMismatch { expected, actual }) => {
                    assert_eq!(actual, len);
                    assert_eq!(expected, encrypted.len());
                }
                other => panic!(
                    "Expected PayloadLengthMismatch for len {}, got: {:?}",
                    len, other
                ),
            }
        }

        // 3. Test Vault::decrypt
        let dec_res = Vault::decrypt(truncated, &password);
        assert!(
            dec_res.is_err(),
            "Vault::decrypt at len {} must fail",
            len
        );
        if len < HEADER_SIZE {
            match dec_res {
                Err(VaultError::Header(HeaderError::TruncatedHeader { actual })) => {
                    assert_eq!(actual, len);
                }
                other => panic!(
                    "Expected TruncatedHeader for Vault::decrypt at len {}, got: {:?}",
                    len, other
                ),
            }
        } else {
            match dec_res {
                Err(VaultError::Header(HeaderError::PayloadLengthMismatch { expected, actual })) => {
                    assert_eq!(actual, len);
                    assert_eq!(expected, encrypted.len());
                }
                other => panic!(
                    "Expected PayloadLengthMismatch for Vault::decrypt at len {}, got: {:?}",
                    len, other
                ),
            }
        }
    }

    // Exhaustive sweep: Every length from 0 to encrypted.len() - 1 must fail safely
    for len in 0..encrypted.len() {
        let truncated = &encrypted[..len];
        let res = Vault::decrypt(truncated, &password);
        assert!(
            res.is_err(),
            "Vault::decrypt MUST fail on truncated length {} / {}",
            len,
            encrypted.len()
        );
    }
}

// ============================================================================
// Scenario 2: Mutated Magic, Version, Algorithms in Header
// ============================================================================
#[test]
fn test_adversarial_mutated_magic_version_algorithms() {
    let vault = create_test_vault();
    let password = SecretString::new("HeaderMutationPassword!".to_string());
    let encrypted = vault
        .encrypt(&password, Some(fast_test_params()))
        .expect("encryption succeeds");

    // 1. Mutate Magic (bytes 0..8)
    let bad_magics: Vec<[u8; 8]> = vec![
        *b"GCOVERT0",
        *b"GCOVERT2",
        *b"gcovert1",
        *b"BCOVERT1",
        *b"GCOVERT\0",
        [0u8; 8],
        [0xFFu8; 8],
        *b"1TREVCOG",
    ];

    for bad_magic in bad_magics {
        let mut tampered = encrypted.clone();
        tampered[0..8].copy_from_slice(&bad_magic);

        let err = Vault::decrypt(&tampered, &password).unwrap_err();
        match err {
            VaultError::Header(HeaderError::InvalidMagic) => (),
            other => panic!("Expected InvalidMagic, got: {:?}", other),
        }
    }

    // Mutate each single byte in magic
    for byte_idx in 0..8 {
        let mut tampered = encrypted.clone();
        tampered[byte_idx] ^= 0x01;
        let err = Vault::decrypt(&tampered, &password).unwrap_err();
        match err {
            VaultError::Header(HeaderError::InvalidMagic) => (),
            other => panic!("Expected InvalidMagic at byte {}, got: {:?}", byte_idx, other),
        }
    }

    // 2. Mutate Format Version (bytes 8..10)
    let bad_versions: Vec<u16> = vec![0, 2, 3, 10, 255, 65535];
    for bad_ver in bad_versions {
        let mut tampered = encrypted.clone();
        tampered[8..10].copy_from_slice(&bad_ver.to_le_bytes());

        let err = Vault::decrypt(&tampered, &password).unwrap_err();
        match err {
            VaultError::Header(HeaderError::UnsupportedVersion(v)) => assert_eq!(v, bad_ver),
            other => panic!("Expected UnsupportedVersion({}), got: {:?}", bad_ver, other),
        }
    }

    // 3. Mutate KDF Algorithm (byte 10)
    let bad_kdfs: Vec<u8> = vec![0x00, 0x02, 0x03, 0x10, 0xFF];
    for bad_kdf in bad_kdfs {
        let mut tampered = encrypted.clone();
        tampered[10] = bad_kdf;

        let err = Vault::decrypt(&tampered, &password).unwrap_err();
        match err {
            VaultError::Header(HeaderError::UnsupportedKdfAlgo(k)) => assert_eq!(k, bad_kdf),
            other => panic!("Expected UnsupportedKdfAlgo({}), got: {:?}", bad_kdf, other),
        }
    }

    // 4. Mutate Cipher Algorithm (byte 11)
    let bad_ciphers: Vec<u8> = vec![0x00, 0x02, 0x03, 0x10, 0xFF];
    for bad_cipher in bad_ciphers {
        let mut tampered = encrypted.clone();
        tampered[11] = bad_cipher;

        let err = Vault::decrypt(&tampered, &password).unwrap_err();
        match err {
            VaultError::Header(HeaderError::UnsupportedCipherAlgo(c)) => {
                assert_eq!(c, bad_cipher)
            }
            other => panic!(
                "Expected UnsupportedCipherAlgo({}), got: {:?}",
                bad_cipher, other
            ),
        }
    }
}

// ============================================================================
// Scenario 3: Out-of-Bounds KDF Parameters
// m_cost = 0, 65535, 1048577, 4GB; t_cost = 0, 1, 16; p_cost = 0, 17
// ============================================================================
#[test]
fn test_adversarial_out_of_bounds_parameters() {
    let vault = create_test_vault();
    let password = SecretString::new("ParamBoundsPassword!".to_string());
    let encrypted = vault
        .encrypt(&password, Some(fast_test_params()))
        .expect("encryption succeeds");

    // Test m_cost bounds
    let m_cost_tests: Vec<(u32, &str)> = vec![
        (0, "m_cost = 0 (zero)"),
        (1, "m_cost = 1"),
        (65_535, "m_cost = 65535 (MIN_M_COST - 1)"),
        (1_048_577, "m_cost = 1048577 (MAX_M_COST + 1)"),
        (2_000_000, "m_cost = 2000000"),
        (4_000_000_000, "m_cost = 4,000,000,000 (~4GB DoS attempt)"),
        (u32::MAX, "m_cost = 4,294,967,295 (u32::MAX / 4GB)"),
    ];

    for (m_val, desc) in m_cost_tests {
        // Constructor bounds check
        assert_eq!(
            Argon2Params::new(m_val, 4, 4),
            Err(HeaderError::MCostOutOfRange(m_val)),
            "Argon2Params::new must reject {}",
            desc
        );

        // Header parsing bounds check
        let mut tampered = encrypted.clone();
        tampered[12..16].copy_from_slice(&m_val.to_le_bytes());
        let err = Vault::decrypt(&tampered, &password).unwrap_err();
        match err {
            VaultError::Header(HeaderError::MCostOutOfRange(v)) => assert_eq!(v, m_val),
            other => panic!("Expected MCostOutOfRange for {}, got: {:?}", desc, other),
        }
    }

    // Test t_cost bounds
    let t_cost_tests: Vec<(u32, &str)> = vec![
        (0, "t_cost = 0"),
        (1, "t_cost = 1 (MIN_T_COST - 1)"),
        (16, "t_cost = 16 (MAX_T_COST + 1)"),
        (100, "t_cost = 100"),
        (u32::MAX, "t_cost = u32::MAX"),
    ];

    for (t_val, desc) in t_cost_tests {
        assert_eq!(
            Argon2Params::new(MIN_M_COST, t_val, 4),
            Err(HeaderError::TCostOutOfRange(t_val)),
            "Argon2Params::new must reject {}",
            desc
        );

        let mut tampered = encrypted.clone();
        tampered[16..20].copy_from_slice(&t_val.to_le_bytes());
        let err = Vault::decrypt(&tampered, &password).unwrap_err();
        match err {
            VaultError::Header(HeaderError::TCostOutOfRange(v)) => assert_eq!(v, t_val),
            other => panic!("Expected TCostOutOfRange for {}, got: {:?}", desc, other),
        }
    }

    // Test p_cost bounds
    let p_cost_tests: Vec<(u32, &str)> = vec![
        (0, "p_cost = 0"),
        (17, "p_cost = 17 (MAX_P_COST + 1)"),
        (100, "p_cost = 100"),
        (u32::MAX, "p_cost = u32::MAX"),
    ];

    for (p_val, desc) in p_cost_tests {
        assert_eq!(
            Argon2Params::new(MIN_M_COST, 4, p_val),
            Err(HeaderError::PCostOutOfRange(p_val)),
            "Argon2Params::new must reject {}",
            desc
        );

        let mut tampered = encrypted.clone();
        tampered[20..24].copy_from_slice(&p_val.to_le_bytes());
        let err = Vault::decrypt(&tampered, &password).unwrap_err();
        match err {
            VaultError::Header(HeaderError::PCostOutOfRange(v)) => assert_eq!(v, p_val),
            other => panic!("Expected PCostOutOfRange for {}, got: {:?}", desc, other),
        }
    }

    // Verify valid boundary extremes pass
    assert!(Argon2Params::new(MIN_M_COST, MIN_T_COST, MIN_P_COST).is_ok());
    assert!(Argon2Params::new(MAX_M_COST, MAX_T_COST, MAX_P_COST).is_ok());
    assert!(Argon2Params::new(DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST).is_ok());
}

// ============================================================================
// Scenario 4: 1-Bit Bitflips in Header (704 bits), Ciphertext, and Poly1305 Tag (128 bits)
// ============================================================================
#[test]
fn test_adversarial_1bit_bitflips_header_ciphertext_tag() {
    let vault = create_test_vault();
    let password = SecretString::new("BitflipTestMasterPassword_2026!".to_string());
    let encrypted = vault
        .encrypt(&password, Some(fast_test_params()))
        .expect("encryption succeeds");

    let total_len = encrypted.len();
    assert!(total_len >= HEADER_SIZE + TAG_SIZE);

    // 1. Bitflips across entire 88-byte Header:
    // Testing 88 bytes * 8 bits = 704 individual 1-bit mutations
    for byte_idx in 0..HEADER_SIZE {
        for bit_idx in 0..8 {
            let mut tampered = encrypted.clone();
            tampered[byte_idx] ^= 1 << bit_idx;

            let result = Vault::decrypt(&tampered, &password);
            assert!(
                result.is_err(),
                "Header bitflip at byte {}, bit {} must be rejected, but succeeded!",
                byte_idx,
                bit_idx
            );
        }
    }

    // 2. Bitflips across Ciphertext:
    // Ciphertext resides at bytes [88 .. (total_len - 16)]
    let ciphertext_start = HEADER_SIZE;
    let ciphertext_end = total_len - TAG_SIZE;
    let ct_len = ciphertext_end - ciphertext_start;
    assert!(ct_len > 0);

    // Sample distinct positions across the ciphertext: start, 1/4, 1/2, 3/4, end
    let sample_ct_offsets = [
        ciphertext_start,
        ciphertext_start + ct_len / 4,
        ciphertext_start + ct_len / 2,
        ciphertext_start + (3 * ct_len) / 4,
        ciphertext_end - 1,
    ];

    for &offset in &sample_ct_offsets {
        for bit_idx in 0..8 {
            let mut tampered = encrypted.clone();
            tampered[offset] ^= 1 << bit_idx;

            let result = Vault::decrypt(&tampered, &password);
            match result {
                Err(VaultError::Crypto(CryptoError::AuthenticationFailed)) => (),
                other => panic!(
                    "Expected AuthenticationFailed for ciphertext bitflip at offset {}, bit {}, got: {:?}",
                    offset, bit_idx, other
                ),
            }
        }
    }

    // 3. Bitflips across Poly1305 Tag:
    // Tag resides at bytes [(total_len - 16) .. total_len]
    // Test ALL 16 bytes * 8 bits = 128 individual 1-bit mutations
    for tag_byte_idx in 0..TAG_SIZE {
        let offset = ciphertext_end + tag_byte_idx;
        for bit_idx in 0..8 {
            let mut tampered = encrypted.clone();
            tampered[offset] ^= 1 << bit_idx;

            let result = Vault::decrypt(&tampered, &password);
            match result {
                Err(VaultError::Crypto(CryptoError::AuthenticationFailed)) => (),
                other => panic!(
                    "Expected AuthenticationFailed for Poly1305 tag bitflip at offset {}, bit {}, got: {:?}",
                    offset, bit_idx, other
                ),
            }
        }
    }
}

// ============================================================================
// Scenario 5: Ciphertext Length Spoofing and Integer Overflow Resistance
// ============================================================================
#[test]
fn test_adversarial_ciphertext_length_attacks() {
    let vault = create_test_vault();
    let password = SecretString::new("LengthSpoofPassword!".to_string());
    let encrypted = vault
        .encrypt(&password, Some(fast_test_params()))
        .expect("encryption succeeds");

    // Attack 5A: Spoof ciphertext_len = 0
    let mut tampered_0 = encrypted.clone();
    tampered_0[80..88].copy_from_slice(&0u64.to_le_bytes());
    let res_0 = Vault::decrypt(&tampered_0, &password);
    match res_0 {
        Err(VaultError::Header(HeaderError::PayloadLengthMismatch { expected, actual })) => {
            assert_eq!(expected, HEADER_SIZE + TAG_SIZE);
            assert_eq!(actual, encrypted.len());
        }
        other => panic!("Expected PayloadLengthMismatch for len=0 spoof, got: {:?}", other),
    }

    // Attack 5B: Spoof ciphertext_len > MAX_CIPHERTEXT_LEN
    let too_large_values = [
        MAX_CIPHERTEXT_LEN + 1,
        100 * 1024 * 1024,
        u64::MAX - 100,
        u64::MAX,
    ];
    for &too_large in &too_large_values {
        let mut tampered = encrypted.clone();
        tampered[80..88].copy_from_slice(&too_large.to_le_bytes());
        let res = Vault::decrypt(&tampered, &password);
        match res {
            Err(VaultError::Header(HeaderError::CiphertextTooLarge(v))) => assert_eq!(v, too_large),
            other => panic!(
                "Expected CiphertextTooLarge for {}, got: {:?}",
                too_large, other
            ),
        }
    }

    // Attack 5C: Off-by-one payload length mismatch
    // Claim 1 byte more ciphertext
    let actual_ct_len = u64::from_le_bytes(encrypted[80..88].try_into().unwrap());
    let mut tampered_plus_1 = encrypted.clone();
    tampered_plus_1[80..88].copy_from_slice(&(actual_ct_len + 1).to_le_bytes());
    match Vault::decrypt(&tampered_plus_1, &password) {
        Err(VaultError::Header(HeaderError::PayloadLengthMismatch { .. })) => (),
        other => panic!("Expected PayloadLengthMismatch, got: {:?}", other),
    }

    // Claim 1 byte less ciphertext
    let mut tampered_minus_1 = encrypted.clone();
    tampered_minus_1[80..88].copy_from_slice(&(actual_ct_len - 1).to_le_bytes());
    match Vault::decrypt(&tampered_minus_1, &password) {
        Err(VaultError::Header(HeaderError::PayloadLengthMismatch { .. })) => (),
        other => panic!("Expected PayloadLengthMismatch, got: {:?}", other),
    }
}

// ============================================================================
// Scenario 6: Corrupted CBOR Payload Handling
// ============================================================================
#[test]
fn test_adversarial_corrupted_cbor_payloads() {
    let key = [0x55u8; 32];
    let nonce = [0x66u8; 24];
    let header = VaultHeader::new(
        [0xAAu8; 32],
        nonce,
        0, // placeholder, updated below
        fast_test_params(),
    );

    // 1. Plaintext is empty bytes: CBOR parser must fail with Serialization error, not panic
    let empty_plaintext = b"";
    let mut header_empty = header.clone();
    header_empty.ciphertext_len = empty_plaintext.len() as u64;
    let header_bytes = header_empty.to_bytes();

    let ciphertext_and_tag = encrypt_payload(&key, &nonce, &header_bytes, empty_plaintext)
        .expect("encryption succeeds");

    let mut raw_vault = Vec::new();
    raw_vault.extend_from_slice(&header_bytes);
    raw_vault.extend_from_slice(&ciphertext_and_tag);

    // Directly test decrypt_payload and CBOR parsing
    let decrypted = decrypt_payload(&key, &nonce, &header_bytes, &ciphertext_and_tag)
        .expect("AEAD decrypt succeeds");
    let cbor_result: Result<Vault, _> = ciborium::from_reader(&decrypted[..]);
    assert!(cbor_result.is_err(), "Empty CBOR must fail deserialization");

    // 2. Plaintext is random garbage bytes (invalid CBOR major types)
    let garbage_plaintext = vec![0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x11, 0x22, 0x33];
    let mut header_garbage = header.clone();
    header_garbage.ciphertext_len = garbage_plaintext.len() as u64;
    let header_bytes_g = header_garbage.to_bytes();

    let ct_g = encrypt_payload(&key, &nonce, &header_bytes_g, &garbage_plaintext)
        .expect("encrypt succeeds");
    let decrypted_g =
        decrypt_payload(&key, &nonce, &header_bytes_g, &ct_g).expect("AEAD decrypt succeeds");
    let cbor_g_res: Result<Vault, _> = ciborium::from_reader(&decrypted_g[..]);
    assert!(cbor_g_res.is_err(), "Garbage CBOR must fail deserialization");

    // 3. Plaintext is a truncated CBOR map (major type 5, length 5, but ends abruptly)
    let truncated_cbor_map = vec![0xA5, 0x64, 0x6E, 0x61, 0x6D, 0x65]; // map header + string "name"
    let mut header_trunc = header.clone();
    header_trunc.ciphertext_len = truncated_cbor_map.len() as u64;
    let header_bytes_t = header_trunc.to_bytes();

    let ct_t = encrypt_payload(&key, &nonce, &header_bytes_t, &truncated_cbor_map)
        .expect("encrypt succeeds");
    let decrypted_t =
        decrypt_payload(&key, &nonce, &header_bytes_t, &ct_t).expect("AEAD decrypt succeeds");
    let cbor_t_res: Result<Vault, _> = ciborium::from_reader(&decrypted_t[..]);
    assert!(cbor_t_res.is_err(), "Truncated CBOR map must fail deserialization");
}

// ============================================================================
// Scenario 7: Extreme and Unicode Passwords
// ============================================================================
#[test]
fn test_adversarial_extreme_and_unicode_passwords() {
    let vault = create_test_vault();

    let test_passwords = [
        ("Empty password", SecretString::new("".to_string())),
        (
            "French accented password",
            SecretString::new("MotDePasse_Sécurisé_Élégant_1234!".to_string()),
        ),
        (
            "CJK Unicode characters",
            SecretString::new("密碼_堅固_ガステネル_коверт_2026".to_string()),
        ),
        (
            "Emoji and symbols",
            SecretString::new("🔑🛡️🔐🦀_Super_Secret_Gastinel_!@#$%^&*()".to_string()),
        ),
        (
            "Embedded NUL character",
            SecretString::new("pass\0word\0with\0nulls".to_string()),
        ),
        (
            "Long password (1,000 chars)",
            SecretString::new("A".repeat(1000)),
        ),
    ];

    for (desc, pw) in &test_passwords {
        let enc = vault
            .encrypt(pw, Some(fast_test_params()))
            .unwrap_or_else(|e| panic!("Encryption failed for {}: {:?}", desc, e));

        let (dec, _) = vault_decrypt_checked(&enc, pw)
            .unwrap_or_else(|e| panic!("Decryption failed for {}: {:?}", desc, e));

        assert_eq!(
            dec.items.len(),
            vault.items.len(),
            "Decrypted items match for {}",
            desc
        );
        assert_eq!(
            dec.metadata.name, vault.metadata.name,
            "Decrypted metadata match for {}",
            desc
        );
    }
}

fn vault_decrypt_checked(
    data: &[u8],
    pw: &SecretString,
) -> Result<(Vault, VaultHeader), VaultError> {
    Vault::decrypt(data, pw)
}

// ============================================================================
// Scenario 8: Crypto Primitive Boundary Edge Cases
// ============================================================================
#[test]
fn test_adversarial_crypto_primitive_boundaries() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 24];
    let aad = b"AuthenticatedAssociatedData";

    // 1. decrypt_payload with empty slice (0 bytes) -> must fail safely without panic
    let res_empty = decrypt_payload(&key, &nonce, aad, &[]);
    assert_eq!(
        res_empty,
        Err(CryptoError::AuthenticationFailed),
        "decrypt_payload on empty slice must return AuthenticationFailed"
    );

    // 2. decrypt_payload with slice shorter than 16-byte Poly1305 tag (1..15 bytes)
    for len in 1..16 {
        let short_buf = vec![0xEEu8; len];
        let res_short = decrypt_payload(&key, &nonce, aad, &short_buf);
        assert_eq!(
            res_short,
            Err(CryptoError::AuthenticationFailed),
            "decrypt_payload on length {} must return AuthenticationFailed without panic",
            len
        );
    }

    // 3. encrypt empty plaintext
    let enc_empty = encrypt_payload(&key, &nonce, aad, &[]).expect("Empty plaintext encrypts");
    assert_eq!(
        enc_empty.len(),
        16,
        "Empty plaintext results in exactly 16-byte Poly1305 tag"
    );

    // 4. decrypt empty plaintext
    let dec_empty =
        decrypt_payload(&key, &nonce, aad, &enc_empty).expect("Empty plaintext decrypts");
    assert_eq!(&*dec_empty, b"", "Decrypted empty plaintext is empty");

    // 5. Tampering aad causes authentication failure
    let tampered_aad = b"AuthenticatedAssociatedDatA";
    let res_bad_aad = decrypt_payload(&key, &nonce, tampered_aad, &enc_empty);
    assert_eq!(res_bad_aad, Err(CryptoError::AuthenticationFailed));
}
