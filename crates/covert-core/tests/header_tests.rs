//! Unit tests for binary header parsing, validation, and pre-allocation bounds checking.

use covert_core::header::{
    Argon2Params, HeaderError, VaultHeader, CIPHER_ALGO_XCHACHA20_POLY1305, DEFAULT_M_COST,
    DEFAULT_P_COST, DEFAULT_T_COST, FORMAT_VERSION, HEADER_SIZE, KDF_ALGO_ARGON2ID, MAGIC,
    MAX_CIPHERTEXT_LEN, MAX_M_COST, MAX_P_COST, MAX_T_COST, MIN_M_COST, MIN_T_COST,
};

#[test]
fn test_header_exact_88_bytes_layout() {
    let salt = [0xAAu8; 32];
    let nonce = [0xBBu8; 24];
    let ciphertext_len = 1024u64;
    let params = Argon2Params::default();

    let header = VaultHeader::new(salt, nonce, ciphertext_len, params);
    let bytes = header.to_bytes();

    assert_eq!(bytes.len(), HEADER_SIZE);
    assert_eq!(&bytes[0..8], &MAGIC);
    assert_eq!(u16::from_le_bytes(bytes[8..10].try_into().unwrap()), FORMAT_VERSION);
    assert_eq!(bytes[10], KDF_ALGO_ARGON2ID);
    assert_eq!(bytes[11], CIPHER_ALGO_XCHACHA20_POLY1305);
    assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), DEFAULT_M_COST);
    assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), DEFAULT_T_COST);
    assert_eq!(u32::from_le_bytes(bytes[20..24].try_into().unwrap()), DEFAULT_P_COST);
    assert_eq!(&bytes[24..56], &salt);
    assert_eq!(&bytes[56..80], &nonce);
    assert_eq!(u64::from_le_bytes(bytes[80..88].try_into().unwrap()), ciphertext_len);

    let parsed = VaultHeader::from_bytes(&bytes).expect("valid header parses cleanly");
    assert_eq!(parsed, header);
}

#[test]
fn test_truncated_header_safely_rejected_all_lengths() {
    let valid_header = VaultHeader::new([0u8; 32], [0u8; 24], 100, Argon2Params::default());
    let bytes = valid_header.to_bytes();

    // Test every length from 0 to 87
    for len in 0..HEADER_SIZE {
        let truncated_slice = &bytes[0..len];
        let result = VaultHeader::from_bytes(truncated_slice);
        assert_eq!(
            result,
            Err(HeaderError::TruncatedHeader { actual: len }),
            "length {} must safely return TruncatedHeader without panic",
            len
        );
    }
}

#[test]
fn test_invalid_magic_rejected() {
    let mut bytes = VaultHeader::new([0u8; 32], [0u8; 24], 100, Argon2Params::default()).to_bytes();
    bytes[0] = b'X';
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::InvalidMagic));
}

#[test]
fn test_unsupported_version_rejected() {
    let mut bytes = VaultHeader::new([0u8; 32], [0u8; 24], 100, Argon2Params::default()).to_bytes();
    bytes[8] = 2; // format_version = 2
    bytes[9] = 0;
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::UnsupportedVersion(2)));
}

#[test]
fn test_unsupported_kdf_algo_rejected() {
    let mut bytes = VaultHeader::new([0u8; 32], [0u8; 24], 100, Argon2Params::default()).to_bytes();
    bytes[10] = 0x02; // e.g. Scrypt
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::UnsupportedKdfAlgo(0x02)));
}

#[test]
fn test_unsupported_cipher_algo_rejected() {
    let mut bytes = VaultHeader::new([0u8; 32], [0u8; 24], 100, Argon2Params::default()).to_bytes();
    bytes[11] = 0x02; // e.g. AES-256-GCM
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::UnsupportedCipherAlgo(0x02)));
}

#[test]
fn test_m_cost_bounds_rejected_before_allocation() {
    // Underflow: MIN_M_COST - 1 (65535)
    let mut bytes = VaultHeader::new([0u8; 32], [0u8; 24], 100, Argon2Params::default()).to_bytes();
    let under = MIN_M_COST - 1;
    bytes[12..16].copy_from_slice(&under.to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::MCostOutOfRange(under)));

    // Zero
    bytes[12..16].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::MCostOutOfRange(0)));

    // Overflow: MAX_M_COST + 1 (1048577)
    let over = MAX_M_COST + 1;
    bytes[12..16].copy_from_slice(&over.to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::MCostOutOfRange(over)));

    // Huge value (DoS attempt: 4,000,000,000)
    let dos_val = 4_000_000_000u32;
    bytes[12..16].copy_from_slice(&dos_val.to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::MCostOutOfRange(dos_val)));
}

#[test]
fn test_t_cost_bounds_rejected_before_allocation() {
    let mut bytes = VaultHeader::new([0u8; 32], [0u8; 24], 100, Argon2Params::default()).to_bytes();

    // Underflow: 0 and 1
    bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::TCostOutOfRange(0)));

    bytes[16..20].copy_from_slice(&(MIN_T_COST - 1).to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::TCostOutOfRange(MIN_T_COST - 1)));

    // Overflow: 16 and 1000
    bytes[16..20].copy_from_slice(&(MAX_T_COST + 1).to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::TCostOutOfRange(MAX_T_COST + 1)));

    bytes[16..20].copy_from_slice(&1000u32.to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::TCostOutOfRange(1000)));
}

#[test]
fn test_p_cost_bounds_rejected_before_allocation() {
    let mut bytes = VaultHeader::new([0u8; 32], [0u8; 24], 100, Argon2Params::default()).to_bytes();

    // Underflow: 0
    bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::PCostOutOfRange(0)));

    // Overflow: 17 and 1000
    bytes[20..24].copy_from_slice(&(MAX_P_COST + 1).to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::PCostOutOfRange(MAX_P_COST + 1)));

    bytes[20..24].copy_from_slice(&1000u32.to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::PCostOutOfRange(1000)));
}

#[test]
fn test_ciphertext_too_large_rejected() {
    let mut bytes = VaultHeader::new([0u8; 32], [0u8; 24], 100, Argon2Params::default()).to_bytes();
    let too_large = MAX_CIPHERTEXT_LEN + 1;
    bytes[80..88].copy_from_slice(&too_large.to_le_bytes());
    assert_eq!(VaultHeader::from_bytes(&bytes), Err(HeaderError::CiphertextTooLarge(too_large)));
}

#[test]
fn test_validate_buffer_length_mismatch() {
    let header = VaultHeader::new([0u8; 32], [0u8; 24], 50, Argon2Params::default());
    let mut buf = Vec::new();
    buf.extend_from_slice(&header.to_bytes());
    // Required length: 88 + 50 + 16 = 154
    buf.resize(150, 0); // Only 150 bytes (4 bytes short)

    assert_eq!(
        VaultHeader::validate_buffer(&buf),
        Err(HeaderError::PayloadLengthMismatch {
            expected: 154,
            actual: 150,
        })
    );
}
