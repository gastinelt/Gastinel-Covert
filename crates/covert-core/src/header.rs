//! Binary header layout, parsing, and bounds validation for Gastinel Covert vaults.

pub use crate::error::HeaderError;

/// Exact byte size of the binary vault header.
pub const HEADER_SIZE: usize = 88;

/// Expected magic bytes identifying a Gastinel Covert vault file.
pub const MAGIC: [u8; 8] = *b"GCOVERT1";

/// Current format version.
pub const FORMAT_VERSION: u16 = 1;

/// Identifier for Argon2id key derivation algorithm.
pub const KDF_ALGO_ARGON2ID: u8 = 0x01;

/// Identifier for XChaCha20-Poly1305 AEAD cipher.
pub const CIPHER_ALGO_XCHACHA20_POLY1305: u8 = 0x01;

/// Size of salt in bytes (256 bits).
pub const SALT_SIZE: usize = 32;

/// Size of XChaCha20 nonce in bytes (192 bits).
pub const NONCE_SIZE: usize = 24;

/// Size of Poly1305 authentication tag in bytes (128 bits).
pub const TAG_SIZE: usize = 16;

/// Minimum allowable Argon2 memory cost in KiB (64 MiB).
pub const MIN_M_COST: u32 = 65_536;

/// Maximum allowable Argon2 memory cost in KiB (1024 MiB = 1 GiB).
pub const MAX_M_COST: u32 = 1_048_576;

/// Default Argon2 memory cost in KiB (256 MiB).
pub const DEFAULT_M_COST: u32 = 262_144;

/// Minimum allowable Argon2 time cost (iterations).
pub const MIN_T_COST: u32 = 2;

/// Maximum allowable Argon2 time cost (iterations).
pub const MAX_T_COST: u32 = 15;

/// Default Argon2 time cost (iterations).
pub const DEFAULT_T_COST: u32 = 4;

/// Minimum allowable Argon2 parallelism cost (lanes/threads).
pub const MIN_P_COST: u32 = 1;

/// Maximum allowable Argon2 parallelism cost (lanes/threads).
pub const MAX_P_COST: u32 = 16;

/// Default Argon2 parallelism cost (lanes/threads).
pub const DEFAULT_P_COST: u32 = 4;

/// Maximum allowable ciphertext length (64 MiB) to guard against resource exhaustion.
pub const MAX_CIPHERTEXT_LEN: u64 = 64 * 1024 * 1024;

/// Argon2 parameters with enforced pre-allocation safety bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl Argon2Params {
    /// Create new Argon2 parameters after strictly verifying pre-allocation bounds.
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self, HeaderError> {
        if !(MIN_M_COST..=MAX_M_COST).contains(&m_cost) {
            return Err(HeaderError::MCostOutOfRange(m_cost));
        }
        if !(MIN_T_COST..=MAX_T_COST).contains(&t_cost) {
            return Err(HeaderError::TCostOutOfRange(t_cost));
        }
        if !(MIN_P_COST..=MAX_P_COST).contains(&p_cost) {
            return Err(HeaderError::PCostOutOfRange(p_cost));
        }
        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
        })
    }
}

/// Exact 88-byte Little-Endian binary header for Gastinel Covert vaults.
///
/// Layout:
/// - magic: [u8; 8] = b"GCOVERT1"
/// - format_version: u16 LE = 1
/// - kdf_algo: u8 = 0x01
/// - cipher_algo: u8 = 0x01
/// - argon2_m_cost: u32 LE
/// - argon2_t_cost: u32 LE
/// - argon2_p_cost: u32 LE
/// - salt: [u8; 32]
/// - nonce: [u8; 24]
/// - ciphertext_len: u64 LE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub magic: [u8; 8],
    pub format_version: u16,
    pub kdf_algo: u8,
    pub cipher_algo: u8,
    pub argon2_m_cost: u32,
    pub argon2_t_cost: u32,
    pub argon2_p_cost: u32,
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext_len: u64,
}

/// Type alias for VaultHeader as specified in interface contracts.
pub type Header = VaultHeader;

impl VaultHeader {
    /// Construct a new valid VaultHeader.
    pub fn new(
        salt: [u8; SALT_SIZE],
        nonce: [u8; NONCE_SIZE],
        ciphertext_len: u64,
        params: Argon2Params,
    ) -> Self {
        Self {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            kdf_algo: KDF_ALGO_ARGON2ID,
            cipher_algo: CIPHER_ALGO_XCHACHA20_POLY1305,
            argon2_m_cost: params.m_cost,
            argon2_t_cost: params.t_cost,
            argon2_p_cost: params.p_cost,
            salt,
            nonce,
            ciphertext_len,
        }
    }

    /// Serialize the header into an exact 88-byte Little-Endian array.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..8].copy_from_slice(&self.magic);
        bytes[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        bytes[10] = self.kdf_algo;
        bytes[11] = self.cipher_algo;
        bytes[12..16].copy_from_slice(&self.argon2_m_cost.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.argon2_t_cost.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.argon2_p_cost.to_le_bytes());
        bytes[24..56].copy_from_slice(&self.salt);
        bytes[56..80].copy_from_slice(&self.nonce);
        bytes[80..88].copy_from_slice(&self.ciphertext_len.to_le_bytes());
        bytes
    }

    /// Parse and validate an 88-byte header from a raw byte slice.
    ///
    /// Performs hardcoded parameter bounds checking before any memory allocation.
    pub fn from_bytes(slice: &[u8]) -> Result<Self, HeaderError> {
        if slice.len() < HEADER_SIZE {
            return Err(HeaderError::TruncatedHeader {
                actual: slice.len(),
            });
        }

        let magic: [u8; 8] = slice[0..8]
            .try_into()
            .map_err(|_| HeaderError::TruncatedHeader { actual: slice.len() })?;
        if magic != MAGIC {
            return Err(HeaderError::InvalidMagic);
        }

        let format_version = u16::from_le_bytes(
            slice[8..10]
                .try_into()
                .map_err(|_| HeaderError::TruncatedHeader { actual: slice.len() })?,
        );
        if format_version != FORMAT_VERSION {
            return Err(HeaderError::UnsupportedVersion(format_version));
        }

        let kdf_algo = slice[10];
        if kdf_algo != KDF_ALGO_ARGON2ID {
            return Err(HeaderError::UnsupportedKdfAlgo(kdf_algo));
        }

        let cipher_algo = slice[11];
        if cipher_algo != CIPHER_ALGO_XCHACHA20_POLY1305 {
            return Err(HeaderError::UnsupportedCipherAlgo(cipher_algo));
        }

        let argon2_m_cost = u32::from_le_bytes(
            slice[12..16]
                .try_into()
                .map_err(|_| HeaderError::TruncatedHeader { actual: slice.len() })?,
        );
        if !(MIN_M_COST..=MAX_M_COST).contains(&argon2_m_cost) {
            return Err(HeaderError::MCostOutOfRange(argon2_m_cost));
        }

        let argon2_t_cost = u32::from_le_bytes(
            slice[16..20]
                .try_into()
                .map_err(|_| HeaderError::TruncatedHeader { actual: slice.len() })?,
        );
        if !(MIN_T_COST..=MAX_T_COST).contains(&argon2_t_cost) {
            return Err(HeaderError::TCostOutOfRange(argon2_t_cost));
        }

        let argon2_p_cost = u32::from_le_bytes(
            slice[20..24]
                .try_into()
                .map_err(|_| HeaderError::TruncatedHeader { actual: slice.len() })?,
        );
        if !(MIN_P_COST..=MAX_P_COST).contains(&argon2_p_cost) {
            return Err(HeaderError::PCostOutOfRange(argon2_p_cost));
        }

        let salt: [u8; SALT_SIZE] = slice[24..56]
            .try_into()
            .map_err(|_| HeaderError::TruncatedHeader { actual: slice.len() })?;

        let nonce: [u8; NONCE_SIZE] = slice[56..80]
            .try_into()
            .map_err(|_| HeaderError::TruncatedHeader { actual: slice.len() })?;

        let ciphertext_len = u64::from_le_bytes(
            slice[80..88]
                .try_into()
                .map_err(|_| HeaderError::TruncatedHeader { actual: slice.len() })?,
        );
        if ciphertext_len > MAX_CIPHERTEXT_LEN {
            return Err(HeaderError::CiphertextTooLarge(ciphertext_len));
        }

        Ok(Self {
            magic,
            format_version,
            kdf_algo,
            cipher_algo,
            argon2_m_cost,
            argon2_t_cost,
            argon2_p_cost,
            salt,
            nonce,
            ciphertext_len,
        })
    }

    /// Parse header from buffer and strictly validate that total buffer length
    /// equals HEADER_SIZE (88) + ciphertext_len + TAG_SIZE (16).
    pub fn validate_buffer(buffer: &[u8]) -> Result<Self, HeaderError> {
        let header = Self::from_bytes(buffer)?;
        let expected_total = HEADER_SIZE
            .checked_add(header.ciphertext_len as usize)
            .and_then(|sum| sum.checked_add(TAG_SIZE))
            .ok_or(HeaderError::CiphertextTooLarge(header.ciphertext_len))?;

        if buffer.len() != expected_total {
            return Err(HeaderError::PayloadLengthMismatch {
                expected: expected_total,
                actual: buffer.len(),
            });
        }

        Ok(header)
    }

    /// Extract validated Argon2 parameters from this header.
    pub fn argon2_params(&self) -> Result<Argon2Params, HeaderError> {
        Argon2Params::new(
            self.argon2_m_cost,
            self.argon2_t_cost,
            self.argon2_p_cost,
        )
    }
}
