//! Aegis-compatible RFC 6238 TOTP engine and emergency recovery code manager.
//!
//! Provides:
//! - 6-digit TOTP verification with 30s timestep and HMAC-SHA1 (default) or HMAC-SHA256.
//! - Constant-time comparison using `subtle::ConstantTimeEq` evaluating candidate window
//!   (t-1, t, t+1 for +-30s drift) without early termination timing leaks.
//! - Replay protection tracking `last_used_step` to reject repeated use in the same window.
//! - 10 single-use emergency recovery codes with constant-time verification and consumption.

use crate::error::TotpError;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// Supported TOTP HMAC algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
}

impl std::str::FromStr for TotpAlgorithm {
    type Err = TotpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA256" | "SHA-256" => Ok(Self::Sha256),
            other => Err(TotpError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

impl std::fmt::Display for TotpAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha1 => write!(f, "SHA1"),
            Self::Sha256 => write!(f, "SHA256"),
        }
    }
}

/// RFC 6238 TOTP Engine.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TotpEngine {
    secret: Vec<u8>,
    #[zeroize(skip)]
    digits: u32,
    #[zeroize(skip)]
    step_seconds: u64,
    #[zeroize(skip)]
    algorithm: TotpAlgorithm,
    #[zeroize(skip)]
    last_used_step: Option<u64>,
}

impl TotpEngine {
    /// Create a new `TotpEngine` from raw secret bytes.
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            secret,
            digits: 6,
            step_seconds: 30,
            algorithm: TotpAlgorithm::Sha1,
            last_used_step: None,
        }
    }

    /// Create a new `TotpEngine` from an RFC 4648 Base32 encoded secret.
    pub fn from_base32(base32_secret: &str) -> Result<Self, TotpError> {
        let secret = decode_base32(base32_secret)?;
        Ok(Self::new(secret))
    }

    /// Configure digit length (typically 6 or 8).
    pub fn with_digits(mut self, digits: u32) -> Self {
        self.digits = digits;
        self
    }

    /// Configure timestep in seconds (typically 30).
    pub fn with_step_seconds(mut self, step_seconds: u64) -> Self {
        self.step_seconds = step_seconds;
        self
    }

    /// Configure HMAC algorithm (Sha1 or Sha256).
    pub fn with_algorithm(mut self, algorithm: TotpAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set initial last accepted timestep (e.g. restored from vault).
    pub fn with_last_used_step(mut self, last_step: Option<u64>) -> Self {
        self.last_used_step = last_step;
        self
    }

    /// Returns the last accepted timestep.
    pub fn last_used_step(&self) -> Option<u64> {
        self.last_used_step
    }

    /// Returns the configured digit length.
    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// Returns the configured timestep in seconds.
    pub fn step_seconds(&self) -> u64 {
        self.step_seconds
    }

    /// Returns the configured algorithm.
    pub fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    /// Generates a TOTP code for the specified Unix timestamp in seconds.
    pub fn generate_at(&self, current_time: u64) -> Result<String, TotpError> {
        let step = current_time / self.step_seconds;
        self.generate_step_code(step)
    }

    /// Generates an HOTP code for a specific counter step.
    pub fn generate_step_code(&self, step: u64) -> Result<String, TotpError> {
        let counter_bytes = step.to_be_bytes();
        let modulo = 10u32.pow(self.digits);

        match self.algorithm {
            TotpAlgorithm::Sha1 => {
                let mut mac = HmacSha1::new_from_slice(&self.secret)
                    .map_err(|_| TotpError::HmacError)?;
                mac.update(&counter_bytes);
                let hash = mac.finalize().into_bytes();
                let offset = (hash[hash.len() - 1] & 0x0F) as usize;
                let binary_code = ((hash[offset] & 0x7F) as u32) << 24
                    | ((hash[offset + 1] as u32) << 16)
                    | ((hash[offset + 2] as u32) << 8)
                    | (hash[offset + 3] as u32);
                let otp = binary_code % modulo;
                Ok(format!("{:0width$}", otp, width = self.digits as usize))
            }
            TotpAlgorithm::Sha256 => {
                let mut mac = HmacSha256::new_from_slice(&self.secret)
                    .map_err(|_| TotpError::HmacError)?;
                mac.update(&counter_bytes);
                let hash = mac.finalize().into_bytes();
                let offset = (hash[hash.len() - 1] & 0x0F) as usize;
                let binary_code = ((hash[offset] & 0x7F) as u32) << 24
                    | ((hash[offset + 1] as u32) << 16)
                    | ((hash[offset + 2] as u32) << 8)
                    | (hash[offset + 3] as u32);
                let otp = binary_code % modulo;
                Ok(format!("{:0width$}", otp, width = self.digits as usize))
            }
        }
    }

    /// Verifies candidate code in constant time across the drift window (T-1, T, T+1).
    ///
    /// Evaluates ALL candidate steps unconditionally to prevent early-exit timing leaks.
    /// Also enforces replay protection against `last_used_step`.
    /// On success, records `last_used_step` and returns the accepted step number.
    pub fn verify(&mut self, candidate: &str, current_time: u64) -> Result<u64, TotpError> {
        let trimmed = candidate.trim();
        if trimmed.len() != self.digits as usize {
            return Err(TotpError::InvalidLength {
                expected: self.digits,
                actual: trimmed.len(),
            });
        }
        if !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return Err(TotpError::InvalidCharacters);
        }

        let current_step = current_time / self.step_seconds;
        let steps = [
            current_step.saturating_sub(1),
            current_step,
            current_step.saturating_add(1),
        ];

        let mut matched_step: Option<u64> = None;
        let mut overall_match = subtle::Choice::from(0);

        // Constant-time evaluation across all 3 steps without early break
        for &step in &steps {
            let expected = self.generate_step_code(step)?;
            let is_match = trimmed.as_bytes().ct_eq(expected.as_bytes());
            if bool::from(is_match) && matched_step.is_none() {
                matched_step = Some(step);
            }
            overall_match |= is_match;
        }

        if !bool::from(overall_match) {
            return Err(TotpError::CodeMismatch);
        }

        let step = matched_step.ok_or(TotpError::CodeMismatch)?;

        // Replay protection: cannot accept step <= last_used_step
        if let Some(last_step) = self.last_used_step {
            if step <= last_step {
                return Err(TotpError::ReplayedCode);
            }
        }

        self.last_used_step = Some(step);
        Ok(step)
    }

    /// Exports standard `otpauth://` URI compatible with Aegis Authenticator.
    pub fn export_otpauth_uri(&self, label: &str, issuer: &str) -> String {
        let b32_secret = encode_base32(&self.secret);
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            url_encode(issuer),
            url_encode(label),
            b32_secret,
            url_encode(issuer),
            self.algorithm,
            self.digits,
            self.step_seconds
        )
    }
}

/// Standalone helper to verify a TOTP code against a Base32 secret with +-30s drift and replay protection.
pub fn verify_totp(
    base32_secret: &str,
    candidate_code: &str,
    current_time: u64,
    step_seconds: u64,
    digits: u32,
    last_accepted_step: Option<u64>,
) -> Result<u64, TotpError> {
    let mut engine = TotpEngine::from_base32(base32_secret)?
        .with_digits(digits)
        .with_step_seconds(step_seconds)
        .with_last_used_step(last_accepted_step);
    engine.verify(candidate_code, current_time)
}

/// Standalone helper to compute a TOTP code from a Base32 secret at current timestamp.
pub fn compute_totp_code(
    base32_secret: &str,
    current_time: u64,
    step_seconds: u64,
    digits: u32,
) -> Result<String, TotpError> {
    let engine = TotpEngine::from_base32(base32_secret)?
        .with_digits(digits)
        .with_step_seconds(step_seconds);
    engine.generate_at(current_time)
}

// =========================================================================
// Emergency Recovery Codes
// =========================================================================

/// Clean alphanumeric alphabet for recovery codes omitting confusing characters (0, O, 1, I, L).
const RECOVERY_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// Generates a set of single-use emergency recovery codes (default 10).
/// Format: `RECV-XXXX-XXXX` where XXXX are random characters from Crockford/clean alphabet.
pub fn generate_recovery_codes(count: usize) -> Vec<String> {
    let mut codes = Vec::with_capacity(count);
    let mut rng = OsRng;

    for i in 1..=count {
        let mut random_chars = [0u8; 8];
        for b in &mut random_chars {
            let mut rand_byte = [0u8; 1];
            rng.fill_bytes(&mut rand_byte);
            *b = RECOVERY_ALPHABET[(rand_byte[0] as usize) % RECOVERY_ALPHABET.len()];
        }
        let part1 = std::str::from_utf8(&random_chars[0..4]).unwrap_or("AAAA");
        let part2 = std::str::from_utf8(&random_chars[4..8]).unwrap_or("BBBB");
        codes.push(format!("RECV-{:04}-{}-{}", i, part1, part2));
    }

    codes
}

/// Normalizes a recovery code by stripping whitespace and dashes and converting to uppercase.
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Constant-time verification and consumption of a single-use emergency recovery code.
///
/// Evaluates ALL available recovery codes unconditionally using `subtle::ConstantTimeEq`
/// to prevent timing leaks. Upon match, the consumed code is removed from `codes` and returned.
pub fn verify_and_consume_recovery_code(
    codes: &mut Vec<String>,
    candidate: &str,
) -> Result<String, TotpError> {
    let norm_candidate = normalize_recovery_code(candidate);
    if norm_candidate.is_empty() {
        return Err(TotpError::InvalidRecoveryCode);
    }

    let mut matched_index: Option<usize> = None;
    let mut match_found = subtle::Choice::from(0);

    for (i, code) in codes.iter().enumerate() {
        let norm_code = normalize_recovery_code(code);
        // Compare normalized codes in constant time if length matches
        let is_match = if norm_candidate.len() == norm_code.len() {
            norm_candidate.as_bytes().ct_eq(norm_code.as_bytes())
        } else {
            subtle::Choice::from(0)
        };

        if bool::from(is_match) && matched_index.is_none() {
            matched_index = Some(i);
        }
        match_found |= is_match;
    }

    if bool::from(match_found) {
        if let Some(idx) = matched_index {
            let consumed = codes.remove(idx);
            return Ok(consumed);
        }
    }

    Err(TotpError::RecoveryCodeNotFound)
}

// =========================================================================
// Base32 RFC 4648 Encoding & Decoding
// =========================================================================

/// Decodes standard RFC 4648 Base32 string, ignoring spaces, dashes, and '=' padding.
pub fn decode_base32(input: &str) -> Result<Vec<u8>, TotpError> {
    let mut clean: Vec<u8> = Vec::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' => clean.push(b - b'A'),
            b'a'..=b'z' => clean.push(b - b'a'),
            b'2'..=b'7' => clean.push(b - b'2' + 26),
            b'=' | b' ' | b'-' => {}
            _ => {
                return Err(TotpError::InvalidBase32(format!(
                    "Invalid Base32 character: '{}'",
                    b as char
                )))
            }
        }
    }

    if clean.is_empty() {
        return Err(TotpError::InvalidBase32("Empty Base32 secret".to_string()));
    }

    let mut out = Vec::with_capacity((clean.len() * 5) / 8);
    let mut buffer: u32 = 0;
    let mut bits_left = 0;

    for val in clean {
        buffer = (buffer << 5) | (val as u32);
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            out.push((buffer >> bits_left) as u8);
            buffer &= (1 << bits_left) - 1;
        }
    }

    Ok(out)
}

/// Encodes raw bytes into standard RFC 4648 Base32 string (without padding).
pub fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u32);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}

fn url_encode(s: &str) -> String {
    let mut encoded = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            encoded.push(c);
        } else {
            for byte in c.to_string().as_bytes() {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}
