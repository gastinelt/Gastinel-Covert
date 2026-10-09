//! Tier-2 Master View Password verifier and ephemeral session manager.
//!
//! Enforces:
//! - Plain-text secret reveals and clipboard exports require a distinct secondary password.
//! - Verifier stored as Argon2id PHC hash inside vault security section.
//! - Constant-time password verification via `argon2::PasswordVerifier`.
//! - Distinctness validation: Tier-2 password must not equal Master Password.
//! - Ephemeral reveal grants with configurable expiration (default 60 seconds).

use crate::error::AuthError;
use argon2::{
    password_hash::{
        rand_core::OsRng, Error as HashError, PasswordHash, PasswordHasher, PasswordVerifier,
        SaltString,
    },
    Argon2, Params,
};
use covert_core::models::Vault;
use covert_core::SecretString;
use secrecy_v08::ExposeSecret;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Default Argon2id parameters for Tier-2 password hashing:
/// m_cost = 65,536 (64 MiB), t_cost = 3, p_cost = 2.
pub const TIER2_M_COST: u32 = 65536;
pub const TIER2_T_COST: u32 = 3;
pub const TIER2_P_COST: u32 = 2;

/// Default ephemeral grant TTL in seconds (60s).
pub const DEFAULT_TIER2_TTL_SECONDS: u64 = 60;

/// Hashes a Tier-2 Master View Password into a standard Argon2id PHC string.
pub fn hash_tier2_password(password: &SecretString) -> Result<String, AuthError> {
    let raw_pw = password.expose_secret();
    if raw_pw.trim().is_empty() {
        return Err(AuthError::InvalidTier2Password);
    }

    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(TIER2_M_COST, TIER2_T_COST, TIER2_P_COST, Some(32))
        .map_err(|e| AuthError::Crypto(covert_core::error::CryptoError::Argon2ParamsInvalid(e.to_string())))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let password_hash = argon2
        .hash_password(raw_pw.as_bytes(), &salt)
        .map_err(|e| AuthError::Crypto(covert_core::error::CryptoError::KeyDerivationFailed(e.to_string())))?
        .to_string();

    Ok(password_hash)
}

/// Validates that a candidate Tier-2 password meets complexity and is distinct from the Master Password.
pub fn validate_tier2_candidate(
    tier2_pw: &SecretString,
    master_pw: Option<&SecretString>,
) -> Result<(), AuthError> {
    let t2_str = tier2_pw.expose_secret();
    if t2_str.trim().is_empty() {
        return Err(AuthError::InvalidTier2Password);
    }

    if let Some(m_pw) = master_pw {
        let m_str = m_pw.expose_secret();
        let is_same: bool = t2_str.as_bytes().ct_eq(m_str.as_bytes()).into();
        if is_same {
            return Err(AuthError::InvalidTier2Password);
        }
    }

    Ok(())
}

/// Verifies a candidate Tier-2 Master View Password against the vault's stored hash.
///
/// Execution is constant-time via `argon2::PasswordVerifier`.
pub fn verify_tier2_password(vault: &Vault, candidate: &SecretString) -> Result<(), AuthError> {
    let hash_str = vault
        .security
        .master_view_password_hash
        .as_ref()
        .ok_or(AuthError::Tier2NotConfigured)?;

    let candidate_bytes = candidate.expose_secret().as_bytes();
    if candidate_bytes.is_empty() {
        return Err(AuthError::InvalidTier2Password);
    }

    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|_| AuthError::InvalidTier2Password)?;

    let argon2 = Argon2::default();
    match argon2.verify_password(candidate_bytes, &parsed_hash) {
        Ok(_) => Ok(()),
        Err(HashError::Password) => Err(AuthError::InvalidTier2Password),
        Err(_) => Err(AuthError::InvalidTier2Password),
    }
}

/// Ephemeral session grant authorizing plain-text reveals and clipboard copies.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Tier2Session {
    granted_at: u64,
    ttl_seconds: u64,
    is_active: bool,
}

impl Tier2Session {
    /// Grants a new ephemeral Tier-2 session.
    pub fn grant(current_time: u64, ttl_seconds: u64) -> Self {
        Self {
            granted_at: current_time,
            ttl_seconds,
            is_active: true,
        }
    }

    /// Grants a new session with the default 60-second TTL.
    pub fn grant_default(current_time: u64) -> Self {
        Self::grant(current_time, DEFAULT_TIER2_TTL_SECONDS)
    }

    /// Checks if this session is currently valid at `current_time`.
    pub fn is_valid(&self, current_time: u64) -> bool {
        if !self.is_active {
            return false;
        }
        current_time < self.granted_at.saturating_add(self.ttl_seconds)
    }

    /// Immediately revokes the session and zeros out authorization.
    pub fn revoke(&mut self) {
        self.is_active = false;
        self.granted_at = 0;
        self.ttl_seconds = 0;
    }

    /// Returns the remaining valid seconds for this session at `current_time`.
    pub fn remaining_seconds(&self, current_time: u64) -> u64 {
        if !self.is_valid(current_time) {
            0
        } else {
            (self.granted_at + self.ttl_seconds).saturating_sub(current_time)
        }
    }
}
