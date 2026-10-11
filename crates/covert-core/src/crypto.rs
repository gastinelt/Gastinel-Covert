//! Cryptographic primitives: Argon2id key derivation and XChaCha20-Poly1305 AEAD.

use crate::error::CryptoError;
use crate::header::{Argon2Params, NONCE_SIZE, SALT_SIZE};
use argon2::{Algorithm, Argon2, AssociatedData, Params, ParamsBuilder, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// Key length in bytes for XChaCha20-Poly1305.
pub const KEY_SIZE: usize = 32;

/// Generate cryptographically secure random 32-byte salt using OsRng.
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate cryptographically secure random 24-byte nonce using OsRng.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derive a 32-byte encryption key from master password and salt using Argon2id.
///
/// Pre-allocation parameter bounds checking must be performed prior to calling this function.
/// Returns a zeroized 32-byte buffer.
pub fn derive_key(
    password: &SecretString,
    salt: &[u8; SALT_SIZE],
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_SIZE))
        .map_err(|e| CryptoError::Argon2ParamsInvalid(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut derived_key = Zeroizing::new([0u8; KEY_SIZE]);

    argon2
        .hash_password_into(
            password.expose_secret().as_bytes(),
            salt,
            &mut *derived_key,
        )
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(derived_key)
}

/// Low-level Argon2id derivation with optional secret and associated data (for RFC 9106 test vectors).
#[allow(clippy::too_many_arguments)]
pub fn derive_key_raw(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    secret: Option<&[u8]>,
    ad: Option<&[u8]>,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let mut builder = ParamsBuilder::new();
    builder.m_cost(m_cost);
    builder.t_cost(t_cost);
    builder.p_cost(p_cost);
    builder.output_len(out.len());

    if let Some(ad_data) = ad {
        let associated_data = AssociatedData::new(ad_data)
            .map_err(|e| CryptoError::Argon2ParamsInvalid(e.to_string()))?;
        builder.data(associated_data);
    }

    let params = builder
        .build()
        .map_err(|e| CryptoError::Argon2ParamsInvalid(e.to_string()))?;

    let argon2 = if let Some(secret_data) = secret {
        Argon2::new_with_secret(secret_data, Algorithm::Argon2id, Version::V0x13, params)
            .map_err(|e| CryptoError::Argon2ParamsInvalid(e.to_string()))?
    } else {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    };

    argon2
        .hash_password_into(password, salt, out)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(())
}

/// Encrypt plaintext with XChaCha20-Poly1305 AEAD, binding associated authenticated data (AAD).
///
/// Output format: `[ciphertext] + [16 bytes Poly1305 tag]`.
pub fn encrypt_payload(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext_and_tag = cipher
        .encrypt(xnonce, payload)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(ciphertext_and_tag)
}

/// Decrypt `ciphertext_and_tag` with XChaCha20-Poly1305 AEAD, validating associated authenticated data (AAD).
///
/// If password, ciphertext, nonce, or any bit of AAD is altered, authentication fails safely.
/// Returns zeroized plaintext bytes on success.
pub fn decrypt_payload(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext_and_tag,
        aad,
    };

    let decrypted = cipher
        .decrypt(xnonce, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(Zeroizing::new(decrypted))
}
