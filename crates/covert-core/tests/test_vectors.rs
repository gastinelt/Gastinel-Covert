//! Official cryptographic test vectors for XChaCha20-Poly1305 and Argon2id.

use covert_core::crypto::{decrypt_payload, derive_key_raw, encrypt_payload};

/// RFC / draft-irtf-cfrg-xchacha-03, Appendix A.3.1
/// XChaCha20-Poly1305 test vector
#[test]
fn test_xchacha20_poly1305_canonical_vector() {
    let key_bytes = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        .expect("valid hex key");
    let nonce_bytes = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
        .expect("valid hex nonce");
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7")
        .expect("valid hex aad");
    let plaintext = hex::decode(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
    ).expect("valid hex plaintext");

    let expected_ciphertext = hex::decode(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e"
    ).expect("valid hex ciphertext");

    let expected_tag = hex::decode("c0875924c1c7987947deafd8780acf49")
        .expect("valid hex tag");

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);

    // Encrypt
    let encrypted = encrypt_payload(&key, &nonce, &aad, &plaintext)
        .expect("encryption succeeds");

    // Output is ciphertext + 16-byte tag
    assert_eq!(encrypted.len(), plaintext.len() + 16);
    let (ciphertext, tag) = encrypted.split_at(plaintext.len());
    assert_eq!(ciphertext, expected_ciphertext.as_slice(), "ciphertext matches test vector");
    assert_eq!(tag, expected_tag.as_slice(), "poly1305 tag matches test vector");

    // Decrypt
    let decrypted = decrypt_payload(&key, &nonce, &aad, &encrypted)
        .expect("decryption succeeds");
    assert_eq!(&*decrypted, &plaintext, "decrypted plaintext matches original");
}

/// RFC 9106, Section 5.3
/// Argon2id canonical test vector
#[test]
fn test_argon2id_rfc9106_canonical_vector() {
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let ad = [0x04u8; 12];

    let m_cost = 32; // 32 KiB
    let t_cost = 3;  // 3 iterations
    let p_cost = 4;  // 4 lanes

    let expected_tag = hex::decode(
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    ).expect("valid hex expected tag");

    let mut out = [0u8; 32];
    derive_key_raw(
        &password,
        &salt,
        m_cost,
        t_cost,
        p_cost,
        Some(&secret),
        Some(&ad),
        &mut out,
    ).expect("argon2id raw derivation succeeds");

    assert_eq!(out.as_slice(), expected_tag.as_slice(), "Argon2id tag matches RFC 9106 Section 5.3");
}
