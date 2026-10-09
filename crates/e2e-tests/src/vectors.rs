//! Known official RFC test vectors for Argon2id, ChaCha20-Poly1305, and RFC 6238 TOTP.

/// RFC 6238 TOTP Test Vectors (HMAC-SHA1, 8-byte timestep counter, 6 digits).
pub struct TotpTestVector {
    pub time_seconds: u64,
    pub expected_code: &'static str,
}

pub const RFC6238_SEED: &[u8] = b"12345678901234567890"; // 20 bytes ASCII

pub const RFC6238_VECTORS: &[TotpTestVector] = &[
    TotpTestVector {
        time_seconds: 59,
        expected_code: "287082",
    },
    TotpTestVector {
        time_seconds: 1111111109,
        expected_code: "081804",
    },
    TotpTestVector {
        time_seconds: 1111111111,
        expected_code: "050471",
    },
    TotpTestVector {
        time_seconds: 1234567890,
        expected_code: "005924",
    },
    TotpTestVector {
        time_seconds: 2000000000,
        expected_code: "279037",
    },
];

/// RFC 9106 Argon2id Test Vector (Section 5.3):
pub struct Argon2idVector {
    pub password: &'static [u8],
    pub salt: &'static [u8],
    pub secret: &'static [u8],
    pub ad: &'static [u8],
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub expected_output_hex: &'static str,
}

pub const RFC9106_ARGON2ID_VECTOR: Argon2idVector = Argon2idVector {
    password: &[0x01; 32],
    salt: &[0x02; 16],
    secret: &[0x03; 8],
    ad: &[0x04; 12],
    m_cost: 32,
    t_cost: 3,
    p_cost: 4,
    expected_output_hex: "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
};

/// XChaCha20-Poly1305 draft-irtf-cfrg-xchacha-03 Test Vector 1 (Appendix A.3.1):
pub struct XChaCha20Vector {
    pub key: [u8; 32],
    pub nonce: [u8; 24],
    pub plaintext: &'static [u8],
    pub aad: &'static [u8],
    pub expected_ciphertext_hex: &'static str,
    pub expected_tag_hex: &'static str,
}

pub const XCHACHA20_VECTOR_1: XChaCha20Vector = XChaCha20Vector {
    key: [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ],
    nonce: [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ],
    plaintext: b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    aad: &[
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ],
    expected_ciphertext_hex: "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
    expected_tag_hex: "c0875924c1c7987947deafd8780acf49",
};
