//! Aegis RFC 6238 TOTP reference engine for constant-time 6-digit verification,
//! drift window evaluation (+-30s), and replay prevention.

use subtle::ConstantTimeEq;

/// Verify an Aegis TOTP code against a Base32 secret for a specific unix timestamp,
/// with +-30s drift window evaluation and constant-time comparison.
pub fn verify_totp(
    base32_secret: &str,
    candidate_code: &str,
    current_time: u64,
    step_seconds: u64,
    digits: u32,
    last_accepted_step: Option<u64>,
) -> Result<u64, TotpError> {
    if candidate_code.len() != digits as usize {
        return Err(TotpError::InvalidLength);
    }
    if !candidate_code.chars().all(|c| c.is_ascii_digit()) {
        return Err(TotpError::InvalidCharacters);
    }

    let secret_bytes = decode_base32(base32_secret)?;
    let current_step = current_time / step_seconds;

    // Check drift steps: current_step - 1, current_step, current_step + 1
    let steps = [
        current_step.saturating_sub(1),
        current_step,
        current_step.saturating_add(1),
    ];

    let mut matched_step: Option<u64> = None;

    for &step in &steps {
        let expected_code = generate_totp_code_from_bytes(&secret_bytes, step, digits);
        // Constant-time comparison
        let is_match: bool = candidate_code
            .as_bytes()
            .ct_eq(expected_code.as_bytes())
            .into();

        if is_match {
            // Replay protection: cannot accept a step <= last_accepted_step
            if let Some(last_step) = last_accepted_step {
                if step <= last_step {
                    return Err(TotpError::ReplayedCode);
                }
            }
            matched_step = Some(step);
            break;
        }
    }

    matched_step.ok_or(TotpError::CodeMismatch)
}

/// Compute 6-digit TOTP code from Base32 secret at current timestamp.
pub fn compute_totp_code(
    base32_secret: &str,
    current_time: u64,
    step_seconds: u64,
    digits: u32,
) -> Result<String, TotpError> {
    let secret_bytes = decode_base32(base32_secret)?;
    let step = current_time / step_seconds;
    Ok(generate_totp_code_from_bytes(&secret_bytes, step, digits))
}

/// Generate HOTP code from secret bytes and counter step (RFC 4226 / RFC 6238).
pub fn generate_totp_code_from_bytes(secret: &[u8], step: u64, digits: u32) -> String {
    let counter_bytes = step.to_be_bytes();
    let hash = hmac_sha1(secret, &counter_bytes);

    // Dynamic truncation (RFC 4226 Section 5.4)
    let offset = (hash[hash.len() - 1] & 0x0F) as usize;
    let binary_code = ((hash[offset] & 0x7F) as u32) << 24
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);

    let modulo = 10u32.pow(digits);
    let otp = binary_code % modulo;
    format!("{:0width$}", otp, width = digits as usize)
}

/// Decode standard Base32 string (RFC 4648).
pub fn decode_base32(input: &str) -> Result<Vec<u8>, TotpError> {
    let mut clean: Vec<u8> = Vec::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' => clean.push(b - b'A'),
            b'a'..=b'z' => clean.push(b - b'a'),
            b'2'..=b'7' => clean.push(b - b'2' + 26),
            b'=' | b' ' | b'-' => {}
            _ => return Err(TotpError::InvalidBase32),
        }
    }

    if clean.is_empty() {
        return Err(TotpError::InvalidBase32);
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

/// Standard HMAC-SHA1 calculation (RFC 2104).
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let block_size = 64;
    let mut key_block = [0u8; 64];

    if key.len() > block_size {
        let key_hash = sha1(key);
        key_block[..20].copy_from_slice(&key_hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5C;
    }

    let mut inner_input = Vec::with_capacity(64 + message.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner_hash = sha1(&inner_input);

    let mut outer_input = Vec::with_capacity(64 + 20);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner_hash);
    sha1(&outer_input)
}

/// Standard SHA-1 implementation (FIPS 180-1 / RFC 3174).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let total_bits = (data.len() as u64) * 8;
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&total_bits.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("Candidate code length does not match expected digits")]
    InvalidLength,
    #[error("Candidate code contains non-numeric characters")]
    InvalidCharacters,
    #[error("Invalid Base32 secret string")]
    InvalidBase32,
    #[error("TOTP code does not match within drift window")]
    CodeMismatch,
    #[error("Replayed TOTP code within same timestep")]
    ReplayedCode,
}
