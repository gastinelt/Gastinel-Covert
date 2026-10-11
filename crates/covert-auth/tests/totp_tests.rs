use covert_auth::error::TotpError;
use covert_auth::totp::{decode_base32, encode_base32, TotpAlgorithm, TotpEngine};

#[test]
fn test_rfc6238_official_vectors_sha1() {
    // RFC 6238 Appendix B test vector for SHA1:
    // Secret = "12345678901234567890" (20 bytes ASCII)
    let secret = b"12345678901234567890".to_vec();
    let engine = TotpEngine::new(secret)
        .with_digits(8)
        .with_step_seconds(30)
        .with_algorithm(TotpAlgorithm::Sha1);

    // Test cases from RFC 6238 Appendix B Table 1 (SHA1):
    let vectors: &[(u64, &str)] = &[
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ];

    for &(time, expected_8digit) in vectors {
        let code = engine.generate_at(time).unwrap();
        assert_eq!(code, expected_8digit, "Failed at time {}", time);

        // For 6-digit standard: last 6 digits match
        let engine_6digit = TotpEngine::new(b"12345678901234567890".to_vec())
            .with_digits(6)
            .with_step_seconds(30);
        let code_6 = engine_6digit.generate_at(time).unwrap();
        assert_eq!(code_6, &expected_8digit[2..], "Failed 6-digit at time {}", time);
    }
}

#[test]
fn test_rfc6238_official_vectors_sha256() {
    // RFC 6238 Appendix B test vector for SHA256:
    // Secret = 32 bytes ASCII "12345678901234567890123456789012"
    let secret = b"12345678901234567890123456789012".to_vec();
    let engine = TotpEngine::new(secret)
        .with_digits(8)
        .with_step_seconds(30)
        .with_algorithm(TotpAlgorithm::Sha256);

    let vectors: &[(u64, &str)] = &[
        (59, "46119246"),
        (1111111109, "68084774"),
        (1111111111, "67062674"),
        (1234567890, "91819424"),
        (2000000000, "90698825"),
        (20000000000, "77737706"),
    ];

    for &(time, expected) in vectors {
        let code = engine.generate_at(time).unwrap();
        assert_eq!(code, expected, "Failed SHA256 at time {}", time);
    }
}

#[test]
fn test_totp_drift_tolerance_boundaries() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";
    let base_time = 1700000000u64; // step = 56666666
    let step_secs = 30u64;

    let mut engine = TotpEngine::from_base32(secret_b32).unwrap();

    // Generate code for current step T
    let code_current = engine.generate_at(base_time).unwrap();
    // Generate code for past step T-1
    let code_past = engine.generate_at(base_time - step_secs).unwrap();
    // Generate code for future step T+1
    let code_future = engine.generate_at(base_time + step_secs).unwrap();

    // 1. Current code verified at base_time
    assert!(engine.verify(&code_current, base_time).is_ok());

    // Reset last used step to allow independent verification tests
    let mut engine = TotpEngine::from_base32(secret_b32).unwrap();
    // 2. Past code (T - 30s) accepted within drift window
    assert!(engine.verify(&code_past, base_time).is_ok());

    let mut engine = TotpEngine::from_base32(secret_b32).unwrap();
    // 3. Future code (T + 30s) accepted within drift window
    assert!(engine.verify(&code_future, base_time).is_ok());

    let mut engine = TotpEngine::from_base32(secret_b32).unwrap();
    // 4. Code from 2 steps back (T - 60s) strictly rejected
    let code_too_old = engine.generate_at(base_time - step_secs * 2).unwrap();
    assert_eq!(
        engine.verify(&code_too_old, base_time).unwrap_err(),
        TotpError::CodeMismatch
    );

    // 5. Code from 2 steps forward (T + 60s) strictly rejected
    let code_too_far = engine.generate_at(base_time + step_secs * 2).unwrap();
    assert_eq!(
        engine.verify(&code_too_far, base_time).unwrap_err(),
        TotpError::CodeMismatch
    );
}

#[test]
fn test_totp_replay_prevention() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";
    // Align base_time to exact step boundary
    let base_time = (1700000000u64 / 30) * 30; // 1699999980
    let mut engine = TotpEngine::from_base32(secret_b32).unwrap();

    let code = engine.generate_at(base_time).unwrap();

    // First attempt in window succeeds
    let step = engine.verify(&code, base_time).unwrap();
    assert_eq!(step, base_time / 30);
    assert_eq!(engine.last_used_step(), Some(step));

    // Second attempt in SAME window rejected as replay
    let err = engine.verify(&code, base_time + 5).unwrap_err();
    assert_eq!(err, TotpError::ReplayedCode);

    // An earlier code (T-1) rejected as replay because step <= last_used_step
    let code_past = engine.generate_at(base_time - 30).unwrap();
    let err_past = engine.verify(&code_past, base_time + 5).unwrap_err();
    assert_eq!(err_past, TotpError::ReplayedCode);

    // Code for next step (T+1 at base_time + 30) succeeds
    let code_next = engine.generate_at(base_time + 30).unwrap();
    let next_step = engine.verify(&code_next, base_time + 30).unwrap();
    assert_eq!(next_step, (base_time + 30) / 30);
    assert_eq!(engine.last_used_step(), Some(next_step));
}

#[test]
fn test_totp_leading_zero_formatting() {
    // Secret & timestamp chosen to produce leading zero
    let secret = b"12345678901234567890".to_vec();
    let engine = TotpEngine::new(secret).with_digits(6);

    // Time 1111111109 produces 8-digit "07081804", so 6-digit is "081804"
    let code = engine.generate_at(1111111109).unwrap();
    assert_eq!(code, "081804");
    assert_eq!(code.len(), 6);

    // Time 1234567890 produces 8-digit "89005924", so 6-digit is "005924" (two leading zeros!)
    let code_double_zero = engine.generate_at(1234567890).unwrap();
    assert_eq!(code_double_zero, "005924");
    assert_eq!(code_double_zero.len(), 6);
}

#[test]
fn test_totp_invalid_inputs() {
    let secret_b32 = "JBSWY3DPEHPK3PXP";
    let mut engine = TotpEngine::from_base32(secret_b32).unwrap();

    // Wrong length
    assert!(matches!(
        engine.verify("12345", 1700000000),
        Err(TotpError::InvalidLength { .. })
    ));
    assert!(matches!(
        engine.verify("1234567", 1700000000),
        Err(TotpError::InvalidLength { .. })
    ));

    // Non-numeric
    assert_eq!(
        engine.verify("abcdef", 1700000000),
        Err(TotpError::InvalidCharacters)
    );
    assert_eq!(
        engine.verify("123 45", 1700000000),
        Err(TotpError::InvalidCharacters)
    );

    // Bad Base32 secret
    assert!(matches!(
        TotpEngine::from_base32("InvalidBase32Secret!@#"),
        Err(TotpError::InvalidBase32(_))
    ));
}

#[test]
fn test_export_otpauth_uri() {
    let engine = TotpEngine::from_base32("JBSWY3DPEHPK3PXP").unwrap();
    let uri = engine.export_otpauth_uri("alice@internal", "Gastinel Covert");

    assert!(uri.starts_with("otpauth://totp/Gastinel%20Covert:alice%40internal?"));
    assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
    assert!(uri.contains("issuer=Gastinel%20Covert"));
    assert!(uri.contains("algorithm=SHA1"));
    assert!(uri.contains("digits=6"));
    assert!(uri.contains("period=30"));
}

#[test]
fn test_base32_roundtrip() {
    let data = b"Hello Gastinel Covert 2026!";
    let encoded = encode_base32(data);
    let decoded = decode_base32(&encoded).unwrap();
    assert_eq!(data.to_vec(), decoded);
}
