use covert_auth::error::TotpError;
use covert_auth::totp::{
    generate_recovery_codes, normalize_recovery_code, verify_and_consume_recovery_code,
};

#[test]
fn test_recovery_code_generation_ten_codes() {
    let codes = generate_recovery_codes(10);
    assert_eq!(codes.len(), 10);

    // All codes must be unique
    let mut unique = codes.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 10);

    // Format check: starts with RECV-
    for code in &codes {
        assert!(code.starts_with("RECV-"));
        assert_eq!(code.len(), 19); // RECV-0001-XXXX-XXXX = 19 chars
    }
}

#[test]
fn test_recovery_code_consumption_single_use() {
    let mut codes = generate_recovery_codes(10);
    let target_code = codes[3].clone();

    // 1. Consume target code
    let consumed = verify_and_consume_recovery_code(&mut codes, &target_code).unwrap();
    assert_eq!(consumed, target_code);
    assert_eq!(codes.len(), 9);
    assert!(!codes.contains(&target_code));

    // 2. Second attempt with the SAME code must fail (already consumed)
    let err = verify_and_consume_recovery_code(&mut codes, &target_code).unwrap_err();
    assert_eq!(err, TotpError::RecoveryCodeNotFound);
    assert_eq!(codes.len(), 9);
}

#[test]
fn test_recovery_code_normalization_and_formatting() {
    let mut codes = vec![
        "RECV-0001-ABCD-EFGH".to_string(),
        "RECV-0002-JKMN-PQRT".to_string(),
    ];

    // Case-insensitivity: lowercase matches
    let consumed = verify_and_consume_recovery_code(&mut codes, "recv-0001-abcd-efgh").unwrap();
    assert_eq!(consumed, "RECV-0001-ABCD-EFGH");
    assert_eq!(codes.len(), 1);

    // Without dashes matches
    let consumed2 = verify_and_consume_recovery_code(&mut codes, "RECV0002JKMNPQRT").unwrap();
    assert_eq!(consumed2, "RECV-0002-JKMN-PQRT");
    assert_eq!(codes.len(), 0);

    // Direct normalize test
    assert_eq!(normalize_recovery_code(" recv - 0001 - abcd "), "RECV0001ABCD");
}

#[test]
fn test_recovery_code_invalid_rejected() {
    let mut codes = generate_recovery_codes(10);

    // Non-existent code
    let err = verify_and_consume_recovery_code(&mut codes, "RECV-9999-ZZZZ-ZZZZ").unwrap_err();
    assert_eq!(err, TotpError::RecoveryCodeNotFound);
    assert_eq!(codes.len(), 10);

    // Empty code
    let err_empty = verify_and_consume_recovery_code(&mut codes, "").unwrap_err();
    assert_eq!(err_empty, TotpError::InvalidRecoveryCode);
    assert_eq!(codes.len(), 10);
}
