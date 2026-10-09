//! Unit tests for sequence AST parser.

use covert_autotype::{
    parse_sequence, AutoTypeError, AutoTypeSequence, AutoTypeToken,
};

#[test]
fn test_parse_single_tokens() {
    assert_eq!(
        parse_sequence("{USERNAME}").unwrap(),
        vec![AutoTypeToken::Username]
    );
    assert_eq!(
        parse_sequence("{PASSWORD}").unwrap(),
        vec![AutoTypeToken::Password]
    );
    assert_eq!(
        parse_sequence("{TOTP}").unwrap(),
        vec![AutoTypeToken::Totp]
    );
    assert_eq!(
        parse_sequence("{TAB}").unwrap(),
        vec![AutoTypeToken::Tab]
    );
    assert_eq!(
        parse_sequence("{ENTER}").unwrap(),
        vec![AutoTypeToken::Enter]
    );
    assert_eq!(
        parse_sequence("{RETURN}").unwrap(),
        vec![AutoTypeToken::Enter]
    );
    assert_eq!(
        parse_sequence("{ESC}").unwrap(),
        vec![AutoTypeToken::Escape]
    );
    assert_eq!(
        parse_sequence("{ESCAPE}").unwrap(),
        vec![AutoTypeToken::Escape]
    );
    assert_eq!(
        parse_sequence("{BACKSPACE}").unwrap(),
        vec![AutoTypeToken::Backspace]
    );
    assert_eq!(
        parse_sequence("{BS}").unwrap(),
        vec![AutoTypeToken::Backspace]
    );
    assert_eq!(
        parse_sequence("{SPACE}").unwrap(),
        vec![AutoTypeToken::Space]
    );
    assert_eq!(
        parse_sequence("{CLEARFIELD}").unwrap(),
        vec![AutoTypeToken::ClearField]
    );
    assert_eq!(
        parse_sequence("{DELAY}").unwrap(),
        vec![AutoTypeToken::Delay(500)]
    );
    assert_eq!(
        parse_sequence("{DELAY 1000}").unwrap(),
        vec![AutoTypeToken::Delay(1000)]
    );
}

#[test]
fn test_parse_case_insensitivity() {
    assert_eq!(
        parse_sequence("{username}{tab}{password}{enter}").unwrap(),
        vec![
            AutoTypeToken::Username,
            AutoTypeToken::Tab,
            AutoTypeToken::Password,
            AutoTypeToken::Enter,
        ]
    );
}

#[test]
fn test_parse_default_login_sequences() {
    let default_seq = AutoTypeSequence::default_login();
    assert_eq!(
        default_seq.tokens,
        vec![
            AutoTypeToken::Username,
            AutoTypeToken::Tab,
            AutoTypeToken::Password,
            AutoTypeToken::Enter,
        ]
    );

    let default_mfa = AutoTypeSequence::default_mfa();
    assert_eq!(
        default_mfa.tokens,
        vec![
            AutoTypeToken::Username,
            AutoTypeToken::Tab,
            AutoTypeToken::Password,
            AutoTypeToken::Tab,
            AutoTypeToken::Totp,
            AutoTypeToken::Enter,
        ]
    );
}

#[test]
fn test_parse_mixed_text_and_tokens() {
    let seq = "user: {USERNAME} pass: {PASSWORD} {ENTER}";
    let tokens = parse_sequence(seq).unwrap();
    assert_eq!(
        tokens,
        vec![
            AutoTypeToken::Text("user: ".to_string()),
            AutoTypeToken::Username,
            AutoTypeToken::Text(" pass: ".to_string()),
            AutoTypeToken::Password,
            AutoTypeToken::Text(" ".to_string()),
            AutoTypeToken::Enter,
        ]
    );
}

#[test]
fn test_parse_escaped_braces() {
    let seq = "literal {{bracket}} here";
    let tokens = parse_sequence(seq).unwrap();
    assert_eq!(
        tokens,
        vec![AutoTypeToken::Text("literal {bracket} here".to_string())]
    );
}

#[test]
fn test_parse_empty_sequence_fails() {
    assert_eq!(parse_sequence(""), Err(AutoTypeError::EmptySequence));
    assert_eq!(parse_sequence("   "), Err(AutoTypeError::EmptySequence));
    assert_eq!(parse_sequence("\t\n"), Err(AutoTypeError::EmptySequence));
}

#[test]
fn test_parse_unterminated_tag_fails() {
    assert_eq!(
        parse_sequence("{USERNAME"),
        Err(AutoTypeError::UnterminatedTag)
    );
    assert_eq!(
        parse_sequence("prefix {TAB suffix"),
        Err(AutoTypeError::UnterminatedTag)
    );
}

#[test]
fn test_parse_unknown_placeholder_fails() {
    assert_eq!(
        parse_sequence("{UNKNOWN_TAG}"),
        Err(AutoTypeError::UnknownPlaceholder("UNKNOWN_TAG".to_string()))
    );
    assert_eq!(
        parse_sequence("{FOO_BAR}"),
        Err(AutoTypeError::UnknownPlaceholder("FOO_BAR".to_string()))
    );
}
