//! Unit tests for token interpolation.

use covert_autotype::{
    interpolate, parse_sequence, AutoTypeEngine, AutoTypeError, AutoTypeToken, SimulatedKeystroke,
};
use covert_core::models::VaultItem;

fn create_sample_item() -> VaultItem {
    VaultItem::new_credential(
        "Gastinel Portal",
        "covert_agent@internal.net",
        "S3cur3!Vault#2026",
        Some("https://internal.net/login".to_string()),
    )
}

#[test]
fn test_interpolation_full_mfa_sequence() {
    let item = create_sample_item();
    let totp = "123456";

    let seq = "{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}";
    let tokens = parse_sequence(seq).unwrap();
    let stream = interpolate(&tokens, &item, Some(totp)).unwrap();

    let mut username_chars = Vec::new();
    let mut password_chars = Vec::new();
    let mut totp_chars = Vec::new();
    let mut tab_count = 0;
    let mut enter_count = 0;

    let mut phase = 0;
    for stroke in stream {
        match stroke {
            SimulatedKeystroke::UnicodeChar(c) => match phase {
                0 => username_chars.push(c),
                1 => password_chars.push(c),
                2 => totp_chars.push(c),
                _ => {}
            },
            SimulatedKeystroke::VirtualKey(0x09) => {
                tab_count += 1;
                phase += 1;
            }
            SimulatedKeystroke::VirtualKey(0x0D) => {
                enter_count += 1;
            }
            _ => {}
        }
    }

    assert_eq!(tab_count, 2);
    assert_eq!(enter_count, 1);
    assert_eq!(
        username_chars.into_iter().collect::<String>(),
        "covert_agent@internal.net"
    );
    assert_eq!(
        password_chars.into_iter().collect::<String>(),
        "S3cur3!Vault#2026"
    );
    assert_eq!(totp_chars.into_iter().collect::<String>(), "123456");
}

#[test]
fn test_interpolation_missing_username_error() {
    let mut item = create_sample_item();
    item.username = None;

    let tokens = vec![AutoTypeToken::Username];
    let res = interpolate(&tokens, &item, None);
    assert_eq!(res, Err(AutoTypeError::MissingField("username".to_string())));
}

#[test]
fn test_interpolation_missing_password_error() {
    let mut item = create_sample_item();
    item.password = None;

    let tokens = vec![AutoTypeToken::Password];
    let res = interpolate(&tokens, &item, None);
    assert_eq!(res, Err(AutoTypeError::MissingField("password".to_string())));
}

#[test]
fn test_interpolation_missing_totp_error() {
    let item = create_sample_item();
    let tokens = vec![AutoTypeToken::Totp];
    let res = interpolate(&tokens, &item, None);
    assert_eq!(res, Err(AutoTypeError::MissingTotp));
}

#[test]
fn test_interpolation_static_api_on_autotype_engine() {
    let item = create_sample_item();
    let tokens = AutoTypeEngine::parse_sequence("{USERNAME}{ENTER}").unwrap();
    let stream = AutoTypeEngine::interpolate(&tokens, &item, None).unwrap();
    assert_eq!(stream.len(), "covert_agent@internal.net".len() + 1);
    assert_eq!(
        *stream.last().unwrap(),
        SimulatedKeystroke::VirtualKey(0x0D)
    );
}
