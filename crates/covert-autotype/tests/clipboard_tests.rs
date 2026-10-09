//! Verification that Auto-Type has ZERO clipboard dependency.

use covert_autotype::{AutoTypeEngine, SecretString};
use covert_core::models::VaultItem;
use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;

#[test]
fn test_zero_clipboard_guarantee() {
    let initial_seq = unsafe { GetClipboardSequenceNumber() };

    let (engine, _) = AutoTypeEngine::new_simulated();

    // 1. Type secret string
    let secret = SecretString::from("SuperSecretZeroClipboardPassword99!");
    engine.type_unicode_string(&secret).unwrap();

    let seq_after_secret = unsafe { GetClipboardSequenceNumber() };
    assert_eq!(
        initial_seq, seq_after_secret,
        "Clipboard sequence number changed during type_unicode_string — violation of zero clipboard dependency!"
    );

    // 2. Execute full sequence with username, password, TOTP
    let item = VaultItem::new_credential(
        "SecureSite",
        "covert_agent",
        "P@$$w0rd!1234",
        Some("https://securesite.org".to_string()),
    );

    engine
        .execute_sequence(
            "{CLEARFIELD}{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}",
            &item,
            Some("987654"),
        )
        .unwrap();

    let seq_after_sequence = unsafe { GetClipboardSequenceNumber() };
    assert_eq!(
        initial_seq, seq_after_sequence,
        "Clipboard sequence number changed during execute_sequence — violation of zero clipboard dependency!"
    );
}
