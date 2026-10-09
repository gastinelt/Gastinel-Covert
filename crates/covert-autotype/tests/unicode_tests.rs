//! Unit tests for Unicode encoding and surrogate pair generation.

use covert_autotype::{
    encode_utf16_events, AutoTypeEngine, KeyAction, RecordedEvent, SecretString,
};

#[test]
fn test_unicode_bmp_encoding() {
    // ASCII
    assert_eq!(encode_utf16_events("A"), vec![0x0041]);
    assert_eq!(encode_utf16_events("hello"), vec![0x0068, 0x0065, 0x006C, 0x006C, 0x006F]);

    // BMP Latin accents
    assert_eq!(encode_utf16_events("é"), vec![0x00E9]);
    assert_eq!(encode_utf16_events("ç"), vec![0x00E7]);

    // BMP Symbols and CJK
    assert_eq!(encode_utf16_events("€"), vec![0x20AC]);
    assert_eq!(encode_utf16_events("日"), vec![0x65E5]);
}

#[test]
fn test_unicode_surrogate_pair_decomposition() {
    // Non-BMP emoji: Key symbol '🔑' (U+1F511)
    // UTF-16 surrogate pair calculation:
    // U' = 0x1F511 - 0x10000 = 0xF511
    // High surrogate = 0xD800 + (0xF511 >> 10) = 0xD800 + 0x003D = 0xD83D
    // Low surrogate  = 0xDC00 + (0xF511 & 0x3FF) = 0xDC00 + 0x0111 = 0xDD11
    let key_events = encode_utf16_events("🔑");
    assert_eq!(key_events, vec![0xD83D, 0xDD11]);

    // Crab emoji '🦀' (U+1F980)
    let crab_events = encode_utf16_events("🦀");
    assert_eq!(crab_events, vec![0xD83E, 0xDD80]);

    // Rocket emoji '🚀' (U+1F680)
    let rocket_events = encode_utf16_events("🚀");
    assert_eq!(rocket_events, vec![0xD83D, 0xDE80]);
}

#[test]
fn test_simulated_backend_surrogate_pairs_injection() {
    let (engine, backend) = AutoTypeEngine::new_simulated();

    // Type string containing non-BMP emoji and BMP characters
    let secret = SecretString::from("Pass🔑🦀2026");
    engine.type_unicode_string(&secret).unwrap();

    let recorded = backend.recorded_events();

    // Collect all down events
    let down_code_units: Vec<u16> = recorded
        .iter()
        .filter_map(|ev| match ev {
            RecordedEvent::UnicodeChar {
                code_unit,
                action: KeyAction::KeyDown,
            } => Some(*code_unit),
            _ => None,
        })
        .collect();

    // Expected code units: 'P', 'a', 's', 's', 0xD83D, 0xDD11, 0xD83E, 0xDD80, '2', '0', '2', '6'
    let expected: Vec<u16> = "Pass🔑🦀2026".encode_utf16().collect();
    assert_eq!(down_code_units, expected);

    // Verify every KeyDown has a matching KeyUp
    for window in recorded.windows(2) {
        if let (
            RecordedEvent::UnicodeChar {
                code_unit: cu1,
                action: KeyAction::KeyDown,
            },
            RecordedEvent::UnicodeChar {
                code_unit: cu2,
                action: KeyAction::KeyUp,
            },
        ) = (&window[0], &window[1])
        {
            assert_eq!(cu1, cu2);
        }
    }
}
