//! Empirical Challenge Test Suite for `covert-autotype`.
//!
//! Rigorously verifies:
//! 1. Clipboard Isolation: SendInput keystroke injection NEVER touches, alters, or queries the Windows clipboard.
//! 2. Non-BMP Unicode & Surrogate Pairs: Full decomposition, validation bounds (U+10000 to U+10FFFF),
//!    roundtrip decoding, and ordering.
//! 3. AST Sequence Parsing & Dynamic Interpolation: Extreme edge cases, macros, combinations,
//!    malformed inputs, and error handling.

use covert_autotype::{
    encode_utf16_events, interpolate, parse_sequence, send_char, AutoTypeEngine, AutoTypeError,
    AutoTypeToken, KeyAction, KeystrokeBackend, RecordedEvent, SimulatedKeystroke,
    SimulationBackend, VirtualKey,
};
use covert_core::models::VaultItem;
#[cfg(windows)]
use covert_autotype::{SecretString, Win32SendInputBackend};
#[cfg(windows)]
use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;

// =========================================================================
// Area 1: Keystroke Injection NEVER Touches or Alters the Windows Clipboard
// =========================================================================

#[cfg(windows)]
#[test]
fn test_challenge_clipboard_isolation_under_simulation_and_win32() {
    let initial_seq = unsafe { GetClipboardSequenceNumber() };

    // 1. Simulation backend with complex sequence
    let (sim_engine, sim_backend) = AutoTypeEngine::new_simulated();
    let item = VaultItem::new_credential(
        "BankOfGastinel",
        "top_secret_agent_007",
        "SuperP@ssw0rd!🔑🦀2026",
        Some("https://bank.gastinel.internal".to_string()),
    );

    let complex_seq = "{CLEARFIELD}{DELAY 10}{USERNAME}{TAB}{CLEARFIELD}{PASSWORD}{TAB}{TOTP}{ENTER}";
    sim_engine
        .execute_sequence(complex_seq, &item, Some("654321"))
        .expect("Simulation execution must succeed");

    let post_sim_seq = unsafe { GetClipboardSequenceNumber() };
    assert_eq!(
        initial_seq, post_sim_seq,
        "Simulated auto-type sequence must not alter clipboard sequence number"
    );
    assert!(!sim_backend.recorded_events().is_empty());

    // 2. Win32 backend: verify send_unicode_code_unit does not touch clipboard
    let win32_backend = Win32SendInputBackend::new();
    // Dispatch a harmless surrogate pair code unit via Win32 SendInput
    // (Note: SendInput posts to message queue, never to clipboard)
    let _ = win32_backend.send_unicode_code_unit(0x0041); // 'A'
    let post_win32_unit = unsafe { GetClipboardSequenceNumber() };
    assert_eq!(
        initial_seq, post_win32_unit,
        "Win32SendInputBackend::send_unicode_code_unit must not alter clipboard sequence number"
    );

    // 3. Win32 backend: verify send_virtual_key does not touch clipboard
    let _ = win32_backend.send_virtual_key(VirtualKey::Tab);
    let post_win32_vk = unsafe { GetClipboardSequenceNumber() };
    assert_eq!(
        initial_seq, post_win32_vk,
        "Win32SendInputBackend::send_virtual_key must not alter clipboard sequence number"
    );

    // 4. Win32 backend: verify send_clear_field does not touch clipboard
    // Clearfield executes Ctrl+A then Backspace (NOT Ctrl+X / Ctrl+C)
    let _ = win32_backend.send_clear_field();
    let post_clear_seq = unsafe { GetClipboardSequenceNumber() };
    assert_eq!(
        initial_seq, post_clear_seq,
        "Win32SendInputBackend::send_clear_field must not touch or alter clipboard"
    );

    // 5. Typing SecretString with unicode and emojis
    let secret = SecretString::from("SensitiveP@sswordWithEmojis🔑🛡️🚀2026");
    sim_engine
        .type_unicode_string(&secret)
        .expect("type_unicode_string must succeed");

    let final_seq = unsafe { GetClipboardSequenceNumber() };
    assert_eq!(
        initial_seq, final_seq,
        "type_unicode_string must never touch clipboard"
    );
}

#[test]
fn test_challenge_clearfield_does_not_use_clipboard_cut() {
    let backend = SimulationBackend::new();
    backend
        .send_clear_field()
        .expect("send_clear_field should succeed");

    let events = backend.recorded_events();
    // ClearField must use Ctrl + A then Backspace (NOT Ctrl+X)
    // Recorded virtual keys:
    // 0x11 (Ctrl Down), 0x41 ('A' Down), 0x41 ('A' Up), 0x11 (Ctrl Up), 0x08 (Backspace Down), 0x08 (Backspace Up)
    let vk_events: Vec<(u16, KeyAction)> = events
        .iter()
        .filter_map(|e| match e {
            RecordedEvent::VirtualKey { vk, action } => Some((*vk, *action)),
            _ => None,
        })
        .collect();

    assert_eq!(
        vk_events,
        vec![
            (0x11, KeyAction::KeyDown), // Ctrl
            (0x41, KeyAction::KeyDown), // 'A'
            (0x41, KeyAction::KeyUp),   // 'A'
            (0x11, KeyAction::KeyUp),   // Ctrl
            (0x08, KeyAction::KeyDown), // Backspace
            (0x08, KeyAction::KeyUp),   // Backspace
        ],
        "ClearField must strictly send Ctrl+A then Backspace to avoid modifying clipboard"
    );

    // Verify 'X' (0x58) is NEVER sent
    assert!(
        !vk_events.iter().any(|(vk, _)| *vk == 0x58),
        "Ctrl+X (Cut) must NEVER be used in ClearField as it would overwrite the clipboard!"
    );
}

// =========================================================================
// Area 2: Non-BMP Unicode Characters and UTF-16 Surrogate Pairs
// =========================================================================

#[test]
fn test_challenge_non_bmp_boundaries_and_surrogate_decomposition() {
    // 1. Minimum Non-BMP code point: U+10000 (Linear B Syllable B008 A: '\u{10000}')
    let min_non_bmp = '\u{10000}';
    let min_units = encode_utf16_events(&min_non_bmp.to_string());
    assert_eq!(min_units.len(), 2);
    assert_eq!(min_units[0], 0xD800, "High surrogate for U+10000 must be 0xD800");
    assert_eq!(min_units[1], 0xDC00, "Low surrogate for U+10000 must be 0xDC00");

    // 2. Maximum valid Unicode code point: U+10FFFF ('\u{10FFFF}')
    let max_non_bmp = '\u{10FFFF}';
    let max_units = encode_utf16_events(&max_non_bmp.to_string());
    assert_eq!(max_units.len(), 2);
    assert_eq!(max_units[0], 0xDBFF, "High surrogate for U+10FFFF must be 0xDBFF");
    assert_eq!(max_units[1], 0xDFFF, "Low surrogate for U+10FFFF must be 0xDFFF");

    // 3. BMP Boundary points:
    // U+D7FF (just before surrogate block)
    let before_surrogate = '\u{D7FF}';
    let bs_units = encode_utf16_events(&before_surrogate.to_string());
    assert_eq!(bs_units, vec![0xD7FF], "U+D7FF is BMP, must be single code unit");

    // U+E000 (just after surrogate block)
    let after_surrogate = '\u{E000}';
    let as_units = encode_utf16_events(&after_surrogate.to_string());
    assert_eq!(as_units, vec![0xE000], "U+E000 is BMP, must be single code unit");

    // U+FFFF (last BMP code point)
    let last_bmp = '\u{FFFF}';
    let lb_units = encode_utf16_events(&last_bmp.to_string());
    assert_eq!(lb_units, vec![0xFFFF], "U+FFFF is BMP, must be single code unit");
}

#[test]
fn test_challenge_emoji_and_supplementary_scripts_surrogate_pairs() {
    let test_cases = [
        // (character, description, expected_high, expected_low)
        ('🔑', "Key Emoji U+1F511", 0xD83D, 0xDD11),
        ('🦀', "Rust Crab U+1F980", 0xD83E, 0xDD80),
        ('🚀', "Rocket Emoji U+1F680", 0xD83D, 0xDE80),
        ('🛡', "Shield Emoji U+1F6E1", 0xD83D, 0xDEE1),
        ('💖', "Sparkling Heart U+1F496", 0xD83D, 0xDC96),
        ('𝄞', "Musical Symbol G-Clef U+1D11E", 0xD834, 0xDD1E),
        ('𠀀', "CJK Extension B U+20000", 0xD840, 0xDC00),
        ('𐀀', "Linear B A U+10000", 0xD800, 0xDC00),
        ('󰀀', "Supplementary Private Use A U+F0000", 0xDB80, 0xDC00),
        ('􀀀', "Supplementary Private Use B U+100000", 0xDBC0, 0xDC00),
    ];

    for (ch, desc, exp_high, exp_low) in test_cases {
        let text = ch.to_string();
        let units = encode_utf16_events(&text);
        assert_eq!(
            units.len(),
            2,
            "{} must decompose into exactly 2 UTF-16 surrogate code units",
            desc
        );
        assert_eq!(units[0], exp_high, "High surrogate mismatch for {}", desc);
        assert_eq!(units[1], exp_low, "Low surrogate mismatch for {}", desc);

        // High surrogate must strictly be in 0xD800..=0xDBFF
        assert!(
            (0xD800..=0xDBFF).contains(&units[0]),
            "High surrogate out of range for {}: 0x{:04X}",
            desc,
            units[0]
        );
        // Low surrogate must strictly be in 0xDC00..=0xDFFF
        assert!(
            (0xDC00..=0xDFFF).contains(&units[1]),
            "Low surrogate out of range for {}: 0x{:04X}",
            desc,
            units[1]
        );

        // Roundtrip verification: UTF-16 code units decode back to exact original character
        let decoded: Vec<Result<char, _>> = char::decode_utf16(units.iter().copied()).collect();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].as_ref().unwrap(), &ch, "Roundtrip decode failed for {}", desc);

        // Verify simulation backend event injection ordering
        let backend = SimulationBackend::new();
        send_char(&backend, ch).expect("send_char must succeed");

        let events = backend.recorded_events();
        assert_eq!(
            events,
            vec![
                RecordedEvent::UnicodeChar {
                    code_unit: exp_high,
                    action: KeyAction::KeyDown,
                },
                RecordedEvent::UnicodeChar {
                    code_unit: exp_high,
                    action: KeyAction::KeyUp,
                },
                RecordedEvent::UnicodeChar {
                    code_unit: exp_low,
                    action: KeyAction::KeyDown,
                },
                RecordedEvent::UnicodeChar {
                    code_unit: exp_low,
                    action: KeyAction::KeyUp,
                },
            ],
            "Keystroke events for {} must strictly dispatch High surrogate KeyDown/Up then Low surrogate KeyDown/Up",
            desc
        );
    }
}

#[test]
fn test_challenge_exhaustive_surrogate_pair_properties() {
    // Systematic sampling of non-BMP Unicode code points from 0x10000 to 0x10FFFF
    // Step by 0x3E7 (999) to cover over 1000 diverse code points
    for cp in (0x10000u32..=0x10FFFFu32).step_by(999) {
        if let Some(ch) = char::from_u32(cp) {
            let mut utf16_buf = [0u16; 2];
            let encoded = ch.encode_utf16(&mut utf16_buf);
            assert_eq!(encoded.len(), 2, "Code point U+{:06X} must be a surrogate pair", cp);

            let high = encoded[0];
            let low = encoded[1];

            // Verify standard surrogate bounds
            assert!(
                (0xD800..=0xDBFF).contains(&high),
                "High surrogate 0x{:04X} out of range for U+{:06X}",
                high,
                cp
            );
            assert!(
                (0xDC00..=0xDFFF).contains(&low),
                "Low surrogate 0x{:04X} out of range for U+{:06X}",
                low,
                cp
            );

            // Verify math formula: U' = cp - 0x10000
            let u_prime = cp - 0x10000;
            let expected_high = 0xD800 + ((u_prime >> 10) as u16);
            let expected_low = 0xDC00 + ((u_prime & 0x3FF) as u16);
            assert_eq!(high, expected_high);
            assert_eq!(low, expected_low);

            // Verify decode roundtrip
            let decoded = char::decode_utf16([high, low]).next().unwrap().unwrap();
            assert_eq!(decoded, ch);
        }
    }
}

// =========================================================================
// Area 3: Sequence AST Parsing and Interpolation Stress-Testing
// =========================================================================

#[test]
fn test_challenge_complex_multi_token_sequences() {
    let item = VaultItem::new_credential(
        "SuperPortal",
        "the_admin@secure.net",
        "P@ssw0rd!#123",
        Some("https://secure.net".to_string()),
    );
    let totp = "876543";

    // Complex sequence with clearfields, delays, tabs, username, password, totp, enters
    let complex_seq = "{CLEARFIELD}{DELAY 150}{USERNAME}{TAB}{CLEARFIELD}{DELAY 50}{PASSWORD}{TAB}{DELAY 200}{TOTP}{ENTER}";
    let parsed = parse_sequence(complex_seq).expect("Parsing complex sequence must succeed");

    assert_eq!(
        parsed,
        vec![
            AutoTypeToken::ClearField,
            AutoTypeToken::Delay(150),
            AutoTypeToken::Username,
            AutoTypeToken::Tab,
            AutoTypeToken::ClearField,
            AutoTypeToken::Delay(50),
            AutoTypeToken::Password,
            AutoTypeToken::Tab,
            AutoTypeToken::Delay(200),
            AutoTypeToken::Totp,
            AutoTypeToken::Enter,
        ]
    );

    let interpolated = interpolate(&parsed, &item, Some(totp)).expect("Interpolation must succeed");

    // Verify order of tokens in simulated stream:
    // 1. ClearField: 0x11, 0x41, 0x08
    assert_eq!(interpolated[0], SimulatedKeystroke::VirtualKey(0x11));
    assert_eq!(interpolated[1], SimulatedKeystroke::VirtualKey(0x41));
    assert_eq!(interpolated[2], SimulatedKeystroke::VirtualKey(0x08));

    // 2. Delay(150)
    assert_eq!(interpolated[3], SimulatedKeystroke::Delay(150));

    // 3. Username chars
    let _username_len = "the_admin@secure.net".len();
    let mut offset = 4;
    for ch in "the_admin@secure.net".chars() {
        assert_eq!(interpolated[offset], SimulatedKeystroke::UnicodeChar(ch));
        offset += 1;
    }

    // 4. Tab (0x09)
    assert_eq!(interpolated[offset], SimulatedKeystroke::VirtualKey(0x09));
    offset += 1;

    // 5. ClearField
    assert_eq!(interpolated[offset], SimulatedKeystroke::VirtualKey(0x11));
    assert_eq!(interpolated[offset + 1], SimulatedKeystroke::VirtualKey(0x41));
    assert_eq!(interpolated[offset + 2], SimulatedKeystroke::VirtualKey(0x08));
    offset += 3;

    // 6. Delay(50)
    assert_eq!(interpolated[offset], SimulatedKeystroke::Delay(50));
    offset += 1;

    // 7. Password chars
    for ch in "P@ssw0rd!#123".chars() {
        assert_eq!(interpolated[offset], SimulatedKeystroke::UnicodeChar(ch));
        offset += 1;
    }

    // 8. Tab (0x09)
    assert_eq!(interpolated[offset], SimulatedKeystroke::VirtualKey(0x09));
    offset += 1;

    // 9. Delay(200)
    assert_eq!(interpolated[offset], SimulatedKeystroke::Delay(200));
    offset += 1;

    // 10. TOTP chars
    for ch in "876543".chars() {
        assert_eq!(interpolated[offset], SimulatedKeystroke::UnicodeChar(ch));
        offset += 1;
    }

    // 11. Enter (0x0D)
    assert_eq!(interpolated[offset], SimulatedKeystroke::VirtualKey(0x0D));
    assert_eq!(offset + 1, interpolated.len());
}

#[test]
fn test_challenge_parser_escaped_braces_and_edge_cases() {
    // Escaped double braces: {{ and }}
    let seq = "{{BRACE_PREFIX}} {USERNAME} and {{LITERAL}}";
    let parsed = parse_sequence(seq).unwrap();
    assert_eq!(
        parsed,
        vec![
            AutoTypeToken::Text("{BRACE_PREFIX} ".to_string()),
            AutoTypeToken::Username,
            AutoTypeToken::Text(" and {LITERAL}".to_string()),
        ]
    );

    // Literal single closing brace without open brace is treated as literal
    let seq2 = "Literal}closing brace {PASSWORD}";
    let parsed2 = parse_sequence(seq2).unwrap();
    assert_eq!(
        parsed2,
        vec![
            AutoTypeToken::Text("Literal}closing brace ".to_string()),
            AutoTypeToken::Password,
        ]
    );

    // Multiple adjacent tokens with no spaces
    let seq3 = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
    let parsed3 = parse_sequence(seq3).unwrap();
    assert_eq!(
        parsed3,
        vec![
            AutoTypeToken::Username,
            AutoTypeToken::Tab,
            AutoTypeToken::Password,
            AutoTypeToken::Enter,
        ]
    );

    // Case insensitivity stress
    let seq4 = "{cLeArFiElD}{uSeRnAmE}{tAb}{pAsSwOrD}{tOtP}{dElAy 120}{eNtEr}";
    let parsed4 = parse_sequence(seq4).unwrap();
    assert_eq!(
        parsed4,
        vec![
            AutoTypeToken::ClearField,
            AutoTypeToken::Username,
            AutoTypeToken::Tab,
            AutoTypeToken::Password,
            AutoTypeToken::Totp,
            AutoTypeToken::Delay(120),
            AutoTypeToken::Enter,
        ]
    );

    // Whitespace inside tags
    let seq5 = "{  USERNAME  }{   TAB   }{  PASSWORD  }";
    let parsed5 = parse_sequence(seq5).unwrap();
    assert_eq!(
        parsed5,
        vec![
            AutoTypeToken::Username,
            AutoTypeToken::Tab,
            AutoTypeToken::Password,
        ]
    );
}

#[test]
fn test_challenge_parser_error_handling() {
    // Empty sequences
    assert_eq!(parse_sequence(""), Err(AutoTypeError::EmptySequence));
    assert_eq!(parse_sequence("   "), Err(AutoTypeError::EmptySequence));
    assert_eq!(parse_sequence("\t\r\n"), Err(AutoTypeError::EmptySequence));

    // Unterminated tags
    assert_eq!(parse_sequence("{USERNAME"), Err(AutoTypeError::UnterminatedTag));
    assert_eq!(parse_sequence("test {TAB"), Err(AutoTypeError::UnterminatedTag));
    assert_eq!(parse_sequence("{DELAY 100"), Err(AutoTypeError::UnterminatedTag));
    assert_eq!(parse_sequence("{"), Err(AutoTypeError::UnterminatedTag));

    // Unknown tags
    assert_eq!(
        parse_sequence("{UNKNOWN_TAG}"),
        Err(AutoTypeError::UnknownPlaceholder("UNKNOWN_TAG".to_string()))
    );
    assert_eq!(
        parse_sequence("{SHIFT}"),
        Err(AutoTypeError::UnknownPlaceholder("SHIFT".to_string()))
    );
    assert_eq!(
        parse_sequence("{}"),
        Err(AutoTypeError::UnknownPlaceholder("".to_string()))
    );
    assert_eq!(
        parse_sequence("{   }"),
        Err(AutoTypeError::UnknownPlaceholder("   ".to_string()))
    );
}

#[test]
fn test_challenge_interpolation_error_handling() {
    let mut item = VaultItem::new_credential(
        "Service",
        "user",
        "pass",
        None,
    );

    // Missing username
    item.username = None;
    let tokens = vec![AutoTypeToken::Username];
    let err = interpolate(&tokens, &item, None).unwrap_err();
    assert_eq!(err, AutoTypeError::MissingField("username".to_string()));

    // Missing password
    item.username = Some("user".to_string());
    item.password = None;
    let tokens2 = vec![AutoTypeToken::Password];
    let err2 = interpolate(&tokens2, &item, None).unwrap_err();
    assert_eq!(err2, AutoTypeError::MissingField("password".to_string()));

    // Missing TOTP code when sequence requests {TOTP}
    item.password = Some("pass".to_string());
    let tokens3 = vec![AutoTypeToken::Totp];
    let err3 = interpolate(&tokens3, &item, None).unwrap_err();
    assert_eq!(err3, AutoTypeError::MissingTotp);
}

#[test]
fn test_challenge_unicode_and_emojis_in_passwords_during_autotype() {
    let (engine, backend) = AutoTypeEngine::new_simulated();

    // Password containing mixed ASCII, Latin accents, CJK, and non-BMP Emojis
    let complex_password = "P@ss🗝️🦀\u{10000}2026";
    let item = VaultItem::new_credential(
        "GastinelSecure",
        "agent",
        complex_password,
        None,
    );

    engine
        .execute_sequence("{PASSWORD}", &item, None)
        .expect("Autotype execution with emoji password must succeed");

    let events = backend.recorded_events();
    let down_units: Vec<u16> = events
        .iter()
        .filter_map(|e| match e {
            RecordedEvent::UnicodeChar {
                code_unit,
                action: KeyAction::KeyDown,
            } => Some(*code_unit),
            _ => None,
        })
        .collect();

    let expected_units: Vec<u16> = complex_password.encode_utf16().collect();
    assert_eq!(
        down_units, expected_units,
        "Auto-type must faithfully inject all code units including surrogate pairs for complex passwords"
    );
}
