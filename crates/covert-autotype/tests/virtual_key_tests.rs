//! Unit tests for virtual key mapping and macro actions.

use covert_autotype::{
    AutoTypeEngine, KeyAction, RecordedEvent, VirtualKey,
};
use covert_core::models::VaultItem;

#[test]
fn test_virtual_key_codes() {
    assert_eq!(VirtualKey::Tab.to_vk_code(), 0x09);
    assert_eq!(VirtualKey::Return.to_vk_code(), 0x0D);
    assert_eq!(VirtualKey::Escape.to_vk_code(), 0x1B);
    assert_eq!(VirtualKey::Backspace.to_vk_code(), 0x08);
    assert_eq!(VirtualKey::Space.to_vk_code(), 0x20);
    assert_eq!(VirtualKey::Control.to_vk_code(), 0x11);
    assert_eq!(VirtualKey::A.to_vk_code(), 0x41);
    assert_eq!(VirtualKey::Custom(0x7F).to_vk_code(), 0x7F);

    assert_eq!(VirtualKey::from_vk_code(0x09), VirtualKey::Tab);
    assert_eq!(VirtualKey::from_vk_code(0x0D), VirtualKey::Return);
    assert_eq!(VirtualKey::from_vk_code(0x1B), VirtualKey::Escape);
    assert_eq!(VirtualKey::from_vk_code(0x08), VirtualKey::Backspace);
    assert_eq!(VirtualKey::from_vk_code(0x20), VirtualKey::Space);
    assert_eq!(VirtualKey::from_vk_code(0x11), VirtualKey::Control);
    assert_eq!(VirtualKey::from_vk_code(0x41), VirtualKey::A);
    assert_eq!(VirtualKey::from_vk_code(0x99), VirtualKey::Custom(0x99));
}

#[test]
fn test_simulated_backend_virtual_key_injection() {
    let (engine, backend) = AutoTypeEngine::new_simulated();

    engine.send_key_press(VirtualKey::Tab).unwrap();
    engine.send_key_press(VirtualKey::Return).unwrap();

    let events = backend.recorded_events();
    assert_eq!(
        events,
        vec![
            RecordedEvent::VirtualKey {
                vk: 0x09,
                action: KeyAction::KeyDown,
            },
            RecordedEvent::VirtualKey {
                vk: 0x09,
                action: KeyAction::KeyUp,
            },
            RecordedEvent::VirtualKey {
                vk: 0x0D,
                action: KeyAction::KeyDown,
            },
            RecordedEvent::VirtualKey {
                vk: 0x0D,
                action: KeyAction::KeyUp,
            },
        ]
    );
}

#[test]
fn test_clearfield_macro_sequence() {
    let (engine, backend) = AutoTypeEngine::new_simulated();

    let item = VaultItem::new_credential(
        "Service",
        "user123",
        "secretpass",
        None,
    );

    // Sequence with CLEARFIELD prefix
    engine
        .execute_sequence("{CLEARFIELD}{USERNAME}", &item, None)
        .unwrap();

    let events = backend.recorded_events();

    // Verify ClearField produces Ctrl+A then Backspace
    // Ctrl Down, A Down, A Up, Ctrl Up, Backspace Down, Backspace Up
    let expected_prefix = [
        RecordedEvent::VirtualKey {
            vk: 0x11, // Control
            action: KeyAction::KeyDown,
        },
        RecordedEvent::VirtualKey {
            vk: 0x41, // 'A'
            action: KeyAction::KeyDown,
        },
        RecordedEvent::VirtualKey {
            vk: 0x41, // 'A'
            action: KeyAction::KeyUp,
        },
        RecordedEvent::VirtualKey {
            vk: 0x11, // Control
            action: KeyAction::KeyUp,
        },
        RecordedEvent::VirtualKey {
            vk: 0x08, // Backspace
            action: KeyAction::KeyDown,
        },
        RecordedEvent::VirtualKey {
            vk: 0x08, // Backspace
            action: KeyAction::KeyUp,
        },
    ];

    assert_eq!(&events[..6], &expected_prefix[..]);

    // Following events are username chars
    let username_events: Vec<u16> = events[6..]
        .iter()
        .filter_map(|ev| match ev {
            RecordedEvent::UnicodeChar {
                code_unit,
                action: KeyAction::KeyDown,
            } => Some(*code_unit),
            _ => None,
        })
        .collect();

    let expected_user: Vec<u16> = "user123".encode_utf16().collect();
    assert_eq!(username_events, expected_user);
}
