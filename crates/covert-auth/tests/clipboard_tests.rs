use covert_auth::clipboard::{
    clear_clipboard_if_sequence_matches, get_clipboard_sequence_number, register_clipboard_format,
    write_to_clipboard_with_flags, ClipboardGuard, ClipboardPrivacyFormats,
    CF_CAN_INCLUDE_IN_CLIPBOARD_HISTORY, CF_CAN_UPLOAD_TO_CLOUD_CLIPBOARD,
    CF_EXCLUDE_CLIPBOARD_MONITOR,
};
use covert_core::SecretString;

#[test]
fn test_win32_clipboard_privacy_flags_registration() {
    let formats = ClipboardPrivacyFormats::register().expect("Registration failed");

    // All registered format atoms must be non-zero
    assert_ne!(formats.can_include_in_clipboard_history, 0);
    assert_ne!(formats.can_upload_to_cloud_clipboard, 0);
    assert_ne!(formats.exclude_clipboard_content_from_monitor_processing, 0);

    // Direct registration check
    let atom1 = register_clipboard_format(CF_CAN_INCLUDE_IN_CLIPBOARD_HISTORY).unwrap();
    let atom2 = register_clipboard_format(CF_CAN_UPLOAD_TO_CLOUD_CLIPBOARD).unwrap();
    let atom3 = register_clipboard_format(CF_EXCLUDE_CLIPBOARD_MONITOR).unwrap();

    assert_eq!(atom1, formats.can_include_in_clipboard_history);
    assert_eq!(atom2, formats.can_upload_to_cloud_clipboard);
    assert_eq!(atom3, formats.exclude_clipboard_content_from_monitor_processing);
}

#[test]
fn test_clipboard_guard_timeout_and_sequence_retention() {
    let payload = SecretString::new("SuperSecretApiKeyForTesting".to_string());
    let copy_time = 5000u64;
    let timeout = 30u64;
    let initial_sequence = 42u32;

    let mut guard = ClipboardGuard::new(payload, copy_time, timeout, initial_sequence);

    assert!(guard.has_content());
    assert!(guard.history_flag_set);
    assert!(guard.cloud_sync_flag_set);
    assert!(guard.monitor_exclusion_flag_set);
    assert_eq!(guard.sequence_number(), initial_sequence);

    // 10s later: should NOT wipe
    assert!(!guard.should_wipe(copy_time + 10, initial_sequence));

    // 29s later: should NOT wipe
    assert!(!guard.should_wipe(copy_time + 29, initial_sequence));

    // 30s later (timeout reached): SHOULD wipe
    assert!(guard.should_wipe(copy_time + 30, initial_sequence));

    // 35s later: SHOULD wipe
    assert!(guard.should_wipe(copy_time + 35, initial_sequence));

    // CRITICAL: If clipboard sequence number changed (user copied something else), do NOT wipe
    let external_sequence = 43u32;
    assert!(!guard.should_wipe(copy_time + 30, external_sequence));
    assert!(!guard.should_wipe(copy_time + 60, external_sequence));

    // Execute wipe: clears in-memory content
    guard.wipe();
    assert!(!guard.has_content());
    assert!(!guard.should_wipe(copy_time + 35, initial_sequence));
}

#[cfg(windows)]
#[test]
fn test_win32_clipboard_live_copy_and_wipe() {
    let secret = SecretString::new("GastinelCovertLiveSecret2026".to_string());

    // Copy to clipboard with privacy flags
    let seq = write_to_clipboard_with_flags(&secret).expect("Write to clipboard failed");
    assert!(seq > 0);

    // Current sequence must match returned sequence
    let current_seq = get_clipboard_sequence_number();
    assert_eq!(seq, current_seq);

    // Clear clipboard if sequence matches
    let wiped = clear_clipboard_if_sequence_matches(seq).expect("Clear clipboard failed");
    assert!(wiped);

    // Trying to clear again with old sequence must return false (sequence changed after EmptyClipboard)
    let new_seq = get_clipboard_sequence_number();
    assert_ne!(seq, new_seq);
    let second_wipe = clear_clipboard_if_sequence_matches(seq).unwrap();
    assert!(!second_wipe, "Wipe should be skipped when sequence changed");
}
