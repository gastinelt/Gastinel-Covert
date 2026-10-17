//! Unit tests for WindowManager and HotkeyManager.

use covert_autotype::{
    AutoTypeError, HotkeyManager, WindowManager, DEFAULT_HOTKEY_ID,
    DEFAULT_HOTKEY_MODIFIERS, DEFAULT_HOTKEY_VK,
};
use std::time::Duration;
use windows::Win32::Foundation::HWND;

#[test]
fn test_window_manager_delays() {
    let wm_default = WindowManager::default_delay();
    assert_eq!(wm_default.switch_delay(), Duration::from_millis(500));

    let wm_custom = WindowManager::new(Duration::from_millis(150));
    assert_eq!(wm_custom.switch_delay(), Duration::from_millis(150));
}

#[test]
fn test_window_manager_invalid_hwnd() {
    let wm = WindowManager::new(Duration::from_millis(10));
    let invalid_hwnd = HWND(std::ptr::null_mut());

    let res = wm.set_foreground_window(invalid_hwnd);
    assert_eq!(res, Err(AutoTypeError::TargetWindowInvalid));

    let title = WindowManager::get_window_title(invalid_hwnd);
    assert!(title.is_empty());
}

#[test]
fn test_window_manager_active_foreground() {
    // If a window is currently active, we can retrieve its handle and title
    if let Some(hwnd) = WindowManager::get_foreground_window() {
        assert!(!hwnd.is_invalid());
        let _title = WindowManager::get_window_title(hwnd);
    }
}

#[test]
fn test_hotkey_constants() {
    assert_eq!(DEFAULT_HOTKEY_ID, 0x4743);
    assert_eq!(DEFAULT_HOTKEY_VK, 0x41); // 'A'
    const { assert!(DEFAULT_HOTKEY_MODIFIERS & 0x0002 != 0) }; // MOD_CONTROL
    const { assert!(DEFAULT_HOTKEY_MODIFIERS & 0x0001 != 0) }; // MOD_ALT
}

#[test]
#[ignore = "injecte de vraies frappes clavier / manipule la fenetre au premier plan ; lancer volontairement avec: cargo test -- --ignored"]
fn test_hotkey_manager_lifecycle() {
    // Attempt registration with a unique test hotkey ID and unregistration
    // Using VK_F12 (0x7B) with Ctrl+Alt to avoid collision with standard hotkeys
    let test_id = 0x5555;
    let test_vk = 0x7B; // VK_F12
    let test_mod = 0x0002 | 0x0001; // MOD_CONTROL | MOD_ALT

    // Registration may succeed or fail if hotkey is held by another process;
    // but if it succeeds, unregistration must succeed and drop must be safe
    if let Ok(mut mgr) = HotkeyManager::register(None, test_id, test_mod, test_vk) {
        assert!(mgr.is_registered());
        assert_eq!(mgr.id(), test_id);
        assert!(mgr.unregister().is_ok());
        assert!(!mgr.is_registered());
    }
}
