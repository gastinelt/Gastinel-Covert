//! Global Windows hotkey registration and message pump listener.

use crate::error::AutoTypeError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    RegisterHotKey, UnregisterHotKey, HOT_KEY_MODIFIERS, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    PeekMessageW, MSG, PM_REMOVE, WM_HOTKEY, WM_QUIT,
};

/// Default hotkey identifier.
pub const DEFAULT_HOTKEY_ID: i32 = 0x4743; // 'G' 'C'

/// Default modifiers: Ctrl + Alt + NoRepeat.
pub const DEFAULT_HOTKEY_MODIFIERS: u32 = MOD_CONTROL.0 | MOD_ALT.0 | MOD_NOREPEAT.0;

/// Default virtual key: 'A' (0x41).
pub const DEFAULT_HOTKEY_VK: u32 = 0x41;

/// RAII manager for a registered global Windows hotkey.
pub struct HotkeyManager {
    id: i32,
    hwnd: Option<HWND>,
    registered: bool,
}

impl HotkeyManager {
    /// Register a global hotkey for the given window (or thread if `None`).
    pub fn register(
        hwnd: Option<HWND>,
        id: i32,
        modifiers: u32,
        vk: u32,
    ) -> Result<Self, AutoTypeError> {
        let res = unsafe {
            RegisterHotKey(
                hwnd,
                id,
                HOT_KEY_MODIFIERS(modifiers),
                vk,
            )
        };

        if let Err(e) = res {
            return Err(AutoTypeError::HotkeyFailed(format!(
                "Failed to register hotkey id {id} (mod {modifiers:#x}, vk {vk:#x}): {e}"
            )));
        }

        Ok(Self {
            id,
            hwnd,
            registered: true,
        })
    }

    /// Register default shortcut: `Ctrl + Alt + A`.
    pub fn register_default(hwnd: Option<HWND>) -> Result<Self, AutoTypeError> {
        Self::register(
            hwnd,
            DEFAULT_HOTKEY_ID,
            DEFAULT_HOTKEY_MODIFIERS,
            DEFAULT_HOTKEY_VK,
        )
    }

    /// Explicitly unregister the hotkey.
    pub fn unregister(&mut self) -> Result<(), AutoTypeError> {
        if self.registered {
            let res = unsafe { UnregisterHotKey(self.hwnd, self.id) };
            if let Err(e) = res {
                return Err(AutoTypeError::HotkeyFailed(format!(
                    "Failed to unregister hotkey id {}: {e}",
                    self.id
                )));
            }
            self.registered = false;
        }
        Ok(())
    }

    /// Returns whether the hotkey is currently registered.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Return the hotkey ID.
    pub fn id(&self) -> i32 {
        self.id
    }
}

impl Drop for HotkeyManager {
    fn drop(&mut self) {
        let _ = self.unregister();
    }
}

/// Dedicated background message pump listener for `WM_HOTKEY` events.
pub struct HotkeyListener {
    running: Arc<AtomicBool>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl HotkeyListener {
    /// Start listening for hotkey triggers on a dedicated message-pump thread.
    pub fn start<F>(id: i32, modifiers: u32, vk: u32, callback: F) -> Result<Self, AutoTypeError>
    where
        F: Fn() + Send + 'static,
    {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let (tx, rx) = std::sync::mpsc::channel();

        let handle = std::thread::spawn(move || {
            let reg_res = unsafe {
                RegisterHotKey(
                    None,
                    id,
                    HOT_KEY_MODIFIERS(modifiers),
                    vk,
                )
            };

            if let Err(e) = reg_res {
                let _ = tx.send(Err(AutoTypeError::HotkeyFailed(format!("{e}"))));
                return;
            }

            let _ = tx.send(Ok(()));

            let mut msg = MSG::default();
            while running_clone.load(Ordering::SeqCst) {
                let has_msg = unsafe {
                    PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool()
                };

                if has_msg {
                    if msg.message == WM_QUIT {
                        break;
                    }
                    if msg.message == WM_HOTKEY && msg.wParam.0 as i32 == id {
                        callback();
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(15));
                }
            }

            unsafe {
                let _ = UnregisterHotKey(None, id);
            }
        });

        match rx.recv() {
            Ok(Ok(())) => Ok(Self {
                running,
                thread_handle: Some(handle),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(AutoTypeError::HotkeyFailed(
                "Hotkey listener thread terminated prematurely".to_string(),
            )),
        }
    }

    /// Start listening for default shortcut `Ctrl + Alt + A`.
    pub fn start_default<F>(callback: F) -> Result<Self, AutoTypeError>
    where
        F: Fn() + Send + 'static,
    {
        Self::start(
            DEFAULT_HOTKEY_ID,
            DEFAULT_HOTKEY_MODIFIERS,
            DEFAULT_HOTKEY_VK,
            callback,
        )
    }

    /// Stop the message pump listener and unregister the hotkey.
    pub fn stop(&mut self) {
        if self.running.swap(false, Ordering::SeqCst) {
            if let Some(handle) = self.thread_handle.take() {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for HotkeyListener {
    fn drop(&mut self) {
        self.stop();
    }
}
