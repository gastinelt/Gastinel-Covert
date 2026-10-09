//! Window detection, focus switching, and delay management.

use crate::error::AutoTypeError;
use std::time::Duration;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW, IsWindow, SetForegroundWindow,
    ShowWindow, SW_RESTORE,
};

/// Window focus and target resolution manager.
pub struct WindowManager {
    switch_delay: Duration,
}

impl WindowManager {
    /// Default delay before injecting keystrokes after switching focus (500ms).
    pub const DEFAULT_SWITCH_DELAY: Duration = Duration::from_millis(500);

    /// Create new WindowManager with a custom switch delay.
    pub fn new(switch_delay: Duration) -> Self {
        Self { switch_delay }
    }

    /// Default constructor with 500ms delay.
    pub fn default_delay() -> Self {
        Self::new(Self::DEFAULT_SWITCH_DELAY)
    }

    /// Current switch delay.
    pub fn switch_delay(&self) -> Duration {
        self.switch_delay
    }

    /// Query the current active foreground window.
    pub fn get_foreground_window() -> Option<HWND> {
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.is_invalid() || !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
            None
        } else {
            Some(hwnd)
        }
    }

    /// Query the window title text for a given HWND.
    pub fn get_window_title(hwnd: HWND) -> String {
        if !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
            return String::new();
        }
        let len = unsafe { GetWindowTextLengthW(hwnd) };
        if len <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; (len + 1) as usize];
        let copied = unsafe { GetWindowTextW(hwnd, &mut buf) };
        if copied > 0 {
            String::from_utf16_lossy(&buf[..copied as usize])
        } else {
            String::new()
        }
    }

    /// Switch foreground focus to the specified target window.
    pub fn set_foreground_window(&self, hwnd: HWND) -> Result<(), AutoTypeError> {
        if !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
            return Err(AutoTypeError::TargetWindowInvalid);
        }

        unsafe {
            // Restore window if minimized
            let _ = ShowWindow(hwnd, SW_RESTORE);
            let _ = SetForegroundWindow(hwnd);
        }

        Ok(())
    }

    /// Switch focus to the target window and wait for the configured switch delay.
    pub fn switch_and_wait(&self, hwnd: HWND) -> Result<(), AutoTypeError> {
        self.set_foreground_window(hwnd)?;
        std::thread::sleep(self.switch_delay);

        if !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
            return Err(AutoTypeError::TargetWindowInvalid);
        }

        Ok(())
    }
}

impl Default for WindowManager {
    fn default() -> Self {
        Self::default_delay()
    }
}
