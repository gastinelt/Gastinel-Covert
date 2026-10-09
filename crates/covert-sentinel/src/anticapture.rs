//! Anti-screen-capture protection via SetWindowDisplayAffinity.

use crate::error::SentinelError;

#[cfg(windows)]
use windows::Win32::Foundation::HWND;
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR,
};

/// Apply screen capture exclusion protection to the specified window handle.
///
/// Under Windows, this invokes `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` (0x00000011).
/// If `WDA_EXCLUDEFROMCAPTURE` is not supported (e.g. older Windows builds), it falls back
/// to `WDA_MONITOR` (0x00000001).
pub fn apply_screen_capture_protection(hwnd: isize) -> Result<(), SentinelError> {
    if hwnd <= 0 {
        return Err(SentinelError::InvalidHandle(hwnd));
    }

    #[cfg(windows)]
    {
        let window_handle = HWND(hwnd as *mut _);

        // First attempt: WDA_EXCLUDEFROMCAPTURE (Windows 10 2004+)
        let result = unsafe { SetWindowDisplayAffinity(window_handle, WDA_EXCLUDEFROMCAPTURE) };
        if result.is_ok() {
            return Ok(());
        }

        // Fallback: WDA_MONITOR
        let fallback_result = unsafe { SetWindowDisplayAffinity(window_handle, WDA_MONITOR) };
        if fallback_result.is_ok() {
            return Ok(());
        }

        Err(SentinelError::AntiCapture(format!(
            "SetWindowDisplayAffinity failed with error: {:?}",
            result.err()
        )))
    }

    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_handle_rejected() {
        let res = apply_screen_capture_protection(0);
        assert!(res.is_err());
        match res.unwrap_err() {
            SentinelError::InvalidHandle(h) => assert_eq!(h, 0),
            other => panic!("Unexpected error variant: {:?}", other),
        }

        let res_neg = apply_screen_capture_protection(-1);
        assert!(res_neg.is_err());
        match res_neg.unwrap_err() {
            SentinelError::InvalidHandle(h) => assert_eq!(h, -1),
            other => panic!("Unexpected error variant: {:?}", other),
        }
    }
}
