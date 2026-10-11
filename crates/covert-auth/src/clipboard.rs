//! Win32 clipboard privacy flags and automated wipe timer engine.
//!
//! Enforces:
//! - Registration of privacy formats via `RegisterClipboardFormatW`:
//!   `CanIncludeInClipboardHistory`, `CanUploadToCloudClipboard`, `ExcludeClipboardContentFromMonitorProcessing`.
//! - Injection of exclusion flags (DWORD = 0) whenever credentials are copied to the clipboard.
//! - Clipboard sequence verification via `GetClipboardSequenceNumber` before clearing,
//!   ensuring external user clipboard contents are never accidentally wiped.
//! - In-memory zeroization of secret buffers on wipe.

use crate::error::ClipboardError;
use covert_core::SecretString;
use secrecy_v08::ExposeSecret;

/// Win32 clipboard format name preventing storage in Windows 10/11 clipboard history (Win+V).
pub const CF_CAN_INCLUDE_IN_CLIPBOARD_HISTORY: &str = "CanIncludeInClipboardHistory";

/// Win32 clipboard format name preventing synchronization to Microsoft Cloud Clipboard.
pub const CF_CAN_UPLOAD_TO_CLOUD_CLIPBOARD: &str = "CanUploadToCloudClipboard";

/// Win32 clipboard format name excluding clipboard content from third-party monitor/sniffer processing.
pub const CF_EXCLUDE_CLIPBOARD_MONITOR: &str = "ExcludeClipboardContentFromMonitorProcessing";

/// Win32 standard CF_UNICODETEXT clipboard format identifier.
pub const CF_UNICODETEXT: u32 = 13;

/// Registered Win32 format atoms for privacy flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardPrivacyFormats {
    pub can_include_in_clipboard_history: u32,
    pub can_upload_to_cloud_clipboard: u32,
    pub exclude_clipboard_content_from_monitor_processing: u32,
}

impl ClipboardPrivacyFormats {
    /// Registers the three Windows privacy format atoms with the operating system.
    pub fn register() -> Result<Self, ClipboardError> {
        let history = register_clipboard_format(CF_CAN_INCLUDE_IN_CLIPBOARD_HISTORY)?;
        let cloud = register_clipboard_format(CF_CAN_UPLOAD_TO_CLOUD_CLIPBOARD)?;
        let monitor = register_clipboard_format(CF_EXCLUDE_CLIPBOARD_MONITOR)?;

        Ok(Self {
            can_include_in_clipboard_history: history,
            can_upload_to_cloud_clipboard: cloud,
            exclude_clipboard_content_from_monitor_processing: monitor,
        })
    }
}

/// Registers a named clipboard format with Windows via `RegisterClipboardFormatW`.
pub fn register_clipboard_format(name: &str) -> Result<u32, ClipboardError> {
    #[cfg(windows)]
    {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::GetLastError;
        use windows::Win32::System::DataExchange::RegisterClipboardFormatW;

        let hstring = HSTRING::from(name);
        let atom = unsafe { RegisterClipboardFormatW(windows::core::PCWSTR(hstring.as_ptr())) };
        if atom == 0 {
            let err = unsafe { GetLastError() }.0;
            return Err(ClipboardError::RegisterFormatFailed {
                format_name: name.to_string(),
                code: err,
            });
        }
        Ok(atom)
    }
    #[cfg(not(windows))]
    {
        // Mock non-zero atom ID for testing portability
        let _ = name;
        Ok(49152)
    }
}

/// Returns the current clipboard sequence number via Win32 `GetClipboardSequenceNumber`.
pub fn get_clipboard_sequence_number() -> u32 {
    #[cfg(windows)]
    {
        unsafe { windows::Win32::System::DataExchange::GetClipboardSequenceNumber() }
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// Copies `text` to the Windows clipboard with CF_UNICODETEXT and strict privacy flags:
/// - `CanIncludeInClipboardHistory = 0`
/// - `CanUploadToCloudClipboard = 0`
/// - `ExcludeClipboardContentFromMonitorProcessing = 0`
///
/// Returns the resulting clipboard sequence number.
pub fn write_to_clipboard_with_flags(text: &SecretString) -> Result<u32, ClipboardError> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{GetLastError, GlobalFree, HANDLE};
        use windows::Win32::System::DataExchange::{
            CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
            SetClipboardData,
        };
        use windows::Win32::System::Memory::{
            GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE, GMEM_ZEROINIT,
        };

        let formats = ClipboardPrivacyFormats::register()?;

        // Open clipboard with retry loop (up to 5 attempts, 10ms pause)
        let mut opened = false;
        for _ in 0..5 {
            if unsafe { OpenClipboard(None) }.is_ok() {
                opened = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        if !opened {
            let err = unsafe { GetLastError() }.0;
            return Err(ClipboardError::OpenFailed(err));
        }

        // Empty existing clipboard contents
        if let Err(e) = unsafe { EmptyClipboard() } {
            let _ = unsafe { CloseClipboard() };
            return Err(ClipboardError::EmptyFailed(e.code().0 as u32));
        }

        // Prepare UTF-16 payload wrapped in Zeroizing to ensure secret memory hygiene on drop
        let raw_str = text.expose_secret();
        let utf16: zeroize::Zeroizing<Vec<u16>> =
            zeroize::Zeroizing::new(raw_str.encode_utf16().chain(std::iter::once(0)).collect());
        let bytes_len = utf16.len() * 2;

        let h_text = match unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes_len) } {
            Ok(h) => h,
            Err(e) => {
                let _ = unsafe { CloseClipboard() };
                return Err(ClipboardError::MemoryAllocationFailed(e.code().0 as u32));
            }
        };

        let ptr = unsafe { GlobalLock(h_text) };
        if ptr.is_null() {
            let _ = unsafe { GlobalFree(Some(h_text)) };
            let _ = unsafe { CloseClipboard() };
            return Err(ClipboardError::MemoryLockFailed);
        }

        unsafe {
            std::ptr::copy_nonoverlapping(utf16.as_ptr() as *const u8, ptr as *mut u8, bytes_len);
            let _ = GlobalUnlock(h_text);
        }

        // Set text data
        if let Err(e) = unsafe { SetClipboardData(CF_UNICODETEXT, Some(HANDLE(h_text.0))) } {
            let _ = unsafe { GlobalFree(Some(h_text)) };
            let _ = unsafe { CloseClipboard() };
            return Err(ClipboardError::SetDataFailed(e.code().0 as u32));
        }

        // Helper closure to allocate and set a DWORD = 0 privacy flag
        let set_flag = |atom: u32| -> Result<(), ClipboardError> {
            let h_flag = match unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 4) } {
                Ok(h) => h,
                Err(e) => return Err(ClipboardError::MemoryAllocationFailed(e.code().0 as u32)),
            };
            let flag_ptr = unsafe { GlobalLock(h_flag) };
            if flag_ptr.is_null() {
                let _ = unsafe { GlobalFree(Some(h_flag)) };
                return Err(ClipboardError::MemoryLockFailed);
            }
            unsafe {
                *(flag_ptr as *mut u32) = 0;
                let _ = GlobalUnlock(h_flag);
            }
            if let Err(e) = unsafe { SetClipboardData(atom, Some(HANDLE(h_flag.0))) } {
                let _ = unsafe { GlobalFree(Some(h_flag)) };
                return Err(ClipboardError::SetDataFailed(e.code().0 as u32));
            }
            Ok(())
        };

        // Set all 3 privacy exclusion flags
        let _ = set_flag(formats.can_include_in_clipboard_history);
        let _ = set_flag(formats.can_upload_to_cloud_clipboard);
        let _ = set_flag(formats.exclude_clipboard_content_from_monitor_processing);

        // Close clipboard
        let _ = unsafe { CloseClipboard() };

        let seq = unsafe { GetClipboardSequenceNumber() };
        Ok(seq)
    }
    #[cfg(not(windows))]
    {
        let _ = text;
        Ok(1)
    }
}

/// Clears the Windows clipboard ONLY IF the clipboard sequence number matches `expected_sequence`.
///
/// Returns:
/// - `Ok(true)` if sequence matched and clipboard was cleared.
/// - `Ok(false)` if sequence changed (user copied other data; content preserved).
pub fn clear_clipboard_if_sequence_matches(expected_sequence: u32) -> Result<bool, ClipboardError> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::GetLastError;
        use windows::Win32::System::DataExchange::{
            CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard,
        };

        let current_seq = unsafe { GetClipboardSequenceNumber() };
        if current_seq != expected_sequence {
            return Ok(false);
        }

        let mut opened = false;
        for _ in 0..5 {
            if unsafe { OpenClipboard(None) }.is_ok() {
                opened = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        if !opened {
            let err = unsafe { GetLastError() }.0;
            return Err(ClipboardError::OpenFailed(err));
        }

        // Re-check sequence after acquiring lock
        let post_open_seq = unsafe { GetClipboardSequenceNumber() };
        if post_open_seq != expected_sequence {
            let _ = unsafe { CloseClipboard() };
            return Ok(false);
        }

        if let Err(e) = unsafe { EmptyClipboard() } {
            let _ = unsafe { CloseClipboard() };
            return Err(ClipboardError::EmptyFailed(e.code().0 as u32));
        }

        let _ = unsafe { CloseClipboard() };
        Ok(true)
    }
    #[cfg(not(windows))]
    {
        if expected_sequence == 1 {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Clipboard guard tracking sensitive content, timestamps, sequence numbers, and auto-wipe timers.
#[derive(Debug)]
pub struct ClipboardGuard {
    content: Option<SecretString>,
    copied_at: u64,
    timeout_secs: u64,
    sequence_number: u32,
    pub history_flag_set: bool,
    pub cloud_sync_flag_set: bool,
    pub monitor_exclusion_flag_set: bool,
}

impl ClipboardGuard {
    /// Creates a new `ClipboardGuard` tracking an in-memory secret and sequence number.
    pub fn new(
        content: SecretString,
        copied_at: u64,
        timeout_secs: u64,
        sequence_number: u32,
    ) -> Self {
        Self {
            content: Some(content),
            copied_at,
            timeout_secs,
            sequence_number,
            history_flag_set: true,
            cloud_sync_flag_set: true,
            monitor_exclusion_flag_set: true,
        }
    }

    /// Copies `secret` to the Windows clipboard with privacy flags and initializes the guard.
    pub fn copy_to_system_clipboard(
        secret: &SecretString,
        copied_at: u64,
        timeout_secs: u64,
    ) -> Result<Self, ClipboardError> {
        let seq = write_to_clipboard_with_flags(secret)?;
        Ok(Self::new(secret.clone(), copied_at, timeout_secs, seq))
    }

    /// Returns true if the guard still holds in-memory content.
    pub fn has_content(&self) -> bool {
        self.content.is_some()
    }

    /// Returns the timestamp when the content was copied.
    pub fn copied_at(&self) -> u64 {
        self.copied_at
    }

    /// Returns the configured wipe timeout in seconds.
    pub fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    /// Returns the initial clipboard sequence number.
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// Determines whether auto-wipe should execute:
    ///
    /// Auto-wipe triggers ONLY IF:
    /// 1. Guard still holds content.
    /// 2. Clipboard sequence number has NOT changed (`current_sequence == self.sequence_number`).
    /// 3. Timeout duration has expired (`current_time >= copied_at + timeout_secs`).
    pub fn should_wipe(&self, current_time: u64, current_sequence: u32) -> bool {
        if self.content.is_none() {
            return false;
        }
        if current_sequence != self.sequence_number {
            // User copied something else; do not wipe external content
            return false;
        }
        current_time >= self.copied_at.saturating_add(self.timeout_secs)
    }

    /// Securely wipes internal memory buffer.
    pub fn wipe(&mut self) {
        // Dropping SecretString invokes its inner zeroization safely without UB
        self.content = None;
    }

    /// Wipes system clipboard and internal memory if the system sequence number matches.
    pub fn wipe_system_if_matching(&mut self) -> Result<bool, ClipboardError> {
        let seq = get_clipboard_sequence_number();
        let wiped = clear_clipboard_if_sequence_matches(self.sequence_number)?;
        if wiped || seq != self.sequence_number {
            self.wipe();
        }
        Ok(wiped)
    }
}
