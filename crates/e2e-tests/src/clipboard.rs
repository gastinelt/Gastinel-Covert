//! Windows clipboard security flags and auto-wipe timer model.

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

pub const CF_CAN_INCLUDE_IN_CLIPBOARD_HISTORY: &str = "CanIncludeInClipboardHistory";
pub const CF_CAN_UPLOAD_TO_CLOUD_CLIPBOARD: &str = "CanUploadToCloudClipboard";
pub const CF_EXCLUDE_CLIPBOARD_MONITOR: &str = "ExcludeClipboardContentFromMonitorProcessing";

pub struct ClipboardGuard {
    content: Option<SecretString>,
    copied_at: u64,
    timeout_secs: u64,
    sequence_number: u32,
    pub history_flag_set: bool,
    pub cloud_sync_flag_set: bool,
}

impl ClipboardGuard {
    pub fn new(content: SecretString, copied_at: u64, timeout_secs: u64, sequence_number: u32) -> Self {
        Self {
            content: Some(content),
            copied_at,
            timeout_secs,
            sequence_number,
            history_flag_set: true,
            cloud_sync_flag_set: true,
        }
    }

    pub fn has_content(&self) -> bool {
        self.content.is_some()
    }

    /// Check if auto-wipe should execute.
    ///
    /// Auto-wipe triggers ONLY IF:
    /// 1. Timeout duration has expired (`current_time >= copied_at + timeout_secs`)
    /// 2. Clipboard sequence number has NOT changed (user hasn't copied other data)
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

    /// Execute secure memory wipe of clipboard buffer.
    pub fn wipe(&mut self) {
        if let Some(secret) = self.content.take() {
            // Zeroize exposed bytes
            unsafe {
                let bytes = secret.expose_secret().as_bytes() as *const [u8] as *mut [u8];
                (*bytes).zeroize();
            }
        }
    }
}
