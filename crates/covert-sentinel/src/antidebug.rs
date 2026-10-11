//! Anti-debugger watchdog inspecting IsDebuggerPresent and the PEB BeingDebugged flag.

use crate::error::SentinelError;
use crate::{SecurityEvent, SecurityEventSink};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;

/// Read the PEB `BeingDebugged` byte directly on x86_64 Windows architectures.
#[cfg(all(windows, target_arch = "x86_64"))]
pub fn check_peb_being_debugged() -> bool {
    unsafe {
        use std::arch::asm;
        let peb: usize;
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(pure, readonly, nostack)
        );
        if peb == 0 {
            return false;
        }
        let being_debugged = *(peb as *const u8).add(2);
        being_debugged != 0
    }
}

/// Fallback for non-x86_64 or non-Windows platforms.
#[cfg(not(all(windows, target_arch = "x86_64")))]
pub fn check_peb_being_debugged() -> bool {
    false
}

/// Detects if a debugger is currently attached using Win32 API and direct PEB inspection.
pub fn is_debugger_attached() -> bool {
    #[cfg(windows)]
    {
        let api_flag = unsafe { IsDebuggerPresent().as_bool() };
        if api_flag {
            return true;
        }
        if check_peb_being_debugged() {
            return true;
        }
        false
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Background watchdog thread checking for debugger attachment.
pub struct AntiDebugWatchdog {
    stop_signal: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl AntiDebugWatchdog {
    /// Start the anti-debug watchdog with the specified polling interval.
    pub fn start(
        sink: Arc<dyn SecurityEventSink>,
        interval: Duration,
    ) -> Result<Self, SentinelError> {
        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop_signal);

        let handle = thread::Builder::new()
            .name("covert-antidebug-watchdog".to_string())
            .spawn(move || {
                while !stop_clone.load(Ordering::Relaxed) {
                    if is_debugger_attached() {
                        sink.on_security_alert(SecurityEvent::DebuggerAttached);
                    }
                    thread::sleep(interval);
                }
            })
            .map_err(|e| SentinelError::ThreadError(e.to_string()))?;

        Ok(Self {
            stop_signal,
            handle: Some(handle),
        })
    }

    /// Stop the watchdog background thread.
    pub fn stop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for AntiDebugWatchdog {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debugger_detection_callable() {
        // Under normal test execution without a debugger attached, this returns false
        let attached = is_debugger_attached();
        // Just verify it doesn't crash or fault
        let _ = attached;
    }
}
