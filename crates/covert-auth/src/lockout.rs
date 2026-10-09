//! Anti-brute-force rate limiter and persistent lockout state machine.
//!
//! Enforces:
//! - 2 maximum failed attempts -> 1-hour lockout (3,600s).
//! - Repeat lockouts use exponential backoff (3600 * 2^(k-1)).
//! - Persistent state in `dx12_pipeline.lock` (with custom path support for sandboxed tests).
//! - Monotonic tick protection using `GetTickCount64` and monotonic timestamp validation against clock rollback.

use crate::error::LockoutError;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};

/// Base lockout duration in seconds (1 hour).
pub const BASE_LOCKOUT_SECONDS: u64 = 3600;

/// Maximum failed attempts before activating lockout.
pub const MAX_FAILED_ATTEMPTS: u32 = 2;

/// Maximum exponential multiplier shift (prevents integer overflow: 2^10 = 1024x).
pub const MAX_BACKOFF_SHIFT: u32 = 10;

/// Persistent lockout record serialized to disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LockoutRecord {
    /// Number of consecutive failed attempts in the current window.
    pub failed_attempts: u32,
    /// Number of consecutive lockouts triggered (for exponential backoff).
    pub consecutive_lockouts: u32,
    /// Expiration timestamp of the active lockout (Unix epoch seconds).
    pub locked_until_utc: u64,
    /// Timestamp of the last authentication event (Unix epoch seconds).
    pub last_event_utc: u64,
    /// Monotonic system tick count at last event (ms since boot, via GetTickCount64).
    #[serde(default)]
    pub last_boot_tick: u64,
}

/// Status returned after checking or registering an authentication attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockoutStatus {
    /// Authentication attempt is permitted.
    Allowed,
    /// Attempt failed, but lockout threshold has not yet been reached.
    AttemptFailed { attempts_remaining: u32 },
    /// Lockout has been triggered or is currently active.
    LockedOut {
        duration_seconds: u64,
        locked_until_utc: u64,
    },
}

/// Anti-brute-force lockout manager coordinating in-memory state and disk persistence.
#[derive(Debug, Clone)]
pub struct LockoutManager {
    record: LockoutRecord,
    lockout_path: PathBuf,
}

impl Default for LockoutManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LockoutManager {
    /// Creates a new `LockoutManager` with the default camouflaged path:
    /// `%LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.lock`.
    /// Loads any existing record from disk if present.
    pub fn new() -> Self {
        let path = match covert_storage::default_camouflaged_path() {
            Ok(vault_path) => covert_storage::derive_lock_path(&vault_path),
            Err(_) => PathBuf::from("dx12_pipeline.lock"),
        };
        Self::load_or_default(&path)
    }

    /// Creates a `LockoutManager` with a custom file path (e.g. for sandboxed unit tests).
    /// Loads any existing record from disk if present.
    pub fn with_path<P: Into<PathBuf>>(path: P) -> Self {
        let p = path.into();
        Self::load_or_default(&p)
    }

    /// Creates a `LockoutManager` from an existing record and default path.
    pub fn from_record(record: LockoutRecord) -> Self {
        let path = match covert_storage::default_camouflaged_path() {
            Ok(vault_path) => covert_storage::derive_lock_path(&vault_path),
            Err(_) => PathBuf::from("dx12_pipeline.lock"),
        };
        Self {
            record,
            lockout_path: path,
        }
    }

    /// Creates a `LockoutManager` from an existing record and a custom path.
    pub fn from_record_and_path<P: Into<PathBuf>>(record: LockoutRecord, path: P) -> Self {
        Self {
            record,
            lockout_path: path.into(),
        }
    }

    /// Returns a reference to the active `LockoutRecord`.
    pub fn record(&self) -> &LockoutRecord {
        &self.record
    }

    /// Returns a reference to the configured lockout file path.
    pub fn lockout_path(&self) -> &Path {
        &self.lockout_path
    }

    /// Sets the lockout file path.
    pub fn set_lockout_path<P: Into<PathBuf>>(&mut self, path: P) {
        self.lockout_path = path.into();
    }

    /// Checks if authentication is currently locked out at `current_utc`.
    ///
    /// Returns `Ok(true)` if locked out, `Ok(false)` if allowed.
    /// Returns `Err(LockoutError::ClockRollbackDetected)` if `current_utc < last_event_utc`.
    pub fn check_status(&self, current_utc: u64) -> Result<bool, LockoutError> {
        if self.record.last_event_utc > 0 && current_utc < self.record.last_event_utc {
            return Err(LockoutError::ClockRollbackDetected);
        }
        Ok(current_utc < self.record.locked_until_utc)
    }

    /// Checks status and returns an explicit error if currently locked out.
    pub fn check_lockout(&self, current_utc: u64) -> Result<(), LockoutError> {
        if self.check_status(current_utc)? {
            let remaining = self.record.locked_until_utc.saturating_sub(current_utc);
            return Err(LockoutError::LockedOut {
                remaining_seconds: remaining,
            });
        }
        Ok(())
    }

    /// Checks status with monotonic tick verification.
    ///
    /// Evaluates:
    /// 1. Clock rollback: `current_utc < last_event_utc` -> `Err(ClockRollbackDetected)`.
    /// 2. Active lockout check:
    ///    - If a lockout is active (`required_duration > 0`):
    ///      - If `self.record.last_boot_tick > 0` and `current_tick >= self.record.last_boot_tick`:
    ///        - Physical elapsed seconds = `(current_tick - self.record.last_boot_tick) / 1000`.
    ///        - If `elapsed_tick_secs < required_duration`:
    ///          - If `current_utc >= self.record.locked_until_utc`, a clock fast-forward attack
    ///            was attempted -> `Err(ClockRollbackDetected)`.
    ///          - Otherwise, lockout remains active -> `Ok(true)`.
    /// 3. Fallback: post-reboot or expired check:
    ///    - If `current_tick < self.record.last_boot_tick`, a reboot occurred (ticks reset).
    ///    - Fall back to UTC verification: `current_utc < self.record.locked_until_utc`.
    pub fn check_status_monotonic(
        &self,
        current_utc: u64,
        current_tick: u64,
    ) -> Result<bool, LockoutError> {
        // 1. UTC Clock rollback detection
        if self.record.last_event_utc > 0 && current_utc < self.record.last_event_utc {
            return Err(LockoutError::ClockRollbackDetected);
        }

        // 2. Active lockout evaluation
        let required_duration = if self.record.last_event_utc > 0 {
            self.record
                .locked_until_utc
                .saturating_sub(self.record.last_event_utc)
        } else {
            0
        };

        if required_duration > 0 {
            // Check if monotonic ticks are valid and system did not reboot
            if self.record.last_boot_tick > 0 && current_tick >= self.record.last_boot_tick {
                let elapsed_tick_secs = (current_tick - self.record.last_boot_tick) / 1000;
                if elapsed_tick_secs < required_duration {
                    // Physical lockout duration has not yet elapsed.
                    // If UTC indicates expiry, the system clock was tampered with (fast-forwarded).
                    if current_utc >= self.record.locked_until_utc {
                        return Err(LockoutError::ClockRollbackDetected);
                    }
                    return Ok(true);
                }
            }
        }

        // 3. Fallback: post-reboot or expired check
        Ok(current_utc < self.record.locked_until_utc)
    }

    /// Checks status and returns an explicit error if locked out, including monotonic tick verification.
    pub fn check_lockout_monotonic(
        &self,
        current_utc: u64,
        current_tick: u64,
    ) -> Result<(), LockoutError> {
        if self.check_status_monotonic(current_utc, current_tick)? {
            let remaining = self.record.locked_until_utc.saturating_sub(current_utc);
            return Err(LockoutError::LockedOut {
                remaining_seconds: remaining,
            });
        }
        Ok(())
    }

    /// Evaluates lockout status at the current live system time and monotonic tick count.
    pub fn check_status_current(&self) -> Result<bool, LockoutError> {
        let now_utc = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let now_tick = get_system_tick_count();
        self.check_status_monotonic(now_utc, now_tick)
    }

    /// Records a failed authentication attempt at `current_utc`.
    ///
    /// Enforces:
    /// - Clock rollback detection.
    /// - 2 failed attempts -> 1-hour lockout.
    /// - Repeat lockouts -> exponential backoff: `3600 * 2^(k - 1)`.
    pub fn register_failure(&mut self, current_utc: u64) -> Result<LockoutStatus, LockoutError> {
        self.register_failure_at_time_and_tick(current_utc, None)
    }

    /// Records a failed authentication attempt with optional monotonic tick.
    pub fn register_failure_at_time_and_tick(
        &mut self,
        current_utc: u64,
        tick: Option<u64>,
    ) -> Result<LockoutStatus, LockoutError> {
        if self.record.last_event_utc > 0 && current_utc < self.record.last_event_utc {
            return Err(LockoutError::ClockRollbackDetected);
        }

        self.record.last_event_utc = current_utc;
        self.record.last_boot_tick = tick.unwrap_or_else(get_system_tick_count);
        self.record.failed_attempts += 1;

        if self.record.failed_attempts >= MAX_FAILED_ATTEMPTS {
            self.record.consecutive_lockouts += 1;
            let shift = self
                .record
                .consecutive_lockouts
                .saturating_sub(1)
                .min(MAX_BACKOFF_SHIFT);
            let duration = BASE_LOCKOUT_SECONDS * (1u64 << shift);
            self.record.locked_until_utc = current_utc.saturating_add(duration);
            self.record.failed_attempts = 0; // Reset failed attempts after activating lockout

            Ok(LockoutStatus::LockedOut {
                duration_seconds: duration,
                locked_until_utc: self.record.locked_until_utc,
            })
        } else {
            let remaining = MAX_FAILED_ATTEMPTS.saturating_sub(self.record.failed_attempts);
            Ok(LockoutStatus::AttemptFailed {
                attempts_remaining: remaining,
            })
        }
    }

    /// Records a successful authentication, resetting failed attempts, consecutive lockouts,
    /// and active lockout timers.
    pub fn register_success(&mut self, current_utc: u64) {
        self.register_success_at_time_and_tick(current_utc, None);
    }

    /// Records a successful authentication with optional monotonic tick.
    pub fn register_success_at_time_and_tick(&mut self, current_utc: u64, tick: Option<u64>) {
        self.record.failed_attempts = 0;
        self.record.consecutive_lockouts = 0;
        self.record.locked_until_utc = 0;
        self.record.last_event_utc = current_utc;
        self.record.last_boot_tick = tick.unwrap_or_else(get_system_tick_count);
    }

    /// Saves the current lockout record to a specific file in CBOR format atomically
    /// via a temporary file and Win32 ReplaceFileW/FlushFileBuffers substitution.
    pub fn save_to_file(&self, path: &Path) -> Result<(), LockoutError> {
        let mut buffer = Vec::new();
        ciborium::into_writer(&self.record, &mut buffer)
            .map_err(|e| LockoutError::Io(e.to_string()))?;
        covert_storage::write_atomic_no_backup(path, &buffer)
            .map_err(|e| LockoutError::Io(e.to_string()))?;
        Ok(())
    }

    /// Loads a lockout record from a specific file in CBOR format.
    pub fn load_from_file(path: &Path) -> Result<Self, LockoutError> {
        let f = File::open(path).map_err(|e| LockoutError::Io(e.to_string()))?;
        let record: LockoutRecord =
            ciborium::from_reader(f).map_err(|e| LockoutError::Io(e.to_string()))?;
        Ok(Self {
            record,
            lockout_path: path.to_path_buf(),
        })
    }

    /// Saves the current lockout record to `self.lockout_path`.
    pub fn save(&self) -> Result<(), LockoutError> {
        self.save_to_file(&self.lockout_path)
    }

    /// Loads the lockout record from `self.lockout_path`.
    pub fn load(&mut self) -> Result<(), LockoutError> {
        let loaded = Self::load_from_file(&self.lockout_path)?;
        self.record = loaded.record;
        Ok(())
    }

    /// Loads state from `path` if it exists, otherwise creates a new manager with `path`.
    ///
    /// Fail-Closed Resilience: If the file exists but cannot be deserialized (e.g. truncated,
    /// corrupted, or zeroed out), a safety lockout is enforced rather than resetting counters to 0.
    /// This prevents attackers from bypassing active lockouts by corrupting the lock file.
    pub fn load_or_default(path: &Path) -> Self {
        if path.exists() {
            match Self::load_from_file(path) {
                Ok(loaded) => return loaded,
                Err(_) => {
                    // Fail closed: enforce mandatory safety lockout to prevent bypass attacks.
                    let now_utc = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let manager = Self {
                        record: LockoutRecord {
                            failed_attempts: MAX_FAILED_ATTEMPTS,
                            consecutive_lockouts: 1,
                            locked_until_utc: now_utc.saturating_add(BASE_LOCKOUT_SECONDS),
                            last_event_utc: now_utc,
                            last_boot_tick: get_system_tick_count(),
                        },
                        lockout_path: path.to_path_buf(),
                    };
                    let _ = manager.save();
                    return manager;
                }
            }
        }
        Self {
            record: LockoutRecord::default(),
            lockout_path: path.to_path_buf(),
        }
    }
}

/// Queries monotonic tick count from the operating system.
///
/// On Windows, invokes `GetTickCount64()`.
/// On other platforms, falls back to elapsed process time or 0.
pub fn get_system_tick_count() -> u64 {
    #[cfg(windows)]
    {
        unsafe { windows::Win32::System::SystemInformation::GetTickCount64() }
    }
    #[cfg(not(windows))]
    {
        0
    }
}
