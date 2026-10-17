//! Anti-brute-force rate limiter and persistent lockout state machine.
//!
//! Enforces:
//! - 2 maximum failed attempts -> 1-hour lockout (3,600s).
//! - Repeat lockouts use exponential backoff (3600 * 2^(k-1)).
//! - Persistent state in `dx12_pipeline.lock` (with custom path support for sandboxed tests).
//! - Monotonic tick protection using `GetTickCount64` and monotonic timestamp validation against clock rollback.

use crate::error::LockoutError;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
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
    /// Tracks whether the lockout file has been persisted on disk in this or a prior session,
    /// allowing deletion of `.lock` to be caught immediately as a tamper event.
    persisted_on_disk: Cell<bool>,
}

impl Default for LockoutManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LockoutManager {
    /// Creates a new in-memory `LockoutManager` with the default camouflaged path:
    /// `%LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.lock`.
    /// Loads any existing record from disk if present without touching disk on construction.
    pub fn new() -> Self {
        let path = match covert_storage::default_camouflaged_path() {
            Ok(vault_path) => covert_storage::derive_lock_path(&vault_path),
            Err(_) => PathBuf::from("dx12_pipeline.lock"),
        };
        if path.exists() {
            if let Ok(loaded) = Self::load_from_file(&path) {
                return loaded;
            }
        }
        Self {
            record: LockoutRecord::default(),
            lockout_path: path,
            persisted_on_disk: Cell::new(false),
        }
    }

    /// Creates a `LockoutManager` with a specific file path.
    /// Loads any existing record from disk if present, or fails closed if the companion
    /// vault (`.bin` / `.bin.bak`) exists on disk while `.lock` was deleted.
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
            persisted_on_disk: Cell::new(false),
        }
    }

    /// Creates a `LockoutManager` from an existing record and a custom path.
    pub fn from_record_and_path<P: Into<PathBuf>>(record: LockoutRecord, path: P) -> Self {
        let p = path.into();
        let exists = p.exists();
        Self {
            record,
            lockout_path: p,
            persisted_on_disk: Cell::new(exists),
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
        let p = path.into();
        let exists = p.exists();
        self.lockout_path = p;
        self.persisted_on_disk.set(exists);
    }

    /// Returns `true` if the companion primary vault (`.bin`) or backup vault (`.bin.bak`)
    /// exists on disk alongside `lock_path`.
    pub fn companion_vault_exists(lock_path: &Path) -> bool {
        let primary = lock_path.with_extension("bin");
        let backup = covert_storage::derive_backup_path(&primary);
        primary.exists() || backup.exists()
    }

    /// Enforces a fail-closed safety lockout (at least 1 hour, preserving any higher backoff tier)
    /// and immediately writes the lockout record to `self.lockout_path`.
    fn enforce_fail_closed(&mut self, current_utc: u64, tick: Option<u64>) {
        let next_lockouts = self.record.consecutive_lockouts.max(1);
        let shift = next_lockouts.saturating_sub(1).min(MAX_BACKOFF_SHIFT);
        let duration = BASE_LOCKOUT_SECONDS * (1u64 << shift);
        let effective_utc = current_utc.max(self.record.last_event_utc);
        self.record = LockoutRecord {
            failed_attempts: MAX_FAILED_ATTEMPTS,
            consecutive_lockouts: next_lockouts,
            locked_until_utc: effective_utc.saturating_add(duration),
            last_event_utc: effective_utc,
            last_boot_tick: tick.unwrap_or_else(get_system_tick_count),
        };
        self.persisted_on_disk.set(true);
        let _ = self.save_to_file(&self.lockout_path);
    }

    /// Verifies that the `.lock` file on disk has not been deleted or corrupted after persistence
    /// or while its companion `.bin` / `.bin.bak` exists.
    ///
    /// If tamper/deletion is detected, immediately triggers a fail-closed safety lockout at
    /// `current_utc` and returns `true`.
    pub fn verify_lock_file_integrity(&mut self, current_utc: u64, tick: Option<u64>) -> bool {
        if self.lockout_path.exists() {
            if Self::load_from_file(&self.lockout_path).is_err() {
                self.enforce_fail_closed(current_utc, tick);
                return true;
            }
            self.persisted_on_disk.set(true);
            return false;
        }

        if self.persisted_on_disk.get() || Self::companion_vault_exists(&self.lockout_path) {
            self.enforce_fail_closed(current_utc, tick);
            return true;
        }

        false
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

        if self.verify_lock_file_integrity(current_utc, tick) {
            let duration = self
                .record
                .locked_until_utc
                .saturating_sub(self.record.last_event_utc);
            return Ok(LockoutStatus::LockedOut {
                duration_seconds: duration,
                locked_until_utc: self.record.locked_until_utc,
            });
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
        if path == self.lockout_path {
            self.persisted_on_disk.set(true);
        }
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
            persisted_on_disk: Cell::new(true),
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
        self.persisted_on_disk.set(true);
        Ok(())
    }

    /// Loads state from `path` if it exists, otherwise creates a new manager with `path`.
    ///
    /// Fail-Closed Resilience:
    /// - If the file exists but cannot be deserialized (e.g. truncated, corrupted, or zeroed out),
    ///   a 1-hour safety lockout is enforced rather than resetting counters to 0.
    /// - If the `.lock` file does NOT exist on disk, but the companion vault (`.bin` or `.bin.bak`)
    ///   DOES exist on disk, the `.lock` file was deleted after vault creation — a 1-hour safety
    ///   lockout is immediately enforced and persisted to disk.
    pub fn load_or_default(path: &Path) -> Self {
        if path.exists() {
            match Self::load_from_file(path) {
                Ok(loaded) => return loaded,
                Err(_) => return Self::new_fail_closed(path),
            }
        }
        if Self::companion_vault_exists(path) {
            return Self::new_fail_closed(path);
        }
        Self {
            record: LockoutRecord::default(),
            lockout_path: path.to_path_buf(),
            persisted_on_disk: Cell::new(false),
        }
    }

    /// Constructs and persists a fail-closed 1-hour safety lockout at `path`.
    fn new_fail_closed(path: &Path) -> Self {
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
            persisted_on_disk: Cell::new(true),
        };
        let _ = manager.save();
        manager
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
