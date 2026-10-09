//! Rate limiting and persistent anti-brute-force lockout state machine.
//!
//! Enforces:
//! - 2 maximum failures -> 1 hour lockout
//! - Exponential backoff on repeat lockouts (3600 * 2^(k-1))
//! - Monotonic clock check (detects clock rollback)
//! - State persistence simulation to `dx12_pipeline.lock`

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockoutRecord {
    pub failed_attempts: u32,
    pub consecutive_lockouts: u32,
    pub locked_until_utc: u64,
    pub last_event_utc: u64,
}

impl Default for LockoutRecord {
    fn default() -> Self {
        Self {
            failed_attempts: 0,
            consecutive_lockouts: 0,
            locked_until_utc: 0,
            last_event_utc: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LockoutStatus {
    Allowed,
    AttemptFailed { attempts_remaining: u32 },
    LockedOut { duration_seconds: u64, locked_until_utc: u64 },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LockoutError {
    #[error("Clock rollback detected: system time is earlier than last recorded event")]
    ClockRollbackDetected,
    #[error("IO error operating on lockout record: {0}")]
    Io(String),
}

pub struct LockoutManager {
    record: LockoutRecord,
}

impl LockoutManager {
    pub fn new() -> Self {
        Self {
            record: LockoutRecord::default(),
        }
    }

    pub fn from_record(record: LockoutRecord) -> Self {
        Self { record }
    }

    pub fn record(&self) -> &LockoutRecord {
        &self.record
    }

    /// Check if currently locked out at `current_utc`.
    pub fn check_status(&self, current_utc: u64) -> Result<bool, LockoutError> {
        if self.record.last_event_utc > 0 && current_utc < self.record.last_event_utc {
            return Err(LockoutError::ClockRollbackDetected);
        }
        Ok(current_utc < self.record.locked_until_utc)
    }

    /// Record a failed authentication attempt.
    pub fn register_failure(&mut self, current_utc: u64) -> Result<LockoutStatus, LockoutError> {
        if self.record.last_event_utc > 0 && current_utc < self.record.last_event_utc {
            return Err(LockoutError::ClockRollbackDetected);
        }

        self.record.last_event_utc = current_utc;
        self.record.failed_attempts += 1;

        if self.record.failed_attempts >= 2 {
            self.record.consecutive_lockouts += 1;
            // 3600 * 2^(k - 1)
            let multiplier = 1u64 << (self.record.consecutive_lockouts.saturating_sub(1).min(10));
            let duration = 3600 * multiplier;
            self.record.locked_until_utc = current_utc + duration;
            self.record.failed_attempts = 0; // reset counter after locking out
            Ok(LockoutStatus::LockedOut {
                duration_seconds: duration,
                locked_until_utc: self.record.locked_until_utc,
            })
        } else {
            Ok(LockoutStatus::AttemptFailed {
                attempts_remaining: 2 - self.record.failed_attempts,
            })
        }
    }

    /// Record a successful authentication, resetting failed attempts and lockout counters.
    pub fn register_success(&mut self, current_utc: u64) {
        self.record.failed_attempts = 0;
        self.record.consecutive_lockouts = 0;
        self.record.locked_until_utc = 0;
        self.record.last_event_utc = current_utc;
    }

    /// Save state to disk in CBOR format.
    pub fn save_to_file(&self, path: &Path) -> Result<(), LockoutError> {
        let f = File::create(path).map_err(|e| LockoutError::Io(e.to_string()))?;
        ciborium::into_writer(&self.record, f).map_err(|e| LockoutError::Io(e.to_string()))?;
        Ok(())
    }

    /// Load state from disk in CBOR format.
    pub fn load_from_file(path: &Path) -> Result<Self, LockoutError> {
        let f = File::open(path).map_err(|e| LockoutError::Io(e.to_string()))?;
        let record: LockoutRecord =
            ciborium::from_reader(f).map_err(|e| LockoutError::Io(e.to_string()))?;
        Ok(Self { record })
    }
}
