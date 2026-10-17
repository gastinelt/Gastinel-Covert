//! Gastinel Covert Authentication Crate (`covert-auth`).
//!
//! Provides:
//! - Tier 1 Authentication: Master password validation + Aegis RFC 6238 TOTP with +-30s drift tolerance.
//! - Constant-time verification avoiding early-exit timing leaks (`subtle::ConstantTimeEq`).
//! - Anti-brute-force rate limiting: 2 failed attempts -> 1-hour lockout with exponential backoff.
//! - Persistent lockout record in `dx12_pipeline.lock` with monotonic tick (`GetTickCount64`) rollback guard.
//! - Single-use emergency recovery codes (10 codes generated during 2FA enrollment, consumed on use).
//! - Tier 2 Authentication: Master View Password for plain-text reveals and clipboard exports.
//! - Win32 clipboard privacy flags: `CanIncludeInClipboardHistory = 0`, `CanUploadToCloudClipboard = 0`,
//!   `ExcludeClipboardContentFromMonitorProcessing = 0`, and sequence-guarded auto-wipe timer.

pub mod clipboard;
pub mod error;
pub mod lockout;
pub mod tier2;
pub mod totp;

pub use clipboard::{
    clear_clipboard_if_sequence_matches, get_clipboard_sequence_number, register_clipboard_format,
    write_to_clipboard_with_flags, ClipboardGuard, ClipboardPrivacyFormats,
    CF_CAN_INCLUDE_IN_CLIPBOARD_HISTORY, CF_CAN_UPLOAD_TO_CLOUD_CLIPBOARD,
    CF_EXCLUDE_CLIPBOARD_MONITOR, CF_UNICODETEXT,
};
pub use error::{AuthError, ClipboardError, LockoutError, TotpError};
pub use lockout::{
    get_system_tick_count, LockoutManager, LockoutRecord, LockoutStatus, BASE_LOCKOUT_SECONDS,
    MAX_BACKOFF_SHIFT, MAX_FAILED_ATTEMPTS,
};
pub use tier2::{
    hash_tier2_password, validate_tier2_candidate, verify_tier2_password, Tier2Session,
    DEFAULT_TIER2_TTL_SECONDS, TIER2_M_COST, TIER2_P_COST, TIER2_T_COST,
};
pub use totp::{
    compute_totp_code, decode_base32, encode_base32, generate_recovery_codes,
    normalize_recovery_code, verify_and_consume_recovery_code, verify_totp, TotpAlgorithm,
    TotpEngine,
};

use covert_core::header::VaultHeader;
use covert_core::models::Vault;
use covert_core::SecretString;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Alias for `VaultHeader` to fulfill architectural interface contracts.
pub type Header = VaultHeader;

/// High-level authentication manager coordinating Tier 1, rate-limiting lockout,
/// Tier 2 view verifications, and clipboard protection.
#[derive(Debug)]
pub struct AuthManager {
    lockout_manager: LockoutManager,
    active_clipboard: Option<ClipboardGuard>,
    last_accepted_totp_step: Option<u64>,
}

impl Default for AuthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthManager {
    /// Creates a new `AuthManager` with default camouflaged lockout path:
    /// `%LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.lock`.
    /// Automatically loads existing lockout records from disk across sessions.
    pub fn new() -> Self {
        let lockout_manager = LockoutManager::new();
        Self {
            lockout_manager,
            active_clipboard: None,
            last_accepted_totp_step: None,
        }
    }

    /// Creates an `AuthManager` bound to a specific lockout file path (e.g. for testing).
    /// Automatically loads existing lockout records from disk across sessions.
    pub fn with_lockout_path<P: Into<PathBuf>>(path: P) -> Self {
        let lockout_manager = LockoutManager::with_path(path);
        Self {
            lockout_manager,
            active_clipboard: None,
            last_accepted_totp_step: None,
        }
    }

    /// Creates an `AuthManager` using an existing `LockoutManager`.
    pub fn with_lockout_manager(lockout_manager: LockoutManager) -> Self {
        Self {
            lockout_manager,
            active_clipboard: None,
            last_accepted_totp_step: None,
        }
    }

    /// Returns a reference to the underlying `LockoutManager`.
    pub fn lockout_manager(&self) -> &LockoutManager {
        &self.lockout_manager
    }

    /// Returns a mutable reference to the underlying `LockoutManager`.
    pub fn lockout_manager_mut(&mut self) -> &mut LockoutManager {
        &mut self.lockout_manager
    }

    /// Returns a reference to the active `ClipboardGuard`, if present.
    pub fn active_clipboard(&self) -> Option<&ClipboardGuard> {
        self.active_clipboard.as_ref()
    }

    /// Step 1: Verify master password against raw encrypted vault bytes using live system time
    /// and genuine monotonic tick validation (GetTickCount64).
    pub fn verify_master_password(
        &mut self,
        raw_vault: &[u8],
        password: &SecretString,
    ) -> Result<(Vault, Header), AuthError> {
        self.verify_master_password_at_time_and_tick(
            raw_vault,
            password,
            current_system_time(),
            Some(get_system_tick_count()),
        )
    }

    /// Step 1: Verify master password against raw encrypted vault bytes at explicit `current_time`.
    pub fn verify_master_password_at_time(
        &mut self,
        raw_vault: &[u8],
        password: &SecretString,
        current_time: u64,
    ) -> Result<(Vault, Header), AuthError> {
        self.verify_master_password_at_time_and_tick(raw_vault, password, current_time, None)
    }

    /// Step 1: Verify master password with explicit time and optional monotonic tick count.
    pub fn verify_master_password_at_time_and_tick(
        &mut self,
        raw_vault: &[u8],
        password: &SecretString,
        current_time: u64,
        tick: Option<u64>,
    ) -> Result<(Vault, Header), AuthError> {
        // 0. Detect deletion or corruption of .lock file after persistence or when .bin exists
        self.lockout_manager
            .verify_lock_file_integrity(current_time, tick);

        // 1. Lockout check (with monotonic tick evaluation if provided)
        let is_locked = match tick {
            Some(t) => self.lockout_manager.check_status_monotonic(current_time, t)?,
            None => self.lockout_manager.check_status(current_time)?,
        };
        if is_locked {
            let remaining = self
                .lockout_manager
                .record()
                .locked_until_utc
                .saturating_sub(current_time);
            return Err(AuthError::LockoutActive(Duration::from_secs(remaining)));
        }

        // 2. Decrypt vault
        match Vault::decrypt(raw_vault, password) {
            Ok((vault, header)) => {
                if vault.security.totp_secret.is_none() {
                    self.lockout_manager
                        .register_success_at_time_and_tick(current_time, tick);
                    let _ = self.lockout_manager.save();
                }
                Ok((vault, header))
            }
            Err(_) => {
                let _ = self
                    .lockout_manager
                    .register_failure_at_time_and_tick(current_time, tick)?;
                self.lockout_manager.save()?;
                Err(AuthError::InvalidMasterPassword)
            }
        }
    }

    /// Step 2: Verify Aegis TOTP code (6 digits) with +-30s drift tolerance and replay protection.
    pub fn verify_totp(
        &mut self,
        vault: &Vault,
        candidate: &str,
        current_time: u64,
    ) -> Result<(), AuthError> {
        self.verify_totp_at_time_and_tick(vault, candidate, current_time, None)
    }

    /// Step 2: Verify Aegis TOTP code with optional monotonic tick verification.
    pub fn verify_totp_at_time_and_tick(
        &mut self,
        vault: &Vault,
        candidate: &str,
        current_time: u64,
        tick: Option<u64>,
    ) -> Result<(), AuthError> {
        self.lockout_manager
            .verify_lock_file_integrity(current_time, tick);

        let is_locked = match tick {
            Some(t) => self.lockout_manager.check_status_monotonic(current_time, t)?,
            None => self.lockout_manager.check_status(current_time)?,
        };
        if is_locked {
            let remaining = self
                .lockout_manager
                .record()
                .locked_until_utc
                .saturating_sub(current_time);
            return Err(AuthError::LockoutActive(Duration::from_secs(remaining)));
        }

        let secret = vault
            .security
            .totp_secret
            .as_ref()
            .ok_or(AuthError::TotpNotConfigured)?;

        let algorithm: TotpAlgorithm = vault
            .security
            .totp_algorithm
            .parse()
            .unwrap_or(TotpAlgorithm::Sha1);

        let mut engine = TotpEngine::from_base32(secret)?
            .with_digits(vault.security.totp_digits)
            .with_step_seconds(vault.security.totp_period)
            .with_algorithm(algorithm)
            .with_last_used_step(self.last_accepted_totp_step);

        match engine.verify(candidate, current_time) {
            Ok(step) => {
                self.last_accepted_totp_step = Some(step);
                self.lockout_manager
                    .register_success_at_time_and_tick(current_time, tick);
                self.lockout_manager.save()?;
                Ok(())
            }
            Err(TotpError::ReplayedCode) => {
                let _ = self
                    .lockout_manager
                    .register_failure_at_time_and_tick(current_time, tick)?;
                self.lockout_manager.save()?;
                Err(AuthError::TotpCodeReplayed)
            }
            Err(_) => {
                let _ = self
                    .lockout_manager
                    .register_failure_at_time_and_tick(current_time, tick)?;
                self.lockout_manager.save()?;
                Err(AuthError::InvalidTotpCode)
            }
        }
    }

    /// Step 2 Alternative: Verify single-use emergency recovery code using live system time and GetTickCount64.
    pub fn verify_recovery_code(
        &mut self,
        vault: &mut Vault,
        code: &str,
    ) -> Result<(), AuthError> {
        self.verify_recovery_code_at_time_and_tick(
            vault,
            code,
            current_system_time(),
            Some(get_system_tick_count()),
        )
    }

    /// Step 2 Alternative: Verify single-use emergency recovery code at explicit `current_time`.
    pub fn verify_recovery_code_at_time(
        &mut self,
        vault: &mut Vault,
        code: &str,
        current_time: u64,
    ) -> Result<(), AuthError> {
        self.verify_recovery_code_at_time_and_tick(vault, code, current_time, None)
    }

    /// Step 2 Alternative: Verify single-use emergency recovery code with explicit time and optional monotonic tick.
    pub fn verify_recovery_code_at_time_and_tick(
        &mut self,
        vault: &mut Vault,
        code: &str,
        current_time: u64,
        tick: Option<u64>,
    ) -> Result<(), AuthError> {
        self.lockout_manager
            .verify_lock_file_integrity(current_time, tick);

        let is_locked = match tick {
            Some(t) => self.lockout_manager.check_status_monotonic(current_time, t)?,
            None => self.lockout_manager.check_status(current_time)?,
        };
        if is_locked {
            let remaining = self
                .lockout_manager
                .record()
                .locked_until_utc
                .saturating_sub(current_time);
            return Err(AuthError::LockoutActive(Duration::from_secs(remaining)));
        }

        match verify_and_consume_recovery_code(&mut vault.security.recovery_codes, code) {
            Ok(_) => {
                self.lockout_manager
                    .register_success_at_time_and_tick(current_time, tick);
                self.lockout_manager.save()?;
                Ok(())
            }
            Err(_) => {
                let _ = self
                    .lockout_manager
                    .register_failure_at_time_and_tick(current_time, tick)?;
                self.lockout_manager.save()?;
                Err(AuthError::InvalidRecoveryCode)
            }
        }
    }

    /// Tier 2: Verify Master View Password for plain-text inspection or clipboard export.
    pub fn verify_tier2_password(
        &self,
        vault: &Vault,
        password: &SecretString,
    ) -> Result<(), AuthError> {
        verify_tier2_password(vault, password)
    }

    /// Tier 2 Clipboard Copy: Authorizes with `tier2_password`, copies to Windows clipboard
    /// with security flags, and tracks the active guard with auto-wipe timer.
    pub fn copy_to_clipboard(
        &mut self,
        vault: &Vault,
        tier2_password: &SecretString,
        secret: &SecretString,
        timeout_secs: u64,
    ) -> Result<u32, AuthError> {
        self.verify_tier2_password(vault, tier2_password)?;
        let now = current_system_time();
        let guard = ClipboardGuard::copy_to_system_clipboard(secret, now, timeout_secs)?;
        let seq = guard.sequence_number();
        self.active_clipboard = Some(guard);
        Ok(seq)
    }

    /// Checks if the active clipboard guard has expired and wipes system clipboard if matching.
    pub fn wipe_clipboard_if_expired(&mut self, current_time: u64) -> Result<bool, AuthError> {
        if let Some(guard) = &mut self.active_clipboard {
            let current_seq = get_clipboard_sequence_number();
            if guard.should_wipe(current_time, current_seq) {
                let wiped = guard.wipe_system_if_matching()?;
                self.active_clipboard = None;
                return Ok(wiped);
            }
        }
        Ok(false)
    }
}

/// Helper returning current Unix timestamp in seconds.
fn current_system_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
