//! State management for covert-gui.
//!
//! Enforces:
//! - In-memory secret zeroization on lock or drop.
//! - Anti-brute-force lockout and 2-step sequential unlock flow.
//! - Tier-2 authorization for secret reveals and clipboard exports.
//! - Inactivity timeout and item filtering/search.

use covert_auth::tier2::{hash_tier2_password, verify_tier2_password, Tier2Session};
use covert_auth::totp::{encode_base32, generate_recovery_codes};
use covert_auth::AuthManager;
use covert_core::models::{Category, Vault, VaultItem};
use covert_core::{ExposeSecret, SecretString};
use covert_storage::VaultStorage;
use rand_core::{OsRng, RngCore};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GuiError {
    #[error("Storage error: {0}")]
    Storage(#[from] covert_storage::StorageError),
    #[error("Authentication error: {0}")]
    Auth(#[from] covert_auth::AuthError),
    #[error("Core vault error: {0}")]
    Core(#[from] covert_core::VaultError),
    #[error("Vault is already locked")]
    AlreadyLocked,
    #[error("Vault is not unlocked")]
    NotUnlocked,
    #[error("Item not found with specified ID")]
    ItemNotFound,
    #[error("Invalid master password confirmation")]
    PasswordMismatch,
    #[error("Master password cannot be empty or shorter than 8 characters")]
    PasswordTooShort,
    #[error("Tier-2 password cannot match master password")]
    Tier2MatchesMaster,
    #[error("Tier-2 verification failed")]
    Tier2Failed,
    #[error("Lockout active: retry in {0} seconds")]
    LockoutActive(u64),
    #[error("No step 1 pending authentication")]
    NoPendingStep1,
}

/// In-memory state of the application.
pub struct AppState {
    pub storage: VaultStorage,
    pub auth_manager: AuthManager,
    pub vault: Option<Vault>,
    pub master_password: Option<SecretString>,

    // Pending step 1 credentials waiting for step 2 (TOTP / Recovery)
    pub pending_master_password: Option<SecretString>,
    pub pending_vault: Option<Vault>,

    // Tier-2 authorization session
    pub tier2_session: Option<Tier2Session>,
    pub tier2_revealed_items: HashSet<[u8; 16]>,

    // Inactivity tracking
    pub inactivity_timeout_secs: u64,
    pub last_activity_time: u64,

    // Filter & selection
    pub active_category_filter: Option<Category>,
    pub search_query: String,
    pub selected_item_id: Option<[u8; 16]>,

    // Active clipboard guard for auto-wipe
    pub active_clipboard: Option<covert_auth::clipboard::ClipboardGuard>,
}

impl AppState {
    /// Create a new `AppState` with storage bound to the specified path or default camouflage.
    pub fn new(path: Option<PathBuf>) -> Result<Self, GuiError> {
        let storage = match path {
            Some(p) => VaultStorage::from_path(p),
            None => VaultStorage::default_camouflaged()?,
        };
        let auth_manager = AuthManager::with_lockout_path(storage.lock_path());
        let now = current_time_secs();

        Ok(Self {
            storage,
            auth_manager,
            vault: None,
            master_password: None,
            pending_master_password: None,
            pending_vault: None,
            tier2_session: None,
            tier2_revealed_items: HashSet::new(),
            inactivity_timeout_secs: 900, // 15 minutes default
            last_activity_time: now,
            active_category_filter: None,
            search_query: String::new(),
            selected_item_id: None,
            active_clipboard: None,
        })
    }

    /// Returns true if the vault file exists on disk.
    pub fn vault_exists(&self) -> bool {
        self.storage.exists()
    }

    /// Returns true if the vault is currently decrypted and unlocked in RAM.
    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some() && self.master_password.is_some()
    }

    /// Reset user activity timestamp.
    pub fn touch_activity(&mut self) {
        self.last_activity_time = current_time_secs();
    }

    /// Checks if the inactivity timeout has expired. If so, locks the vault and returns true.
    pub fn check_inactivity(&mut self) -> bool {
        if !self.is_unlocked() {
            return false;
        }
        let now = current_time_secs();
        if now.saturating_sub(self.last_activity_time) >= self.inactivity_timeout_secs {
            self.lock_vault();
            true
        } else {
            false
        }
    }

    /// Get remaining seconds before automatic inactivity lock.
    pub fn inactivity_remaining_secs(&self) -> u64 {
        if !self.is_unlocked() {
            return 0;
        }
        let now = current_time_secs();
        let elapsed = now.saturating_sub(self.last_activity_time);
        self.inactivity_timeout_secs.saturating_sub(elapsed)
    }

    /// Check if anti-brute-force lockout is currently active.
    /// Returns `Some(remaining_seconds)` if locked out, or `None` if unlocked.
    pub fn check_lockout(&mut self) -> Option<u64> {
        let now = current_time_secs();
        match self.auth_manager.lockout_manager_mut().check_status(now) {
            Ok(is_locked) => {
                if is_locked {
                    let locked_until = self
                        .auth_manager
                        .lockout_manager()
                        .record()
                        .locked_until_utc;
                    Some(locked_until.saturating_sub(now))
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Initialize a new vault on disk (Onboarding).
    /// If `totp_setup` is provided, preserves the specified TOTP secret and recovery codes
    /// (e.g. from the Onboarding UI preview); otherwise generates fresh random ones.
    /// Returns `(Option<totp_secret>, Vec<recovery_codes>)`.
    pub fn init_vault(
        &mut self,
        name: &str,
        master_password: &SecretString,
        enable_totp: bool,
        tier2_password: Option<&SecretString>,
        totp_setup: Option<(String, Vec<String>)>,
    ) -> Result<(Option<String>, Vec<String>), GuiError> {
        let raw_pw = master_password.expose_secret();
        if raw_pw.len() < 8 {
            return Err(GuiError::PasswordTooShort);
        }

        let vault_name = if name.trim().is_empty() {
            "Gastinel Covert"
        } else {
            name.trim()
        };

        let mut vault = Vault::new(vault_name);

        let totp_info = if enable_totp {
            let (totp_secret, recovery_codes) = match totp_setup {
                Some((secret, codes)) if !secret.is_empty() && !codes.is_empty() => (secret, codes),
                _ => {
                    let mut raw_secret = [0u8; 20];
                    OsRng.fill_bytes(&mut raw_secret);
                    let secret = encode_base32(&raw_secret);
                    let codes = generate_recovery_codes(10);
                    (secret, codes)
                }
            };

            vault.security.totp_secret = Some(totp_secret.clone());
            vault.security.totp_digits = 6;
            vault.security.totp_period = 30;
            vault.security.totp_algorithm = "SHA1".to_string();
            vault.security.recovery_codes = recovery_codes.clone();

            Some((totp_secret, recovery_codes))
        } else {
            None
        };

        if let Some(t2_pw) = tier2_password {
            if !t2_pw.expose_secret().is_empty() {
                if t2_pw.expose_secret() == master_password.expose_secret() {
                    return Err(GuiError::Tier2MatchesMaster);
                }
                let t2_hash = hash_tier2_password(t2_pw)?;
                vault.security.master_view_password_hash = Some(t2_hash);
            }
        }

        // Save vault atomically to disk
        self.storage.save_vault(&vault, master_password, None)?;

        // Transition immediately to unlocked state
        self.vault = Some(vault);
        self.master_password = Some(master_password.clone());
        self.touch_activity();

        let (totp_secret, rec_codes) = match totp_info {
            Some((s, c)) => (Some(s), c),
            None => (None, Vec::new()),
        };

        Ok((totp_secret, rec_codes))
    }

    /// Step 1: Master Password verification.
    /// Returns `Ok(true)` if fully unlocked (no 2FA required),
    /// or `Ok(false)` if Step 2 (TOTP/Recovery) is required.
    pub fn unlock_step1(&mut self, password: &SecretString) -> Result<bool, GuiError> {
        let raw_vault = self.storage.load_raw()?;
        let (vault, _header) = match self
            .auth_manager
            .verify_master_password(&raw_vault, password)
        {
            Ok(res) => res,
            Err(covert_auth::AuthError::LockoutActive(d)) => {
                return Err(GuiError::LockoutActive(d.as_secs()));
            }
            Err(e) => return Err(GuiError::Auth(e)),
        };

        if vault.security.totp_secret.is_some() {
            // Needs Step 2
            self.pending_master_password = Some(password.clone());
            self.pending_vault = Some(vault);
            Ok(false)
        } else {
            // No 2FA required: immediately unlock
            self.vault = Some(vault);
            self.master_password = Some(password.clone());
            self.touch_activity();
            Ok(true)
        }
    }

    /// Step 2: Verify TOTP code (6 digits).
    pub fn unlock_step2_totp(&mut self, candidate: &str) -> Result<(), GuiError> {
        let vault = self.pending_vault.as_ref().ok_or(GuiError::NoPendingStep1)?;
        let now = current_time_secs();

        match self.auth_manager.verify_totp(vault, candidate, now) {
            Ok(()) => {}
            Err(covert_auth::AuthError::LockoutActive(d)) => {
                return Err(GuiError::LockoutActive(d.as_secs()));
            }
            Err(e) => return Err(GuiError::Auth(e)),
        }

        // Promote pending vault & password to active unlocked session
        self.vault = self.pending_vault.take();
        self.master_password = self.pending_master_password.take();
        self.touch_activity();

        Ok(())
    }

    /// Step 2: Verify emergency single-use recovery code.
    pub fn unlock_step2_recovery(&mut self, recovery_code: &str) -> Result<(), GuiError> {
        let mut vault = self.pending_vault.take().ok_or(GuiError::NoPendingStep1)?;
        let master_password = self
            .pending_master_password
            .take()
            .ok_or(GuiError::NoPendingStep1)?;

        match self
            .auth_manager
            .verify_recovery_code(&mut vault, recovery_code)
        {
            Ok(()) => {}
            Err(covert_auth::AuthError::LockoutActive(d)) => {
                return Err(GuiError::LockoutActive(d.as_secs()));
            }
            Err(e) => return Err(GuiError::Auth(e)),
        }

        // Atomically save vault with consumed recovery code
        self.storage.save_vault(&vault, &master_password, None)?;

        self.vault = Some(vault);
        self.master_password = Some(master_password);
        self.touch_activity();

        Ok(())
    }

    /// Lock the vault immediately and wipe all secrets from RAM and sensitive clipboard.
    pub fn lock_vault(&mut self) {
        self.vault = None;
        self.master_password = None;
        self.pending_vault = None;
        self.pending_master_password = None;

        if let Some(mut session) = self.tier2_session.take() {
            session.revoke();
        }
        self.tier2_revealed_items.clear();
        self.selected_item_id = None;
        self.search_query.clear();

        // Wipe sensitive clipboard immediately if guard is still active
        if let Some(mut guard) = self.active_clipboard.take() {
            let _ = guard.wipe_system_if_matching();
        }
    }

    /// Copies a secret to the system clipboard with privacy exclusion flags
    /// and registers an auto-wipe timer guard on `active_clipboard`.
    pub fn copy_to_clipboard(
        &mut self,
        secret: &SecretString,
        timeout_secs: u64,
    ) -> Result<(), GuiError> {
        let now = current_time_secs();
        let guard = covert_auth::clipboard::ClipboardGuard::copy_to_system_clipboard(
            secret,
            now,
            timeout_secs,
        )
        .map_err(|e| GuiError::Auth(covert_auth::AuthError::Clipboard(e.to_string())))?;
        self.active_clipboard = Some(guard);
        self.touch_activity();
        Ok(())
    }

    /// Checks if the active clipboard guard has expired and wipes system clipboard if matching.
    pub fn wipe_clipboard_if_expired(&mut self, current_time: u64) -> Result<bool, GuiError> {
        if let Some(guard) = &mut self.active_clipboard {
            let current_seq = covert_auth::clipboard::get_clipboard_sequence_number();
            if guard.should_wipe(current_time, current_seq) {
                let wiped = guard
                    .wipe_system_if_matching()
                    .map_err(|e| GuiError::Auth(covert_auth::AuthError::Clipboard(e.to_string())))?;
                self.active_clipboard = None;
                return Ok(wiped);
            }
        }
        Ok(false)
    }

    /// Check if a specific item's secret is currently unmasked in the UI.
    pub fn is_secret_revealed(&self, item_id: &[u8; 16]) -> bool {
        self.tier2_revealed_items.contains(item_id)
    }

    /// Check if Tier-2 password challenge is configured for this vault.
    pub fn has_tier2_configured(&self) -> bool {
        self.vault
            .as_ref()
            .map(|v| v.security.master_view_password_hash.is_some())
            .unwrap_or(false)
    }

    /// Check if Tier-2 authorization is currently active.
    pub fn is_tier2_active(&self) -> bool {
        if !self.is_unlocked() {
            return false;
        }
        if !self.has_tier2_configured() {
            return true; // No Tier-2 configured: naturally authorized
        }
        let now = current_time_secs();
        self.tier2_session
            .as_ref()
            .map(|s| s.is_valid(now))
            .unwrap_or(false)
    }

    /// Verify candidate Tier-2 password and grant session.
    /// `ttl_seconds`: 0 for single use, 60 for 60s, 300 for 5 min.
    pub fn verify_tier2(
        &mut self,
        candidate: &SecretString,
        ttl_seconds: u64,
    ) -> Result<(), GuiError> {
        let vault = self.vault.as_ref().ok_or(GuiError::NotUnlocked)?;
        if vault.security.master_view_password_hash.is_none() {
            return Ok(());
        }

        verify_tier2_password(vault, candidate)?;

        let now = current_time_secs();
        if ttl_seconds > 0 {
            self.tier2_session = Some(Tier2Session::grant(now, ttl_seconds));
        } else {
            // Single use: session active for 0 seconds (only immediate action authorized)
            self.tier2_session = None;
        }

        Ok(())
    }

    /// Check if a specific item's secret can be revealed or copied.
    pub fn can_reveal_item(&self, item_id: &[u8; 16]) -> bool {
        if !self.has_tier2_configured() {
            return true;
        }
        if self.is_tier2_active() {
            return true;
        }
        self.tier2_revealed_items.contains(item_id)
    }

    /// Mark an item's secret as revealed in the UI.
    pub fn reveal_item_secret(&mut self, item_id: [u8; 16]) {
        self.tier2_revealed_items.insert(item_id);
    }

    /// Hide an item's revealed secret.
    pub fn hide_item_secret(&mut self, item_id: &[u8; 16]) {
        self.tier2_revealed_items.remove(item_id);
    }

    /// Add a new item to the vault and save atomically.
    pub fn add_item(&mut self, item: VaultItem) -> Result<[u8; 16], GuiError> {
        let id = item.id;
        let master_pw = self.master_password.clone().ok_or(GuiError::NotUnlocked)?;
        let vault = self.vault.as_mut().ok_or(GuiError::NotUnlocked)?;

        vault.add_item(item);
        self.storage.save_vault(vault, &master_pw, None)?;
        self.touch_activity();

        Ok(id)
    }

    /// Update an existing item in the vault and save atomically.
    pub fn update_item(&mut self, updated: VaultItem) -> Result<(), GuiError> {
        let master_pw = self.master_password.clone().ok_or(GuiError::NotUnlocked)?;
        let vault = self.vault.as_mut().ok_or(GuiError::NotUnlocked)?;

        let target_id = updated.id;
        if let Some(item) = vault.get_item_mut(&target_id) {
            *item = updated;
            item.updated_at = current_time_secs();
        } else {
            return Err(GuiError::ItemNotFound);
        }

        self.storage.save_vault(vault, &master_pw, None)?;
        self.touch_activity();

        Ok(())
    }

    /// Remove an item by ID from the vault and save atomically.
    pub fn delete_item(&mut self, item_id: &[u8; 16]) -> Result<(), GuiError> {
        let master_pw = self.master_password.clone().ok_or(GuiError::NotUnlocked)?;
        let vault = self.vault.as_mut().ok_or(GuiError::NotUnlocked)?;

        if !vault.remove_item(item_id) {
            return Err(GuiError::ItemNotFound);
        }

        self.storage.save_vault(vault, &master_pw, None)?;
        self.tier2_revealed_items.remove(item_id);
        if self.selected_item_id.as_ref() == Some(item_id) {
            self.selected_item_id = None;
        }
        self.touch_activity();

        Ok(())
    }

    /// Return reference to an item by ID.
    pub fn get_item(&self, item_id: &[u8; 16]) -> Option<&VaultItem> {
        self.vault.as_ref().and_then(|v| v.get_item(item_id))
    }

    /// Return items filtered by active category and search query.
    pub fn filtered_items(&self) -> Vec<&VaultItem> {
        let vault = match self.vault.as_ref() {
            Some(v) => v,
            None => return Vec::new(),
        };

        let query = self.search_query.trim().to_lowercase();

        vault
            .items
            .iter()
            .filter(|item| {
                // Category filter
                if let Some(cat) = self.active_category_filter {
                    if item.category != cat {
                        return false;
                    }
                }

                // Query filter
                if query.is_empty() {
                    return true;
                }

                if item.title.to_lowercase().contains(&query) {
                    return true;
                }
                if let Some(user) = &item.username {
                    if user.to_lowercase().contains(&query) {
                        return true;
                    }
                }
                if let Some(url) = &item.url {
                    if url.to_lowercase().contains(&query) {
                        return true;
                    }
                }
                if let Some(notes) = &item.notes {
                    if notes.to_lowercase().contains(&query) {
                        return true;
                    }
                }

                false
            })
            .collect()
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        self.lock_vault();
    }
}

pub fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_app_state_lifecycle_and_zeroization() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dx12_pipeline.bin");
        let mut state = AppState::new(Some(path.clone())).unwrap();

        assert!(!state.is_unlocked());

        let master_pw = SecretString::from("MasterPassword123!".to_string());
        let (totp_opt, rec_codes) = state
            .init_vault("Test Vault", &master_pw, true, None, None)
            .unwrap();

        assert!(state.is_unlocked());
        assert!(totp_opt.is_some());
        assert_eq!(rec_codes.len(), 10);

        // Lock vault
        state.lock_vault();
        assert!(!state.is_unlocked());
        assert!(state.vault.is_none());
        assert!(state.master_password.is_none());

        // Step 1 unlock
        let needs_step2 = !state.unlock_step1(&master_pw).unwrap();
        assert!(needs_step2);
        assert!(!state.is_unlocked());
        assert!(state.pending_vault.is_some());

        // Step 2 with recovery code
        let code = &rec_codes[0];
        state.unlock_step2_recovery(code).unwrap();
        assert!(state.is_unlocked());

        // CRUD Item
        let item = VaultItem::new_credential(
            "GitHub",
            "octocat",
            "ghp_secretpassword",
            Some("https://github.com".into()),
        );
        let id = state.add_item(item).unwrap();
        assert_eq!(state.filtered_items().len(), 1);

        // Filter by category
        state.active_category_filter = Some(Category::SSH);
        assert_eq!(state.filtered_items().len(), 0);
        state.active_category_filter = Some(Category::Web);
        assert_eq!(state.filtered_items().len(), 1);

        // Search query
        state.search_query = "octo".to_string();
        assert_eq!(state.filtered_items().len(), 1);
        state.search_query = "google".to_string();
        assert_eq!(state.filtered_items().len(), 0);
        state.search_query.clear();

        // Delete item
        state.delete_item(&id).unwrap();
        assert_eq!(state.filtered_items().len(), 0);
    }

    #[test]
    fn test_tier2_password_flow() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dx12_pipeline.bin");
        let mut state = AppState::new(Some(path.clone())).unwrap();

        let master_pw = SecretString::from("MasterPassword123!".to_string());
        let tier2_pw = SecretString::from("Tier2SecretView!".to_string());

        state
            .init_vault("Tier2 Vault", &master_pw, false, Some(&tier2_pw), None)
            .unwrap();
        assert!(state.has_tier2_configured());
        assert!(!state.is_tier2_active());

        // Wrong Tier 2
        let bad_t2 = SecretString::from("WrongTier2!".to_string());
        assert!(state.verify_tier2(&bad_t2, 60).is_err());
        assert!(!state.is_tier2_active());

        // Correct Tier 2 (60s)
        state.verify_tier2(&tier2_pw, 60).unwrap();
        assert!(state.is_tier2_active());
    }
}
