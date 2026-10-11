use covert_auth::totp::compute_totp_code;
use covert_core::models::{Category, VaultItem};
use covert_core::SecretString;
use covert_gui::app::{AppController, AppWindow};
use covert_gui::state::{current_time_secs, AppState, GuiError};
use slint::Model;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

#[test]
fn test_gui_onboarding_and_unlock_flow() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dx12_pipeline.bin");
    let mut state = AppState::new(Some(path.clone())).expect("AppState::new");

    assert!(!state.vault_exists());
    assert!(!state.is_unlocked());

    let master_pw = SecretString::from("MasterPassphrase2026!".to_string());
    let tier2_pw = SecretString::from("Tier2ViewPassphrase2026!".to_string());

    // 1. Initialize vault (Onboarding)
    let (totp_opt, recovery_codes) = state
        .init_vault(
            "Mon Coffre Perso",
            &master_pw,
            true,
            Some(&tier2_pw),
            None,
        )
        .expect("init_vault");

    let totp_secret = totp_opt.expect("TOTP secret must be generated");
    assert_eq!(recovery_codes.len(), 10);
    assert!(state.vault_exists());
    assert!(state.is_unlocked());

    // 2. Lock vault -> memory purge
    state.lock_vault();
    assert!(!state.is_unlocked());
    assert!(state.vault.is_none());
    assert!(state.master_password.is_none());

    // 3. Step 1: Wrong password fails
    let wrong_pw = SecretString::from("BadPassword123!".to_string());
    let err = state.unlock_step1(&wrong_pw);
    assert!(err.is_err());
    assert!(!state.is_unlocked());

    // 4. Step 1: Correct password succeeds, requires Step 2
    let needs_step2 = !state.unlock_step1(&master_pw).expect("Step 1 unlock");
    assert!(needs_step2);
    assert!(!state.is_unlocked());
    assert!(state.pending_vault.is_some());

    // 5. Step 2: Valid TOTP code unlocks
    let now = current_time_secs();
    let valid_code = compute_totp_code(&totp_secret, now, 30, 6)
        .expect("compute_totp_code");
    state.unlock_step2_totp(&valid_code).expect("Step 2 TOTP unlock");
    assert!(state.is_unlocked());
    assert_eq!(state.vault.as_ref().unwrap().metadata.name, "Mon Coffre Perso");
}

#[test]
fn test_gui_lockout_trigger_after_two_failed_attempts() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dx12_pipeline.bin");
    let mut state = AppState::new(Some(path.clone())).expect("AppState::new");

    let master_pw = SecretString::from("MasterPassphrase2026!".to_string());
    state
        .init_vault("Lockout Test", &master_pw, false, None, None)
        .expect("init_vault");

    state.lock_vault();

    let wrong_pw = SecretString::from("WrongPassword1!".to_string());

    // Attempt 1: Fails, no lockout yet
    assert!(state.unlock_step1(&wrong_pw).is_err());
    assert_eq!(state.check_lockout(), None);

    // Attempt 2: Fails -> 1-hour anti-brute-force lockout triggered!
    assert!(state.unlock_step1(&wrong_pw).is_err());
    let remaining = state.check_lockout();
    assert!(remaining.is_some());
    assert!(remaining.unwrap() > 3500);

    // Attempt 3 while locked: Rejected with LockoutActive
    match state.unlock_step1(&master_pw) {
        Err(GuiError::LockoutActive(rem)) => assert!(rem > 3500),
        other => panic!("Expected LockoutActive, got: {:?}", other),
    }
}

#[test]
fn test_gui_recovery_code_consumption() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dx12_pipeline.bin");
    let mut state = AppState::new(Some(path.clone())).expect("AppState::new");

    let master_pw = SecretString::from("MasterPassphrase2026!".to_string());
    let (_totp, recovery_codes) = state
        .init_vault("Recovery Test", &master_pw, true, None, None)
        .expect("init_vault");

    state.lock_vault();

    // Step 1
    state.unlock_step1(&master_pw).expect("Step 1");

    // Consume first recovery code
    let code_to_use = recovery_codes[0].clone();
    state.unlock_step2_recovery(&code_to_use).expect("Step 2 recovery");
    assert!(state.is_unlocked());

    // Check that recovery code count decreased
    assert_eq!(
        state.vault.as_ref().unwrap().security.recovery_codes.len(),
        9
    );

    // Lock again
    state.lock_vault();

    // Attempt to re-use consumed recovery code
    state.unlock_step1(&master_pw).expect("Step 1");
    let reuse_err = state.unlock_step2_recovery(&code_to_use);
    assert!(reuse_err.is_err());
    assert!(!state.is_unlocked());
}

#[test]
fn test_gui_tier2_challenge_and_reveal() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dx12_pipeline.bin");
    let mut state = AppState::new(Some(path.clone())).expect("AppState::new");

    let master_pw = SecretString::from("MasterPassphrase2026!".to_string());
    let tier2_pw = SecretString::from("Tier2ViewPassphrase2026!".to_string());

    state
        .init_vault("Tier2 Test", &master_pw, false, Some(&tier2_pw), None)
        .expect("init_vault");

    let item = VaultItem::new_credential("TestSite", "alice", "secret123", None);
    let item_id = state.add_item(item).expect("add_item");

    // Should not be revealable without Tier-2 session
    assert!(!state.can_reveal_item(&item_id));

    // Wrong Tier-2 password
    let bad_t2 = SecretString::from("WrongTier2!".to_string());
    assert!(state.verify_tier2(&bad_t2, 60).is_err());
    assert!(!state.can_reveal_item(&item_id));

    // Correct Tier-2 password (grant 60s)
    state.verify_tier2(&tier2_pw, 60).expect("verify_tier2");
    assert!(state.is_tier2_active());
    assert!(state.can_reveal_item(&item_id));

    // Reveal item secret
    state.reveal_item_secret(item_id);
    assert!(state.can_reveal_item(&item_id));
    assert!(state.is_secret_revealed(&item_id));

    // Hide item secret
    state.hide_item_secret(&item_id);
    // Since session is still active, can_reveal_item is still true, but is_secret_revealed is false
    assert!(state.can_reveal_item(&item_id));
    assert!(!state.is_secret_revealed(&item_id));

    // Explicitly lock vault -> resets Tier-2
    state.lock_vault();
    assert!(!state.is_tier2_active());
}

#[test]
fn test_gui_inactivity_auto_lock() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dx12_pipeline.bin");
    let mut state = AppState::new(Some(path.clone())).expect("AppState::new");

    let master_pw = SecretString::from("MasterPassphrase2026!".to_string());
    state
        .init_vault("Inactivity Test", &master_pw, false, None, None)
        .expect("init_vault");

    // Set 5-second inactivity timeout
    state.inactivity_timeout_secs = 5;
    assert!(state.is_unlocked());

    // Immediately check: not inactive
    assert!(!state.check_inactivity());
    assert!(state.is_unlocked());

    // Simulate activity
    state.touch_activity();

    // Fast-forward last_activity_time to simulate 10s elapsed
    state.last_activity_time = current_time_secs().saturating_sub(10);
    assert!(state.check_inactivity());

    // Vault should now be completely locked
    assert!(!state.is_unlocked());
    assert!(state.vault.is_none());
}

#[test]
fn test_gui_crud_and_category_filters() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dx12_pipeline.bin");
    let mut state = AppState::new(Some(path.clone())).expect("AppState::new");

    let master_pw = SecretString::from("MasterPassphrase2026!".to_string());
    state
        .init_vault("CRUD Test", &master_pw, false, None, None)
        .expect("init_vault");

    // Add diverse items
    let web_item = VaultItem::new_credential("GitHub", "theog", "gh_pass", Some("https://github.com".into()));
    let ssh_item = VaultItem::new_ssh("Prod Server", "ed25519", "ssh-ed25519 AAAA...", "-----BEGIN OPENSSH PRIVATE KEY-----...", None, None);
    let api_item = VaultItem::new_api_key("Stripe API", "stripe", "sk_live_123456", None);
    let note_item = VaultItem::new_note("Secret Recovery Plan", "Stored in safe box #42");
    let raw_item = VaultItem::new_raw_secret("Raw Entropy", vec![0xDE, 0xAD, 0xBE, 0xEF]);

    let id_web = state.add_item(web_item).expect("add web");
    let _id_ssh = state.add_item(ssh_item).expect("add ssh");
    let _id_api = state.add_item(api_item).expect("add api");
    let _id_note = state.add_item(note_item).expect("add note");
    let _id_raw = state.add_item(raw_item).expect("add raw");

    assert_eq!(state.filtered_items().len(), 5);

    // Filter by Web
    state.active_category_filter = Some(Category::Web);
    assert_eq!(state.filtered_items().len(), 1);

    // Filter by SSH
    state.active_category_filter = Some(Category::SSH);
    assert_eq!(state.filtered_items().len(), 1);

    // Reset filter
    state.active_category_filter = None;
    assert_eq!(state.filtered_items().len(), 5);

    // Search query
    state.search_query = "github".to_string();
    assert_eq!(state.filtered_items().len(), 1);

    state.search_query = "safe box".to_string();
    assert_eq!(state.filtered_items().len(), 1);

    state.search_query = "nonexistent".to_string();
    assert_eq!(state.filtered_items().len(), 0);
    state.search_query.clear();

    // Update item
    let mut updated_web = state.get_item(&id_web).unwrap().clone();
    updated_web.title = "GitHub Enterprise".to_string();
    state.update_item(updated_web).expect("update");
    assert_eq!(state.get_item(&id_web).unwrap().title, "GitHub Enterprise");

    // Delete item
    state.delete_item(&id_web).expect("delete");
    assert_eq!(state.filtered_items().len(), 4);
}

#[test]
fn test_gui_slint_comprehensive_controller_suite() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dx12_pipeline.bin");
    let state = Arc::new(Mutex::new(AppState::new(Some(path.clone())).expect("AppState::new")));

    let ui = AppWindow::new().expect("AppWindow::new");
    let _controller = AppController::setup(&ui, Arc::clone(&state));

    // -------------------------------------------------------------------------
    // Phase 1: Onboarding UI & TOTP Preview Preservation (Bug 1)
    // -------------------------------------------------------------------------
    assert_eq!(ui.get_current_view(), "onboarding");
    let displayed_totp = ui.get_onb_totp_secret().to_string();
    assert!(!displayed_totp.is_empty(), "Onboarding must show TOTP secret");

    let rec_model = ui.get_onb_recovery_codes();
    assert_eq!(rec_model.row_count(), 10, "Must show 10 recovery codes");
    let displayed_recovery_0 = rec_model.row_data(0).unwrap().to_string();
    let displayed_recovery_1 = rec_model.row_data(1).unwrap().to_string();

    ui.set_onb_vault_name("Test Suite Vault".into());
    ui.set_onb_master_password("SecureMasterPassword123!".into());
    ui.set_onb_confirm_password("SecureMasterPassword123!".into());
    ui.set_onb_enable_totp(true);
    ui.set_onb_tier2_password("Tier2ViewPassphrase2026!".into());

    ui.invoke_onb_init_vault(
        "Test Suite Vault".into(),
        "SecureMasterPassword123!".into(),
        true,
        "Tier2ViewPassphrase2026!".into(),
    );

    assert_eq!(ui.get_current_view(), "dashboard");
    assert_eq!(ui.get_dsh_vault_name(), "Test Suite Vault");

    // -------------------------------------------------------------------------
    // Phase 2: 2FA Unlock with Previewed TOTP Secret (Bug 1 verification)
    // -------------------------------------------------------------------------
    ui.invoke_dsh_lock_vault();
    assert_eq!(ui.get_current_view(), "unlock");
    assert_eq!(ui.get_unl_step(), 1);

    // Step 1: Submit master password
    ui.set_unl_master_password("SecureMasterPassword123!".into());
    ui.invoke_unl_step1("SecureMasterPassword123!".into());
    assert_eq!(ui.get_unl_step(), 2, "Must advance to Step 2 2FA");

    // Step 2: Submit TOTP code generated from the displayed secret
    let now = current_time_secs();
    let valid_code = compute_totp_code(&displayed_totp, now, 30, 6)
        .expect("compute_totp_code from displayed secret");
    ui.set_unl_totp_code(valid_code.clone().into());
    ui.invoke_unl_step2_totp(valid_code.into());

    assert_eq!(
        ui.get_current_view(),
        "dashboard",
        "Vault MUST unlock using TOTP secret shown during onboarding"
    );

    // -------------------------------------------------------------------------
    // Phase 3: 2FA Unlock with Previewed Recovery Code (Bug 1 verification)
    // -------------------------------------------------------------------------
    ui.invoke_dsh_lock_vault();
    assert_eq!(ui.get_current_view(), "unlock");

    ui.set_unl_master_password("SecureMasterPassword123!".into());
    ui.invoke_unl_step1("SecureMasterPassword123!".into());
    assert_eq!(ui.get_unl_step(), 2);

    ui.invoke_unl_step2_recovery(displayed_recovery_0.into());
    assert_eq!(
        ui.get_current_view(),
        "dashboard",
        "Vault MUST unlock using recovery code shown during onboarding"
    );

    // -------------------------------------------------------------------------
    // Phase 4: Create Items (Credential & RawSecret)
    // -------------------------------------------------------------------------
    // Item 1: Web Credential
    ui.invoke_dsh_save_item(
        "".into(),
        "Super Secret Server".into(),
        "Web".into(),
        "admin".into(),
        "SuperConfidentialPassword999!".into(),
        "https://secret.local".into(),
        "Critical production server".into(),
    );

    // Item 2: RawSecret
    ui.invoke_dsh_save_item(
        "".into(),
        "Root Entropy Key".into(),
        "RawSecret".into(),
        "".into(),
        "DEADBEEFCAFE0123456789".into(),
        "".into(),
        "Cold storage entropy seed".into(),
    );

    assert_eq!(ui.get_dsh_items().row_count(), 2);

    // Find the credential item
    let mut cred_idx = 0;
    for i in 0..ui.get_dsh_items().row_count() {
        if ui.get_dsh_items().row_data(i).unwrap().category == "Web" {
            cred_idx = i;
            break;
        }
    }
    let cred_item = ui.get_dsh_items().row_data(cred_idx).unwrap();
    let cred_id = cred_item.id;

    // -------------------------------------------------------------------------
    // Phase 5: Selection & Cleartext Memory Protection (Bug 3)
    // -------------------------------------------------------------------------
    ui.invoke_dsh_select_item(cred_id.clone());
    assert_eq!(ui.get_dsh_selected_item().title, "Super Secret Server");
    // Cleartext MUST NOT be in Slint memory before Tier-2 reveal!
    assert_eq!(
        ui.get_dsh_selected_item().password_plain,
        "",
        "password_plain MUST be empty before user authorization"
    );
    assert_eq!(ui.get_dsh_selected_item().is_revealed, false);

    // -------------------------------------------------------------------------
    // Phase 6: Tier-2 Edit Challenge Protection (Bug 2)
    // -------------------------------------------------------------------------
    // Click "Modifier" -> MUST require Tier-2 authentication!
    ui.invoke_dsh_edit_current_item();

    // MUST NOT transition to editing form
    assert_eq!(
        ui.get_dsh_is_editing(),
        false,
        "Edit item without Tier-2 authentication must not activate edit form"
    );
    assert!(
        ui.get_t2_is_open(),
        "Tier-2 modal must be opened to challenge user"
    );
    assert_eq!(
        ui.get_dsh_form_password(),
        "",
        "Form password field must not contain cleartext"
    );

    // Wrong Tier-2 password
    ui.invoke_t2_confirmed("WrongTier2!".into(), 60);
    assert_eq!(ui.get_dsh_is_editing(), false);
    assert_eq!(ui.get_dsh_form_password(), "");

    // Correct Tier-2 password
    ui.invoke_t2_confirmed("Tier2ViewPassphrase2026!".into(), 60);

    // NOW it must transition to edit mode with populated fields
    assert_eq!(ui.get_dsh_is_editing(), true);
    assert_eq!(
        ui.get_dsh_form_password(),
        "SuperConfidentialPassword999!",
        "Form password must only be populated after Tier-2 verification"
    );

    // Cancel edit
    ui.invoke_dsh_cancel_edit();
    assert_eq!(ui.get_dsh_is_editing(), false);

    // -------------------------------------------------------------------------
    // Phase 7: Visual Reveal & "Masquer" Masking (Bug 6)
    // -------------------------------------------------------------------------
    ui.invoke_dsh_reveal_secret(cred_id.clone());
    assert_eq!(ui.get_dsh_selected_item().is_revealed, true);
    assert_eq!(
        ui.get_dsh_selected_item().password_plain,
        "SuperConfidentialPassword999!"
    );

    // Click "Masquer"
    ui.invoke_dsh_hide_secret(cred_id.clone());
    assert_eq!(
        ui.get_dsh_selected_item().password_plain,
        "",
        "password_plain must be empty when masked"
    );
    assert_eq!(
        ui.get_dsh_selected_item().is_revealed,
        false,
        "is_revealed must be false when masked"
    );

    // -------------------------------------------------------------------------
    // Phase 8: Clipboard Copy & Lock Zeroization (Bugs 4 & 5)
    // -------------------------------------------------------------------------
    // Copy password to clipboard
    ui.invoke_dsh_copy_field(cred_id.clone(), "password".into());
    {
        let st = state.lock().unwrap();
        assert!(st.active_clipboard.is_some(), "Clipboard guard must be active after copy");
    }

    // Lock vault via UI callback
    ui.invoke_dsh_lock_vault();

    // Verify UI wiped completely
    assert_eq!(ui.get_current_view(), "unlock");
    assert_eq!(ui.get_dsh_items().row_count(), 0, "Items list must be wiped on lock");
    assert_eq!(ui.get_dsh_selected_item().title, "", "Selected item title must be wiped");
    assert_eq!(ui.get_dsh_selected_item().password_plain, "", "Selected item password must be wiped");
    assert_eq!(ui.get_dsh_form_password(), "", "Form password must be wiped");

    // Verify state & clipboard wiped
    let st = state.lock().unwrap();
    assert!(!st.is_unlocked());
    assert!(st.active_clipboard.is_none(), "Active clipboard guard must be wiped on lock");
    drop(st);

    // -------------------------------------------------------------------------
    // Phase 9: RawSecret Selection & Reveal
    // -------------------------------------------------------------------------
    // Unlock again using unused recovery code 1
    ui.set_unl_master_password("SecureMasterPassword123!".into());
    ui.invoke_unl_step1("SecureMasterPassword123!".into());
    assert_eq!(ui.get_unl_step(), 2);
    ui.invoke_unl_step2_recovery(displayed_recovery_1.into());
    assert_eq!(ui.get_current_view(), "dashboard");

    // Find the RawSecret item
    let mut raw_idx = 0;
    for i in 0..ui.get_dsh_items().row_count() {
        if ui.get_dsh_items().row_data(i).unwrap().category == "RawSecret" {
            raw_idx = i;
            break;
        }
    }
    let raw_item = ui.get_dsh_items().row_data(raw_idx).unwrap();
    let raw_id = raw_item.id;

    ui.invoke_dsh_select_item(raw_id.clone());
    assert_eq!(ui.get_dsh_selected_item().category, "RawSecret");

    // Authorize Tier 2 and reveal RawSecret
    ui.invoke_dsh_reveal_secret(raw_id.clone());
    if ui.get_t2_is_open() {
        ui.invoke_t2_confirmed("Tier2ViewPassphrase2026!".into(), 60);
    }
    assert_eq!(
        ui.get_dsh_selected_item().password_plain,
        "DEADBEEFCAFE0123456789"
    );
}

#[test]
fn test_gui_clipboard_auto_wipe_after_timeout() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dx12_pipeline.bin");
    let mut state = AppState::new(Some(path.clone())).expect("AppState::new");

    let master_pw = SecretString::from("MasterPassphrase2026!".to_string());
    state
        .init_vault("Clipboard Test", &master_pw, false, None, None)
        .expect("init_vault");

    let secret = SecretString::from("SensitiveToken12345".to_string());
    state.copy_to_clipboard(&secret, 2).expect("copy_to_clipboard");

    assert!(state.active_clipboard.is_some());

    let now = current_time_secs();
    // Not expired yet
    state.wipe_clipboard_if_expired(now).unwrap();
    assert!(state.active_clipboard.is_some());

    // Fast forward timestamp past 2s timeout
    state.wipe_clipboard_if_expired(now + 10).unwrap();
    assert!(state.active_clipboard.is_none(), "Expired clipboard guard must be wiped and removed");
}

