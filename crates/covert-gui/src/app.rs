//! Slint Application Controller & Event Bindings.

use crate::state::{AppState, GuiError};
use crate::tray::TrayIcon;
use covert_auth::clipboard::write_to_clipboard_with_flags;
use covert_auth::totp::{encode_base32, generate_recovery_codes};
use covert_core::models::{Category, VaultItem};
use covert_core::SecretString;
use rand_core::{OsRng, RngCore};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

slint::include_modules!();

#[derive(Clone, Debug)]
pub enum PendingAction {
    RevealSecret([u8; 16]),
    CopyPassword([u8; 16]),
    EditItem([u8; 16]),
}

pub struct AppController {
    pub ui: slint::Weak<AppWindow>,
    pub state: Arc<Mutex<AppState>>,
    pub pending_action: Arc<Mutex<Option<PendingAction>>>,
    pub tray: Arc<Mutex<Option<TrayIcon>>>,
    _timer: slint::Timer,
}

impl AppController {
    pub fn setup(ui: &AppWindow, state: Arc<Mutex<AppState>>) -> Arc<Self> {
        let ui_weak = ui.as_weak();
        let pending_action = Arc::new(Mutex::new(None));
        let tray = Arc::new(Mutex::new(None));
        let timer = slint::Timer::default();

        let controller = Arc::new(Self {
            ui: ui_weak.clone(),
            state: Arc::clone(&state),
            pending_action: Arc::clone(&pending_action),
            tray: Arc::clone(&tray),
            _timer: timer,
        });

        // Initial setup of UI view state
        {
            let mut st = state.lock().unwrap();
            if !st.vault_exists() {
                ui.set_current_view("onboarding".into());
                // Generate initial preview TOTP & recovery codes for onboarding
                let mut raw = [0u8; 20];
                OsRng.fill_bytes(&mut raw);
                let secret = encode_base32(&raw);
                let codes = generate_recovery_codes(10);
                ui.set_onb_totp_secret(secret.into());
                let codes_model: Vec<SharedString> =
                    codes.iter().map(|c| SharedString::from(c.as_str())).collect();
                ui.set_onb_recovery_codes(ModelRc::new(VecModel::from(codes_model)));
            } else {
                ui.set_current_view("unlock".into());
                ui.set_unl_step(1);
                if let Some(rem) = st.check_lockout() {
                    ui.set_unl_is_locked_out(true);
                    ui.set_unl_lockout_seconds(rem as i32);
                } else {
                    ui.set_unl_is_locked_out(false);
                }
            }
        }

        // Apply screen capture protection
        apply_screen_protection(ui.window());

        // Attach system tray if on Windows
        #[cfg(windows)]
        {
            if let Some(hwnd) = get_window_hwnd(ui.window()) {
                let mut t = TrayIcon::new();
                if t.attach(hwnd) {
                    *tray.lock().unwrap() = Some(t);
                }
            }
        }

        // ==============================================================
        // ONBOARDING CALLBACKS
        // ==============================================================
        {
            let c = Arc::clone(&controller);
            ui.on_onb_refresh_totp(move || {
                if let Some(ui) = c.ui.upgrade() {
                    let mut raw = [0u8; 20];
                    OsRng.fill_bytes(&mut raw);
                    let secret = encode_base32(&raw);
                    let codes = generate_recovery_codes(10);
                    ui.set_onb_totp_secret(secret.into());
                    let codes_model: Vec<SharedString> =
                        codes.iter().map(|c| SharedString::from(c.as_str())).collect();
                    ui.set_onb_recovery_codes(ModelRc::new(VecModel::from(codes_model)));
                    c.show_toast("Nouvelles clés 2FA générées");
                }
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_onb_copy_totp_secret(move || {
                if let Some(ui) = c.ui.upgrade() {
                    let sec = ui.get_onb_totp_secret();
                    let _ = write_to_clipboard_with_flags(&SecretString::from(sec.as_str().to_string()));
                    c.show_toast("Clé secrète TOTP copiée");
                }
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_onb_copy_recovery_codes(move || {
                if let Some(ui) = c.ui.upgrade() {
                    let codes_model = ui.get_onb_recovery_codes();
                    let mut text = String::new();
                    for i in 0..codes_model.row_count() {
                        if let Some(code) = codes_model.row_data(i) {
                            text.push_str(&format!("{}. {}\n", i + 1, code.as_str()));
                        }
                    }
                    let _ = write_to_clipboard_with_flags(&SecretString::from(text));
                    c.show_toast("Codes de secours copiés");
                }
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_onb_init_vault(move |name, master_pw, enable_totp, t2_pw| {
                let Some(ui) = c.ui.upgrade() else { return; };
                let master_str = master_pw.as_str();
                let confirm_str = ui.get_onb_confirm_password();

                if master_str != confirm_str.as_str() {
                    ui.set_onb_error_message("Les mots de passe ne correspondent pas".into());
                    return;
                }
                if master_str.len() < 8 {
                    ui.set_onb_error_message("Le mot de passe doit contenir au moins 8 caractères".into());
                    return;
                }

                let sec_master = SecretString::from(master_str.to_string());
                let sec_t2 = if !t2_pw.as_str().is_empty() {
                    Some(SecretString::from(t2_pw.as_str().to_string()))
                } else {
                    None
                };

                let totp_setup = if enable_totp {
                    let sec = ui.get_onb_totp_secret().to_string();
                    let codes_model = ui.get_onb_recovery_codes();
                    let mut recs = Vec::new();
                    for i in 0..codes_model.row_count() {
                        if let Some(c) = codes_model.row_data(i) {
                            recs.push(c.to_string());
                        }
                    }
                    if !sec.is_empty() && !recs.is_empty() {
                        Some((sec, recs))
                    } else {
                        None
                    }
                } else {
                    None
                };

                let mut st = c.state.lock().unwrap();
                match st.init_vault(
                    name.as_str(),
                    &sec_master,
                    enable_totp,
                    sec_t2.as_ref(),
                    totp_setup,
                ) {
                    Ok(_) => {
                        ui.set_onb_error_message("".into());
                        ui.set_current_view("dashboard".into());
                        ui.set_dsh_vault_name(name.clone());
                        drop(st);
                        c.refresh_dashboard_items();
                        c.show_toast("Coffre initialisé avec succès !");
                    }
                    Err(e) => {
                        ui.set_onb_error_message(format!("{}", e).into());
                    }
                }
            });
        }

        // ==============================================================
        // UNLOCK CALLBACKS
        // ==============================================================
        {
            let c = Arc::clone(&controller);
            ui.on_unl_step1(move |master_pw| {
                let Some(ui) = c.ui.upgrade() else { return; };
                let sec_pw = SecretString::from(master_pw.as_str().to_string());
                let mut st = c.state.lock().unwrap();

                match st.unlock_step1(&sec_pw) {
                    Ok(fully_unlocked) => {
                        ui.set_unl_error_message("".into());
                        ui.set_unl_master_password("".into());

                        if fully_unlocked {
                            ui.set_current_view("dashboard".into());
                            if let Some(v) = st.vault.as_ref() {
                                ui.set_dsh_vault_name(v.metadata.name.clone().into());
                            }
                            drop(st);
                            c.refresh_dashboard_items();
                            c.show_toast("Coffre déverrouillé");
                        } else {
                            ui.set_unl_step(2);
                            ui.set_unl_totp_code("".into());
                            ui.set_unl_recovery_code("".into());
                            ui.set_unl_use_recovery_code(false);
                        }
                    }
                    Err(GuiError::LockoutActive(rem)) => {
                        ui.set_unl_is_locked_out(true);
                        ui.set_unl_lockout_seconds(rem as i32);
                        ui.set_unl_error_message(format!("Compte bloqué (anti-brute-force). Réessayez dans {} s.", rem).into());
                    }
                    Err(e) => {
                        if let Some(rem) = st.check_lockout() {
                            ui.set_unl_is_locked_out(true);
                            ui.set_unl_lockout_seconds(rem as i32);
                            ui.set_unl_error_message(format!("Compte bloqué. Réessayez dans {} s.", rem).into());
                        } else {
                            ui.set_unl_error_message(format!("{}", e).into());
                        }
                    }
                }
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_unl_step2_totp(move |totp_code| {
                let Some(ui) = c.ui.upgrade() else { return; };
                let mut st = c.state.lock().unwrap();

                match st.unlock_step2_totp(totp_code.as_str()) {
                    Ok(()) => {
                        ui.set_unl_error_message("".into());
                        ui.set_unl_totp_code("".into());
                        ui.set_current_view("dashboard".into());
                        if let Some(v) = st.vault.as_ref() {
                            ui.set_dsh_vault_name(v.metadata.name.clone().into());
                        }
                        drop(st);
                        c.refresh_dashboard_items();
                        c.show_toast("Coffre déverrouillé");
                    }
                    Err(e) => {
                        ui.set_unl_error_message(format!("{}", e).into());
                    }
                }
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_unl_step2_recovery(move |code| {
                let Some(ui) = c.ui.upgrade() else { return; };
                let mut st = c.state.lock().unwrap();

                match st.unlock_step2_recovery(code.as_str()) {
                    Ok(()) => {
                        ui.set_unl_error_message("".into());
                        ui.set_unl_recovery_code("".into());
                        ui.set_current_view("dashboard".into());
                        if let Some(v) = st.vault.as_ref() {
                            ui.set_dsh_vault_name(v.metadata.name.clone().into());
                        }
                        drop(st);
                        c.refresh_dashboard_items();
                        c.show_toast("Code de secours consommé — Coffre déverrouillé");
                    }
                    Err(e) => {
                        ui.set_unl_error_message(format!("{}", e).into());
                    }
                }
            });
        }

        {
            let _c = Arc::clone(&controller);
            ui.on_unl_back(move || {
                if let Some(ui) = _c.ui.upgrade() {
                    ui.set_unl_step(1);
                    ui.set_unl_error_message("".into());
                }
            });
        }

        // ==============================================================
        // DASHBOARD CALLBACKS
        // ==============================================================
        {
            let c = Arc::clone(&controller);
            ui.on_dsh_lock_vault(move || {
                c.lock_vault_and_clear_ui();
                c.show_toast("Coffre verrouillé (mémoire purgée)");
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_dsh_select_category(move |cat| {
                let Some(ui) = c.ui.upgrade() else { return; };
                ui.set_dsh_active_category(cat.clone());

                let mut st = c.state.lock().unwrap();
                st.active_category_filter = if cat.as_str() == "All" {
                    None
                } else {
                    Some(parse_category(cat.as_str()))
                };
                st.touch_activity();
                drop(st);
                c.refresh_dashboard_items();
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_dsh_search_changed(move |q| {
                let mut st = c.state.lock().unwrap();
                st.search_query = q.to_string();
                st.touch_activity();
                drop(st);
                c.refresh_dashboard_items();
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_dsh_select_item(move |id_str| {
                let Some(ui) = c.ui.upgrade() else { return; };
                let id = match hex_to_id(id_str.as_str()) {
                    Some(i) => i,
                    None => return,
                };

                let mut st = c.state.lock().unwrap();
                st.selected_item_id = Some(id);
                st.touch_activity();
                drop(st);

                ui.set_dsh_selected_item_id(id_str);
                ui.set_dsh_is_editing(false);
                ui.set_dsh_is_creating(false);

                c.refresh_selected_item();
            });
        }

        {
            let _c = Arc::clone(&controller);
            ui.on_dsh_create_new_item(move || {
                if let Some(ui) = _c.ui.upgrade() {
                    ui.set_dsh_is_creating(true);
                    ui.set_dsh_is_editing(false);
                    ui.set_dsh_form_title("".into());
                    ui.set_dsh_form_category("Web".into());
                    ui.set_dsh_form_username("".into());
                    ui.set_dsh_form_password("".into());
                    ui.set_dsh_form_url("".into());
                    ui.set_dsh_form_notes("".into());
                }
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_dsh_edit_current_item(move || {
                let Some(ui) = c.ui.upgrade() else { return; };
                let st = c.state.lock().unwrap();
                let Some(id) = st.selected_item_id else { return; };

                if !st.can_reveal_item(&id) {
                    drop(st);
                    *c.pending_action.lock().unwrap() = Some(PendingAction::EditItem(id));
                    ui.set_t2_error_message("".into());
                    ui.set_t2_password("".into());
                    ui.set_t2_is_open(true);
                    return;
                }

                if let Some(item) = st.get_item(&id) {
                    ui.set_dsh_is_editing(true);
                    ui.set_dsh_is_creating(false);
                    ui.set_dsh_form_title(item.title.as_str().into());
                    ui.set_dsh_form_category(item.category.to_string().into());
                    ui.set_dsh_form_username(item.username.as_deref().unwrap_or("").into());
                    ui.set_dsh_form_password(item.password.as_deref().unwrap_or("").into());
                    ui.set_dsh_form_url(item.url.as_deref().unwrap_or("").into());
                    ui.set_dsh_form_notes(item.notes.as_deref().unwrap_or("").into());
                }
            });
        }

        {
            let _c = Arc::clone(&controller);
            ui.on_dsh_cancel_edit(move || {
                if let Some(ui) = _c.ui.upgrade() {
                    ui.set_dsh_is_editing(false);
                    ui.set_dsh_is_creating(false);
                    ui.set_dsh_form_title("".into());
                    ui.set_dsh_form_username("".into());
                    ui.set_dsh_form_password("".into());
                    ui.set_dsh_form_url("".into());
                    ui.set_dsh_form_notes("".into());
                }
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_dsh_save_item(move |id_str, title, cat_str, user, pass, url, notes| {
                let Some(ui) = c.ui.upgrade() else { return; };
                let cat = parse_category(cat_str.as_str());

                let mut st = c.state.lock().unwrap();
                let is_creating = ui.get_dsh_is_creating() || id_str.as_str().is_empty();

                if is_creating {
                    let mut item = VaultItem::new(cat, title.as_str());
                    if !user.as_str().is_empty() {
                        item.username = Some(user.as_str().to_string());
                    }
                    if !pass.as_str().is_empty() {
                        item.password = Some(pass.as_str().to_string());
                    }
                    if !url.as_str().is_empty() {
                        item.url = Some(url.as_str().to_string());
                    }
                    if !notes.as_str().is_empty() {
                        item.notes = Some(notes.as_str().to_string());
                    }

                    match st.add_item(item) {
                        Ok(new_id) => {
                            st.selected_item_id = Some(new_id);
                            ui.set_dsh_selected_item_id(id_to_hex(&new_id).into());
                            ui.set_dsh_is_creating(false);
                            ui.set_dsh_form_title("".into());
                            ui.set_dsh_form_username("".into());
                            ui.set_dsh_form_password("".into());
                            ui.set_dsh_form_url("".into());
                            ui.set_dsh_form_notes("".into());
                            drop(st);
                            c.refresh_dashboard_items();
                            c.refresh_selected_item();
                            c.show_toast("Secret créé avec succès");
                        }
                        Err(e) => c.show_toast(&format!("Erreur : {}", e)),
                    }
                } else if let Some(id) = hex_to_id(id_str.as_str()) {
                    if let Some(existing) = st.get_item(&id) {
                        let mut updated = existing.clone();
                        updated.title = title.as_str().to_string();
                        updated.category = cat;
                        updated.username = if !user.as_str().is_empty() {
                            Some(user.as_str().to_string())
                        } else {
                            None
                        };
                        updated.password = if !pass.as_str().is_empty() {
                            Some(pass.as_str().to_string())
                        } else {
                            None
                        };
                        updated.url = if !url.as_str().is_empty() {
                            Some(url.as_str().to_string())
                        } else {
                            None
                        };
                        updated.notes = if !notes.as_str().is_empty() {
                            Some(notes.as_str().to_string())
                        } else {
                            None
                        };

                        match st.update_item(updated) {
                            Ok(()) => {
                                ui.set_dsh_is_editing(false);
                                ui.set_dsh_form_title("".into());
                                ui.set_dsh_form_username("".into());
                                ui.set_dsh_form_password("".into());
                                ui.set_dsh_form_url("".into());
                                ui.set_dsh_form_notes("".into());
                                drop(st);
                                c.refresh_dashboard_items();
                                c.refresh_selected_item();
                                c.show_toast("Secret modifié");
                            }
                            Err(e) => c.show_toast(&format!("Erreur : {}", e)),
                        }
                    }
                }
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_dsh_delete_item(move |id_str| {
                let Some(ui) = c.ui.upgrade() else { return; };
                if let Some(id) = hex_to_id(id_str.as_str()) {
                    let mut st = c.state.lock().unwrap();
                    let _ = st.delete_item(&id);
                    drop(st);
                    ui.set_dsh_selected_item_id("".into());
                    c.refresh_dashboard_items();
                    c.show_toast("Secret supprimé");
                }
            });
        }

        // Tier-2 Reveal Callback
        {
            let c = Arc::clone(&controller);
            ui.on_dsh_reveal_secret(move |id_str| {
                let Some(ui) = c.ui.upgrade() else { return; };
                let id = match hex_to_id(id_str.as_str()) {
                    Some(i) => i,
                    None => return,
                };

                let mut st = c.state.lock().unwrap();
                if st.can_reveal_item(&id) {
                    st.reveal_item_secret(id);
                    drop(st);
                    c.refresh_selected_item();
                } else {
                    // Requires Tier-2 challenge
                    *c.pending_action.lock().unwrap() = Some(PendingAction::RevealSecret(id));
                    ui.set_t2_error_message("".into());
                    ui.set_t2_password("".into());
                    ui.set_t2_is_open(true);
                }
            });
        }

        // Hide secret
        {
            let c = Arc::clone(&controller);
            ui.on_dsh_hide_secret(move |id_str| {
                if let Some(id) = hex_to_id(id_str.as_str()) {
                    let mut st = c.state.lock().unwrap();
                    st.hide_item_secret(&id);
                    drop(st);
                    c.refresh_selected_item();
                }
            });
        }

        // Copy field with Tier-2 check for password
        {
            let c = Arc::clone(&controller);
            ui.on_dsh_copy_field(move |id_str, field| {
                let Some(ui) = c.ui.upgrade() else { return; };
                let id = match hex_to_id(id_str.as_str()) {
                    Some(i) => i,
                    None => return,
                };

                let mut st = c.state.lock().unwrap();
                let item = match st.get_item(&id) {
                    Some(it) => it.clone(),
                    None => return,
                };

                if field.as_str() == "password" {
                    if st.can_reveal_item(&id) {
                        if let Some(pw) = &item.password {
                            let _ = st.copy_to_clipboard(&SecretString::from(pw.clone()), 30);
                            drop(st);
                            c.show_toast("Mot de passe copié (sécurisé, auto-effacé sous 30s)");
                        } else {
                            drop(st);
                        }
                    } else {
                        // Requires Tier-2 challenge
                        drop(st);
                        *c.pending_action.lock().unwrap() =
                            Some(PendingAction::CopyPassword(id));
                        ui.set_t2_error_message("".into());
                        ui.set_t2_password("".into());
                        ui.set_t2_is_open(true);
                    }
                } else {
                    drop(st);
                    let val = match field.as_str() {
                        "username" => item.username.clone().unwrap_or_default(),
                        "url" => item.url.clone().unwrap_or_default(),
                        "notes" => item.notes.clone().unwrap_or_default(),
                        _ => String::new(),
                    };
                    if !val.is_empty() {
                        let _ = write_to_clipboard_with_flags(&SecretString::from(val));
                        c.show_toast("Copié dans le presse-papier");
                    }
                }
            });
        }

        // Auto-Type execution
        {
            let c = Arc::clone(&controller);
            ui.on_dsh_autotype_item(move |id_str| {
                let Some(ui) = c.ui.upgrade() else { return; };
                let id = match hex_to_id(id_str.as_str()) {
                    Some(i) => i,
                    None => return,
                };

                let mut st = c.state.lock().unwrap();
                let item = match st.get_item(&id) {
                    Some(it) => it.clone(),
                    None => return,
                };
                st.touch_activity();
                drop(st);

                let seq = if let Some(custom) = &item.auto_type_sequence {
                    custom.clone()
                } else if item.username.is_some() && item.password.is_some() {
                    "{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string()
                } else if item.password.is_some() {
                    "{PASSWORD}{ENTER}".to_string()
                } else if item.username.is_some() {
                    "{USERNAME}{ENTER}".to_string()
                } else {
                    c.show_toast("Aucun identifiant ou mot de passe à remplir");
                    return;
                };

                // Minimize Slint window to restore target window
                ui.window().set_minimized(true);

                let ui_for_thread = ui.as_weak();
                std::thread::spawn(move || {
                    // Wait 500 ms for focus switch
                    std::thread::sleep(Duration::from_millis(500));

                    let engine = covert_autotype::AutoTypeEngine::new();
                    let res = engine.execute_sequence(&seq, &item, None);

                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_for_thread.upgrade() {
                            let msg = match res {
                                Ok(()) => "Remplissage automatique effectué".to_string(),
                                Err(e) => format!("Erreur Auto-Type : {}", e),
                            };
                            ui.set_toast_message(msg.into());
                            ui.set_toast_visible(true);

                            let ui_weak = ui.as_weak();
                            slint::Timer::single_shot(Duration::from_secs(3), move || {
                                if let Some(ui) = ui_weak.upgrade() {
                                    ui.set_toast_visible(false);
                                }
                            });
                        }
                    })
                    .ok();
                });
            });
        }

        // ==============================================================
        // TIER-2 MODAL CALLBACKS
        // ==============================================================
        {
            let c = Arc::clone(&controller);
            ui.on_t2_confirmed(move |pw, dur| {
                let Some(ui) = c.ui.upgrade() else { return; };
                let sec_t2 = SecretString::from(pw.as_str().to_string());
                let ttl = dur as u64;

                let mut st = c.state.lock().unwrap();
                match st.verify_tier2(&sec_t2, ttl) {
                    Ok(()) => {
                        ui.set_t2_is_open(false);
                        ui.set_t2_error_message("".into());
                        ui.set_t2_password("".into());

                        let action = c.pending_action.lock().unwrap().take();
                        match action {
                            Some(PendingAction::RevealSecret(id)) => {
                                st.reveal_item_secret(id);
                                drop(st);
                                c.refresh_selected_item();
                                c.show_toast("Secret démasqué");
                            }
                            Some(PendingAction::CopyPassword(id)) => {
                                let item = st.get_item(&id).cloned();
                                if let Some(it) = item {
                                    if let Some(pass) = &it.password {
                                        let _ = st.copy_to_clipboard(
                                            &SecretString::from(pass.clone()),
                                            30,
                                        );
                                        drop(st);
                                        c.show_toast("Mot de passe copié (sécurisé, auto-effacé sous 30s)");
                                    } else {
                                        drop(st);
                                    }
                                } else {
                                    drop(st);
                                }
                            }
                            Some(PendingAction::EditItem(id)) => {
                                let item = st.get_item(&id).cloned();
                                drop(st);
                                if let Some(it) = item {
                                    ui.set_dsh_is_editing(true);
                                    ui.set_dsh_is_creating(false);
                                    ui.set_dsh_form_title(it.title.as_str().into());
                                    ui.set_dsh_form_category(it.category.to_string().into());
                                    ui.set_dsh_form_username(it.username.as_deref().unwrap_or("").into());
                                    ui.set_dsh_form_password(it.password.as_deref().unwrap_or("").into());
                                    ui.set_dsh_form_url(it.url.as_deref().unwrap_or("").into());
                                    ui.set_dsh_form_notes(it.notes.as_deref().unwrap_or("").into());
                                    c.show_toast("Édition autorisée (Tier-2)");
                                }
                            }
                            None => {
                                drop(st);
                            }
                        }
                    }
                    Err(_) => {
                        ui.set_t2_error_message("Mot de passe Tier-2 incorrect".into());
                    }
                }
            });
        }

        {
            let c = Arc::clone(&controller);
            ui.on_t2_cancelled(move || {
                if let Some(ui) = c.ui.upgrade() {
                    ui.set_t2_is_open(false);
                    ui.set_t2_password("".into());
                    ui.set_t2_error_message("".into());
                    *c.pending_action.lock().unwrap() = None;
                }
            });
        }

        // ==============================================================
        // HEARTBEAT TIMER (Every 1 second)
        // ==============================================================
        {
            let c = Arc::clone(&controller);
            controller._timer.start(
                slint::TimerMode::Repeated,
                Duration::from_secs(1),
                move || {
                    let Some(ui) = c.ui.upgrade() else { return; };
                    let mut st = c.state.lock().unwrap();

                    // 1. Inactivity check
                    if st.is_unlocked() {
                        let remaining = st.inactivity_remaining_secs();
                        let mins = remaining / 60;
                        let secs = remaining % 60;
                        ui.set_dsh_inactivity_time(format!("{:02}:{:02}", mins, secs).into());

                        if st.check_inactivity() {
                            drop(st);
                            c.lock_vault_and_clear_ui();
                            c.show_toast("Coffre verrouillé pour inactivité");
                            return;
                        }
                    }

                    // 2. Lockout check
                    if let Some(rem) = st.check_lockout() {
                        ui.set_unl_is_locked_out(true);
                        ui.set_unl_lockout_seconds(rem as i32);
                    } else if ui.get_unl_is_locked_out() {
                        ui.set_unl_is_locked_out(false);
                        ui.set_unl_error_message("".into());
                    }

                    // 3. Auto-wipe clipboard if active guard expired
                    let now = crate::state::current_time_secs();
                    let _ = st.wipe_clipboard_if_expired(now);
                },
            );
        }

        controller
    }

    pub fn lock_vault_and_clear_ui(&self) {
        let Some(ui) = self.ui.upgrade() else { return; };
        let mut st = self.state.lock().unwrap();
        st.lock_vault();
        drop(st);

        ui.set_current_view("unlock".into());
        ui.set_unl_step(1);
        ui.set_unl_master_password("".into());
        ui.set_unl_totp_code("".into());
        ui.set_unl_recovery_code("".into());
        ui.set_unl_error_message("".into());

        ui.set_dsh_selected_item_id("".into());
        ui.set_dsh_selected_item(ItemDetail {
            id: "".into(),
            category: "Web".into(),
            title: "".into(),
            username: "".into(),
            password_masked: "".into(),
            password_plain: "".into(),
            is_revealed: false,
            url: "".into(),
            notes: "".into(),
            auto_type_sequence: "".into(),
            ssh_key_type: "".into(),
            ssh_public_key: "".into(),
            api_service: "".into(),
        });
        ui.set_dsh_items(ModelRc::default());
        ui.set_dsh_is_editing(false);
        ui.set_dsh_is_creating(false);
        ui.set_dsh_form_title("".into());
        ui.set_dsh_form_username("".into());
        ui.set_dsh_form_password("".into());
        ui.set_dsh_form_url("".into());
        ui.set_dsh_form_notes("".into());

        ui.set_t2_is_open(false);
        ui.set_t2_password("".into());
        ui.set_t2_error_message("".into());
        *self.pending_action.lock().unwrap() = None;
    }

    pub fn show_toast(&self, msg: &str) {
        if let Some(ui) = self.ui.upgrade() {
            ui.set_toast_message(msg.into());
            ui.set_toast_visible(true);

            let ui_weak = self.ui.clone();
            slint::Timer::single_shot(Duration::from_secs(3), move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_toast_visible(false);
                }
            });
        }
    }

    pub fn refresh_dashboard_items(&self) {
        let Some(ui) = self.ui.upgrade() else { return; };
        let st = self.state.lock().unwrap();
        let filtered = st.filtered_items();

        let summaries: Vec<ItemSummary> = filtered
            .iter()
            .map(|item| ItemSummary {
                id: id_to_hex(&item.id).into(),
                title: item.title.as_str().into(),
                category: item.category.to_string().into(),
                subtitle: item.username.as_deref().unwrap_or("").into(),
            })
            .collect();

        ui.set_dsh_items(ModelRc::new(VecModel::from(summaries)));
    }

    pub fn refresh_selected_item(&self) {
        let Some(ui) = self.ui.upgrade() else { return; };
        let st = self.state.lock().unwrap();

        if let Some(id) = st.selected_item_id {
            if let Some(item) = st.get_item(&id) {
                let is_revealed = st.is_secret_revealed(&id);
                let plain_pw = if is_revealed {
                    item.password.as_deref().unwrap_or("")
                } else {
                    ""
                };

                let detail = ItemDetail {
                    id: id_to_hex(&item.id).into(),
                    category: item.category.to_string().into(),
                    title: item.title.as_str().into(),
                    username: item.username.as_deref().unwrap_or("").into(),
                    password_masked: "••••••••••••".into(),
                    password_plain: plain_pw.into(),
                    is_revealed,
                    url: item.url.as_deref().unwrap_or("").into(),
                    notes: item.notes.as_deref().unwrap_or("").into(),
                    auto_type_sequence: item
                        .auto_type_sequence
                        .as_deref()
                        .unwrap_or("")
                        .into(),
                    ssh_key_type: "".into(),
                    ssh_public_key: "".into(),
                    api_service: "".into(),
                };

                ui.set_dsh_selected_item(detail);
            }
        }
    }
}

pub fn id_to_hex(id: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in id {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_to_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for i in 0..16 {
        let byte_str = &s[i * 2..i * 2 + 2];
        id[i] = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(id)
}

fn parse_category(s: &str) -> Category {
    match s {
        "Web" => Category::Web,
        "SSH" => Category::SSH,
        "ApiKey" => Category::ApiKey,
        "Note" => Category::Note,
        "RawSecret" => Category::RawSecret,
        _ => Category::Web,
    }
}

#[cfg(windows)]
fn get_window_hwnd(window: &slint::Window) -> Option<isize> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let slint_handle = window.window_handle();
    if let Ok(wh) = slint_handle.window_handle() {
        if let RawWindowHandle::Win32(win32_handle) = wh.as_raw() {
            return Some(win32_handle.hwnd.get() as isize);
        }
    }
    None
}

#[cfg(not(windows))]
fn get_window_hwnd(_window: &slint::Window) -> Option<isize> {
    None
}

pub fn apply_screen_protection(window: &slint::Window) {
    if let Some(hwnd) = get_window_hwnd(window) {
        let _ = covert_sentinel::apply_screen_capture_protection(hwnd);
    }
}
