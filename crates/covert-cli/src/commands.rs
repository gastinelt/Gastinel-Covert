//! Command executors for covert-cli.

use crate::args::{
    AddArgs, AutotypeArgs, BackupArgs, ChangeMasterArgs, DaemonArgs, DeleteArgs, EditArgs,
    ExportArgs, GetArgs, ImportArgs, InitArgs, UnlockArgs,
};
use covert_auth::totp::{encode_base32, generate_recovery_codes};
use covert_auth::AuthManager;
use covert_autotype::AutoTypeEngine;
use covert_core::models::{Category, Vault, VaultItem};
use covert_core::ExposeSecret;
use covert_core::SecretString;
use covert_native_msg::NativeMessagingHost;
use covert_sentinel::{SecurityEvent, SecurityEventSink, SentinelMonitor};
use covert_ssh::agent::SshAgent;
use covert_ssh::pipe::run_named_pipe_listener;
use covert_storage::{write_atomic_no_backup, VaultStorage};
use rand_core::{OsRng, RngCore};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn resolve_storage(path: Option<PathBuf>) -> Result<VaultStorage, Box<dyn std::error::Error>> {
    match path {
        Some(p) => Ok(VaultStorage::from_path(p)),
        None => Ok(VaultStorage::default_camouflaged()?),
    }
}

// --- Saisie des secrets ---------------------------------------------------
//
// Les secrets ne sont JAMAIS lus depuis un argument de ligne de commande.
// Ordre de priorite systematique :
//   1. variable d'environnement (voie non-interactive RISQUEE, reservee a
//      l'automatisation : scripts et tests e2e) ;
//   2. saisie interactive (sans echo pour les mots de passe).

/// Lit une variable d'environnement et renvoie sa valeur si elle est definie
/// et non vide.
fn env_secret(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Recupere un secret « a masquer » (mot de passe maitre, mot de passe tier-2).
///
/// Priorite : variable d'environnement `env_var` (automatisation) ; sinon
/// saisie interactive SANS echo du terminal (via `rpassword`).
fn get_password(env_var: &str, prompt: &str) -> Result<SecretString, Box<dyn std::error::Error>> {
    if let Some(v) = env_secret(env_var) {
        return Ok(SecretString::from(v));
    }
    // Lecture sans echo : le mot de passe ne s'affiche pas a l'ecran.
    let pw = rpassword::prompt_password(format!("{}: ", prompt))?;
    Ok(SecretString::from(pw))
}

/// Recupere un nouveau mot de passe avec double saisie interactive de confirmation
/// (ou via `env_var` en mode automatisation).
fn get_confirmed_password(
    env_var: &str,
    prompt: &str,
    confirm_prompt: &str,
) -> Result<SecretString, Box<dyn std::error::Error>> {
    if let Some(v) = env_secret(env_var) {
        return Ok(SecretString::from(v));
    }
    let pw1 = rpassword::prompt_password(format!("{}: ", prompt))?;
    let pw2 = rpassword::prompt_password(format!("{}: ", confirm_prompt))?;
    if pw1 != pw2 {
        return Err("Password confirmation does not match".into());
    }
    Ok(SecretString::from(pw1))
}

/// Lit une ligne visible depuis stdin (utilise pour les codes TOTP / de
/// recuperation, qui ne necessitent pas de masquage de l'echo).
fn read_visible_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}: ", prompt);
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Second facteur d'authentification : code TOTP ou code de recuperation.
enum SecondFactor {
    Totp(String),
    Recovery(String),
}

/// Obtient un second facteur quand le coffre requiert la 2FA.
///
/// Priorite : COVERT_RECOVERY_CODE, puis COVERT_TOTP (automatisation) ; sinon
/// saisie interactive : code TOTP visible, ou code de recuperation si le champ
/// TOTP est laisse vide.
fn get_second_factor() -> Result<SecondFactor, Box<dyn std::error::Error>> {
    if let Some(code) = env_secret("COVERT_RECOVERY_CODE") {
        return Ok(SecondFactor::Recovery(code));
    }
    if let Some(code) = env_secret("COVERT_TOTP") {
        return Ok(SecondFactor::Totp(code));
    }
    // Le code TOTP n'est pas un secret durable : saisie visible (plus ergonomique).
    let totp = read_visible_line("Enter 6-digit TOTP code (leave blank to use a recovery code)")?;
    if !totp.is_empty() {
        return Ok(SecondFactor::Totp(totp));
    }
    let recovery = read_visible_line("Enter emergency recovery code")?;
    if recovery.is_empty() {
        return Err("Vault requires 2FA: no TOTP code or recovery code provided".into());
    }
    Ok(SecondFactor::Recovery(recovery))
}

/// Obtient un code TOTP uniquement (sous-commande autotype : pas de code de
/// recuperation accepte). Priorite : COVERT_TOTP ; sinon saisie visible.
fn get_totp_only() -> Result<String, Box<dyn std::error::Error>> {
    if let Some(code) = env_secret("COVERT_TOTP") {
        return Ok(code);
    }
    let totp = read_visible_line("Enter 6-digit TOTP code")?;
    if totp.is_empty() {
        return Err("Vault requires 2FA: no TOTP code provided (set COVERT_TOTP or type it)".into());
    }
    Ok(totp)
}

/// Deverrouille et authentifie completement le coffre (mot de passe maitre + 2FA si active).
fn unlock_vault_authenticated(
    storage: &VaultStorage,
) -> Result<(Vault, SecretString), Box<dyn std::error::Error>> {
    let password = get_password("COVERT_PASSWORD", "Enter Master Password")?;
    let raw_vault = storage.load_raw()?;
    let mut auth_manager = AuthManager::with_lockout_path(storage.lock_path());

    let (mut vault, _header) = auth_manager.verify_master_password(&raw_vault, &password)?;
    let now = current_timestamp();

    if vault.security.totp_secret.is_some() {
        match get_second_factor()? {
            SecondFactor::Recovery(recovery_code) => {
                auth_manager.verify_recovery_code(&mut vault, &recovery_code)?;
                storage.save_vault(&vault, &password, None)?;
            }
            SecondFactor::Totp(totp_code) => {
                auth_manager.verify_totp(&vault, &totp_code, now)?;
            }
        }
    }

    Ok((vault, password))
}

fn parse_category(s: &str) -> Result<Category, Box<dyn std::error::Error>> {
    match s.trim().to_lowercase().as_str() {
        "web" => Ok(Category::Web),
        "ssh" => Ok(Category::SSH),
        "apikey" | "api-key" | "api_key" => Ok(Category::ApiKey),
        "note" => Ok(Category::Note),
        "raw" | "rawsecret" | "raw-secret" | "raw_secret" => Ok(Category::RawSecret),
        other => Err(format!(
            "Unknown category '{}' (expected: web, ssh, apikey, note, raw)",
            other
        )
        .into()),
    }
}

pub fn execute_init(args: InitArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let password = get_password("COVERT_PASSWORD", "Enter Master Password")?;

    let mut vault = Vault::new(args.name);

    let totp_info = if args.setup_totp {
        let mut raw_secret = [0u8; 20];
        OsRng.fill_bytes(&mut raw_secret);
        let totp_secret = encode_base32(&raw_secret);
        let recovery_codes = generate_recovery_codes(10);

        vault.security.totp_secret = Some(totp_secret.clone());
        vault.security.totp_digits = 6;
        vault.security.totp_period = 30;
        vault.security.totp_algorithm = "SHA1".to_string();
        vault.security.recovery_codes = recovery_codes.clone();

        Some((totp_secret, recovery_codes))
    } else {
        None
    };

    if args.setup_tier2 {
        let sec_t2 = get_password("COVERT_TIER2_PASSWORD", "Enter Tier-2 Master View Password")?;
        vault.security.master_view_password_hash =
            Some(covert_auth::tier2::hash_tier2_password(&sec_t2)?);
    }

    storage.save_vault(&vault, &password, None)?;

    println!("[SUCCESS] Initialized new encrypted vault successfully.");
    println!("  Vault Name:      {}", vault.metadata.name);
    println!("  Storage Path:    {}", storage.vault_path().display());
    println!("  Schema Version:  {}", vault.metadata.schema_version);

    if let Some((secret, codes)) = totp_info {
        println!("\n=== 2FA Aegis TOTP Enrollment ===");
        println!("  Secret (Base32): {}", secret);
        println!("\n=== Emergency Recovery Codes (Single-Use) ===");
        for (i, code) in codes.iter().enumerate() {
            println!("  [{:>2}] {}", i + 1, code);
        }
        println!("\nStore these emergency recovery codes in a secure offline location.");
    }

    Ok(())
}

pub fn execute_unlock(args: UnlockArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let password = get_password("COVERT_PASSWORD", "Enter Master Password")?;

    let raw_vault = storage.load_raw()?;
    let mut auth_manager = AuthManager::with_lockout_path(storage.lock_path());

    let (mut vault, header) = auth_manager.verify_master_password(&raw_vault, &password)?;
    let now = current_timestamp();

    if vault.security.totp_secret.is_some() {
        match get_second_factor()? {
            SecondFactor::Recovery(recovery_code) => {
                auth_manager.verify_recovery_code(&mut vault, &recovery_code)?;
                // Commit consumed recovery code atomically to disk
                storage.save_vault(&vault, &password, None)?;
                println!("[INFO] Recovery code consumed and committed.");
            }
            SecondFactor::Totp(totp_code) => {
                auth_manager.verify_totp(&vault, &totp_code, now)?;
            }
        }
    }

    println!("[SUCCESS] Vault unlocked successfully.");
    println!("  Name:            {}", vault.metadata.name);
    println!("  Cipher Algo:     {}", header.cipher_algo);
    println!("  Total Items:     {}", vault.items.len());
    println!("  Last Modified:   {}", vault.metadata.modified_at);

    Ok(())
}

pub fn execute_get(args: GetArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let (vault, password) = unlock_vault_authenticated(&storage)?;
    let auth_manager = AuthManager::with_lockout_path(storage.lock_path());

    // Devoilement tier-2 declenche par --reveal ou par COVERT_TIER2_PASSWORD.
    let want_reveal = args.reveal || env_secret("COVERT_TIER2_PASSWORD").is_some();
    let is_tier2_revealed = if want_reveal {
        let sec_pw = get_password("COVERT_TIER2_PASSWORD", "Enter Tier-2 Master View Password")?;
        if vault.security.master_view_password_hash.is_some() {
            auth_manager.verify_tier2_password(&vault, &sec_pw)?;
            true
        } else if sec_pw.expose_secret() == password.expose_secret() {
            true
        } else {
            return Err("Tier-2 password incorrect".into());
        }
    } else {
        false
    };

    let query_lower = args.query.as_deref().unwrap_or("").to_lowercase();
    let matched_items: Vec<&VaultItem> = vault
        .items
        .iter()
        .filter(|item| {
            if query_lower.is_empty() {
                return true;
            }
            item.title.to_lowercase().contains(&query_lower)
                || item.username.as_deref().unwrap_or("").to_lowercase().contains(&query_lower)
                || item.url.as_deref().unwrap_or("").to_lowercase().contains(&query_lower)
                || hex_encode(item.id).contains(&query_lower)
        })
        .collect();

    if args.json {
        let mut json_items = Vec::new();
        for item in &matched_items {
            let pass_val = if is_tier2_revealed {
                item.password.clone()
            } else {
                item.password.as_ref().map(|_| "********".to_string())
            };

            json_items.push(serde_json::json!({
                "id": hex_encode(item.id),
                "category": item.category.to_string(),
                "title": item.title,
                "username": item.username,
                "password": pass_val,
                "url": item.url,
                "tags": item.tags,
            }));
        }
        println!("{}", serde_json::to_string_pretty(&json_items)?);
    } else {
        println!("Found {} matching item(s):", matched_items.len());
        for (i, item) in matched_items.iter().enumerate() {
            println!("\n[{}] {}", i + 1, item.title);
            println!("  Category: {}", item.category);
            println!("  ID:       {}", hex_encode(item.id));
            if let Some(user) = &item.username {
                println!("  Username: {}", user);
            }
            if let Some(url) = &item.url {
                println!("  URL:      {}", url);
            }
            if let Some(pass) = &item.password {
                if is_tier2_revealed {
                    println!("  Password: {}", pass);
                } else {
                    println!("  Password: ******** (masked, use --reveal to reveal)");
                }
            }
        }
    }

    Ok(())
}

pub fn execute_add(args: AddArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let (mut vault, master_password) = unlock_vault_authenticated(&storage)?;
    let category = parse_category(&args.category)?;

    if args.title.trim().is_empty() {
        return Err("Item title cannot be empty".into());
    }

    let mut item = match category {
        Category::Web => {
            let secret = get_password("COVERT_ITEM_SECRET", "Enter Credential Password")?;
            let mut it = VaultItem::new_credential(
                args.title,
                args.username.unwrap_or_default(),
                secret.expose_secret().to_string(),
                args.url,
            );
            it.notes = args.notes;
            it
        }
        Category::SSH => {
            let priv_key = get_password("COVERT_ITEM_SECRET", "Enter SSH Private Key")?;
            let mut it = VaultItem::new_ssh(
                args.title,
                args.key_type.unwrap_or_else(|| "ed25519".to_string()),
                args.public_key.unwrap_or_default(),
                priv_key.expose_secret().to_string(),
                None,
                args.comment,
            );
            it.notes = args.notes;
            it
        }
        Category::ApiKey => {
            let token = get_password("COVERT_ITEM_SECRET", "Enter API Token")?;
            let mut it = VaultItem::new_api_key(
                args.title,
                args.service.unwrap_or_default(),
                token.expose_secret().to_string(),
                None,
            );
            it.notes = args.notes;
            it
        }
        Category::Note => {
            let content = match args.notes {
                Some(n) => n,
                None => get_password("COVERT_ITEM_SECRET", "Enter Secure Note Content")?
                    .expose_secret()
                    .to_string(),
            };
            VaultItem::new_note(args.title, content)
        }
        Category::RawSecret => {
            let secret = get_password("COVERT_ITEM_SECRET", "Enter Raw Secret")?;
            let mut it = VaultItem::new_raw_secret(
                args.title,
                secret.expose_secret().as_bytes().to_vec(),
            );
            it.notes = args.notes;
            it
        }
    };

    item.tags = args.tags;
    item.auto_type_sequence = args.sequence;

    let item_id_hex = hex_encode(item.id);
    let item_title = item.title.clone();
    vault.add_item(item);
    storage.save_vault(&vault, &master_password, None)?;

    println!(
        "[SUCCESS] Added item '{}' (ID: {}).",
        item_title, item_id_hex
    );
    Ok(())
}

pub fn execute_edit(args: EditArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let (mut vault, master_password) = unlock_vault_authenticated(&storage)?;

    let query_lower = args.query.trim().to_lowercase();
    let target_id = vault
        .items
        .iter()
        .find(|it| {
            hex_encode(it.id) == query_lower
                || it.title.to_lowercase() == query_lower
                || it.title.to_lowercase().contains(&query_lower)
        })
        .map(|it| it.id)
        .ok_or_else(|| format!("No item matching '{}'", args.query))?;

    let rotate_sec = args.rotate_secret || env_secret("COVERT_ITEM_SECRET").is_some();
    let new_secret = if rotate_sec {
        Some(get_password("COVERT_ITEM_SECRET", "Enter New Item Secret")?)
    } else {
        None
    };

    let now = current_timestamp();
    let item = vault
        .get_item_mut(&target_id)
        .ok_or_else(|| format!("Item '{}' not found", args.query))?;

    if let Some(new_title) = args.title {
        if new_title.trim().is_empty() {
            return Err("Item title cannot be empty".into());
        }
        item.title = new_title;
    }
    if let Some(new_user) = args.username {
        item.username = Some(new_user);
    }
    if let Some(new_url) = args.url {
        item.url = Some(new_url);
    }
    if let Some(new_notes) = args.notes {
        item.notes = Some(new_notes);
    }
    if let Some(new_service) = args.service {
        if let Some(ref mut api) = item.api_key_data {
            api.service = new_service;
        }
    }
    if !args.tags.is_empty() {
        item.tags = args.tags;
    }
    if let Some(new_seq) = args.sequence {
        item.auto_type_sequence = Some(new_seq);
    }

    if let Some(sec) = new_secret {
        let plain = sec.expose_secret().to_string();
        match item.category {
            Category::Web => {
                item.password = Some(plain);
            }
            Category::ApiKey => {
                if let Some(ref mut api) = item.api_key_data {
                    api.token = plain;
                } else {
                    item.password = Some(plain);
                }
            }
            Category::SSH => {
                if let Some(ref mut ssh) = item.ssh_data {
                    ssh.private_key = plain;
                } else {
                    item.password = Some(plain);
                }
            }
            Category::Note => {
                item.notes = Some(plain);
            }
            Category::RawSecret => {
                item.raw_data = Some(plain.into_bytes());
            }
        }
    }

    item.updated_at = now;
    let updated_title = item.title.clone();
    storage.save_vault(&vault, &master_password, None)?;

    println!(
        "[SUCCESS] Updated item '{}' (ID: {}).",
        updated_title,
        hex_encode(target_id)
    );
    Ok(())
}

pub fn execute_delete(args: DeleteArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let (mut vault, master_password) = unlock_vault_authenticated(&storage)?;

    let query_lower = args.query.trim().to_lowercase();
    let (target_id, target_title) = vault
        .items
        .iter()
        .find(|it| {
            hex_encode(it.id) == query_lower
                || it.title.to_lowercase() == query_lower
                || it.title.to_lowercase().contains(&query_lower)
        })
        .map(|it| (it.id, it.title.clone()))
        .ok_or_else(|| format!("No item matching '{}'", args.query))?;

    if !vault.remove_item(&target_id) {
        return Err(format!("Failed to remove item '{}'", args.query).into());
    }

    storage.save_vault(&vault, &master_password, None)?;
    println!(
        "[SUCCESS] Deleted item '{}' (ID: {}).",
        target_title,
        hex_encode(target_id)
    );
    Ok(())
}

pub fn execute_change_master(args: ChangeMasterArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let (mut vault, old_password) = unlock_vault_authenticated(&storage)?;

    let new_password = get_confirmed_password(
        "COVERT_NEW_PASSWORD",
        "Enter New Master Password",
        "Confirm New Master Password",
    )?;

    if new_password.expose_secret().len() < 8 {
        return Err("New master password must be at least 8 characters long".into());
    }
    if new_password.expose_secret() == old_password.expose_secret() {
        return Err("New master password must differ from current master password".into());
    }
    if vault.security.master_view_password_hash.is_some()
        && covert_auth::tier2::verify_tier2_password(&vault, &new_password).is_ok()
    {
        return Err("New master password cannot match Tier-2 Master View Password".into());
    }

    storage.rotate_master_password(&mut vault, &old_password, &new_password, None)?;

    println!("[SUCCESS] Master password rotated atomically (.bin and .bak updated).");
    Ok(())
}

/// Format binaire documente d'un fichier d'export Gastinel Covert :
/// - En-tete binaire de 88 octets (Little-Endian), passe integralement comme AAD Poly1305 :
///   * Octets 0..8   : Magic `b"GCOVERT1"`
///   * Octets 8..12  : Version du format (`1u32` LE)
///   * Octet 12      : Identifiant KDF (`0x01` = Argon2id)
///   * Octet 13      : Identifiant AEAD (`0x01` = XChaCha20-Poly1305)
///   * Octets 14..16 : Reserve (`0x0000`)
///   * Octets 16..20 : `m_cost_kib` Argon2id (`u32` LE, 262144 KiB = 256 MiB)
///   * Octets 20..24 : `t_cost` Argon2id (`u32` LE, 4 iterations)
///   * Octets 24..28 : `p_cost` Argon2id (`u32` LE, 4 voies)
///   * Octets 28..60 : Sel CSPRNG 32 octets
///   * Octets 60..84 : Nonce CSPRNG XChaCha20 24 octets
///   * Octets 84..88 : `ciphertext_len` (`u32` LE)
/// - Octets 88..88+ciphertext_len : Charge CBOR du coffre chiffree avec la cle derivee
///   du mot de passe d'export separe.
/// - 16 derniers octets : Tag d'authentification Poly1305 garantissant l'integrite
///   de l'en-tete et du texte chiffre (toute modification d'un seul bit fait echouer l'import).
pub fn execute_export(args: ExportArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let (vault, master_password) = unlock_vault_authenticated(&storage)?;

    let export_password = get_confirmed_password(
        "COVERT_EXPORT_PASSWORD",
        "Enter Export Password (must differ from Master Password)",
        "Confirm Export Password",
    )?;

    if export_password.expose_secret().len() < 8 {
        return Err("Export password must be at least 8 characters long".into());
    }
    if export_password.expose_secret() == master_password.expose_secret() {
        return Err(
            "Export password must be separate (different from the vault Master Password)".into(),
        );
    }

    let encrypted_export = vault.encrypt(&export_password, None)?;
    write_atomic_no_backup(&args.output, &encrypted_export)?;

    println!(
        "[SUCCESS] Exported {} item(s) to encrypted file: {}",
        vault.items.len(),
        args.output.display()
    );
    Ok(())
}

pub fn execute_import(args: ImportArgs) -> Result<(), Box<dyn std::error::Error>> {
    if !args.input.exists() {
        return Err(format!("Export file not found: {}", args.input.display()).into());
    }

    let export_bytes = std::fs::read(&args.input)?;
    let export_password = get_password("COVERT_EXPORT_PASSWORD", "Enter Export Password")?;

    // Verification cryptographique d'authenticite et d'integrite (AAD 88 octets + Poly1305 tag).
    // Refuse immediatement tout fichier modifie, tronque ou avec mauvais mot de passe d'export.
    let (imported_vault, _header) = Vault::decrypt(&export_bytes, &export_password)
        .map_err(|e| format!("Export file authentication/integrity verification failed: {}", e))?;

    let storage = resolve_storage(args.path)?;
    if storage.exists() {
        let (mut target_vault, master_password) = unlock_vault_authenticated(&storage)?;
        let mut imported_count = 0usize;
        for item in &imported_vault.items {
            if let Some(existing) = target_vault.get_item_mut(&item.id) {
                *existing = item.clone();
            } else {
                target_vault.add_item(item.clone());
            }
            imported_count += 1;
        }
        storage.save_vault(&target_vault, &master_password, None)?;
        println!(
            "[SUCCESS] Imported {} item(s) into existing vault at: {}",
            imported_count,
            storage.vault_path().display()
        );
    } else {
        let master_password = get_password(
            "COVERT_PASSWORD",
            "Enter Master Password for new imported vault",
        )?;
        if master_password.expose_secret().len() < 8 {
            return Err("Master password must be at least 8 characters long".into());
        }
        let count = imported_vault.items.len();
        storage.save_vault(&imported_vault, &master_password, None)?;
        println!(
            "[SUCCESS] Imported {} item(s) into new vault at: {}",
            count,
            storage.vault_path().display()
        );
    }

    Ok(())
}

pub fn execute_backup(args: BackupArgs) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let (_vault, _master_password) = unlock_vault_authenticated(&storage)?;
    let raw_encrypted = storage.load_raw()?;

    std::fs::create_dir_all(&args.output_dir)?;

    let stamp = format_utc_timestamp(current_timestamp());
    let mut candidate = args
        .output_dir
        .join(format!("covert-backup-{}.bin", stamp));
    let mut suffix = 1u32;
    while candidate.exists() {
        candidate = args
            .output_dir
            .join(format!("covert-backup-{}-{}.bin", stamp, suffix));
        suffix += 1;
    }

    write_atomic_no_backup(&candidate, &raw_encrypted)?;
    println!(
        "[SUCCESS] Created dated encrypted backup at: {}",
        candidate.display()
    );
    Ok(candidate)
}

/// Formate un timestamp Unix (secondes UTC) en `YYYYMMDD-HHMMSS` (algorithme civil de Hinnant).
fn format_utc_timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        year, m, d, hour, minute, second
    )
}

pub fn execute_autotype(args: AutotypeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let password = get_password("COVERT_PASSWORD", "Enter Master Password")?;

    let raw_vault = storage.load_raw()?;
    let mut auth_manager = AuthManager::with_lockout_path(storage.lock_path());

    let (vault, _header) = auth_manager.verify_master_password(&raw_vault, &password)?;
    let now = current_timestamp();

    if vault.security.totp_secret.is_some() {
        let totp_code = get_totp_only()?;
        auth_manager.verify_totp(&vault, &totp_code, now)?;
    }

    let query_lower = args.query.to_lowercase();
    let target_item = vault
        .items
        .iter()
        .find(|item| {
            item.title.to_lowercase() == query_lower
                || item.title.to_lowercase().contains(&query_lower)
                || hex_encode(item.id) == query_lower
        })
        .ok_or_else(|| format!("No item matching query '{}'", args.query))?;

    let sequence = args
        .sequence
        .as_deref()
        .or(target_item.auto_type_sequence.as_deref())
        .unwrap_or("{USERNAME}{TAB}{PASSWORD}{ENTER}");

    // Compute live TOTP code if sequence requires it
    let live_totp = if sequence.contains("{TOTP}") {
        if let Some(secret) = &vault.security.totp_secret {
            covert_auth::totp::compute_totp_code(secret, now, 6, 30).ok()
        } else {
            None
        }
    } else {
        None
    };

    if args.simulated {
        let (engine, backend) = AutoTypeEngine::new_simulated();
        engine.execute_sequence(sequence, target_item, live_totp.as_deref())?;
        let count = backend.recorded_events().len();
        println!("[SUCCESS] Recorded {} simulated keystroke events without OS SendInput.", count);
    } else {
        println!("[Auto-Type] Preparing to inject keystrokes for: {}", target_item.title);
        println!("  Target sequence: {}", sequence);
        println!("  Switch focus to target window within {} ms...", args.delay);
        std::thread::sleep(Duration::from_millis(args.delay));

        let engine = AutoTypeEngine::new();
        match engine.execute_sequence(sequence, target_item, live_totp.as_deref()) {
            Ok(()) => {
                println!("[SUCCESS] Keystrokes injected directly via Win32 SendInput without clipboard.");
            }
            Err(covert_autotype::AutoTypeError::SendInputFailed(5)) => {
                println!("[WARN] SendInput access denied (error 5: non-interactive desktop session). Sequence validated successfully.");
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn execute_daemon(args: DaemonArgs) -> Result<(), Box<dyn std::error::Error>> {
    let storage = resolve_storage(args.path)?;
    let stop_signal = Arc::new(AtomicBool::new(false));

    // Optional pre-unlocked vault in memory (opt-in via --unlock)
    let maybe_vault = if args.unlock {
        let password = get_password("COVERT_PASSWORD", "Enter Master Password")?;
        let raw_vault = storage.load_raw()?;
        let mut auth_manager = AuthManager::with_lockout_path(storage.lock_path());
        let (vault, _) = auth_manager.verify_master_password(&raw_vault, &password)?;
        if vault.security.totp_secret.is_some() {
            let totp_code = get_totp_only()?;
            auth_manager.verify_totp(&vault, &totp_code, current_timestamp())?;
        }
        Some(vault)
    } else {
        None
    };

    // SshAgent setup
    let pipe_name = args.pipe.unwrap_or_else(|| covert_ssh::DEFAULT_SSH_PIPE_NAME.to_string());
    let ssh_agent = Arc::new(SshAgent::with_pipe_name(pipe_name.clone()));
    if let Some(ref v) = maybe_vault {
        ssh_agent.load_vault_keys(v);
        eprintln!("[Daemon] OpenSSH Agent initialized with vault SSH keys.");
    }

    // Native Messaging Host setup (if enabled)
    let native_host = if args.native_msg {
        let host = Arc::new(NativeMessagingHost::new());
        host.set_require_caller_auth(true);
        if let Ok(origins_str) = std::env::var("COVERT_ALLOWED_ORIGINS") {
            let origins: Vec<String> = origins_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !origins.is_empty() {
                host.set_allowed_origins(origins)?;
            }
        }
        if let Ok(caller_origin) = std::env::var("COVERT_EXTENSION_ORIGIN") {
            let trimmed = caller_origin.trim();
            if !trimmed.is_empty() {
                host.verify_caller(trimmed)?;
            }
        }
        if let Some(ref v) = maybe_vault {
            host.set_vault(v.clone());
        }
        Some(host)
    } else {
        None
    };

    // Sentinel Defense setup
    let _sentinel = if !args.no_sentinel {
        struct DaemonSink {
            ssh_agent: Arc<SshAgent>,
            native_host: Option<Arc<NativeMessagingHost>>,
        }
        impl SecurityEventSink for DaemonSink {
            fn on_security_alert(&self, event: SecurityEvent) {
                eprintln!("[SENTINEL ALERT] Security alert triggered: {:?}", event);
                self.ssh_agent.on_security_alert(event.clone());
                if let Some(ref h) = self.native_host {
                    h.on_security_alert(event);
                }
            }
        }
        let sink = Arc::new(DaemonSink {
            ssh_agent: Arc::clone(&ssh_agent),
            native_host: native_host.clone(),
        });
        let monitor = SentinelMonitor::start(sink)?;
        eprintln!("[Daemon] Windows Sentinel Active Defense started (session, network 22/3389, antidebug).");
        Some(monitor)
    } else {
        eprintln!("[Daemon] Sentinel defense disabled by flag.");
        None
    };

    // Spawn named pipe listener thread for OpenSSH agent
    let pipe_agent = Arc::clone(&ssh_agent);
    let pipe_stop = Arc::clone(&stop_signal);
    let pipe_name_clone = pipe_name.clone();
    let _pipe_handle = std::thread::spawn(move || {
        let _ = run_named_pipe_listener(&pipe_name_clone, pipe_stop, move |req| {
            pipe_agent.process_request(req)
        });
    });
    eprintln!("[Daemon] OpenSSH Named Pipe active on: {}", pipe_name);

    // If native-msg mode: run stdio loop on main thread
    if let Some(host) = native_host {
        eprintln!("[Daemon] Browser Native Messaging Host listening on stdio.");
        host.run_stdio_loop(io::stdin().lock(), io::stdout().lock())?;
    } else {
        eprintln!("[Daemon] Gastinel Covert headless daemon running. Press Ctrl+C to terminate.");
        while !stop_signal.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    stop_signal.store(true, Ordering::Relaxed);
    eprintln!("[Daemon] Gastinel Covert daemon exited cleanly.");
    Ok(())
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex_encode(bytes: [u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
