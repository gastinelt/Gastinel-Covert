//! Command executors for covert-cli.

use crate::args::{AutotypeArgs, DaemonArgs, GetArgs, InitArgs, UnlockArgs};
use covert_auth::totp::{encode_base32, generate_recovery_codes};
use covert_auth::AuthManager;
use covert_autotype::AutoTypeEngine;
use covert_core::models::{Vault, VaultItem};
use covert_core::SecretString;
use covert_native_msg::NativeMessagingHost;
use covert_sentinel::{SecurityEvent, SecurityEventSink, SentinelMonitor};
use covert_ssh::agent::SshAgent;
use covert_ssh::pipe::run_named_pipe_listener;
use covert_core::ExposeSecret;
use covert_storage::VaultStorage;
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
                    println!("  Password: ******** (masked, use --tier2 to reveal)");
                }
            }
        }
    }

    Ok(())
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
