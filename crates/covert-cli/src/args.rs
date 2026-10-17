//! Command line argument definitions for covert-cli.
//!
//! IMPORTANT (securite) : aucun secret (mot de passe maitre, mot de passe
//! tier-2, code TOTP, code de recuperation) ne peut etre passe en argument de
//! ligne de commande. Les arguments sont visibles dans le Gestionnaire des
//! taches et l'historique du shell ; ils sont donc proscrits.
//!
//! Les secrets sont fournis uniquement :
//!   1. soit en saisie interactive (mot de passe sans echo du terminal) ;
//!   2. soit, pour l'automatisation (scripts, tests e2e) UNIQUEMENT, via une
//!      variable d'environnement. Cette voie est RISQUEE (l'environnement d'un
//!      processus peut etre lu) et reservee aux pipelines non interactifs :
//!        - COVERT_PASSWORD         : mot de passe maitre
//!        - COVERT_NEW_PASSWORD     : nouveau mot de passe maitre (change-master)
//!        - COVERT_ITEM_SECRET      : secret d'une entree (add / edit)
//!        - COVERT_EXPORT_PASSWORD  : mot de passe d'export/import separe (export / import)
//!        - COVERT_TIER2_PASSWORD   : mot de passe tier-2 (devoilement)
//!        - COVERT_TOTP             : code TOTP a 6 chiffres
//!        - COVERT_RECOVERY_CODE    : code de recuperation d'urgence
//!      Ordre de priorite : si la variable d'environnement est definie, elle
//!      est utilisee ; sinon la saisie interactive est demandee.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "covert",
    about = "Gastinel Covert: Zero-trust, local-only secret manager for Windows x86_64",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Initialize a new encrypted vault
    Init(InitArgs),

    /// Unlock and verify vault credentials (master password + 2FA TOTP)
    Unlock(UnlockArgs),

    /// Query and retrieve credentials from the vault
    Get(GetArgs),

    /// Add a new credential or secret item to the vault
    Add(AddArgs),

    /// Edit an existing credential or secret item in the vault
    Edit(EditArgs),

    /// Delete an item from the vault
    Delete(DeleteArgs),

    /// Rotate the vault master password (updates both .bin and .bak atomically)
    ChangeMaster(ChangeMasterArgs),

    /// Export the vault to an authenticated encrypted file with a separate export password
    Export(ExportArgs),

    /// Verify integrity and import items from an encrypted export file
    Import(ImportArgs),

    /// Create a dated encrypted backup copy of the vault in a chosen directory
    Backup(BackupArgs),

    /// Execute direct keystroke injection (Auto-Type) for a credential
    Autotype(AutotypeArgs),

    /// Run background daemon hosting Sentinel defense and OpenSSH agent
    Daemon(DaemonArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Vault human-readable name
    #[arg(short, long, default_value = "Main Vault")]
    pub name: String,

    /// Custom storage destination path (defaults to DirectX ShaderCache camouflage path)
    #[arg(long)]
    pub path: Option<PathBuf>,

    /// Automatically configure 2FA Aegis RFC 6238 TOTP and generate 10 recovery codes
    #[arg(long)]
    pub setup_totp: bool,

    /// Configure an optional Tier-2 Master View Password for unmasking secrets.
    /// The password is requested interactively (no echo) or via COVERT_TIER2_PASSWORD.
    #[arg(long)]
    pub setup_tier2: bool,
}

#[derive(Debug, Args)]
pub struct UnlockArgs {
    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Search query matching title, username, url, or ID
    pub query: Option<String>,

    /// Reveal plain-text secrets by supplying the Tier-2 Master View Password.
    /// The password is requested interactively (no echo) or via COVERT_TIER2_PASSWORD.
    #[arg(long)]
    pub reveal: bool,

    /// Output results in JSON format
    #[arg(long)]
    pub json: bool,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Item title
    #[arg(short, long)]
    pub title: String,

    /// Item category: web, ssh, apikey, note, raw
    #[arg(short, long, default_value = "web")]
    pub category: String,

    /// Username (for Web credentials)
    #[arg(short, long)]
    pub username: Option<String>,

    /// URL (for Web credentials)
    #[arg(long)]
    pub url: Option<String>,

    /// Service name (for ApiKey items)
    #[arg(long)]
    pub service: Option<String>,

    /// SSH key type, e.g. ed25519 or rsa (for SSH items)
    #[arg(long)]
    pub key_type: Option<String>,

    /// SSH public key string (for SSH items)
    #[arg(long)]
    pub public_key: Option<String>,

    /// SSH comment (for SSH items)
    #[arg(long)]
    pub comment: Option<String>,

    /// Notes or description
    #[arg(long)]
    pub notes: Option<String>,

    /// Optional tags
    #[arg(long = "tag")]
    pub tags: Vec<String>,

    /// Custom auto-type sequence template
    #[arg(long)]
    pub sequence: Option<String>,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    /// Target item title or hex ID to edit
    pub query: String,

    /// New item title
    #[arg(short, long)]
    pub title: Option<String>,

    /// New username
    #[arg(short, long)]
    pub username: Option<String>,

    /// New URL
    #[arg(long)]
    pub url: Option<String>,

    /// New notes
    #[arg(long)]
    pub notes: Option<String>,

    /// New service name (for ApiKey items)
    #[arg(long)]
    pub service: Option<String>,

    /// Replace item tags
    #[arg(long = "tag")]
    pub tags: Vec<String>,

    /// New auto-type sequence template
    #[arg(long)]
    pub sequence: Option<String>,

    /// Prompt interactively (no echo) or via COVERT_ITEM_SECRET to update the item's secret
    #[arg(long)]
    pub rotate_secret: bool,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    /// Target item title or hex ID to delete
    pub query: String,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ChangeMasterArgs {
    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Destination file path for the encrypted export
    #[arg(short, long)]
    pub output: PathBuf,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Source file path of the encrypted export to import
    #[arg(short, long)]
    pub input: PathBuf,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct BackupArgs {
    /// Destination directory where the dated encrypted backup copy will be written
    #[arg(short = 'd', long = "output-dir")]
    pub output_dir: PathBuf,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct AutotypeArgs {
    /// Target credential title or ID to auto-type
    pub query: String,

    /// Custom auto-type sequence template
    #[arg(short, long)]
    pub sequence: Option<String>,

    /// Milliseconds delay before typing to switch focus (default 500ms)
    #[arg(long, default_value = "500")]
    pub delay: u64,

    /// Dry run with simulated keystroke recorder (headless test mode)
    #[arg(long)]
    pub simulated: bool,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Pre-unlock the vault in RAM (master password + 2FA) for SSH agent / Native messaging.
    /// Credentials are requested interactively (no echo) or via the COVERT_* env vars.
    #[arg(long)]
    pub unlock: bool,

    /// Custom named pipe path for OpenSSH agent
    #[arg(long)]
    pub pipe: Option<String>,

    /// Run in Browser Extension Native Messaging Host stdio mode
    #[arg(long)]
    pub native_msg: bool,

    /// Disable Sentinel threat monitoring (session lock, network ports, anti-debug)
    #[arg(long)]
    pub no_sentinel: bool,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}
