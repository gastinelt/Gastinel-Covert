//! Command line argument definitions for covert-cli.

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

    /// Execute direct keystroke injection (Auto-Type) for a credential
    Autotype(AutotypeArgs),

    /// Run background daemon hosting Sentinel defense and OpenSSH agent
    Daemon(DaemonArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Master password for vault encryption
    #[arg(short, long)]
    pub password: Option<String>,

    /// Vault human-readable name
    #[arg(short, long, default_value = "Main Vault")]
    pub name: String,

    /// Custom storage destination path (defaults to DirectX ShaderCache camouflage path)
    #[arg(long)]
    pub path: Option<PathBuf>,

    /// Automatically configure 2FA Aegis RFC 6238 TOTP and generate 10 recovery codes
    #[arg(long)]
    pub setup_totp: bool,

    /// Optional Tier-2 Master View Password for unmasking secrets
    #[arg(long)]
    pub tier2_password: Option<String>,
}

#[derive(Debug, Args)]
pub struct UnlockArgs {
    /// Master password
    #[arg(short, long)]
    pub password: Option<String>,

    /// 6-digit TOTP code
    #[arg(short, long)]
    pub totp: Option<String>,

    /// Emergency recovery code (consumed upon successful verification)
    #[arg(long)]
    pub recovery_code: Option<String>,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Search query matching title, username, url, or ID
    pub query: Option<String>,

    /// Master password
    #[arg(short, long)]
    pub password: Option<String>,

    /// 6-digit TOTP code
    #[arg(short, long)]
    pub totp: Option<String>,

    /// Emergency recovery code
    #[arg(long)]
    pub recovery_code: Option<String>,

    /// Tier-2 Master View Password to unmask plain-text secrets
    #[arg(long)]
    pub tier2: Option<String>,

    /// Output results in JSON format
    #[arg(long)]
    pub json: bool,

    /// Custom vault storage path
    #[arg(long)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct AutotypeArgs {
    /// Target credential title or ID to auto-type
    pub query: String,

    /// Master password
    #[arg(short, long)]
    pub password: Option<String>,

    /// 6-digit TOTP code
    #[arg(short, long)]
    pub totp: Option<String>,

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
    /// Master password to pre-unlock vault in RAM for SSH agent / Native messaging
    #[arg(short, long)]
    pub password: Option<String>,

    /// 6-digit TOTP code
    #[arg(short, long)]
    pub totp: Option<String>,

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
