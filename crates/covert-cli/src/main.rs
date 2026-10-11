//! Unified headless CLI binary for Gastinel Covert (`covert-cli`).

#![forbid(unsafe_code)]

use clap::Parser;
use covert_cli::args::{Cli, Commands};
use covert_cli::commands;

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init(args) => commands::execute_init(args),
        Commands::Unlock(args) => commands::execute_unlock(args),
        Commands::Get(args) => commands::execute_get(args),
        Commands::Autotype(args) => commands::execute_autotype(args),
        Commands::Daemon(args) => commands::execute_daemon(args),
    };

    if let Err(e) = result {
        eprintln!("[ERROR] {}", e);
        std::process::exit(1);
    }
}
