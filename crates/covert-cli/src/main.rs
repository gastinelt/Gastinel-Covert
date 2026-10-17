//! Unified headless CLI binary for Gastinel Covert (`covert-cli`).

use clap::Parser;
use covert_cli::args::{Cli, Commands};
use covert_cli::commands;

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init(args) => commands::execute_init(args),
        Commands::Unlock(args) => commands::execute_unlock(args),
        Commands::Get(args) => commands::execute_get(args),
        Commands::Add(args) => commands::execute_add(args),
        Commands::Edit(args) => commands::execute_edit(args),
        Commands::Delete(args) => commands::execute_delete(args),
        Commands::ChangeMaster(args) => commands::execute_change_master(args),
        Commands::Export(args) => commands::execute_export(args),
        Commands::Import(args) => commands::execute_import(args),
        Commands::Backup(args) => commands::execute_backup(args).map(|_| ()),
        Commands::Autotype(args) => commands::execute_autotype(args),
        Commands::Daemon(args) => commands::execute_daemon(args),
    };

    if let Err(e) = result {
        eprintln!("[ERROR] {}", e);
        std::process::exit(1);
    }
}
