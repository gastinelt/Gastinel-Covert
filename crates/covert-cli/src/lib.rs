//! Library interface for covert-cli commands.

pub mod args;
pub mod commands;

pub use args::{
    AddArgs, AutotypeArgs, BackupArgs, ChangeMasterArgs, Cli, Commands, DaemonArgs, DeleteArgs,
    EditArgs, ExportArgs, GetArgs, ImportArgs, InitArgs, UnlockArgs,
};
pub use commands::{
    execute_add, execute_autotype, execute_backup, execute_change_master, execute_daemon,
    execute_delete, execute_edit, execute_export, execute_get, execute_import, execute_init,
    execute_unlock,
};
