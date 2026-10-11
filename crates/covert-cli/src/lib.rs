//! Library interface for covert-cli commands.

#![forbid(unsafe_code)]

pub mod args;
pub mod commands;

pub use args::{AutotypeArgs, Cli, Commands, DaemonArgs, GetArgs, InitArgs, UnlockArgs};
pub use commands::{
    execute_autotype, execute_daemon, execute_get, execute_init, execute_unlock,
};
