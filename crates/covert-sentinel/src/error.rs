//! Error types for the covert-sentinel crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("Failed to register WTS session notification: {0}")]
    SessionRegistration(String),

    #[error("Failed to query TCP table: {0}")]
    NetworkQuery(String),

    #[error("Failed to apply window screen capture affinity: {0}")]
    AntiCapture(String),

    #[error("Debugger watchdog error: {0}")]
    DebuggerWatchdog(String),

    #[error("Monitor thread failure: {0}")]
    ThreadError(String),

    #[error("Invalid window handle: {0}")]
    InvalidHandle(isize),

    #[error("System error: {0}")]
    System(String),
}
