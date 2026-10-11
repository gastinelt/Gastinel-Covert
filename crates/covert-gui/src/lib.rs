//! Gastinel Covert Native GUI (`covert-gui`).
//!
//! Slint-based secure native graphical user interface for Gastinel Covert.

pub mod app;
pub mod state;
pub mod tray;

pub use app::{AppController, AppWindow};
pub use state::{AppState, GuiError};
pub use tray::TrayIcon;
