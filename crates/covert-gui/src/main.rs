#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use covert_gui::app::{AppController, AppWindow};
use covert_gui::state::AppState;
use slint::ComponentHandle;
use std::sync::{Arc, Mutex};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ui = AppWindow::new()?;
    let state = Arc::new(Mutex::new(AppState::new(None)?));
    let _controller = AppController::setup(&ui, state);

    ui.run()?;
    Ok(())
}
