//! Gastinel Covert — E2E Test Suite & Harness Library
//!
//! Provides opaque-box test harnesses, sandboxes, reference oracles, and protocol engines
//! for requirement-driven testing across Tiers 1 through 4.

pub mod autotype;
pub mod clipboard;
pub mod lockout;
pub mod native_msg;
pub mod sandbox;
pub mod sentinel;
pub mod ssh_agent;
pub mod totp;
pub mod vectors;

pub use sandbox::TestSandbox;
