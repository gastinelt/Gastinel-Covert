//! Gastinel Covert Sentinel Active Defense Engine (`covert-sentinel`).
//!
//! Monitors Windows system events, network threats, debugger attachment,
//! and provides anti-screen-capture protection.

pub mod anticapture;
pub mod antidebug;
pub mod error;
pub mod network;
pub mod session;

pub use anticapture::apply_screen_capture_protection;
pub use antidebug::{check_peb_being_debugged, is_debugger_attached, AntiDebugWatchdog};
pub use error::SentinelError;
pub use network::{
    query_established_inbound_tcp_connections, ActiveTcpConnection, NetworkMonitor,
    MONITORED_PORTS,
};
pub use session::SessionMonitor;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// High-priority security threat event detected by covert-sentinel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityEvent {
    /// Windows user locked the desktop session (WTS_SESSION_LOCK).
    SessionLocked,
    /// Remote Desktop connection established (WTS_REMOTE_CONNECT / WTS_SESSION_REMOTE_CONTROL).
    RemoteConnect,
    /// Inbound TCP connection detected on sensitive port (22 SSH or 3389 RDP).
    InboundTcpConnection {
        port: u16,
        remote_addr: SocketAddr,
    },
    /// Debugger attached to the current process (IsDebuggerPresent / PEB BeingDebugged).
    DebuggerAttached,
}

/// Sink trait implemented by components (vault manager, GUI, SSH agent) reacting to alerts.
pub trait SecurityEventSink: Send + Sync {
    fn on_security_alert(&self, event: SecurityEvent);
}

/// Unified Sentinel coordinator managing background monitors.
pub struct SentinelMonitor {
    sink: Arc<dyn SecurityEventSink>,
    session_monitor: Option<SessionMonitor>,
    network_monitor: Option<NetworkMonitor>,
    antidebug_watchdog: Option<AntiDebugWatchdog>,
}

impl SentinelMonitor {
    /// Default network scan interval (500ms).
    pub const DEFAULT_NETWORK_POLL_INTERVAL: Duration = Duration::from_millis(500);
    /// Default anti-debug check interval (200ms).
    pub const DEFAULT_ANTIDEBUG_POLL_INTERVAL: Duration = Duration::from_millis(200);

    /// Start the active sentinel defense monitor with all subsystems.
    pub fn start<S: SecurityEventSink + 'static>(sink: Arc<S>) -> Result<Self, SentinelError> {
        let sink_dyn: Arc<dyn SecurityEventSink> = sink;

        let session_monitor = SessionMonitor::start(Arc::clone(&sink_dyn)).ok();
        let network_monitor =
            NetworkMonitor::start(Arc::clone(&sink_dyn), Self::DEFAULT_NETWORK_POLL_INTERVAL).ok();
        let antidebug_watchdog =
            AntiDebugWatchdog::start(Arc::clone(&sink_dyn), Self::DEFAULT_ANTIDEBUG_POLL_INTERVAL).ok();

        Ok(Self {
            sink: sink_dyn,
            session_monitor,
            network_monitor,
            antidebug_watchdog,
        })
    }

    /// Create a simulated sentinel monitor for testing environments without background threads.
    pub fn new_simulated(sink: Arc<dyn SecurityEventSink>) -> Self {
        Self {
            sink,
            session_monitor: None,
            network_monitor: None,
            antidebug_watchdog: None,
        }
    }

    /// Apply screen capture exclusion protection to a window handle (`SetWindowDisplayAffinity`).
    pub fn apply_screen_capture_protection(hwnd: isize) -> Result<(), SentinelError> {
        anticapture::apply_screen_capture_protection(hwnd)
    }

    /// Explicitly stop all background sentinel monitors.
    pub fn stop(&mut self) {
        if let Some(mut m) = self.session_monitor.take() {
            m.stop();
        }
        if let Some(mut m) = self.network_monitor.take() {
            m.stop();
        }
        if let Some(mut m) = self.antidebug_watchdog.take() {
            m.stop();
        }
    }

    /// Simulate dispatch of a session lock event.
    pub fn dispatch_session_lock(&self) {
        self.sink.on_security_alert(SecurityEvent::SessionLocked);
    }

    /// Simulate dispatch of a remote connect event.
    pub fn dispatch_remote_connect(&self) {
        self.sink.on_security_alert(SecurityEvent::RemoteConnect);
    }

    /// Simulate dispatch of an inbound TCP connection on a sensitive port.
    pub fn dispatch_inbound_tcp(&self, port: u16, remote_addr: SocketAddr) {
        if MONITORED_PORTS.contains(&port) {
            self.sink
                .on_security_alert(SecurityEvent::InboundTcpConnection { port, remote_addr });
        }
    }

    /// Simulate dispatch of a debugger attached event.
    pub fn dispatch_debugger_attached(&self) {
        self.sink.on_security_alert(SecurityEvent::DebuggerAttached);
    }
}

impl Drop for SentinelMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}
