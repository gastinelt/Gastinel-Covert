//! Windows Sentinel active defense simulation: session locks, TCP monitoring, and anti-debug.

use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityEvent {
    SessionLocked,
    RemoteConnect,
    InboundTcpConnection { port: u16, remote_addr: String },
    DebuggerAttached,
}

pub trait SecurityEventSink: Send + Sync {
    fn on_security_alert(&self, event: SecurityEvent);
}

#[derive(Debug, Default, Clone)]
pub struct SentinelState {
    pub is_vault_locked: bool,
    pub memory_zeroized: bool,
    pub alerts_count: usize,
    pub last_event: Option<SecurityEvent>,
}

pub struct TestSentinelSink {
    state: Arc<Mutex<SentinelState>>,
}

impl TestSentinelSink {
    pub fn new() -> (Self, Arc<Mutex<SentinelState>>) {
        let state = Arc::new(Mutex::new(SentinelState {
            is_vault_locked: false,
            memory_zeroized: false,
            alerts_count: 0,
            last_event: None,
        }));
        (Self { state: Arc::clone(&state) }, state)
    }
}

impl SecurityEventSink for TestSentinelSink {
    fn on_security_alert(&self, event: SecurityEvent) {
        let mut st = self.state.lock().unwrap();
        st.is_vault_locked = true;
        st.memory_zeroized = true;
        st.alerts_count += 1;
        st.last_event = Some(event);
    }
}

pub struct SentinelMonitor {
    sink: Arc<dyn SecurityEventSink>,
}

impl SentinelMonitor {
    pub fn new(sink: Arc<dyn SecurityEventSink>) -> Self {
        Self { sink }
    }

    /// Simulate receipt of a Windows session lock event (WTS_SESSION_LOCK).
    pub fn dispatch_session_lock(&self) {
        self.sink.on_security_alert(SecurityEvent::SessionLocked);
    }

    /// Simulate receipt of a remote desktop connection event (WTS_REMOTE_CONNECT).
    pub fn dispatch_remote_connect(&self) {
        self.sink.on_security_alert(SecurityEvent::RemoteConnect);
    }

    /// Simulate TCP network monitor detection of inbound connection on sensitive ports.
    pub fn dispatch_inbound_tcp(&self, port: u16, remote_addr: &str) {
        if port == 22 || port == 3389 {
            self.sink.on_security_alert(SecurityEvent::InboundTcpConnection {
                port,
                remote_addr: remote_addr.to_string(),
            });
        }
    }

    /// Simulate anti-debug watchdog detecting IsDebuggerPresent / PEB BeingDebugged flag.
    pub fn dispatch_debugger_attached(&self) {
        self.sink.on_security_alert(SecurityEvent::DebuggerAttached);
    }
}
