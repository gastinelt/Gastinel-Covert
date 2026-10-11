//! Comprehensive tests for covert-sentinel active defense subsystems.

use covert_sentinel::{
    apply_screen_capture_protection, check_peb_being_debugged, is_debugger_attached,
    query_established_inbound_tcp_connections, SecurityEvent, SecurityEventSink, SentinelError,
    SentinelMonitor, MONITORED_PORTS,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct MockSink {
    events: Mutex<Vec<SecurityEvent>>,
}

impl SecurityEventSink for MockSink {
    fn on_security_alert(&self, event: SecurityEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[test]
fn test_simulated_sentinel_dispatches() {
    let sink = Arc::new(MockSink::default());
    let monitor = SentinelMonitor::new_simulated(Arc::clone(&sink) as Arc<dyn SecurityEventSink>);

    monitor.dispatch_session_lock();
    monitor.dispatch_remote_connect();

    let rdp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321);
    monitor.dispatch_inbound_tcp(3389, rdp_addr);

    let ssh_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65432);
    monitor.dispatch_inbound_tcp(22, ssh_addr);

    // Non-monitored port should be filtered out
    let web_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8080);
    monitor.dispatch_inbound_tcp(80, web_addr);

    monitor.dispatch_debugger_attached();

    let events = sink.events.lock().unwrap().clone();
    assert_eq!(events.len(), 5);
    assert_eq!(events[0], SecurityEvent::SessionLocked);
    assert_eq!(events[1], SecurityEvent::RemoteConnect);
    assert_eq!(
        events[2],
        SecurityEvent::InboundTcpConnection {
            port: 3389,
            remote_addr: rdp_addr,
        }
    );
    assert_eq!(
        events[3],
        SecurityEvent::InboundTcpConnection {
            port: 22,
            remote_addr: ssh_addr,
        }
    );
    assert_eq!(events[4], SecurityEvent::DebuggerAttached);
}

#[test]
fn test_sentinel_lifecycle_start_and_stop() {
    let sink = Arc::new(MockSink::default());
    let monitor = SentinelMonitor::start(sink);
    assert!(monitor.is_ok());

    let mut monitor = monitor.unwrap();
    std::thread::sleep(Duration::from_millis(100));
    monitor.stop();
}

#[test]
fn test_screen_capture_protection_invalid_handle() {
    let res = apply_screen_capture_protection(0);
    assert!(res.is_err());
    assert!(matches!(res.unwrap_err(), SentinelError::InvalidHandle(0)));
}

#[test]
fn test_antidebug_peb_check_does_not_fault() {
    let peb_debugged = check_peb_being_debugged();
    let api_debugged = is_debugger_attached();
    let _ = (peb_debugged, api_debugged);
}

#[test]
fn test_query_tcp_connections() {
    let conns = query_established_inbound_tcp_connections().expect("tcp query should succeed");
    for conn in &conns {
        if MONITORED_PORTS.contains(&conn.local_port) {
            assert!(conn.local_port == 22 || conn.local_port == 3389);
        }
    }
}
