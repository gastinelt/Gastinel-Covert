//! TCP Network Monitor inspecting established connections on sensitive ports (22, 3389).

use crate::error::SentinelError;
use crate::{SecurityEvent, SecurityEventSink};
use std::collections::HashSet;
use std::net::SocketAddr;
#[cfg(windows)]
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    MIB_TCP_STATE_ESTAB,
};
#[cfg(windows)]
use windows::Win32::Networking::WinSock::AF_INET;

pub const MONITORED_PORTS: [u16; 2] = [22, 3389];

/// Active inbound TCP connection entry detected by IP Helper API.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActiveTcpConnection {
    pub local_port: u16,
    pub remote_addr: SocketAddr,
    pub owning_pid: u32,
}

/// Query established IPv4 TCP connections using Win32 IP Helper `GetExtendedTcpTable`.
pub fn query_established_inbound_tcp_connections() -> Result<Vec<ActiveTcpConnection>, SentinelError> {
    #[cfg(windows)]
    {
        let mut size = 0u32;
        // First query to retrieve required buffer size
        let err = unsafe {
            GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
        if err != 0 && err != ERROR_INSUFFICIENT_BUFFER {
            return Err(SentinelError::NetworkQuery(format!(
                "Initial GetExtendedTcpTable query failed with code: {}",
                err
            )));
        }

        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; size as usize];
        let err = unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };

        if err != 0 {
            return Err(SentinelError::NetworkQuery(format!(
                "GetExtendedTcpTable failed with code: {}",
                err
            )));
        }

        let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let num_entries = unsafe { (*table).dwNumEntries } as usize;
        let rows_ptr = unsafe { (*table).table.as_ptr() };

        let mut connections = Vec::new();

        for i in 0..num_entries {
            let row: &MIB_TCPROW_OWNER_PID = unsafe { &*rows_ptr.add(i) };

            // Check if state is ESTABLISHED (MIB_TCP_STATE_ESTAB = 5)
            if row.dwState == MIB_TCP_STATE_ESTAB.0 as u32 {
                // Ports are in network byte order (big endian) in the low 16 bits
                let local_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                let remote_port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);

                let remote_ip_bytes = row.dwRemoteAddr.to_ne_bytes();
                let remote_ip = Ipv4Addr::new(
                    remote_ip_bytes[0],
                    remote_ip_bytes[1],
                    remote_ip_bytes[2],
                    remote_ip_bytes[3],
                );
                let remote_addr = SocketAddr::V4(SocketAddrV4::new(remote_ip, remote_port));

                connections.push(ActiveTcpConnection {
                    local_port,
                    remote_addr,
                    owning_pid: row.dwOwningPid,
                });
            }
        }

        Ok(connections)
    }

    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

/// Periodic TCP connection monitor watching for inbound established connections on ports 22 and 3389.
pub struct NetworkMonitor {
    stop_signal: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl NetworkMonitor {
    /// Start monitoring TCP connections with a given polling interval.
    pub fn start(
        sink: Arc<dyn SecurityEventSink>,
        interval: Duration,
    ) -> Result<Self, SentinelError> {
        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop_signal);

        let handle = thread::Builder::new()
            .name("covert-network-sentinel".to_string())
            .spawn(move || {
                let mut known_connections: HashSet<ActiveTcpConnection> = HashSet::new();

                while !stop_clone.load(Ordering::Relaxed) {
                    if let Ok(current_connections) = query_established_inbound_tcp_connections() {
                        let mut current_set = HashSet::new();

                        for conn in current_connections {
                            if MONITORED_PORTS.contains(&conn.local_port) {
                                if !known_connections.contains(&conn) {
                                    // New inbound established connection detected on sensitive port!
                                    sink.on_security_alert(SecurityEvent::InboundTcpConnection {
                                        port: conn.local_port,
                                        remote_addr: conn.remote_addr,
                                    });
                                }
                                current_set.insert(conn);
                            }
                        }

                        known_connections = current_set;
                    }

                    thread::sleep(interval);
                }
            })
            .map_err(|e| SentinelError::ThreadError(e.to_string()))?;

        Ok(Self {
            stop_signal,
            handle: Some(handle),
        })
    }

    /// Stop the network monitor background thread.
    pub fn stop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for NetworkMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_established_tcp_does_not_panic() {
        let res = query_established_inbound_tcp_connections();
        assert!(res.is_ok(), "query_established_inbound_tcp_connections should succeed: {:?}", res);
    }
}
