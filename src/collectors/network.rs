use anyhow::Result;
use tracing::{info, error, debug};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::process::Command;
use std::collections::HashMap;
use std::time::{Duration, Instant};
// Cross-platform imports
#[cfg(target_os = "linux")]
use procfs::net::{TcpState, tcp, udp};

#[cfg(target_os = "macos")]
use libproc::libproc::proc_pid::{listpids, pidinfo, PidInfo};
#[cfg(target_os = "macos")]
use libproc::libproc::file_info::{ListFDs, ProcFDType};

#[cfg(target_os = "windows")]
use windows::{
    Win32::NetworkManagement::IpHelper::*,
    Win32::Networking::WinSock::*,
    Win32::Foundation::*,
    core::*,
};

use crate::config::NetworkMonitorConfig;
use crate::events::{Event, EventType, EventData, NetworkEventData, NetworkDirection};
use crate::collectors::{Collector, PeriodicCollector};
use crate::agent::CollectorStatus;

#[derive(Debug, Clone)]
struct NetworkConnection {
    protocol: String,
    local_ip: Option<String>,
    local_port: Option<u16>,
    remote_ip: Option<String>,
    remote_port: Option<u16>,
    direction: NetworkDirection,
    state: Option<String>,
    pid: Option<u32>,
    process_name: Option<String>,
}

// Define connection tracking types
type ConnectionKey = (String, u16, String, u16);

#[derive(Debug, Clone)]
struct ConnectionState {
    first_seen: Instant,
    last_seen: Instant,
    last_reported: Instant,
    state: String, // "ESTABLISHED", "LISTEN", etc.
    pid: Option<u32>,
    process_name: Option<String>,
    bytes_sent: u64,
    bytes_received: u64,
    last_tx_bytes: u64,
    last_rx_bytes: u64,
}

#[derive(Debug, Clone)]
enum ConnectionEvent {
    New,      // First time seeing this connection
    Active,   // Connection still active (periodic report)
    Modified, // Connection state changed
    Closed,   // Connection no longer exists
}

// Adaptive memory management constants
const BASE_CACHE_LIMIT: usize = 100; // Base cache size for low-activity systems
const MAX_CACHE_LIMIT: usize = 1000; // Absolute maximum cache size
const CACHE_UTILIZATION_THRESHOLD: f32 = 0.8; // Start cleanup at 80% capacity
const MIN_DEDUP_WINDOW_SECONDS: u64 = 30; // Minimum dedup window
const MAX_DEDUP_WINDOW_SECONDS: u64 = 300; // Maximum dedup window
const HIGH_THROUGHPUT_THRESHOLD: usize = 100; // Events per collection indicating high throughput

#[derive(Debug)]
pub struct NetworkCollector {
    config: NetworkMonitorConfig,
    event_sender: mpsc::Sender<Event>,
    is_running: Arc<RwLock<bool>>,
    hostname: String,
    agent_id: String,
    events_collected: Arc<RwLock<u64>>,
    last_error: Arc<RwLock<Option<String>>>,
    // Connection lifecycle tracking - preserves duration and state changes
    connection_states: Arc<RwLock<HashMap<ConnectionKey, ConnectionState>>>,
}

impl NetworkCollector {
    pub async fn new(
        config: NetworkMonitorConfig,
        event_sender: mpsc::Sender<Event>,
    ) -> Result<Self> {
        let hostname = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        
        let agent_id = uuid::Uuid::new_v4().to_string();
        
        Ok(Self {
            config,
            event_sender,
            is_running: Arc::new(RwLock::new(false)),
            hostname,
            agent_id,
            events_collected: Arc::new(RwLock::new(0)),
            last_error: Arc::new(RwLock::new(None)),
            connection_states: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    fn create_network_event(&self, connection: &NetworkConnection, bytes_sent: Option<u64>, bytes_received: Option<u64>) -> Event {
        let data = EventData::Network(NetworkEventData {
            protocol: connection.protocol.clone(),
            source_ip: connection.local_ip.clone(),
            source_port: connection.local_port,
            destination_ip: connection.remote_ip.clone(),
            destination_port: connection.remote_port,
            direction: connection.direction.clone(),
            bytes_sent,
            bytes_received,
            connection_state: connection.state.clone(),
            dns_query: None,
            dns_response: None,
            process_id: connection.pid,
            process_name: connection.process_name.clone(),
        });
        
        Event::new(
            EventType::NetworkConnection,
            "network_monitor".to_string(),
            self.hostname.clone(),
            self.agent_id.clone(),
            data,
        )
    }
    
    async fn get_network_connections(&self) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        // Use native platform APIs instead of OS tools
        #[cfg(target_os = "linux")]
        {
            connections.extend(self.get_linux_connections().await?);
        }
        
        #[cfg(target_os = "macos")]
        {
            connections.extend(self.get_macos_connections().await?);
        }
        
        #[cfg(target_os = "windows")]
        {
            connections.extend(self.get_windows_connections().await?);
        }
        
        // Fallback to netstat if native methods fail
        if connections.is_empty() {
            debug!("Native methods returned no connections, falling back to netstat");
            connections.extend(self.get_netstat_fallback().await?);
        }
        
        Ok(connections)
    }
    
    // Linux implementation using procfs
    #[cfg(target_os = "linux")]
    async fn get_linux_connections(&self) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        // Get TCP connections
        match tcp() {
            Ok(tcp_entries) => {
                for entry in tcp_entries {
                    let state_str = match entry.state {
                        TcpState::Established => "ESTABLISHED",
                        TcpState::Listen => "LISTEN",
                        TcpState::SynSent => "SYN_SENT",
                        TcpState::SynRecv => "SYN_RECV",
                        TcpState::FinWait1 => "FIN_WAIT1",
                        TcpState::FinWait2 => "FIN_WAIT2",
                        TcpState::TimeWait => "TIME_WAIT",
                        TcpState::Close => "CLOSE",
                        TcpState::CloseWait => "CLOSE_WAIT",
                        TcpState::LastAck => "LAST_ACK",
                        TcpState::Closing => "CLOSING",
                        _ => "UNKNOWN",
                    };
                    
                    let direction = if entry.state == TcpState::Listen {
                        NetworkDirection::Inbound
                    } else {
                        NetworkDirection::Outbound
                    };
                    
                    let mut connection = NetworkConnection {
                        protocol: "tcp".to_string(),
                        local_ip: Some(entry.local_address.ip().to_string()),
                        local_port: Some(entry.local_address.port()),
                        remote_ip: Some(entry.remote_address.ip().to_string()),
                        remote_port: Some(entry.remote_address.port()),
                        direction,
                        state: Some(state_str.to_string()),
                        pid: self.resolve_inode_to_pid(entry.inode),
                        process_name: self.resolve_inode_to_process_name(entry.inode),
                    };
                    
                    connections.push(connection);
                }
            }
            Err(e) => {
                debug!("Failed to read TCP connections from procfs: {}", e);
            }
        }
        
        // Get UDP connections
        match udp() {
            Ok(udp_entries) => {
                for entry in udp_entries {
                    connections.push(NetworkConnection {
                        protocol: "udp".to_string(),
                        local_ip: Some(entry.local_address.ip().to_string()),
                        local_port: Some(entry.local_address.port()),
                        remote_ip: Some(entry.remote_address.ip().to_string()),
                        remote_port: Some(entry.remote_address.port()),
                        direction: NetworkDirection::Outbound,
                        state: None,
                        pid: self.resolve_inode_to_pid(entry.inode),
                        process_name: self.resolve_inode_to_process_name(entry.inode),
                    });
                }
            }
            Err(e) => {
                debug!("Failed to read UDP connections from procfs: {}", e);
            }
        }
        
        Ok(connections)
    }
    
    // macOS implementation using libproc
    #[cfg(target_os = "macos")]
    async fn get_macos_connections(&self) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        match listpids(libproc::libproc::proc_pid::ProcFilter::All) {
            Ok(pids) => {
                for pid in pids {
                    // Get process info
                    let process_name = match pidinfo::<libproc::libproc::proc_pid::ProcBSDInfo>(pid, 0) {
                        Ok(bsd_info) => {
                            // Convert C string to Rust string
                            let name_bytes: Vec<u8> = bsd_info.pbi_name.iter()
                                .take_while(|&&b| b != 0)
                                .map(|&b| b as u8)
                                .collect();
                            String::from_utf8_lossy(&name_bytes).to_string()
                        }
                        Err(_) => "unknown".to_string()
                    };
                    
                    // Get file descriptors for this process
                    match libproc::libproc::file_info::pidinfo_list_fds(pid) {
                        Ok(fds) => {
                            for fd_info in fds {
                                // Check if this FD is a socket
                                if fd_info.proc_fdtype == ProcFDType::Socket {
                                    // Get socket info
                                    match libproc::libproc::file_info::pidinfo::<libproc::libproc::file_info::SocketFDInfo>(pid, fd_info.proc_fd) {
                                        Ok(socket_info) => {
                                            let socket_info = socket_info.psi;
                                            
                                            // Determine protocol
                                            let protocol = match socket_info.soi_protocol {
                                                6 => "tcp",  // IPPROTO_TCP
                                                17 => "udp", // IPPROTO_UDP
                                                _ => continue,
                                            };
                                            
                                            // Parse socket addresses
                                            if socket_info.soi_family == 2 { // AF_INET
                                                let local_addr = socket_info.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4;
                                                let local_port = socket_info.soi_proto.pri_tcp.tcpsi_ini.insi_lport;
                                                let remote_addr = socket_info.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4;
                                                let remote_port = socket_info.soi_proto.pri_tcp.tcpsi_ini.insi_fport;
                                                
                                                let local_ip = format!("{}.{}.{}.{}", 
                                                    (local_addr >> 24) & 0xFF,
                                                    (local_addr >> 16) & 0xFF,
                                                    (local_addr >> 8) & 0xFF,
                                                    local_addr & 0xFF
                                                );
                                                
                                                let remote_ip = if remote_addr != 0 {
                                                    Some(format!("{}.{}.{}.{}", 
                                                        (remote_addr >> 24) & 0xFF,
                                                        (remote_addr >> 16) & 0xFF,
                                                        (remote_addr >> 8) & 0xFF,
                                                        remote_addr & 0xFF
                                                    ))
                                                } else {
                                                    None
                                                };
                                                
                                                let direction = if remote_ip.is_some() {
                                                    NetworkDirection::Outbound
                                                } else {
                                                    NetworkDirection::Inbound
                                                };
                                                
                                                connections.push(NetworkConnection {
                                                    protocol: protocol.to_string(),
                                                    local_ip: Some(local_ip),
                                                    local_port: if local_port > 0 { Some(local_port as u16) } else { None },
                                                    remote_ip,
                                                    remote_port: if remote_port > 0 { Some(remote_port as u16) } else { None },
                                                    direction,
                                                    state: if protocol == "tcp" {
                                                        Some(match socket_info.soi_proto.pri_tcp.tcpsi_state {
                                                            1 => "ESTABLISHED",
                                                            2 => "LISTEN",
                                                            _ => "UNKNOWN",
                                                        }.to_string())
                                                    } else {
                                                        None
                                                    },
                                                    pid: Some(pid as u32),
                                                    process_name: Some(process_name.clone()),
                                                });
                                            }
                                        }
                                        Err(_) => continue,
                                    }
                                }
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
            Err(e) => {
                debug!("Failed to list processes on macOS: {:?}", e);
            }
        }
        
        Ok(connections)
    }
    
    // Windows implementation using safe alternatives
    #[cfg(target_os = "windows")]
    async fn get_windows_connections(&self) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        // Use sysinfo to get network information safely
        let mut sys = sysinfo::System::new_all();
        sys.refresh_networks_list();
        sys.refresh_networks();
        sys.refresh_processes();
        
        // For Windows, we'll primarily rely on netstat fallback
        // since safe pure Rust Windows network connection enumeration 
        // requires complex WinAPI calls that would need unsafe code
        debug!("Windows: Using safe fallback methods for network monitoring");
        
        // Try to get basic network interface information from sysinfo
        for (interface_name, network) in sys.networks() {
            debug!("Network interface: {} - received: {} bytes, transmitted: {} bytes", 
                   interface_name, network.received(), network.transmitted());
        }
        
        // The actual connection enumeration will fall back to netstat
        // which is handled in the main get_network_connections method
        
        Ok(connections)
    }

    
    // Fallback netstat implementation for when native methods fail
    async fn get_netstat_fallback(&self) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        debug!("Using netstat fallback");
        
        #[cfg(target_os = "macos")]
        let output = Command::new("netstat")
            .args(["-tuln", "-p", "tcp"])
            .output();
            
        #[cfg(target_os = "linux")]
        let output = Command::new("netstat")
            .args(["-tuln"])
            .output();
            
        #[cfg(target_os = "windows")]
        let output = Command::new("netstat")
            .args(["-an"])
            .output();
        
        match output {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                connections.extend(self.parse_netstat_output(&output_str)?);
            }
            Err(e) => {
                error!("Netstat fallback also failed: {}", e);
                *self.last_error.write().await = Some(format!("All network methods failed: {}", e));
            }
        }
        
        Ok(connections)
    }
    
    fn parse_netstat_output(&self, output: &str) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        for line in output.lines().skip(2) { // Skip header lines
            if let Some(connection) = self.parse_netstat_line(line) {
                connections.push(connection);
            }
        }
        
        Ok(connections)
    }
    
    fn parse_netstat_line(&self, line: &str) -> Option<NetworkConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }
        
        let protocol = parts[0].to_lowercase();
        if protocol != "tcp" && protocol != "udp" {
            return None;
        }
        
        // Parse local address
        let local_addr = parts[3];
        let (local_ip, local_port) = self.parse_address(local_addr)?;
        
        // Parse remote address (if exists)
        let (remote_ip, remote_port, state) = if parts.len() > 4 {
            let remote_addr = parts[4];
            let (ip, port) = self.parse_address(remote_addr)?;
            let state = if parts.len() > 5 { 
                Some(parts[5].to_string()) 
            } else { 
                None 
            };
            (Some(ip), port, state)
        } else {
            (None, None, None)
        };
        
        let direction = if remote_ip.is_some() {
            NetworkDirection::Outbound
        } else {
            NetworkDirection::Inbound
        };
        
        Some(NetworkConnection {
            protocol,
            local_ip: Some(local_ip),
            local_port,
            remote_ip,
            remote_port,
            direction,
            state,
            pid: None,
            process_name: None,
        })
    }
    
    #[cfg(unix)]
    fn parse_lsof_output(&self, output: &str) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        for line in output.lines().skip(1) { // Skip header
            if let Some(connection) = self.parse_lsof_line(line) {
                connections.push(connection);
            }
        }
        
        Ok(connections)
    }
    
    #[cfg(unix)]
    fn parse_lsof_line(&self, line: &str) -> Option<NetworkConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            return None;
        }
        
        let process_name = Some(parts[0].to_string());
        let pid = parts[1].parse::<u32>().ok();
        let protocol = parts[7].to_lowercase();
        
        if protocol != "tcp" && protocol != "udp" {
            return None;
        }
        
        // Parse the network info (format: local->remote or just local)
        let network_info = parts[8];
        if let Some((local, remote)) = network_info.split_once("->") {
            // Connection with remote endpoint
            let (local_ip, local_port) = self.parse_address(local)?;
            let (remote_ip, remote_port) = self.parse_address(remote)?;
            
            Some(NetworkConnection {
                protocol,
                local_ip: Some(local_ip),
                local_port,
                remote_ip: Some(remote_ip),
                remote_port,
                direction: NetworkDirection::Outbound,
                state: Some("ESTABLISHED".to_string()),
                pid,
                process_name,
            })
        } else {
            // Listening socket
            let (local_ip, local_port) = self.parse_address(network_info)?;
            
            Some(NetworkConnection {
                protocol,
                local_ip: Some(local_ip),
                local_port,
                remote_ip: None,
                remote_port: None,
                direction: NetworkDirection::Inbound,
                state: Some("LISTEN".to_string()),
                pid,
                process_name,
            })
        }
    }
    
    fn parse_address(&self, addr: &str) -> Option<(String, Option<u16>)> {
        if let Some(colon_pos) = addr.rfind(':') {
            let ip = addr[..colon_pos].to_string();
            let port_str = &addr[colon_pos + 1..];
            let port = port_str.parse::<u16>().ok();
            Some((ip, port))
        } else {
            Some((addr.to_string(), None))
        }
    }
    
    fn should_include_connection(&self, connection: &NetworkConnection) -> bool {
        // Skip localhost connections unless specifically configured
        if let Some(ref remote_ip) = connection.remote_ip {
            if remote_ip.starts_with("127.") || remote_ip == "::1" {
                return false;
            }
        }
        
        if let Some(ref local_ip) = connection.local_ip {
            if local_ip.starts_with("127.") || local_ip == "::1" {
                return false;
            }
        }
        
        // Include interesting connections
        true
    }
    
    // Linux-specific: Resolve socket inode to PID by searching /proc/*/fd/*
    #[cfg(target_os = "linux")]
    fn resolve_inode_to_pid(&self, inode: u64) -> Option<u32> {
        use std::fs;
        
        if let Ok(proc_entries) = fs::read_dir("/proc") {
            for entry in proc_entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    // Only check numeric directories (PIDs)
                    if file_name.chars().all(|c| c.is_ascii_digit()) {
                        let fd_dir = format!("/proc/{}/fd", file_name);
                        if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                            for fd_entry in fd_entries.flatten() {
                                if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                                    if let Some(target_str) = link_target.to_str() {
                                        // Check if this fd points to our socket inode
                                        if target_str == format!("socket:[{}]", inode) {
                                            return file_name.parse::<u32>().ok();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
    
    // Linux-specific: Resolve inode to process name via PID
    #[cfg(target_os = "linux")]
    fn resolve_inode_to_process_name(&self, inode: u64) -> Option<String> {
        if let Some(pid) = self.resolve_inode_to_pid(inode) {
            let comm_path = format!("/proc/{}/comm", pid);
            if let Ok(process_name) = std::fs::read_to_string(&comm_path) {
                return Some(process_name.trim().to_string());
            }
        }
        None
    }
    
    // Get socket byte counts - Linux uses procfs statistics
    async fn get_socket_byte_counts(&self, pid: Option<u32>, _connection_key: &ConnectionKey) -> (u64, u64) {
        #[cfg(target_os = "linux")]
        {
            // For Linux, get per-process network statistics from /proc/{pid}/net/dev
            if let Some(pid) = pid {
                return self.get_process_network_bytes(pid).await;
            }
            
            // Fallback to system-wide interface statistics
            self.get_system_network_bytes().await
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            // For non-Linux platforms, use system-wide statistics
            self.get_system_network_bytes().await
        }
    }
    
    // Linux-specific: Get network byte counts for a specific process
    #[cfg(target_os = "linux")]
    async fn get_process_network_bytes(&self, pid: u32) -> (u64, u64) {
        use std::fs;
        
        // Try to read process-specific network device statistics
        let net_dev_path = format!("/proc/{}/net/dev", pid);
        if let Ok(content) = fs::read_to_string(&net_dev_path) {
            let mut total_tx = 0u64;
            let mut total_rx = 0u64;
            
            for line in content.lines().skip(2) { // Skip header lines
                if let Some(colon_pos) = line.find(':') {
                    let interface_name = line[..colon_pos].trim();
                    
                    // Skip loopback interface
                    if interface_name == "lo" {
                        continue;
                    }
                    
                    let stats_part = &line[colon_pos + 1..];
                    let stats: Vec<&str> = stats_part.split_whitespace().collect();
                    
                    if stats.len() >= 9 {
                        // bytes: received (index 0), transmitted (index 8)
                        if let (Ok(rx), Ok(tx)) = (stats[0].parse::<u64>(), stats[8].parse::<u64>()) {
                            total_rx += rx;
                            total_tx += tx;
                        }
                    }
                }
            }
            
            if total_tx > 0 || total_rx > 0 {
                return (total_tx, total_rx);
            }
        }
        
        // Process-specific stats not available or empty, fall back to system-wide
        self.get_system_network_bytes().await
    }
    
    // Get system-wide network byte counts
    async fn get_system_network_bytes(&self) -> (u64, u64) {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            if let Ok(dev_content) = fs::read_to_string("/proc/net/dev") {
                let mut total_rx = 0u64;
                let mut total_tx = 0u64;
                
                for line in dev_content.lines().skip(2) { // Skip header lines
                    if let Some(colon_pos) = line.find(':') {
                        let interface_name = line[..colon_pos].trim();
                        
                        // Skip loopback interface
                        if interface_name == "lo" {
                            continue;
                        }
                        
                        let stats_part = &line[colon_pos + 1..];
                        let stats: Vec<&str> = stats_part.split_whitespace().collect();
                        
                        if stats.len() >= 9 {
                            // bytes: received (index 0), transmitted (index 8)
                            if let (Ok(rx), Ok(tx)) = (stats[0].parse::<u64>(), stats[8].parse::<u64>()) {
                                total_rx += rx;
                                total_tx += tx;
                            }
                        }
                    }
                }
                
                return (total_tx, total_rx);
            }
            
            (0, 0)
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            // Use sysinfo for cross-platform compatibility
            let mut sys = sysinfo::System::new();
            sys.refresh_networks();
            
            let mut total_rx = 0u64;
            let mut total_tx = 0u64;
            
            for (_interface_name, network) in sys.networks() {
                total_rx += network.received();
                total_tx += network.transmitted();
            }
            
            (total_tx, total_rx)
        }
    }
}

#[async_trait::async_trait]
impl Collector for NetworkCollector {
    async fn start(&self) -> Result<()> {
        info!("Starting network collector");
        *self.is_running.write().await = true;
        
        // Spawn the periodic collection task
        let self_clone = self.clone();
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_periodic().await {
                error!("Network collector periodic error: {}", e);
            }
        });
        
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        info!("Stopping network collector");
        *self.is_running.write().await = false;
        Ok(())
    }
    
    async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    async fn get_status(&self) -> CollectorStatus {
        CollectorStatus {
            name: "network_monitor".to_string(),
            enabled: self.config.enabled,
            is_running: self.is_running().await,
            events_collected: *self.events_collected.read().await,
            last_error: self.last_error.read().await.clone(),
        }
    }
    
    fn name(&self) -> &'static str {
        "network_monitor"
    }
}

impl Clone for NetworkCollector {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            event_sender: self.event_sender.clone(),
            is_running: self.is_running.clone(),
            hostname: self.hostname.clone(),
            agent_id: self.agent_id.clone(),
            events_collected: self.events_collected.clone(),
            last_error: self.last_error.clone(),
            connection_states: self.connection_states.clone(),
        }
    }
}

#[async_trait::async_trait]
impl PeriodicCollector for NetworkCollector {
    async fn collect(&self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        
        if !self.config.monitor_connections {
            return Ok(events);
        }
        
        debug!("Collecting network connections");
        
        match self.get_network_connections().await {
            Ok(connections) => {
                // Connection lifecycle tracking with duration monitoring
                let mut states = self.connection_states.write().await;
                let now = Instant::now();
                
                // Memory management: limit to 1000 active connections max
                if states.len() >= 1000 {
                    // Remove oldest connections (by first_seen time)
                    let mut entries: Vec<_> = states.iter().map(|(k, v)| (k.clone(), v.first_seen)).collect();
                    entries.sort_by_key(|(_, first_seen)| *first_seen);
                    let to_remove = entries.len() - 800; // Keep 800, remove rest
                    for (key, _) in entries.iter().take(to_remove) {
                        states.remove(key);
                    }
                    debug!("Connection state cleanup: removed {} old connections", to_remove);
                }
                
                // Track current connections for closure detection
                let mut current_connections = std::collections::HashSet::new();
                
                for connection in connections {
                    // Filter connections based on configuration
                    if self.should_include_connection(&connection) {
                        // Create connection key
                        let key = (
                            connection.local_ip.clone().unwrap_or_default(),
                            connection.local_port.unwrap_or_default(),
                            connection.remote_ip.clone().unwrap_or_default(),
                            connection.remote_port.unwrap_or_default(),
                        );
                        
                        current_connections.insert(key.clone());
                        
                        let connection_event = if let Some(existing_state) = states.get_mut(&key) {
                            // Existing connection - check for changes
                            existing_state.last_seen = now;
                            
                            // Check for state changes (security relevant)
                            if existing_state.state != connection.state.clone().unwrap_or_default() {
                                existing_state.state = connection.state.clone().unwrap_or_default();
                                existing_state.last_reported = now;
                                Some(ConnectionEvent::Modified)
                            } else {
                                // Check if we should report periodic "still active" event
                                // Only for long-running connections (>5 minutes)
                                let duration = now.duration_since(existing_state.first_seen);
                                let time_since_last_report = now.duration_since(existing_state.last_reported);
                                
                                if duration > Duration::from_secs(300) && // Connection >5 min old
                                   time_since_last_report > Duration::from_secs(300) { // Haven't reported in 5 min
                                    existing_state.last_reported = now;
                                    Some(ConnectionEvent::Active)
                                } else {
                                    None // Don't report - reduces noise
                                }
                            }
                        } else {
                            // New connection - always report (security critical)
                            let (tx_bytes, rx_bytes) = self.get_socket_byte_counts(connection.pid, &key).await;
                            states.insert(key.clone(), ConnectionState {
                                first_seen: now,
                                last_seen: now,
                                last_reported: now,
                                state: connection.state.clone().unwrap_or_default(),
                                pid: connection.pid,
                                process_name: connection.process_name.clone(),
                                bytes_sent: tx_bytes,
                                bytes_received: rx_bytes,
                                last_tx_bytes: tx_bytes,
                                last_rx_bytes: rx_bytes,
                            });
                            Some(ConnectionEvent::New)
                        };
                        
                        // Create event with connection duration metadata
                        if let Some(event_type) = connection_event {
                            // Get byte counts for this connection
                            let state = states.get(&key);
                            let bytes_sent = state.map(|s| s.bytes_sent);
                            let bytes_received = state.map(|s| s.bytes_received);
                            
                            let mut event = self.create_network_event(&connection, bytes_sent, bytes_received);
                            
                            // Add duration and lifecycle metadata for security analysis
                            if let EventData::Network(ref mut net_data) = event.data {
                                if let Some(state) = states.get(&key) {
                                    let duration = now.duration_since(state.first_seen);
                                    
                                    // Add duration as metadata for security analysis
                                    event.metadata.insert(
                                        "connection_duration_seconds".to_string(),
                                        duration.as_secs().to_string()
                                    );
                                    
                                    event.metadata.insert(
                                        "connection_event_type".to_string(),
                                        format!("{:?}", event_type)
                                    );
                                    
                                    // Flag long-running connections for security attention
                                    if duration > Duration::from_secs(3600) { // >1 hour
                                        event.metadata.insert(
                                            "long_running_connection".to_string(),
                                            "true".to_string()
                                        );
                                    }
                                }
                            }
                            
                            events.push(event);
                        }
                    }
                }
                
                // Detect closed connections (security critical - always report)
                let closed_connections: Vec<_> = states.keys()
                    .filter(|key| !current_connections.contains(key))
                    .cloned()
                    .collect();
                
                for key in closed_connections {
                    if let Some(state) = states.remove(&key) {
                        let duration = now.duration_since(state.first_seen);
                        
                        // Create a synthetic connection for the closure event
                        let closed_connection = NetworkConnection {
                            protocol: "tcp".to_string(), // We don't know, assume TCP
                            local_ip: Some(key.0.clone()),
                            local_port: Some(key.1),
                            remote_ip: Some(key.2.clone()),
                            remote_port: Some(key.3),
                            direction: NetworkDirection::Outbound,
                            state: Some("CLOSED".to_string()),
                            pid: state.pid,
                            process_name: state.process_name.clone(),
                        };
                        
                        let mut event = self.create_network_event(&closed_connection, Some(state.bytes_sent), Some(state.bytes_received));
                        
                        // Add closure metadata
                        event.metadata.insert(
                            "connection_duration_seconds".to_string(),
                            duration.as_secs().to_string()
                        );
                        
                        event.metadata.insert(
                            "connection_event_type".to_string(),
                            "Closed".to_string()
                        );
                        
                        events.push(event);
                        debug!("Connection closed: {:?} (duration: {:?})", key, duration);
                    }
                }
                
                debug!("Collected {} network events", events.len());
            }
            Err(e) => {
                error!("Failed to collect network connections: {}", e);
                *self.last_error.write().await = Some(format!("Collection failed: {}", e));
            }
        }
        
        *self.events_collected.write().await += events.len() as u64;
        Ok(events)
    }
    
    
    fn collection_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(30) // Collect every 30 seconds
    }
    
    fn get_event_sender(&self) -> &mpsc::Sender<Event> {
        &self.event_sender
    }
}
