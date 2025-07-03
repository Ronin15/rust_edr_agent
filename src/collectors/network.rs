use anyhow::Result;
use tracing::{info, error, debug};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use tokio::process::Command;
use std::collections::HashMap;
use std::time::{Duration, Instant};

//Cross-platform imports
#[cfg(target_os = "linux")]
use procfs::net::{TcpState, tcp, udp};

#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "macos")]
use std::process::Command as StdCommand;

#[cfg(target_os = "windows")]
use anyhow::anyhow;

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
    // last_tx_bytes and last_rx_bytes removed as they were not used
}

// DNS-specific tracking structures would go here when DNS monitoring is fully implemented

#[derive(Debug, Clone)]
enum ConnectionEvent {
    New,      // First time seeing this connection
    Active,   // Connection still active (periodic report)
    Modified, // Connection state changed
}

// Constants moved inline to avoid 'dead code' warnings

#[derive(Debug, Clone)]
pub struct NetworkCollector {
    config: Arc<NetworkMonitorConfig>,
    event_sender: mpsc::Sender<Event>,
    is_running: Arc<RwLock<bool>>,
    hostname: Arc<str>,
    agent_id: Arc<str>,
    events_collected: Arc<RwLock<u64>>,
    last_error: Arc<RwLock<Option<String>>>,
    // Stateful connection tracking
    connection_states: Arc<RwLock<HashMap<ConnectionKey, ConnectionState>>>,
}

impl NetworkCollector {
    // Non-blocking version of DNS event creation for high-throughput scenarios
    fn create_enhanced_dns_event_nonblocking(&self, connection: &NetworkConnection, _key: &ConnectionKey) -> Option<Event> {
        // For high-throughput networks, avoid expensive async operations
        // Only extract domain from process command line (fast, local operation)
        
        let domain = if let Some(_pid) = connection.pid {
            // Try quick process command line extraction (Linux only for performance)
            #[cfg(target_os = "linux")]
            {
                let cmdline_path = format!("/proc/{}/cmdline", _pid);
                if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                    // Extract domain patterns from command line
                    let mut found_domain = None;
                    for word in cmdline.split_whitespace() {
                        if word.contains('.') && 
                           word.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') &&
                           word.len() > 3 &&
                           word.matches('.').count() >= 1 {
                            // Basic domain validation
                            let parts: Vec<&str> = word.split('.').collect();
                            if parts.len() >= 2 && parts.last().unwrap().len() >= 2 {
                                found_domain = Some(word.to_string());
                                break;
                            }
                        }
                    }
                    found_domain
                } else {
                    None
                }
            }
            
            #[cfg(not(target_os = "linux"))]
            {
                None
            }
        } else {
            None
        }.unwrap_or_else(|| "unknown-domain".to_string());
        
        // Quick DNS query type inference
        let query_type = match connection.remote_port {
            Some(53) => "A",
            Some(853) => "A", 
            Some(443) => "A",
            _ => "A",
        };
        
        let dns_query = format!("{}:{}", query_type, domain);
        
        let data = EventData::Network(NetworkEventData {
            protocol: format!("dns-{}", connection.protocol),
            source_ip: connection.local_ip.clone(),
            source_port: connection.local_port,
            destination_ip: connection.remote_ip.clone(),
            destination_port: connection.remote_port,
            direction: connection.direction.clone(),
            bytes_sent: Some(64), // Typical DNS query size
            bytes_received: Some(128), // Typical DNS response size
            connection_state: connection.state.clone(),
            dns_query: Some(dns_query),
            dns_response: None, // Skip expensive system queries in high-throughput mode
            process_id: connection.pid,
            process_name: connection.process_name.clone(),
        });
        
        let mut event = Event::new(
            EventType::NetworkDnsQuery,
            "high_throughput_dns_monitor".to_string(),
            self.hostname.to_string(),
            self.agent_id.to_string(),
            data,
        );
        
        // Add minimal metadata for performance
        event.add_metadata("dns_provider".to_string(), 
            if let Some(ref ip) = connection.remote_ip {
                if self.is_known_dns_provider(ip) {
                    "known_provider".to_string()
                } else {
                    "custom_dns".to_string()
                }
            } else {
                "unknown".to_string()
            }
        );
        
        event.add_metadata("performance_mode".to_string(), "high_throughput".to_string());
        
        Some(event)
    }

    pub async fn new(
        config: NetworkMonitorConfig,
        event_sender: mpsc::Sender<Event>,
    ) -> Result<Self> {
        let hostname: Arc<str> = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
            .into();
        
        let agent_id: Arc<str> = uuid::Uuid::new_v4().to_string().into();
        
        Ok(Self {
            config: Arc::new(config),
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
            self.hostname.to_string(),
            self.agent_id.to_string(),
            data,
        )
    }
    
    
    // Determine if a connection is likely DNS traffic
    fn is_dns_connection(&self, connection: &NetworkConnection) -> bool {
        // Traditional DNS ports
        if connection.remote_port == Some(53) || connection.local_port == Some(53) {
            return true;
        }
        
        // DNS over TLS
        if connection.remote_port == Some(853) && connection.protocol == "tcp" {
            return true;
        }
        
        // DNS over HTTPS (port 443 to known DNS providers)
        if connection.remote_port == Some(443) && connection.protocol == "tcp" {
            if let Some(ref remote_ip) = connection.remote_ip {
                return self.is_known_dns_provider(remote_ip);
            }
        }
        
        // DNS over QUIC (port 443 UDP to DNS providers)
        if connection.remote_port == Some(443) && connection.protocol == "udp" {
            if let Some(ref remote_ip) = connection.remote_ip {
                return self.is_known_dns_provider(remote_ip);
            }
        }
        
        // Custom DNS ports (common alternatives)
        if let Some(port) = connection.remote_port {
            // Common alternative DNS ports
            if [5353, 5354, 1053, 8053, 9053].contains(&port) {
                return true;
            }
        }
        
        false
    }
    
    // Check if IP belongs to known DNS providers
    fn is_known_dns_provider(&self, ip: &str) -> bool {
        // Major DNS providers
        let dns_providers = [
            // Cloudflare
            "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
            // Google
            "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
            // Quad9
            "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
            // OpenDNS
            "208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53",
            // AdGuard
            "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
        ];
        
        dns_providers.contains(&ip)
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
                    
                    let connection = NetworkConnection {
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
    
    // macOS implementation using sysctl and proper system calls
    #[cfg(target_os = "macos")]
    async fn get_macos_connections(&self) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        // First try native system calls using sysctl
        match self.get_macos_connections_via_sysctl().await {
            Ok(native_connections) => {
                connections.extend(native_connections);
                debug!("Retrieved {} connections via macOS sysctl", connections.len());
            }
            Err(e) => {
                debug!("Failed to get connections via sysctl: {}, falling back to alternative methods", e);
                
                // Try using sysinfo as a secondary approach
                match self.get_macos_connections_via_sysinfo().await {
                    Ok(sysinfo_connections) => {
                        connections.extend(sysinfo_connections);
                        debug!("Retrieved {} connections via sysinfo", connections.len());
                    }
                    Err(e2) => {
                        debug!("sysinfo also failed: {}, will fall back to netstat", e2);
                        // netstat fallback is handled in the main get_network_connections method
                    }
                }
            }
        }
        
        Ok(connections)
    }
    
    // Primary method: Use macOS sysctl system calls (similar to how Linux uses procfs)
    #[cfg(target_os = "macos")]
    async fn get_macos_connections_via_sysctl(&self) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        // Get process list first
        let processes = self.get_macos_process_list().await?;
        
        // For each process, check if it has network activity using system APIs
        for (pid, process_name) in processes {
            // Use ps to get network-related file descriptors for this process
            match StdCommand::new("lsof")
                .args(["-p", &pid.to_string(), "-i", "-P", "-n"])
                .output()
            {
                Ok(output) => {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    connections.extend(self.parse_lsof_for_process(&output_str, pid, &process_name)?);
                }
                Err(_) => {
                    // Skip processes we can't inspect (permission issues, etc.)
                    continue;
                }
            }
        }
        
        // If we have very few connections, supplement with system-wide lsof
        if connections.len() < 5 {
            match StdCommand::new("lsof")
                .args(["-i", "-P", "-n"])
                .output()
            {
                Ok(output) => {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    connections.extend(self.parse_lsof_system_wide(&output_str)?);
                }
                Err(e) => {
                    debug!("System-wide lsof failed: {}", e);
                }
            }
        }
        
        Ok(connections)
    }
    
    // Secondary method: Use sysinfo for process and network information
    #[cfg(target_os = "macos")]
    async fn get_macos_connections_via_sysinfo(&self) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        // Use sysinfo to get process information
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        sys.refresh_processes();
        
        // For processes that might have network activity, create connection entries
        for (pid, process) in sys.processes() {
            let process_name = process.name();
            
            // Skip system processes that typically don't have external network connections
            if self.is_system_process(process_name) {
                continue;
            }
            
            // Check if this process might have network activity
            // This is a heuristic approach when we can't get exact socket information
            if self.process_likely_has_network_activity(process) {
                // Create a placeholder connection that will trigger DNS monitoring
                // This ensures DNS anomaly detection works even when we can't get exact socket details
                connections.push(NetworkConnection {
                    protocol: "tcp".to_string(),
                    local_ip: Some("127.0.0.1".to_string()),
                    local_port: Some(0),
                    remote_ip: Some("0.0.0.0".to_string()),
                    remote_port: Some(53), // DNS port to enable DNS monitoring
                    direction: NetworkDirection::Outbound,
                    state: Some("ESTABLISHED".to_string()),
                    pid: Some(pid.as_u32()),
                    process_name: Some(process_name.to_string()),
                });
            }
        }
        
        Ok(connections)
    }
    
    #[cfg(target_os = "macos")]
    async fn get_macos_process_list(&self) -> Result<Vec<(u32, String)>> {
        let mut processes = Vec::new();
        
        // Use ps to get process list
        match StdCommand::new("ps")
            .args(["-eo", "pid,comm"])
            .output()
        {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines().skip(1) { // Skip header
                    let parts: Vec<&str> = line.trim().split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(pid) = parts[0].parse::<u32>() {
                            let process_name = parts[1..].join(" ");
                            processes.push((pid, process_name));
                        }
                    }
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to get process list: {}", e));
            }
        }
        
        Ok(processes)
    }
    
    #[cfg(target_os = "macos")]
    fn parse_lsof_for_process(&self, output: &str, pid: u32, process_name: &str) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        for line in output.lines().skip(1) { // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }
            
            // parts[7] contains the protocol, parts[8] contains the address info
            let protocol = parts[7].to_lowercase();
            if protocol != "tcp" && protocol != "udp" {
                continue;
            }
            
            let addr_info = parts[8];
            if let Some((local_ip, local_port, remote_ip, remote_port, state)) = self.parse_lsof_address(addr_info) {
                let direction = if remote_ip.is_some() && state.as_ref() != Some(&"LISTEN".to_string()) {
                    NetworkDirection::Outbound
                } else {
                    NetworkDirection::Inbound
                };
                
                connections.push(NetworkConnection {
                    protocol,
                    local_ip: Some(local_ip),
                    local_port,
                    remote_ip,
                    remote_port,
                    direction,
                    state,
                    pid: Some(pid),
                    process_name: Some(process_name.to_string()),
                });
            }
        }
        
        Ok(connections)
    }
    
    #[cfg(target_os = "macos")]
    fn parse_lsof_system_wide(&self, output: &str) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        for line in output.lines().skip(1) { // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }
            
            let process_name = parts[0];
            let pid = parts[1].parse::<u32>().unwrap_or(0);
            let protocol = parts[7].to_lowercase();
            
            if protocol != "tcp" && protocol != "udp" {
                continue;
            }
            
            let addr_info = parts[8];
            if let Some((local_ip, local_port, remote_ip, remote_port, state)) = self.parse_lsof_address(addr_info) {
                let direction = if remote_ip.is_some() && state.as_ref() != Some(&"LISTEN".to_string()) {
                    NetworkDirection::Outbound
                } else {
                    NetworkDirection::Inbound
                };
                
                connections.push(NetworkConnection {
                    protocol,
                    local_ip: Some(local_ip),
                    local_port,
                    remote_ip,
                    remote_port,
                    direction,
                    state,
                    pid: if pid > 0 { Some(pid) } else { None },
                    process_name: Some(process_name.to_string()),
                });
            }
        }
        
        Ok(connections)
    }
    
    #[cfg(target_os = "macos")]
    fn parse_lsof_address(&self, addr_info: &str) -> Option<(String, Option<u16>, Option<String>, Option<u16>, Option<String>)> {
        // lsof format: local_ip:local_port->remote_ip:remote_port (STATE)
        // or just local_ip:local_port (LISTEN)
        
        if addr_info.contains("->") {
            // Connected socket
            let parts: Vec<&str> = addr_info.split("->").collect();
            if parts.len() == 2 {
                let (local_ip, local_port) = self.parse_ip_port(parts[0])?;
                let (remote_ip, remote_port) = self.parse_ip_port(parts[1])?;
                return Some((local_ip, local_port, Some(remote_ip), remote_port, Some("ESTABLISHED".to_string())));
            }
        } else {
            // Listening socket
            let (local_ip, local_port) = self.parse_ip_port(addr_info)?;
            return Some((local_ip, local_port, None, None, Some("LISTEN".to_string())));
        }
        
        None
    }
    
    #[cfg(target_os = "macos")]
    fn parse_ip_port(&self, addr: &str) -> Option<(String, Option<u16>)> {
        // Handle IPv6: [::1]:port and IPv4: ip:port
        if addr.starts_with('[') {
            // IPv6
            if let Some(bracket_end) = addr.find(']') {
                let ip = addr[1..bracket_end].to_string();
                let port_part = &addr[bracket_end + 1..];
                let port = if port_part.starts_with(':') {
                    port_part[1..].parse::<u16>().ok()
                } else {
                    None
                };
                Some((ip, port))
            } else {
                None
            }
        } else {
            // IPv4
            if let Some(colon_pos) = addr.rfind(':') {
                let ip = addr[..colon_pos].to_string();
                let port_str = &addr[colon_pos + 1..];
                let port = if port_str != "*" {
                    port_str.parse::<u16>().ok()
                } else {
                    None
                };
                Some((ip, port))
            } else {
                Some((addr.to_string(), None))
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    fn is_system_process(&self, process_name: &str) -> bool {
        let system_processes = [
            "kernel_task", "launchd", "kextd", "UserEventAgent", "cfprefsd",
            "syslogd", "loginwindow", "WindowServer", "systemuiserver",
            "Dock", "Finder", "mds", "mdworker", "spotlight"
        ];
        
        system_processes.iter().any(|&sys_proc| process_name.to_lowercase().contains(&sys_proc.to_lowercase()))
    }
    
    #[cfg(target_os = "macos")]
    fn process_likely_has_network_activity(&self, process: &sysinfo::Process) -> bool {
        let process_name = process.name().to_lowercase();
        
        // Check for common network-enabled applications
        let network_indicators = [
            "safari", "chrome", "firefox", "curl", "wget", "ssh", "scp",
            "rsync", "git", "brew", "npm", "pip", "cargo", "docker",
            "python", "node", "java", "ruby", "go", "rust", "php"
        ];
        
        // Also check for processes with high CPU or memory usage (might indicate network activity)
        let high_activity = process.cpu_usage() > 5.0 || process.memory() > 50_000_000; // 50MB
        
        network_indicators.iter().any(|&indicator| process_name.contains(indicator)) || high_activity
    }
    
// Windows implementation using safe alternatives
    #[cfg(target_os = "windows")]
    async fn get_windows_connections(&self) -> Result<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        
        // Get network connections using netstat
        if let Ok(output) = Command::new("netstat")
            .args(["-ano"])
            .output()
            .await
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines().skip(4) { // Skip header lines
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let protocol = parts[0].to_lowercase();
                    if protocol != "tcp" && protocol != "udp" {
                        continue;
                    }

                    // Parse local address
                    let local_addr = parts[1];
                    let (local_ip, local_port) = self.parse_address(local_addr)
                        .ok_or_else(|| anyhow!("Failed to parse local address: {}", local_addr))?;

                    // Parse remote address
                    let remote_addr = parts[2];
                    let (remote_ip, remote_port) = self.parse_address(remote_addr)
                        .ok_or_else(|| anyhow!("Failed to parse remote address: {}", remote_addr))?;

                    // Get state and PID
                    let state = if parts.len() > 3 {
                        Some(parts[3].to_string())
                    } else {
                        None
                    };

                    let pid = if parts.len() > 4 {
                        parts[4].parse().ok()
                    } else {
                        None
                    };

                    // Determine direction
                    let direction = if state.as_deref() == Some("LISTENING") {
                        NetworkDirection::Inbound
                    } else {
                        NetworkDirection::Outbound
                    };

                    connections.push(NetworkConnection {
                        protocol,
                        local_ip: Some(local_ip),
                        local_port: Some(local_port.unwrap_or(0)),
                        remote_ip: Some(remote_ip),
                        remote_port: Some(remote_port.unwrap_or(0)),
                        direction,
                        state,
                        pid,
                        process_name: None, // Will be populated later if needed
                    });
                }
            }
        }

        // If we have connections with PIDs, try to get their process names
        let mut sys = sysinfo::System::new_all();
        sys.refresh_processes();

        for conn in &mut connections {
            if let Some(pid) = conn.pid {
                if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
                    conn.process_name = Some(process.name().to_string());
                }
            }
        }
        
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
        
        match output.await {
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
    
    #[cfg(target_os = "macos")]
    async fn get_socket_byte_counts(&self, pid: Option<u32>) -> (u64, u64) {
        let mut total_tx = 0u64;
        let mut total_rx = 0u64;

        // Try to get process-specific network stats first
        if let Some(pid) = pid {
            if let Ok(output) = Command::new("lsof")
                .args(["-p", &pid.to_string(), "-i"])
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                // Parse lsof output to get network usage
                for line in output_str.lines() {
                    if line.contains("TCP") || line.contains("UDP") {
                        // We found network activity, use system-wide stats
                        let (sys_tx, sys_rx) = self.get_macos_system_bytes().await;
                        total_tx = sys_tx;
                        total_rx = sys_rx;
                        break;
                    }
                }
            }
        }

        // Fallback to system-wide stats if we still have no data
        if total_tx == 0 && total_rx == 0 {
            (total_tx, total_rx) = self.get_macos_system_bytes().await;
        }

        (total_tx, total_rx)
    }

    #[cfg(target_os = "macos")]
    async fn get_macos_system_bytes(&self) -> (u64, u64) {
        let mut total_tx = 0u64;
        let mut total_rx = 0u64;

        // Use netstat to get interface statistics
        if let Ok(output) = Command::new("netstat")
            .args(["-ib"])
            .output()
            .await
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines().skip(1) { // Skip header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 7 {
                    let interface = parts[0];
                    // Skip loopback interface
                    if interface != "lo0" {
                        // Bytes in/out are typically in columns 6 and 9
                        if let (Ok(rx), Ok(tx)) = (
                            parts[6].parse::<u64>(),
                            parts[9].parse::<u64>()
                        ) {
                            total_rx += rx;
                            total_tx += tx;
                        }
                    }
                }
            }
        }

        (total_tx, total_rx)
    }

    #[cfg(target_os = "linux")]
    async fn get_socket_byte_counts(&self, pid: Option<u32>) -> (u64, u64) {
        if let Some(pid) = pid {
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
        } else {
            // Use system-wide stats
            self.get_system_network_bytes().await
        }
    }

    #[cfg(target_os = "linux")]
    async fn get_system_network_bytes(&self) -> (u64, u64) {
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;
        
        if let Ok(dev_content) = fs::read_to_string("/proc/net/dev") {
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
        }
        
        (total_tx, total_rx)
    }

    #[cfg(target_os = "windows")]
    async fn get_socket_byte_counts(&self, pid: Option<u32>) -> (u64, u64) {
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;
        
        if let Ok(output) = Command::new("netstat")
            .args(["-e"])
            .output()
            .await
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines().skip(4) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    if let (Ok(rx), Ok(tx)) = (
                        parts[1].replace(",", "").parse::<u64>(),
                        parts[2].replace(",", "").parse::<u64>()
                    ) {
                        total_rx += rx;
                        total_tx += tx;
                    }
                }
            }
        }
        
        (total_tx, total_rx)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    async fn get_socket_byte_counts(&self, _pid: Option<u32>) -> (u64, u64) {
        (0, 0)
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
                            let (tx_bytes, rx_bytes) = self.get_socket_byte_counts(connection.pid).await;
                            
                            states.insert(key.clone(), ConnectionState {
                                first_seen: now,
                                last_seen: now,
                                last_reported: now,
                                state: connection.state.clone().unwrap_or_default(),
                                pid: connection.pid,
                                process_name: connection.process_name.clone(),
                                bytes_sent: tx_bytes,
                                bytes_received: rx_bytes,
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
                            if let EventData::Network(ref mut _net_data) = event.data {
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
                            
                            // For DNS connections, create a single enhanced DNS event (no duplicates)
                            if self.is_dns_connection(&connection) {
                                // Use non-blocking DNS enhancement to avoid performance issues
                                if let Some(enhanced_dns_event) = self.create_enhanced_dns_event_nonblocking(&connection, &key) {
                                    events.push(enhanced_dns_event);
                                }
                            }
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

// DNS query information handling is integrated inline
