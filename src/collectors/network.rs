use anyhow::Result;
use tracing::{info, warn, error, debug};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::process::Command;
use std::collections::HashSet;

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

#[derive(Debug)]
pub struct NetworkCollector {
    config: NetworkMonitorConfig,
    event_sender: mpsc::Sender<Event>,
    is_running: Arc<RwLock<bool>>,
    hostname: String,
    agent_id: String,
    events_collected: Arc<RwLock<u64>>,
    last_error: Arc<RwLock<Option<String>>>,
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
        })
    }
    
    fn create_network_event(&self, connection: &NetworkConnection) -> Event {
        let data = EventData::Network(NetworkEventData {
            protocol: connection.protocol.clone(),
            source_ip: connection.local_ip.clone(),
            source_port: connection.local_port,
            destination_ip: connection.remote_ip.clone(),
            destination_port: connection.remote_port,
            direction: connection.direction.clone(),
            bytes_sent: None,
            bytes_received: None,
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
        
        // Use netstat to get network connections
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
                error!("Failed to run netstat: {}", e);
                *self.last_error.write().await = Some(format!("netstat failed: {}", e));
            }
        }
        
        // Also try lsof on Unix systems for more detailed process info
        #[cfg(unix)]
        if let Ok(output) = Command::new("lsof")
            .args(["-i", "-n", "-P"])
            .output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            connections.extend(self.parse_lsof_output(&output_str)?);
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
                for connection in connections {
                    // Filter connections based on configuration
                    if self.should_include_connection(&connection) {
                        let event = self.create_network_event(&connection);
                        events.push(event);
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
