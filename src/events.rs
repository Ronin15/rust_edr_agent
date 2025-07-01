use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub source: String,
    pub hostname: String,
    pub agent_id: String,
    pub data: EventData,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    ProcessCreated,
    ProcessTerminated,
    ProcessModified,
    FileCreated,
    FileModified,
    FileDeleted,
    FileAccessed,
    NetworkConnection,
    NetworkDnsQuery,
    RegistryKeyCreated,
    RegistryKeyModified,
    RegistryKeyDeleted,
    RegistryValueSet,
    SystemBoot,
    SystemShutdown,
    UserLogin,
    UserLogout,
    SecurityAlert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventData {
    Process(ProcessEventData),
    File(FileEventData),
    Network(NetworkEventData),
    Registry(RegistryEventData),
    System(SystemEventData),
    User(UserEventData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEventData {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub path: String,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub session_id: Option<u32>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub cpu_usage: Option<f32>,
    pub memory_usage: Option<u64>,
    pub environment: Option<HashMap<String, String>>,
    pub hashes: Option<FileHashes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventData {
    pub path: String,
    pub size: Option<u64>,
    pub permissions: Option<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub created_time: Option<DateTime<Utc>>,
    pub modified_time: Option<DateTime<Utc>>,
    pub accessed_time: Option<DateTime<Utc>>,
    pub hashes: Option<FileHashes>,
    pub mime_type: Option<String>,
    pub old_path: Option<String>, // For move/rename operations
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventData {
    pub protocol: String,
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_ip: Option<String>,
    pub destination_port: Option<u16>,
    pub direction: NetworkDirection,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub connection_state: Option<String>,
    pub dns_query: Option<String>,
    pub dns_response: Option<Vec<String>>,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEventData {
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_type: Option<String>,
    pub value_data: Option<String>,
    pub old_value_data: Option<String>,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEventData {
    pub event_id: Option<u32>,
    pub description: String,
    pub boot_id: Option<String>,
    pub uptime: Option<u64>,
    pub system_info: Option<SystemInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEventData {
    pub username: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub login_type: Option<String>,
    pub source_ip: Option<String>,
    pub logon_time: Option<DateTime<Utc>>,
    pub logoff_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    pub hostname: String,
    pub total_memory: Option<u64>,
    pub cpu_count: Option<u32>,
}

impl Event {
    pub fn new(
        event_type: EventType,
        source: String,
        hostname: String,
        agent_id: String,
        data: EventData,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            source,
            hostname,
            agent_id,
            data,
            metadata: HashMap::new(),
        }
    }
    
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
    
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
    
    pub fn is_high_priority(&self) -> bool {
        matches!(
            self.event_type,
            EventType::ProcessCreated
                | EventType::NetworkConnection
                | EventType::RegistryKeyModified
                | EventType::UserLogin
                | EventType::UserLogout
        )
    }
    
    pub fn get_severity(&self) -> EventSeverity {
        match self.event_type {
            EventType::ProcessCreated | EventType::ProcessTerminated => EventSeverity::Medium,
            EventType::FileCreated | EventType::FileModified | EventType::FileDeleted => {
                EventSeverity::Low
            }
            EventType::NetworkConnection | EventType::NetworkDnsQuery => EventSeverity::Medium,
            EventType::RegistryKeyCreated
            | EventType::RegistryKeyModified
            | EventType::RegistryKeyDeleted => EventSeverity::Medium,
            EventType::UserLogin | EventType::UserLogout => EventSeverity::High,
            EventType::SystemBoot | EventType::SystemShutdown => EventSeverity::High,
            EventType::SecurityAlert => EventSeverity::Critical,
            _ => EventSeverity::Low,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventBatch {
    pub events: Vec<Event>,
    pub created_at: DateTime<Utc>,
    pub batch_id: String,
}

impl EventBatch {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            created_at: Utc::now(),
            batch_id: Uuid::new_v4().to_string(),
        }
    }
    
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            created_at: Utc::now(),
            batch_id: Uuid::new_v4().to_string(),
        }
    }
    
    pub fn add_event(&mut self, event: Event) {
        self.events.push(event);
    }
    
    pub fn add_events(&mut self, events: Vec<Event>) {
        self.events.extend(events);
    }
    
    pub fn len(&self) -> usize {
        self.events.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
    
    pub fn clear(&mut self) {
        self.events.clear();
        self.created_at = Utc::now();
        self.batch_id = Uuid::new_v4().to_string();
    }
    
    pub fn get_events(&self) -> &Vec<Event> {
        &self.events
    }
    
    pub fn take_events(mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
    
    pub fn filter_by_type(&self, event_type: &EventType) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|event| std::mem::discriminant(&event.event_type) == std::mem::discriminant(event_type))
            .collect()
    }
    
    pub fn filter_by_severity(&self, min_severity: EventSeverity) -> Vec<&Event> {
        let min_level = severity_to_level(&min_severity);
        self.events
            .iter()
            .filter(|event| severity_to_level(&event.get_severity()) >= min_level)
            .collect()
    }
    
    pub fn get_size_bytes(&self) -> usize {
        // Rough estimation of batch size in bytes
        self.events.len() * 1024 // Assume ~1KB per event on average
    }
}

impl Default for EventBatch {
    fn default() -> Self {
        Self::new()
    }
}

fn severity_to_level(severity: &EventSeverity) -> u8 {
    match severity {
        EventSeverity::Low => 0,
        EventSeverity::Medium => 1,
        EventSeverity::High => 2,
        EventSeverity::Critical => 3,
    }
}

// Helper functions for creating common events
pub mod builders {
    use super::*;
    
    pub fn create_process_event(
        pid: u32,
        name: String,
        path: String,
        hostname: String,
        agent_id: String,
    ) -> Event {
        let data = EventData::Process(ProcessEventData {
            pid,
            ppid: None,
            name,
            path,
            command_line: None,
            user: None,
            session_id: None,
            start_time: Some(Utc::now()),
            end_time: None,
            exit_code: None,
            cpu_usage: None,
            memory_usage: None,
            environment: None,
            hashes: None,
        });
        
        Event::new(
            EventType::ProcessCreated,
            "process_monitor".to_string(),
            hostname,
            agent_id,
            data,
        )
    }
    
    pub fn create_file_event(
        event_type: EventType,
        path: String,
        hostname: String,
        agent_id: String,
    ) -> Event {
        let data = EventData::File(FileEventData {
            path,
            size: None,
            permissions: None,
            owner: None,
            group: None,
            created_time: None,
            modified_time: Some(Utc::now()),
            accessed_time: None,
            hashes: None,
            mime_type: None,
            old_path: None,
        });
        
        Event::new(
            event_type,
            "file_monitor".to_string(),
            hostname,
            agent_id,
            data,
        )
    }
    
    pub fn create_network_event(
        protocol: String,
        destination_ip: String,
        destination_port: u16,
        hostname: String,
        agent_id: String,
    ) -> Event {
        let data = EventData::Network(NetworkEventData {
            protocol,
            source_ip: None,
            source_port: None,
            destination_ip: Some(destination_ip),
            destination_port: Some(destination_port),
            direction: NetworkDirection::Outbound,
            bytes_sent: None,
            bytes_received: None,
            connection_state: None,
            dns_query: None,
            dns_response: None,
            process_id: None,
            process_name: None,
        });
        
        Event::new(
            EventType::NetworkConnection,
            "network_monitor".to_string(),
            hostname,
            agent_id,
            data,
        )
    }
    
    pub fn create_registry_event(
        event_type: EventType,
        key_path: String,
        hostname: String,
        agent_id: String,
    ) -> Event {
        let data = EventData::Registry(RegistryEventData {
            key_path,
            value_name: None,
            value_type: None,
            value_data: None,
            old_value_data: None,
            process_id: None,
            process_name: None,
        });
        
        Event::new(
            event_type,
            "registry_monitor".to_string(),
            hostname,
            agent_id,
            data,
        )
    }
}
