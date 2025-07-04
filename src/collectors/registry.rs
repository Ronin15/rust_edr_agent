use anyhow::Result;
use tracing::{info, error};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use crate::config::RegistryMonitorConfig;
use crate::events::{Event, EventType, EventData, RegistryEventData};
use crate::collectors::{Collector, EventCollector};
use crate::agent::CollectorStatus;

#[derive(Debug)]
pub struct RegistryCollector {
    config: RegistryMonitorConfig,
    event_sender: mpsc::Sender<Event>,
    is_running: Arc<RwLock<bool>>,
    hostname: String,
    agent_id: String,
    events_collected: Arc<RwLock<u64>>,
    last_error: Arc<RwLock<Option<String>>>,
}

impl RegistryCollector {
    #[cfg(windows)]
    async fn get_value_name(&self, key_handle: &windows::Win32::System::Registry::HKEY) -> Option<String> {
        use windows::Win32::System::Registry::*;
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        
        unsafe {
            let mut name_size = 0;
            let mut value_count = 0;
            
            // Get info about the key
            let result = RegQueryInfoKeyW(
                *key_handle,
                windows::core::PWSTR::null(),
                None,
                None,
                None,
                None,
                None,
                Some(&mut value_count),
                Some(&mut name_size),
                None,
                None,
                None,
            );
            
            if result.is_err() || value_count == 0 {
                return None;
            }
            
            // Allocate buffer for the value name
            let mut name_buffer = vec![0u16; name_size as usize + 1];
            let mut name_size = name_size + 1;
            
            // Get the last modified value name
            let result = RegEnumValueW(
                *key_handle,
                value_count - 1,
                windows::core::PWSTR(name_buffer.as_mut_ptr()),
                &mut name_size,
                None,
                None,
                None,
                None,
            );
            
            if result.is_ok() {
                name_buffer.truncate(name_size as usize);
                let os_string = OsString::from_wide(&name_buffer);
                os_string.into_string().ok()
            } else {
                None
            }
        }
    }
    
    #[cfg(windows)]
    async fn get_value_type(&self, key_handle: &windows::Win32::System::Registry::HKEY) -> Option<String> {
        use windows::Win32::System::Registry::*;
        
        unsafe {
            let mut value_type = REG_VALUE_TYPE::default();
            
            let result = RegQueryValueExW(
                *key_handle,
                windows::core::PCWSTR::null(),
                None,
                Some(&mut value_type),
                None,
                None,
            );
            
            if result.is_ok() {
                Some(match value_type.0 {
                    1 => "REG_SZ".to_string(),
                    2 => "REG_EXPAND_SZ".to_string(),
                    3 => "REG_BINARY".to_string(),
                    4 => "REG_DWORD".to_string(),
                    5 => "REG_DWORD_BIG_ENDIAN".to_string(),
                    6 => "REG_LINK".to_string(),
                    7 => "REG_MULTI_SZ".to_string(),
                    8 => "REG_RESOURCE_LIST".to_string(),
                    11 => "REG_QWORD".to_string(),
                    _ => format!("Unknown ({})", value_type.0),
                })
            } else {
                None
            }
        }
    }
    
    #[cfg(windows)]
    async fn get_value_data(&self, key_handle: &windows::Win32::System::Registry::HKEY) -> Option<String> {
        use windows::Win32::System::Registry::*;
        
        unsafe {
            let mut data_size = 0;
            let mut value_type = REG_VALUE_TYPE::default();
            
            // Get required buffer size
            let result = RegQueryValueExW(
                *key_handle,
                windows::core::PCWSTR::null(),
                None,
                Some(&mut value_type),
                None,
                Some(&mut data_size),
            );
            
            if result.is_err() || data_size == 0 {
                return None;
            }
            
            let mut data_buffer = vec![0u8; data_size as usize];
            
            let result = RegQueryValueExW(
                *key_handle,
                windows::core::PCWSTR::null(),
                None,
                Some(&mut value_type),
                Some(data_buffer.as_mut_ptr()),
                Some(&mut data_size),
            );
            
            if result.is_ok() {
                match value_type.0 {
                    1 | 2 => { // REG_SZ | REG_EXPAND_SZ
                        let wide_str = std::slice::from_raw_parts(
                            data_buffer.as_ptr() as *const u16,
                            (data_size / 2) as usize,
                        );
                        String::from_utf16_lossy(wide_str)
                            .trim_end_matches('\0')
                            .to_string()
                            .into()
                    }
                    4 => { // REG_DWORD
                        let value = u32::from_ne_bytes(
                            data_buffer[..4].try_into().unwrap_or_default()
                        );
                        Some(format!("{}", value))
                    }
                    11 => { // REG_QWORD
                        let value = u64::from_ne_bytes(
                            data_buffer[..8].try_into().unwrap_or_default()
                        );
                        Some(format!("{}", value))
                    }
                    _ => Some(format!("<{} bytes of binary data>", data_size)),
                }
            } else {
                None
            }
        }
    }
    
    #[cfg(windows)]
    async fn get_process_info(&self) -> (Option<u32>, Option<String>) {
        use windows::Win32::System::Threading::GetCurrentProcessId;
        use windows::Win32::System::Diagnostics::ToolHelp::*;
        use windows::Win32::Foundation::*;
        
        unsafe {
            let pid = GetCurrentProcessId();
            let mut process_name = None;
            
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
            if snapshot == INVALID_HANDLE_VALUE {
                return (Some(pid), None);
            }
            
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            
            if let Ok(()) = Process32FirstW(snapshot, &mut entry) {
                while let Ok(()) = Process32NextW(snapshot, &mut entry) {
                    if entry.th32ProcessID == pid {
                        process_name = String::from_utf16_lossy(&entry.szExeFile)
                            .trim_end_matches('\0')
                            .to_string()
                            .into();
                        break;
                    }
                }
            }
            
            CloseHandle(snapshot).unwrap_or(());
            (Some(pid), process_name)
        }
    }
    pub async fn new(
        config: RegistryMonitorConfig,
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
    
    fn create_registry_event(
        &self,
        event_type: EventType,
        key_path: String,
        value_name: Option<String>,
        value_type: Option<String>,
        value_data: Option<String>,
        old_value_data: Option<String>,
        process_id: Option<u32>,
        process_name: Option<String>,
    ) -> Event {
        let data = EventData::Registry(RegistryEventData {
            key_path,
            value_name,
            value_type,
            value_data,
            old_value_data,
            process_id,
            process_name,
        });
        
        Event::new(
            event_type,
            "registry_monitor".to_string(),
            self.hostname.clone(),
            self.agent_id.clone(),
            data,
        )
    }
}

#[async_trait::async_trait]
impl Collector for RegistryCollector {
    async fn start(&self) -> Result<()> {
        info!("Starting registry collector");
        *self.is_running.write().await = true;
        
        // Spawn the watcher task
        let self_clone = self.clone();
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_watcher().await {
                error!("Registry collector watcher error: {}", e);
            }
        });
        
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        info!("Stopping registry collector");
        *self.is_running.write().await = false;
        Ok(())
    }
    
    async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    async fn get_status(&self) -> CollectorStatus {
        CollectorStatus {
            name: "registry_monitor".to_string(),
            enabled: self.config.enabled,
            is_running: self.is_running().await,
            events_collected: *self.events_collected.read().await,
            last_error: self.last_error.read().await.clone(),
        }
    }
    
    fn name(&self) -> &'static str {
        "registry_monitor"
    }
}

impl Clone for RegistryCollector {
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
impl EventCollector for RegistryCollector {
    async fn watch(&self) -> Result<()> {
        // Registry monitoring is Windows-specific
        #[cfg(not(windows))]
        {
            warn!("Registry monitoring is only available on Windows");
            while self.is_running().await {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            }
            return Ok(());
        }
        
        #[cfg(windows)]
        {
            info!("Starting Windows registry monitoring");
            
            // If no specific keys are configured, monitor common important keys
            let keys_to_monitor = if self.config.watched_keys.is_empty() {
                vec![
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
                    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx".to_string(),
                    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx".to_string(),
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services".to_string(),
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows".to_string(),
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes".to_string(),
                    "HKEY_LOCAL_MACHINE\\SAM".to_string(),
                ]
            } else {
                self.config.watched_keys.clone()
            };
            
            info!("Monitoring {} registry keys", keys_to_monitor.len());
            
            // Create async tasks for each registry key
            let mut tasks = Vec::new();
            
            for key_path in keys_to_monitor {
                let event_sender = self.event_sender.clone();
                let is_running = self.is_running.clone();
                let events_collected = self.events_collected.clone();
                let last_error = self.last_error.clone();
                let hostname = self.hostname.clone();
                let agent_id = self.agent_id.clone();
                
            let self_clone = self.clone();
            let task = tokio::spawn(async move {
                self_clone.monitor_registry_key_blocking(
                        key_path,
                        event_sender,
                        is_running,
                        events_collected,
                        last_error,
                        hostname,
                        agent_id,
                    ).await
                });
                
                tasks.push(task);
            }
            
            // Wait for all monitoring tasks to complete
            for task in tasks {
                if let Err(e) = task.await {
                    error!("Registry monitoring task failed: {:?}", e);
                }
            }
            
            Ok(())
        }
    }
}

#[cfg(windows)]
impl RegistryCollector {
    async fn monitor_registry_key_blocking(
        &self,
        key_path: String,
        event_sender: mpsc::Sender<Event>,
        is_running: Arc<RwLock<bool>>,
        events_collected: Arc<RwLock<u64>>,
        last_error: Arc<RwLock<Option<String>>>,
        _hostname: String,
        _agent_id: String,
    ) {
        info!("Starting async monitoring for registry key: {}", key_path);
        
        // Parse the registry key path
        let (hkey, subkey) = Self::parse_registry_path(&key_path);
        if hkey.is_invalid() {
            error!("Invalid registry key path: {}", key_path);
            return;
        }
        
        while *is_running.read().await {
            use windows::Win32::System::Registry::*;
            use windows::Win32::Foundation::*;
            use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
            use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
            use windows::core::PCWSTR;
            use std::ffi::OsStr;
            use std::os::windows::ffi::OsStrExt;
            
            // Try to open the registry key
            let mut key_handle = HKEY::default();
            let subkey_wide: Vec<u16> = OsStr::new(&subkey)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            
            unsafe {
                // Use winapi directly for simpler error handling
                let result = RegOpenKeyExW(
                    hkey,
                    PCWSTR(subkey_wide.as_ptr()),
                    0,
                    KEY_NOTIFY,
                    &mut key_handle,
                );
                
                if let Err(e) = result {
                    error!("Failed to open registry key {}: error code {}", key_path, e.code().0);
                    *last_error.write().await = Some(format!("Failed to open registry key: {}", e));
                    break;
                }
                
                // Create an event object for notification
                let event_handle = match CreateEventW(None, FALSE, FALSE, PCWSTR::null()) {
                    Ok(handle) => handle,
                    Err(e) => {
                        error!("Failed to create event handle: {:?}", e);
                        *last_error.write().await = Some(format!("Failed to create event handle: {}", e));
                        break;
                    }
                };
                
                // Register for registry change notifications
                let result = RegNotifyChangeKeyValue(
                    key_handle,
                    TRUE, // bWatchSubtree - monitor subtree
                    REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
                    event_handle,
                    TRUE, // fAsynchronous
                );
                
                if let Err(e) = result {
                    error!("Failed to register for registry notifications: error code {}", e.code().0);
                    *last_error.write().await = Some(format!("Failed to register for notifications: {}", e));
                    let _ = CloseHandle(event_handle);
                    let _ = RegCloseKey(key_handle);
                    break;
                }
                
                info!("Successfully registered for registry notifications on: {}", key_path);
                
                // Wait for changes with periodic checks
                loop {
                    if !*is_running.read().await {
                        break;
                    }
                    
                    let wait_result = WaitForSingleObject(event_handle, 1000); // 1 second timeout
                    
                    match wait_result {
                        WAIT_OBJECT_0 => {
                            // Registry change detected
                            info!("Registry change detected in key: {}", key_path);
                            
                            // Get registry value details
                            let value_name = self.get_value_name(&key_handle).await;
                            let value_type = self.get_value_type(&key_handle).await;
                            let value_data = self.get_value_data(&key_handle).await;
                            let (process_id, process_name) = self.get_process_info().await;
                            
                            // Create and send the event
                            let registry_event = self.create_registry_event(
                                EventType::RegistryKeyModified,
                                key_path.clone(),
                                value_name,
                                value_type,
                                value_data,
                                None,
                                process_id,
                                process_name,
                            );
                            
                            if let Err(e) = event_sender.send(registry_event).await {
                                error!("Failed to send registry event: {}", e);
                                *last_error.write().await = Some(format!("Failed to send event: {}", e));
                            } else {
                                *events_collected.write().await += 1;
                            }
                            
                            // Re-register for notifications
                            let result = RegNotifyChangeKeyValue(
                                key_handle,
                                TRUE,
                                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
                                event_handle,
                                TRUE,
                            );
                            
                            if let Err(e) = result {
                                error!("Failed to re-register for notifications: error code {}", e.code().0);
                                *last_error.write().await = Some(format!("Failed to re-register: {}", e));
                                break;
                            }
                        }
                        WAIT_TIMEOUT => continue,
                        _ => {
                            error!("Unexpected wait result for registry monitoring: {:?}", wait_result);
                            *last_error.write().await = Some(format!("Unexpected wait result: {:?}", wait_result));
                            break;
                        }
                    }
                }
                
                // Cleanup
                let _ = CloseHandle(event_handle);
                let _ = RegCloseKey(key_handle);
            }
            
            // Wait before retrying
            if *is_running.read().await {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
        
        info!("Registry monitoring stopped for key: {}", key_path);
    }
    
    fn parse_registry_path(key_path: &str) -> (windows::Win32::System::Registry::HKEY, String) {
        use windows::Win32::System::Registry::*;
        if key_path.starts_with("HKEY_LOCAL_MACHINE\\") {
            (HKEY_LOCAL_MACHINE, key_path[19..].to_string())
        } else if key_path.starts_with("HKEY_CURRENT_USER\\") {
            (HKEY_CURRENT_USER, key_path[18..].to_string())
        } else if key_path.starts_with("HKEY_CLASSES_ROOT\\") {
            (HKEY_CLASSES_ROOT, key_path[18..].to_string())
        } else if key_path.starts_with("HKEY_USERS\\") {
            (HKEY_USERS, key_path[11..].to_string())
        } else if key_path.starts_with("HKEY_CURRENT_CONFIG\\") {
            (HKEY_CURRENT_CONFIG, key_path[20..].to_string())
        } else {
            (HKEY::default(), String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use crate::config::RegistryMonitorConfig;
    
    #[tokio::test]
    async fn test_registry_collector_creation() {
        let config = RegistryMonitorConfig {
            enabled: true,
            watched_keys: vec![
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            ],
        };
        
        let (event_sender, _event_receiver) = mpsc::channel(100);
        
        let collector = RegistryCollector::new(config, event_sender).await;
        assert!(collector.is_ok());
        
        let collector = collector.unwrap();
        assert_eq!(collector.name(), "registry_monitor");
        assert!(!collector.is_running().await);
    }
    
    #[tokio::test]
    async fn test_registry_collector_lifecycle() {
        let config = RegistryMonitorConfig {
            enabled: true,
            watched_keys: vec![],
        };
        
        let (event_sender, _event_receiver) = mpsc::channel(100);
        
        let collector = RegistryCollector::new(config, event_sender).await.unwrap();
        
        // Test initial state
        assert!(!collector.is_running().await);
        
        // Start collector
        let result = collector.start().await;
        assert!(result.is_ok());
        assert!(collector.is_running().await);
        
        // Get status
        let status = collector.get_status().await;
        assert_eq!(status.name, "registry_monitor");
        assert!(status.enabled);
        assert!(status.is_running);
        
        // Stop collector
        let result = collector.stop().await;
        assert!(result.is_ok());
        assert!(!collector.is_running().await);
    }
    
    #[test]
    fn test_parse_registry_path() {
        let test_cases = vec![
            ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Test", "SOFTWARE\\Test"),
            ("HKEY_CURRENT_USER\\SOFTWARE\\Test", "SOFTWARE\\Test"),
            ("HKEY_CLASSES_ROOT\\Test", "Test"),
            ("HKEY_USERS\\Test", "Test"),
            ("HKEY_CURRENT_CONFIG\\Test", "Test"),
        ];
        
        for (input, expected_subkey) in test_cases {
            let (hkey, subkey) = RegistryCollector::parse_registry_path(input);
            assert!(!hkey.is_invalid());
            assert_eq!(subkey, expected_subkey);
        }
        
        // Test invalid path
        let (hkey, subkey) = RegistryCollector::parse_registry_path("INVALID_PATH");
        assert!(hkey.is_invalid());
        assert!(subkey.is_empty());
    }
}
