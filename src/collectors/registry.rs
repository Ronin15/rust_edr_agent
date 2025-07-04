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
    async fn get_value_name(&self, key_handle: &windows::Win32::System::Registry::HKEY, subkey: &str) -> Option<String> {
        use windows::Win32::System::Registry::*;
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        
        unsafe {
            let mut name_size = 0;
            let mut value_count = 0;
            
            // Get info about the key
            let result = RegQueryInfoKeyW(
                *key_handle,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut value_count,
                &mut name_size,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
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
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
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
    async fn get_value_type(&self, key_handle: &windows::Win32::System::Registry::HKEY, subkey: &str) -> Option<String> {
        use windows::Win32::System::Registry::*;
        
        unsafe {
            let mut value_type = 0u32;
            
            let result = RegQueryValueExW(
                *key_handle,
                windows::core::PCWSTR::null(),
                std::ptr::null_mut(),
                Some(&mut value_type),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            
            if result.is_ok() {
                Some(match value_type {
                    REG_SZ => "REG_SZ".to_string(),
                    REG_EXPAND_SZ => "REG_EXPAND_SZ".to_string(),
                    REG_BINARY => "REG_BINARY".to_string(),
                    REG_DWORD => "REG_DWORD".to_string(),
                    REG_DWORD_BIG_ENDIAN => "REG_DWORD_BIG_ENDIAN".to_string(),
                    REG_LINK => "REG_LINK".to_string(),
                    REG_MULTI_SZ => "REG_MULTI_SZ".to_string(),
                    REG_RESOURCE_LIST => "REG_RESOURCE_LIST".to_string(),
                    REG_QWORD => "REG_QWORD".to_string(),
                    _ => format!("Unknown ({})", value_type),
                })
            } else {
                None
            }
        }
    }
    
    #[cfg(windows)]
    async fn get_value_data(&self, key_handle: &windows::Win32::System::Registry::HKEY, subkey: &str) -> Option<String> {
        use windows::Win32::System::Registry::*;
        
        unsafe {
            let mut data_size = 0;
            let mut value_type = 0;
            
            // Get required buffer size
            let result = RegQueryValueExW(
                *key_handle,
                windows::core::PCWSTR::null(),
                std::ptr::null_mut(),
                Some(&mut value_type),
                std::ptr::null_mut(),
                Some(&mut data_size),
            );
            
            if result.is_err() || data_size == 0 {
                return None;
            }
            
            let mut data_buffer = vec![0u8; data_size as usize];
            
            let result = RegQueryValueExW(
                *key_handle,
                windows::core::PCWSTR::null(),
                std::ptr::null_mut(),
                Some(&mut value_type),
                Some(data_buffer.as_mut_ptr()),
                Some(&mut data_size),
            );
            
            if result.is_ok() {
                match value_type {
                    REG_SZ | REG_EXPAND_SZ => {
                        let wide_str = std::slice::from_raw_parts(
                            data_buffer.as_ptr() as *const u16,
                            (data_size / 2) as usize,
                        );
                        String::from_utf16_lossy(wide_str)
                            .trim_end_matches('\0')
                            .to_string()
                            .into()
                    }
                    REG_DWORD => {
                        let value = u32::from_ne_bytes(
                            data_buffer[..4].try_into().unwrap_or_default()
                        );
                        Some(format!("{}", value))
                    }
                    REG_QWORD => {
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
        use windows::Win32::System::ProcessStatus::*;
        use windows::Win32::Foundation::*;
        
        unsafe {
            let pid = GetCurrentProcessId();
            let mut process_name = None;
            
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot.is_invalid() {
                return (Some(pid), None);
            }
            
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                while Process32NextW(snapshot, &mut entry).is_ok() {
                    if entry.th32ProcessID == pid {
                        process_name = String::from_utf16_lossy(&entry.szExeFile)
                            .trim_end_matches('\0')
                            .to_string()
                            .into();
                        break;
                    }
                }
            }
            
            CloseHandle(snapshot);
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
                
                let task = tokio::spawn(async move {
                    Self::monitor_registry_key_async(
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
    async fn monitor_registry_key_async(
        key_path: String,
        event_sender: mpsc::Sender<Event>,
        is_running: Arc<RwLock<bool>>,
        events_collected: Arc<RwLock<u64>>,
        last_error: Arc<RwLock<Option<String>>>,
        hostname: String,
        agent_id: String,
    ) {
        info!("Starting async monitoring for registry key: {}", key_path);
        
        // Parse the registry key path
        let (hkey, subkey) = Self::parse_registry_path(&key_path);
        if hkey.is_invalid() {
            error!("Invalid registry key path: {}", key_path);
            return;
        }
        
        while *is_running.read().await {
            // Use tokio::task::spawn_blocking for Windows registry operations
            let key_path_clone = key_path.clone();
            let hkey_clone = hkey;
            let subkey_clone = subkey.clone();
            let event_sender_clone = event_sender.clone();
            let events_collected_clone = events_collected.clone();
            let last_error_clone = last_error.clone();
            let hostname_clone = hostname.clone();
            let agent_id_clone = agent_id.clone();
            let is_running_clone = is_running.clone();
            
            let result = tokio::task::spawn_blocking(move || {
                Self::monitor_registry_key_blocking(
                    key_path_clone,
                    hkey_clone,
                    subkey_clone,
                    event_sender_clone,
                    events_collected_clone,
                    last_error_clone,
                    hostname_clone,
                    agent_id_clone,
                    is_running_clone,
                )
            }).await;
            
            match result {
                Ok(Ok(())) => {
                    info!("Registry monitoring completed normally for: {}", key_path);
                }
                Ok(Err(e)) => {
                    error!("Registry monitoring error for {}: {}", key_path, e);
                    *last_error.write().await = Some(e.to_string());
                }
                Err(e) => {
                    error!("Registry monitoring task panicked for {}: {:?}", key_path, e);
                    *last_error.write().await = Some(format!("Task panicked: {:?}", e));
                }
            }
            
            // Wait before potentially restarting
            if *is_running.read().await {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
        
        info!("Registry monitoring stopped for key: {}", key_path);
    }
    
    fn monitor_registry_key_blocking(
        key_path: String,
        hkey: windows::Win32::System::Registry::HKEY,
        subkey: String,
        event_sender: mpsc::Sender<Event>,
        events_collected: Arc<RwLock<u64>>,
        last_error: Arc<RwLock<Option<String>>>,
        hostname: String,
        agent_id: String,
        is_running: Arc<RwLock<bool>>,
    ) -> Result<()> {
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
                return Err(anyhow::anyhow!(
                    "Failed to open registry key {}: error code {}", 
                    key_path, 
                    e.code().0
                ));
            }
            
            // Create an event object for notification
            let event_handle = CreateEventW(None, FALSE, FALSE, PCWSTR::null())
                .map_err(|e| anyhow::anyhow!("Failed to create event handle: {:?}", e))?;
            
            // Register for registry change notifications
            let result = RegNotifyChangeKeyValue(
                key_handle,
                TRUE, // bWatchSubtree - monitor subtree
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
                event_handle,
                TRUE, // fAsynchronous
            );
            
            if let Err(e) = result {
                let _ = CloseHandle(event_handle);
                let _ = RegCloseKey(key_handle);
                return Err(anyhow::anyhow!(
                    "Failed to register for registry notifications: error code {}", 
                    e.code().0
                ));
            }
            
            info!("Successfully registered for registry notifications on: {}", key_path);
            
            // Monitor for changes using a runtime handle
            let rt = tokio::runtime::Handle::current();
            
            // Wait for changes with periodic checks
            loop {
                // Check if we should stop (non-blocking check)
                let running = rt.block_on(async {
                    *is_running.read().await
                });
                
                if !running {
                    break;
                }
                
                let wait_result = WaitForSingleObject(event_handle, 1000); // 1 second timeout
                
                match wait_result {
                    WAIT_OBJECT_0 => {
                        // Registry change detected
                        info!("Registry change detected in key: {}", key_path);
                        
                        // Create and send event using the instance method
                        let collector = RegistryCollector {
                            config: RegistryMonitorConfig { enabled: true, watched_keys: vec![] },
                            event_sender: event_sender.clone(),
                            is_running: Arc::new(RwLock::new(true)),
                            hostname: hostname.clone(),
                            agent_id: agent_id.clone(),
                            events_collected: Arc::new(RwLock::new(0)),
                            last_error: Arc::new(RwLock::new(None)),
                        };
                        let registry_event = collector.create_registry_event(
                            EventType::RegistryKeyModified,
                            key_path.clone(),
                            self.get_value_name(&key_handle, &subkey).await,
                            self.get_value_type(&key_handle, &subkey).await,
                            self.get_value_data(&key_handle, &subkey).await,
                            None,
                            self.get_process_info().await.0,
                            self.get_process_info().await.1,
                        );
                        
                        // Send the event asynchronously
                        let sender = event_sender.clone();
                        let events_collected_clone = events_collected.clone();
                        
                        rt.spawn(async move {
                            if let Err(e) = sender.send(registry_event).await {
                                error!("Failed to send registry event: {}", e);
                            } else {
                                let mut count = events_collected_clone.write().await;
                                *count += 1;
                            }
                        });
                        
                        // Re-register for notifications
                        let result = RegNotifyChangeKeyValue(
                            key_handle,
                            TRUE,
                            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
                            event_handle,
                            TRUE,
                        );
                        
                        if let Err(e) = result {
                            let _ = CloseHandle(event_handle);
                            let _ = RegCloseKey(key_handle);
                            return Err(anyhow::anyhow!(
                                "Failed to re-register for registry notifications: error code {}", 
                                e.code().0
                            ));
                        }
                    }
                    WAIT_TIMEOUT => {
                        // Timeout - continue loop
                        continue;
                    }
                    _ => {
                        let _ = CloseHandle(event_handle);
                        let _ = RegCloseKey(key_handle);
                        return Err(anyhow::anyhow!(
                            "Unexpected wait result for registry monitoring: {:?}", 
                            wait_result
                        ));
                    }
                }
            }
            
            // Cleanup
            let _ = CloseHandle(event_handle);
            let _ = RegCloseKey(key_handle);
        }
        
        Ok(())
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
