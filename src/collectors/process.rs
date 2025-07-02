use anyhow::Result;
use tracing::{debug, error, info};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use sysinfo::System;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::config::ProcessMonitorConfig;
use crate::events::{Event, EventType, EventData, ProcessEventData};
use crate::collectors::{Collector, PeriodicCollector};
use crate::agent::CollectorStatus;

// Process signature for deduplication (PID + memory + cpu usage)
type ProcessSignature = (u32, u64, String); // (pid, memory, rounded_cpu)

// Memory safety constants for process monitoring
const MAX_PROCESS_CACHE_ENTRIES: usize = 500; // Hard limit on cache size
const PROCESS_CACHE_CLEANUP_THRESHOLD: usize = 400; // Start aggressive cleanup at this point
const PROCESS_CACHE_TTL_SECONDS: u64 = 300; // 5 minutes max TTL
// These constants are embedded inline where used for clarity

#[derive(Debug)]
pub struct ProcessCollector {
    config: ProcessMonitorConfig,
    event_sender: mpsc::Sender<Event>,
    system: Arc<RwLock<System>>,
    is_running: Arc<RwLock<bool>>,
    hostname: String,
    agent_id: String,
    events_collected: Arc<RwLock<u64>>,
    last_error: Arc<RwLock<Option<String>>>,
    previous_processes: Arc<RwLock<HashMap<u32, ProcessInfo>>>,
    // Conservative deduplication for ProcessModified events
    process_state_cache: Arc<RwLock<HashMap<ProcessSignature, Instant>>>,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    path: String,
    start_time: std::time::SystemTime,
    cpu_usage: f32,
    memory_usage: u64,
}

impl ProcessCollector {
    pub async fn new(
        config: ProcessMonitorConfig,
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
            system: Arc::new(RwLock::new(System::new_all())),
            previous_processes: Arc::new(RwLock::new(HashMap::new())),
            hostname,
            agent_id,
            events_collected: Arc::new(RwLock::new(0)),
            last_error: Arc::new(RwLock::new(None)),
            process_state_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    async fn scan_processes(&self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let mut system = self.system.write().await;
        
        // Refresh system information
        system.refresh_processes();
        
        let mut previous_processes = self.previous_processes.write().await;
        let mut state_cache = self.process_state_cache.write().await;
        let now = Instant::now();
        
        // Aggressive memory management for process state cache
        if state_cache.len() >= PROCESS_CACHE_CLEANUP_THRESHOLD {
            // Emergency cleanup: remove oldest 50% of entries
            let mut entries: Vec<_> = state_cache.iter().map(|(k, &v)| (k.clone(), v)).collect();
            entries.sort_by_key(|(_, instant)| *instant);
            let to_remove = entries.len() / 2;
            let keys_to_remove: Vec<_> = entries.iter().take(to_remove).map(|(k, _)| k.clone()).collect();
            for key in keys_to_remove {
                state_cache.remove(&key);
            }
            debug!("Emergency process cache cleanup: removed {} entries, {} remaining", to_remove, state_cache.len());
        }
        
        // Regular TTL cleanup (older than 5 minutes)
        let entries_before = state_cache.len();
        state_cache.retain(|_, &mut last_seen| {
            now.duration_since(last_seen) < Duration::from_secs(PROCESS_CACHE_TTL_SECONDS)
        });
        let cleaned = entries_before - state_cache.len();
        if cleaned > 0 {
            debug!("Process TTL cleanup: removed {} entries, {} remaining", cleaned, state_cache.len());
        }
        
        // Hard limit enforcement - should never be reached with proper cleanup
        if state_cache.len() > MAX_PROCESS_CACHE_ENTRIES {
            state_cache.clear();
            debug!("EMERGENCY: Process cache hit hard limit, cleared all entries");
        }
        let mut current_pids = std::collections::HashSet::new();
        
        // Check for new and updated processes
        for (pid, process) in system.processes() {
            let pid_val = pid.as_u32();
            current_pids.insert(pid_val);
            
            let process_info = ProcessInfo {
                pid: pid_val,
                name: process.name().to_string(),
                path: process.exe().map(|p| p.display().to_string()).unwrap_or_default(),
                start_time: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(process.start_time()),
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
            };
            
            if !previous_processes.contains_key(&pid_val) {
                // New process detected - ALWAYS report (security critical)
                debug!("New process detected: {} (PID: {})", process_info.name, pid_val);
                
                let event = self.create_process_event(
                    EventType::ProcessCreated,
                    &process_info,
                    process,
                );
                events.push(event);
                
                previous_processes.insert(pid_val, process_info);
            } else {
                // Update existing process info with conservative deduplication
                if let Some(previous_process) = previous_processes.get_mut(&pid_val) {
                    // Check for significant changes
                    let has_significant_change = (previous_process.cpu_usage - process_info.cpu_usage).abs() > 10.0
                        || (previous_process.memory_usage as i64 - process_info.memory_usage as i64).abs() > 10_000_000; // 10MB change
                    
                    if has_significant_change {
                        // Create process signature for deduplication
                        let signature = (
                            pid_val,
                            process_info.memory_usage / 1_000_000, // Round to nearest MB
                            format!("{:.1}", process_info.cpu_usage), // Round CPU to 1 decimal
                        );
                        
                        // Conservative deduplication: only skip if we've reported this exact state very recently
                        let should_report = match state_cache.get(&signature) {
                            Some(&last_seen) => {
                                // Only report if it's been more than 2 minutes (very conservative for security)
                                now.duration_since(last_seen) > Duration::from_secs(120)
                            }
                            None => true, // Always report new states
                        };
                        
                        if should_report {
                            state_cache.insert(signature, now);
                            let event = self.create_process_event(
                                EventType::ProcessModified,
                                &process_info,
                                process,
                            );
                            events.push(event);
                        }
                    }
                    *previous_process = process_info;
                }
            }
        }
        
        // Check for terminated processes - ALWAYS report (security critical)
        let terminated_pids: Vec<u32> = previous_processes
            .keys()
            .filter(|pid| !current_pids.contains(pid))
            .cloned()
            .collect();
        
        for pid in terminated_pids {
            if let Some(process_info) = previous_processes.remove(&pid) {
                debug!("Process terminated: {} (PID: {})", process_info.name, pid);
                
                let event = self.create_termination_event(&process_info);
                events.push(event);
            }
        }
        
        // Update events collected counter
        *self.events_collected.write().await += events.len() as u64;
        
        Ok(events)
    }
    
    fn create_process_event(
        &self,
        event_type: EventType,
        process_info: &ProcessInfo,
        process: &sysinfo::Process,
    ) -> Event {
        let mut command_line = None;
        let mut environment = None;
        
        if self.config.collect_command_line {
            command_line = Some(process.cmd().join(" "));
        }
        
        if self.config.collect_environment {
            environment = Some(
                process
                    .environ()
                    .iter()
                    .map(|env| {
                        let parts: Vec<&str> = env.splitn(2, '=').collect();
                        if parts.len() == 2 {
                            (parts[0].to_string(), parts[1].to_string())
                        } else {
                            (env.clone(), String::new())
                        }
                    })
                    .collect(),
            );
        }
        
        let data = EventData::Process(ProcessEventData {
            pid: process_info.pid,
            ppid: process.parent().map(|p| p.as_u32()),
            name: process_info.name.clone(),
            path: process_info.path.clone(),
            command_line,
            user: process.user_id().map(|u| u.to_string()),
            session_id: None, // Not available in sysinfo
            start_time: Some(chrono::DateTime::from(process_info.start_time)),
            end_time: None,
            exit_code: None,
            cpu_usage: Some(process_info.cpu_usage),
            memory_usage: Some(process_info.memory_usage),
            environment,
            hashes: None, // TODO: Calculate file hashes if needed
        });
        
        Event::new(
            event_type,
            "process_monitor".to_string(),
            self.hostname.clone(),
            self.agent_id.clone(),
            data,
        )
    }
    
    fn create_termination_event(&self, process_info: &ProcessInfo) -> Event {
        let data = EventData::Process(ProcessEventData {
            pid: process_info.pid,
            ppid: None,
            name: process_info.name.clone(),
            path: process_info.path.clone(),
            command_line: None,
            user: None,
            session_id: None,
            start_time: None,
            end_time: Some(chrono::Utc::now()),
            exit_code: None, // Not available
            cpu_usage: Some(process_info.cpu_usage),
            memory_usage: Some(process_info.memory_usage),
            environment: None,
            hashes: None,
        });
        
        Event::new(
            EventType::ProcessTerminated,
            "process_monitor".to_string(),
            self.hostname.clone(),
            self.agent_id.clone(),
            data,
        )
    }
}

#[async_trait::async_trait]
impl Collector for ProcessCollector {
    async fn start(&self) -> Result<()> {
        info!("Starting process collector");
        *self.is_running.write().await = true;
        
        // Spawn the periodic collection task
        let self_clone = self.clone();
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_periodic().await {
                error!("Process collector periodic error: {}", e);
            }
        });
        
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        info!("Stopping process collector");
        *self.is_running.write().await = false;
        Ok(())
    }
    
    async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    async fn get_status(&self) -> CollectorStatus {
        CollectorStatus {
            name: "process_monitor".to_string(),
            enabled: self.config.enabled,
            is_running: self.is_running().await,
            events_collected: *self.events_collected.read().await,
            last_error: self.last_error.read().await.clone(),
        }
    }
    
    fn name(&self) -> &'static str {
        "process_monitor"
    }
}

impl Clone for ProcessCollector {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            event_sender: self.event_sender.clone(),
            is_running: self.is_running.clone(),
            system: self.system.clone(),
            previous_processes: self.previous_processes.clone(),
            process_state_cache: self.process_state_cache.clone(),
            hostname: self.hostname.clone(),
            agent_id: self.agent_id.clone(),
            events_collected: self.events_collected.clone(),
            last_error: self.last_error.clone(),
        }
    }
}

#[async_trait::async_trait]
impl PeriodicCollector for ProcessCollector {
    async fn collect(&self) -> Result<Vec<Event>> {
        self.scan_processes().await
    }
    
    fn collection_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.config.scan_interval_ms)
    }
    
    fn get_event_sender(&self) -> &mpsc::Sender<Event> {
        &self.event_sender
    }
}
