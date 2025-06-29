use anyhow::Result;
use tracing::{debug, error, warn, info};
use tokio::sync::{mpsc, RwLock};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{System, Process, Pid};

use crate::config::ProcessMonitorConfig;
use crate::events::{Event, EventType, EventData, ProcessEventData};
use crate::collectors::{Collector, PeriodicCollector};
use crate::agent::CollectorStatus;

#[derive(Debug)]
pub struct ProcessCollector {
    config: ProcessMonitorConfig,
    event_sender: mpsc::Sender<Event>,
    is_running: Arc<RwLock<bool>>,
    system: Arc<RwLock<System>>,
    known_processes: Arc<RwLock<HashMap<u32, ProcessInfo>>>,
    hostname: String,
    agent_id: String,
    events_collected: Arc<RwLock<u64>>,
    last_error: Arc<RwLock<Option<String>>>,
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
            known_processes: Arc::new(RwLock::new(HashMap::new())),
            hostname,
            agent_id,
            events_collected: Arc::new(RwLock::new(0)),
            last_error: Arc::new(RwLock::new(None)),
        })
    }
    
    async fn scan_processes(&self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        let mut system = self.system.write().await;
        
        // Refresh system information
        system.refresh_processes();
        
        let mut known_processes = self.known_processes.write().await;
        let mut current_pids = std::collections::HashSet::new();
        
        // Check for new and updated processes
        for (pid, process) in system.processes() {
            let pid_val = pid.as_u32();
            current_pids.insert(pid_val);
            
            let process_info = ProcessInfo {
                pid: pid_val,
                name: process.name().to_string(),
                path: process.exe().map(|p| p.display().to_string()).unwrap_or_default(),
                start_time: std::time::SystemTime::now(), // sysinfo doesn't provide start time directly
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
            };
            
            if !known_processes.contains_key(&pid_val) {
                // New process detected
                debug!("New process detected: {} (PID: {})", process_info.name, pid_val);
                
                let event = self.create_process_event(
                    EventType::ProcessCreated,
                    &process_info,
                    process,
                );
                events.push(event);
                
                known_processes.insert(pid_val, process_info);
            } else {
                // Update existing process info
                if let Some(known_process) = known_processes.get_mut(&pid_val) {
                    // Check for significant changes
                    if (known_process.cpu_usage - process_info.cpu_usage).abs() > 10.0
                        || known_process.memory_usage != process_info.memory_usage
                    {
                        let event = self.create_process_event(
                            EventType::ProcessModified,
                            &process_info,
                            process,
                        );
                        events.push(event);
                    }
                    *known_process = process_info;
                }
            }
        }
        
        // Check for terminated processes
        let terminated_pids: Vec<u32> = known_processes
            .keys()
            .filter(|pid| !current_pids.contains(pid))
            .cloned()
            .collect();
        
        for pid in terminated_pids {
            if let Some(process_info) = known_processes.remove(&pid) {
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
            start_time: Some(chrono::Utc::now()), // Approximate
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
            known_processes: self.known_processes.clone(),
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
