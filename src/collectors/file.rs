use anyhow::Result;
use tracing::{info, warn, error};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use notify::{Watcher, RecursiveMode, Result as NotifyResult, Event as NotifyEvent};

use crate::config::FileMonitorConfig;
use crate::events::{Event, EventType, EventData, FileEventData};
use crate::collectors::{Collector, EventCollector};
use crate::agent::CollectorStatus;

#[derive(Debug)]
pub struct FileCollector {
    config: FileMonitorConfig,
    event_sender: mpsc::Sender<Event>,
    is_running: Arc<RwLock<bool>>,
    hostname: String,
    agent_id: String,
    events_collected: Arc<RwLock<u64>>,
    last_error: Arc<RwLock<Option<String>>>,
}

impl FileCollector {
    pub async fn new(
        config: FileMonitorConfig,
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
    
    fn create_file_event(&self, event_type: EventType, path: String) -> Event {
        let data = EventData::File(FileEventData {
            path: path.clone(),
            size: None,
            permissions: None,
            owner: None,
            group: None,
            created_time: None,
            modified_time: Some(chrono::Utc::now()),
            accessed_time: None,
            hashes: None,
            mime_type: None,
            old_path: None,
        });
        
        Event::new(
            event_type,
            "file_monitor".to_string(),
            self.hostname.clone(),
            self.agent_id.clone(),
            data,
        )
    }
}

#[async_trait::async_trait]
impl Collector for FileCollector {
    async fn start(&self) -> Result<()> {
        info!("Starting file collector");
        *self.is_running.write().await = true;
        
        // Spawn the watcher task
        let self_clone = self.clone();
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_watcher().await {
                error!("File collector watcher error: {}", e);
            }
        });
        
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        info!("Stopping file collector");
        *self.is_running.write().await = false;
        Ok(())
    }
    
    async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    async fn get_status(&self) -> CollectorStatus {
        CollectorStatus {
            name: "file_monitor".to_string(),
            enabled: self.config.enabled,
            is_running: self.is_running().await,
            events_collected: *self.events_collected.read().await,
            last_error: self.last_error.read().await.clone(),
        }
    }
    
    fn name(&self) -> &'static str {
        "file_monitor"
    }
}

impl Clone for FileCollector {
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
impl EventCollector for FileCollector {
    async fn watch(&self) -> Result<()> {
        warn!("File watching not yet fully implemented");
        
        // TODO: Implement actual file watching using notify crate
        // For now, just sleep to simulate watching
        while self.is_running().await {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
        
        Ok(())
    }
}
