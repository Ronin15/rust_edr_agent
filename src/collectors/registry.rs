use anyhow::Result;
use tracing::{info, warn, error};
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
    
    fn create_registry_event(&self, event_type: EventType, key_path: String) -> Event {
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
            // TODO: Implement Windows registry monitoring
            warn!("Windows registry monitoring not yet implemented");
            while self.is_running().await {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
            Ok(())
        }
    }
}
