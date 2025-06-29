use anyhow::Result;
use tracing::{info, warn, error};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;

use crate::config::NetworkMonitorConfig;
use crate::events::{Event, EventType, EventData, NetworkEventData, NetworkDirection};
use crate::collectors::{Collector, PeriodicCollector};
use crate::agent::CollectorStatus;

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
    
    fn create_network_event(&self, protocol: String, dest_ip: String, dest_port: u16) -> Event {
        let data = EventData::Network(NetworkEventData {
            protocol,
            source_ip: None,
            source_port: None,
            destination_ip: Some(dest_ip),
            destination_port: Some(dest_port),
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
            self.hostname.clone(),
            self.agent_id.clone(),
            data,
        )
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
        
        // TODO: Implement actual network monitoring
        // For now, just create a placeholder event
        warn!("Network monitoring not yet fully implemented");
        
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
