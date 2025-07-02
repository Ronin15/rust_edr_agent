use anyhow::Result;
use tracing::{info, warn, error, debug};
use tokio::sync::mpsc;

use crate::config::CollectorsConfig;
use crate::events::Event;
use crate::agent::CollectorStatus;

// Import from the collectors submodules
use super::process::ProcessCollector;
use super::file::FileCollector;
use super::network::NetworkCollector;

#[cfg(windows)]
use super::registry::RegistryCollector;

// Enum to hold different collector types instead of trait objects
#[derive(Debug)]
pub enum CollectorInstance {
    Process(ProcessCollector),
    File(FileCollector),
    Network(NetworkCollector),
    
    #[cfg(windows)]
    Registry(RegistryCollector),
}

impl CollectorInstance {
    pub async fn start(&self) -> Result<()> {
        match self {
            CollectorInstance::Process(c) => c.start().await,
            CollectorInstance::File(c) => c.start().await,
            CollectorInstance::Network(c) => c.start().await,
            
            #[cfg(windows)]
            CollectorInstance::Registry(c) => c.start().await,
        }
    }
    
    pub async fn stop(&self) -> Result<()> {
        match self {
            CollectorInstance::Process(c) => c.stop().await,
            CollectorInstance::File(c) => c.stop().await,
            CollectorInstance::Network(c) => c.stop().await,
            
            #[cfg(windows)]
            CollectorInstance::Registry(c) => c.stop().await,
        }
    }
    
    pub async fn is_running(&self) -> bool {
        match self {
            CollectorInstance::Process(c) => c.is_running().await,
            CollectorInstance::File(c) => c.is_running().await,
            CollectorInstance::Network(c) => c.is_running().await,
            
            #[cfg(windows)]
            CollectorInstance::Registry(c) => c.is_running().await,
        }
    }
    
    pub async fn get_status(&self) -> CollectorStatus {
        match self {
            CollectorInstance::Process(c) => c.get_status().await,
            CollectorInstance::File(c) => c.get_status().await,
            CollectorInstance::Network(c) => c.get_status().await,
            
            #[cfg(windows)]
            CollectorInstance::Registry(c) => c.get_status().await,
        }
    }
    
    pub fn name(&self) -> &'static str {
        match self {
            CollectorInstance::Process(c) => c.name(),
            CollectorInstance::File(c) => c.name(),
            CollectorInstance::Network(c) => c.name(),
            
            #[cfg(windows)]
            CollectorInstance::Registry(c) => c.name(),
        }
    }
}

#[async_trait::async_trait]
pub trait Collector: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn is_running(&self) -> bool;
    async fn get_status(&self) -> CollectorStatus;
    fn name(&self) -> &'static str;
}

pub struct CollectorManager {
    config: CollectorsConfig,
    event_sender: mpsc::Sender<Event>,
    collectors: Vec<CollectorInstance>,
}

impl CollectorManager {
    pub async fn new(
        config: CollectorsConfig,
        event_sender: mpsc::Sender<Event>,
    ) -> Result<Self> {
        let mut collectors: Vec<CollectorInstance> = Vec::new();
        
        // Initialize process collector
        if config.process_monitor.enabled {
            info!("Initializing process collector");
            let collector = ProcessCollector::new(
                config.process_monitor.clone(),
                event_sender.clone(),
            ).await?;
            collectors.push(CollectorInstance::Process(collector));
        }
        
        // Initialize file collector
        if config.file_monitor.enabled {
            info!("Initializing file collector");
            let collector = FileCollector::new(
                config.file_monitor.clone(),
                event_sender.clone(),
            ).await?;
            collectors.push(CollectorInstance::File(collector));
        }
        
        // Initialize network collector
        if config.network_monitor.enabled {
            info!("Initializing network collector");
            let collector = NetworkCollector::new(
                config.network_monitor.clone(),
                event_sender.clone(),
            ).await?;
            collectors.push(CollectorInstance::Network(collector));
        }
        
        // Initialize registry collector (Windows only)
        #[cfg(windows)]
        if config.registry_monitor.enabled {
            info!("Initializing registry collector");
            let collector = RegistryCollector::new(
                config.registry_monitor.clone(),
                event_sender.clone(),
            ).await?;
            collectors.push(CollectorInstance::Registry(collector));
        }
        
        Ok(Self {
            config,
            event_sender,
            collectors,
        })
    }
    
    pub async fn start(&self) -> Result<()> {
        info!("Starting {} collectors", self.collectors.len());
        
        for collector in &self.collectors {
            match collector.start().await {
                Ok(()) => {
                    info!("Started collector: {}", collector.name());
                }
                Err(e) => {
                    error!("Failed to start collector {}: {}", collector.name(), e);
                    // Continue with other collectors
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping {} collectors", self.collectors.len());
        
        for collector in &self.collectors {
            match collector.stop().await {
                Ok(()) => {
                    info!("Stopped collector: {}", collector.name());
                }
                Err(e) => {
                    warn!("Error stopping collector {}: {}", collector.name(), e);
                    // Continue with other collectors
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn get_status(&self) -> Vec<CollectorStatus> {
        let mut statuses = Vec::new();
        
        for collector in &self.collectors {
            statuses.push(collector.get_status().await);
        }
        
        statuses
    }
    
    pub async fn update_config(&self, _new_config: CollectorsConfig) -> Result<()> {
        info!("Updating collector configuration");
        
        // For now, we'll just log the update
        // In a real implementation, you'd need to handle dynamic reconfiguration
        // This might involve stopping and restarting collectors with new settings
        
        warn!("Dynamic configuration update not yet implemented");
        Ok(())
    }
    
    pub async fn restart_collector(&self, collector_name: &str) -> Result<()> {
        info!("Restarting collector: {}", collector_name);
        
        for collector in &self.collectors {
            if collector.name() == collector_name {
                collector.stop().await?;
                collector.start().await?;
                info!("Restarted collector: {}", collector_name);
                return Ok(());
            }
        }
        
        anyhow::bail!("Collector not found: {}", collector_name);
    }
    
    pub async fn get_collector_names(&self) -> Vec<String> {
        self.collectors
            .iter()
            .map(|c| c.name().to_string())
            .collect()
    }
    
    pub fn get_event_sender(&self) -> mpsc::Sender<Event> {
        self.event_sender.clone()
    }
    
    pub fn get_config(&self) -> &CollectorsConfig {
        &self.config
    }
}

// Helper trait for collectors that need periodic execution
#[async_trait::async_trait]
pub trait PeriodicCollector: Collector {
    async fn collect(&self) -> Result<Vec<Event>>;
    fn collection_interval(&self) -> std::time::Duration;
    
    async fn run_periodic(&self) -> Result<()> {
        let mut interval = tokio::time::interval(self.collection_interval());
        
        while self.is_running().await {
            interval.tick().await;
            
            if !self.is_running().await {
                break; // Exit if stopped during interval
            }
            
            match self.collect().await {
                Ok(events) => {
                    for event in events {
                        // Check if still running before sending each event
                        if !self.is_running().await {
                            debug!("Collector {} stopping, discarding remaining events", self.name());
                            break;
                        }
                        
                        if let Err(e) = self.get_event_sender().send(event).await {
                            if self.is_running().await {
                                error!("Failed to send event from {}: {}", self.name(), e);
                            } else {
                                debug!("Collector {} stopped, channel closed during event sending", self.name());
                            }
                            break; // Stop sending if channel is closed
                        }
                    }
                }
                Err(e) => {
                    if self.is_running().await {
                        error!("Collection error in {}: {}", self.name(), e);
                    }
                }
            }
        }
        
        debug!("Periodic collector {} stopped gracefully", self.name());
        Ok(())
    }
    
    fn get_event_sender(&self) -> &mpsc::Sender<Event>;
}

// Helper trait for collectors that watch for real-time events
#[async_trait::async_trait]
pub trait EventCollector: Collector {
    async fn watch(&self) -> Result<()>;
    
    async fn run_watcher(&self) -> Result<()> {
        while self.is_running().await {
            if let Err(e) = self.watch().await {
                error!("Watcher error in {}: {}", self.name(), e);
                // Wait a bit before retrying
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use tokio::sync::mpsc;
    
    #[tokio::test]
    async fn test_collector_manager_creation() {
        let config = CollectorsConfig {
            process_monitor: ProcessMonitorConfig {
                enabled: false,
                scan_interval_ms: 1000,
                track_child_processes: true,
                collect_command_line: true,
                collect_environment: false,
            },
            file_monitor: FileMonitorConfig {
                enabled: false,
                watched_paths: vec![],
                ignored_extensions: vec![],
                max_file_size_mb: 100,
                calculate_hashes: false,
            },
            network_monitor: NetworkMonitorConfig {
                enabled: false,
                monitor_connections: true,
                monitor_dns: true,
                capture_packets: false,
                max_packet_size: 1500,
            },
            registry_monitor: RegistryMonitorConfig {
                enabled: false,
                watched_keys: vec![],
            },
        };
        
        let (event_sender, _event_receiver) = mpsc::channel(100);
        
        let manager = CollectorManager::new(config, event_sender).await;
        assert!(manager.is_ok());
        
        let manager = manager.unwrap();
        assert_eq!(manager.collectors.len(), 0); // All collectors disabled
    }
}