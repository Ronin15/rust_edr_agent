use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::events::{Event, EventBatch};
use crate::collectors::CollectorManager;
use crate::storage::StorageManager;
use crate::network::NetworkManager;
use crate::detectors::{DetectorManager, DetectorAlert};

pub struct Agent {
    config: Config,
    collector_manager: Arc<CollectorManager>,
    detector_manager: Arc<DetectorManager>,
    storage_manager: Arc<StorageManager>,
    network_manager: Option<Arc<NetworkManager>>,
    event_receiver: Arc<RwLock<Option<mpsc::Receiver<Event>>>>,
    alert_receiver: Arc<RwLock<Option<mpsc::Receiver<DetectorAlert>>>>,
    shutdown_sender: Arc<RwLock<Option<mpsc::Sender<()>>>>,
    is_running: Arc<RwLock<bool>>,
}

impl Agent {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing EDR Agent");
        
        // Create communication channels
        let (event_sender, event_receiver) = mpsc::channel::<Event>(10000);
        let (alert_sender, alert_receiver) = mpsc::channel::<DetectorAlert>(1000);
        let (shutdown_sender, _shutdown_receiver) = mpsc::channel::<()>(1);
        
        // Initialize storage manager
        let storage_manager = Arc::new(
            StorageManager::new(config.storage.clone())
                .await
                .context("Failed to initialize storage manager")?
        );
        
        // Initialize network manager if enabled
        let network_manager = if config.network.enabled {
            Some(Arc::new(
                NetworkManager::new(config.network.clone())
                    .await
                    .context("Failed to initialize network manager")?
            ))
        } else {
            None
        };
        
        // Initialize collector manager
        let collector_manager = Arc::new(
            CollectorManager::new(config.collectors.clone(), event_sender.clone())
                .await
                .context("Failed to initialize collector manager")?
        );
        
        // Initialize detector manager
        let agent_id = config.agent.agent_id.clone().unwrap_or_else(|| "unknown".to_string());
        let hostname = config.agent.hostname.clone().unwrap_or_else(|| "localhost".to_string());
        let detector_manager = Arc::new(
            DetectorManager::new(
                config.detectors.clone(),
                alert_sender,
                agent_id,
                hostname,
            )
            .await
            .context("Failed to initialize detector manager")?
        );
        
        Ok(Self {
            config,
            collector_manager,
            detector_manager,
            storage_manager,
            network_manager,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            alert_receiver: Arc::new(RwLock::new(Some(alert_receiver))),
            shutdown_sender: Arc::new(RwLock::new(Some(shutdown_sender))),
            is_running: Arc::new(RwLock::new(false)),
        })
    }
    
    pub async fn run(&self) -> Result<()> {
        info!("Starting EDR Agent");
        
        // Mark as running
        *self.is_running.write().await = true;
        
        // Start collectors
        self.collector_manager.start().await?;
        info!("Collectors started");
        
        // Start detectors
        self.detector_manager.start().await?;
        info!("Detectors started");
        
        // Start event processing loop
        let event_receiver = {
            let mut receiver_guard = self.event_receiver.write().await;
            receiver_guard.take()
                .context("Event receiver already taken")?
        };
        
        let alert_receiver = {
            let mut receiver_guard = self.alert_receiver.write().await;
            receiver_guard.take()
                .context("Alert receiver already taken")?
        };
        
        info!("Starting alert processing");
        
        // Run both event processing and alert handling concurrently
        let (event_result, alert_result) = tokio::join!(
            self.process_events(event_receiver),
            self.process_alerts(alert_receiver)
        );
        
        event_result?;
        alert_result?;
        
        Ok(())
    }
    
    async fn process_events(&self, mut event_receiver: mpsc::Receiver<Event>) -> Result<()> {
        let mut event_batch = EventBatch::new();
        let mut last_batch_time = std::time::Instant::now();
        
        let batch_interval = Duration::from_millis(self.config.agent.collection_interval_ms);
        let max_batch_size = self.config.agent.max_events_per_batch;
        
        while *self.is_running.read().await {
            tokio::select! {
                // Receive new events
                event_opt = event_receiver.recv() => {
                    match event_opt {
                        Some(event) => {
                            debug!("Received event: {:?}", event.event_type);
                            event_batch.add_event(event);
                            
                            // Process batch if it's full
                            if event_batch.len() >= max_batch_size {
                                self.process_batch(&mut event_batch).await?;
                                last_batch_time = std::time::Instant::now();
                            }
                        }
                        None => {
                            warn!("Event receiver channel closed");
                            break;
                        }
                    }
                }
                
                // Process batch on timeout
                _ = tokio::time::sleep_until(
                    tokio::time::Instant::from(last_batch_time + batch_interval)
                ) => {
                    if !event_batch.is_empty() {
                        self.process_batch(&mut event_batch).await?;
                        last_batch_time = std::time::Instant::now();
                    }
                }
            }
        }
        
        // Process any remaining events
        if !event_batch.is_empty() {
            self.process_batch(&mut event_batch).await?;
        }
        
        info!("Event processing stopped");
        Ok(())
    }
    
    async fn process_batch(&self, batch: &mut EventBatch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        
        debug!("Processing batch with {} events", batch.len());
        
        // Forward events to detectors for analysis
        for event in batch.get_events() {
            if let Err(e) = self.detector_manager.process_event(event).await {
                warn!("Failed to process event in detectors: {}", e);
            }
        }
        
        // Store events locally
        if let Err(e) = self.storage_manager.store_batch(batch).await {
            error!("Failed to store batch locally: {}", e);
        }
        
        // Send to remote server if network is enabled
        if let Some(ref network_manager) = self.network_manager {
            if let Err(e) = network_manager.send_batch(batch).await {
                warn!("Failed to send batch to remote server: {}", e);
                // Don't fail here - local storage is our backup
            }
        }
        
        // Clear the batch
        batch.clear();
        
        Ok(())
    }
    
    async fn process_alerts(&self, mut alert_receiver: mpsc::Receiver<DetectorAlert>) -> Result<()> {
        info!("Starting alert processing");
        
        while *self.is_running.read().await {
            tokio::select! {
                alert_opt = alert_receiver.recv() => {
                    match alert_opt {
                        Some(alert) => {
                            self.handle_alert(alert).await;
                        }
                        None => {
                            warn!("Alert receiver channel closed");
                            break;
                        }
                    }
                }
            }
        }
        
        info!("Alert processing stopped");
        Ok(())
    }
    
    async fn handle_alert(&self, alert: DetectorAlert) {
        // Log the alert with appropriate severity
        match alert.severity.as_str() {
            "critical" => {
                error!(
                    "🚨 CRITICAL SECURITY ALERT: {} (Risk: {:.1}) - {}",
                    alert.title, alert.risk_score, alert.description
                );
                error!("Recommended Actions: {:?}", alert.recommended_actions);
            }
            "high" => {
                warn!(
                    "⚠️  HIGH SECURITY ALERT: {} (Risk: {:.1}) - {}",
                    alert.title, alert.risk_score, alert.description
                );
                warn!("Recommended Actions: {:?}", alert.recommended_actions);
            }
            "medium" => {
                warn!(
                    "🔶 MEDIUM SECURITY ALERT: {} (Risk: {:.1}) - {}",
                    alert.title, alert.risk_score, alert.description
                );
                info!("Recommended Actions: {:?}", alert.recommended_actions);
            }
            _ => {
                info!(
                    "ℹ️  Security Alert: {} (Risk: {:.1}) - {}",
                    alert.title, alert.risk_score, alert.description
                );
                debug!("Recommended Actions: {:?}", alert.recommended_actions);
            }
        }
        
        // Store the alert
        if let Err(e) = self.store_alert(&alert).await {
            error!("Failed to store security alert: {}", e);
        }
        
        // Send alert to remote server if network is enabled
        if let Some(ref network_manager) = self.network_manager {
            if let Err(e) = self.send_alert_to_server(&alert, network_manager).await {
                warn!("Failed to send alert to remote server: {}", e);
            }
        }
        
        // Execute automated response if configured and severity is high enough
        if alert.risk_score >= 0.8 {
            self.execute_automated_response(&alert).await;
        }
    }
    
    async fn store_alert(&self, alert: &DetectorAlert) -> Result<()> {
        // Get hostname and agent_id from self.config since they are not in DetectorAlert
        let hostname = self.config.agent.hostname.clone().unwrap_or_else(|| "localhost".to_string());
        let agent_id = self.config.agent.agent_id.clone().unwrap_or_else(|| "unknown".to_string());
        
        // Convert alert to event for storage
        let alert_event = Event::new(
            crate::events::EventType::SecurityAlert,
            format!("detector_{}", alert.detector_name),
            hostname,
            agent_id,
            crate::events::EventData::System(
                crate::events::SystemEventData {
                    event_id: None,
                    description: format!("{}: {}", alert.title, alert.description),
                    boot_id: None,
                    uptime: None,
                    system_info: None,
                }
            ),
        )
        .with_metadata("alert_id".to_string(), alert.id.clone())
        .with_metadata("severity".to_string(), alert.severity.as_str().to_string())
        .with_metadata("risk_score".to_string(), alert.risk_score.to_string())
        .with_metadata("detector".to_string(), alert.detector_name.clone())
        .with_metadata("recommended_actions".to_string(), format!("{:?}", alert.recommended_actions));
        
        let mut batch = crate::events::EventBatch::new();
        batch.add_event(alert_event);
        
        self.storage_manager.store_batch(&batch).await
    }
    
    async fn send_alert_to_server(&self, alert: &DetectorAlert, network_manager: &NetworkManager) -> Result<()> {
        // This would be implemented to send alerts to a SIEM or security management platform
        // For now, we'll just log that we would send it
        debug!("Would send alert {} to remote server", alert.id);
        Ok(())
    }
    
    async fn execute_automated_response(&self, alert: &DetectorAlert) {
        info!("Executing automated response for critical alert: {}", alert.title);
        
        // Example automated responses based on alert type
        if alert.title.contains("Process Injection") {
            // Could kill suspicious processes, isolate system, etc.
            warn!("Automated response: Would terminate suspicious process and isolate system");
        }
        
        // More response logic would go here
        debug!("Automated response completed for alert: {}", alert.id);
    }
    
    pub async fn shutdown(&self) {
        info!("Shutting down EDR Agent");
        
        // Mark as not running
        *self.is_running.write().await = false;
        
        // Stop collectors
        if let Err(e) = self.collector_manager.stop().await {
            error!("Error stopping collectors: {}", e);
        }
        
        // Stop detectors
        if let Err(e) = self.detector_manager.stop().await {
            error!("Error stopping detectors: {}", e);
        }
        
        // Send shutdown signal
        if let Some(sender) = self.shutdown_sender.write().await.take() {
            let _ = sender.send(()).await;
        }
        
        info!("EDR Agent shutdown complete");
    }
    
    pub async fn get_status(&self) -> AgentStatus {
        AgentStatus {
            is_running: *self.is_running.read().await,
            agent_id: self.config.agent.agent_id.clone().unwrap_or_default(),
            hostname: self.config.agent.hostname.clone().unwrap_or_default(),
            uptime: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default(),
            memory_usage: self.get_memory_usage().await,
            collectors_status: self.collector_manager.get_status().await,
        }
    }
    
    async fn get_memory_usage(&self) -> u64 {
        // Simple memory usage estimation
        // In a real implementation, you'd use proper system APIs
        0
    }
    
    pub async fn reload_config(&self, new_config: Config) -> Result<()> {
        info!("Reloading configuration");
        
        // Stop current collectors
        self.collector_manager.stop().await?;
        
        // Update collector configuration
        self.collector_manager.update_config(new_config.collectors.clone()).await?;
        
        // Restart collectors
        self.collector_manager.start().await?;
        
        info!("Configuration reloaded successfully");
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AgentStatus {
    pub is_running: bool,
    pub agent_id: String,
    pub hostname: String,
    pub uptime: Duration,
    pub memory_usage: u64,
    pub collectors_status: Vec<CollectorStatus>,
}

#[derive(Debug, Clone)]
pub struct CollectorStatus {
    pub name: String,
    pub enabled: bool,
    pub is_running: bool,
    pub events_collected: u64,
    pub last_error: Option<String>,
}

// Implement Display for better logging
impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Agent Status - Running: {}, ID: {}, Hostname: {}, Uptime: {:?}",
            self.is_running, self.agent_id, self.hostname, self.uptime
        )
    }
}