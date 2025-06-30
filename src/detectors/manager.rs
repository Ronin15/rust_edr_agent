use anyhow::{Result, Context};
use tracing::{info, warn, error};
use tokio::sync::mpsc;
use std::sync::Arc;

use crate::config::DetectorsConfig;
use crate::events::Event;
#[derive(Debug, Clone)]
pub struct DetectorStatus {
    pub name: String,
    pub is_running: bool,
    pub events_processed: u64,
    pub alerts_generated: u64,
    pub processes_tracked: u64,
    pub last_activity: std::time::Instant,
    pub memory_usage_kb: u64,
    pub cpu_usage_percent: f32,
}

use super::injection::InjectionDetector;
use super::registry::RegistryDetector;

// Enum to hold different detector types
#[derive(Debug)]
pub enum DetectorInstance {
    Injection(InjectionDetector),
    Registry(RegistryDetector),
    // Future detectors:
    // Malware(MalwareDetector),
    // Anomaly(AnomalyDetector),
}

impl DetectorInstance {
    pub async fn start(&self) -> Result<()> {
        match self {
            DetectorInstance::Injection(d) => d.start().await,
            DetectorInstance::Registry(d) => d.start().await,
        }
    }
    
    pub async fn stop(&self) -> Result<()> {
        match self {
            DetectorInstance::Injection(d) => d.stop().await,
            DetectorInstance::Registry(d) => d.stop().await,
        }
    }
    
    pub async fn is_running(&self) -> bool {
        match self {
            DetectorInstance::Injection(d) => d.is_running().await,
            DetectorInstance::Registry(d) => d.is_running().await,
        }
    }
    
    pub async fn get_status(&self) -> DetectorStatus {
        match self {
            DetectorInstance::Injection(d) => d.get_status().await,
            DetectorInstance::Registry(d) => d.get_status().await,
        }
    }
    
    pub fn name(&self) -> &'static str {
        match self {
            DetectorInstance::Injection(d) => d.name(),
            DetectorInstance::Registry(d) => d.name(),
        }
    }
    
    pub async fn process_event(&self, event: &Event) -> Result<()> {
        match self {
            DetectorInstance::Injection(d) => d.process_event(event).await,
            DetectorInstance::Registry(d) => d.process_event(event).await,
        }
    }
}

#[async_trait::async_trait]
pub trait Detector: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn is_running(&self) -> bool;
    async fn get_status(&self) -> DetectorStatus;
    async fn process_event(&self, event: &Event) -> Result<()>;
    fn name(&self) -> &'static str;
}

pub struct DetectorManager {
    config: DetectorsConfig,
    alert_sender: mpsc::Sender<DetectorAlert>,
    detectors: Vec<DetectorInstance>,
}

// Alert structure for detector findings
#[derive(Debug, Clone)]
pub struct DetectorAlert {
    pub id: String,
    pub detector_name: String,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub affected_processes: Vec<u32>,
    pub indicators: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub risk_score: f32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Low => "low",
            AlertSeverity::Medium => "medium",
            AlertSeverity::High => "high",
            AlertSeverity::Critical => "critical",
        }
    }
}

impl DetectorManager {
    pub async fn new(
        config: DetectorsConfig,
        alert_sender: mpsc::Sender<DetectorAlert>,
        agent_id: String,
        hostname: String,
    ) -> Result<Self> {
        let mut detectors: Vec<DetectorInstance> = Vec::new();
        
        // Initialize injection detector
        if config.injection.enabled {
            info!("Initializing injection detector");
            let detector = InjectionDetector::new(
                config.injection.clone(),
                alert_sender.clone(),
                agent_id.clone(),
                hostname.clone(),
            ).await?;
            detectors.push(DetectorInstance::Injection(detector));
        }
        
        // Initialize registry detector
        if config.registry_monitor.enabled {
            info!("Initializing registry detector");
            let detector = RegistryDetector::new(
                config.registry_monitor.clone(),
                alert_sender.clone(),
                agent_id.clone(),
                hostname.clone(),
            ).await?;
            detectors.push(DetectorInstance::Registry(detector));
        }
        
        // Future detectors can be initialized here
        
        Ok(Self {
            config,
            alert_sender,
            detectors,
        })
    }
    
    pub async fn start(&self) -> Result<()> {
        info!("Starting {} detectors", self.detectors.len());
        
        for detector in &self.detectors {
            match detector.start().await {
                Ok(()) => {
                    info!("Started detector: {}", detector.name());
                }
                Err(e) => {
                    error!("Failed to start detector {}: {}", detector.name(), e);
                    // Continue with other detectors
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping {} detectors", self.detectors.len());
        
        for detector in &self.detectors {
            match detector.stop().await {
                Ok(()) => {
                    info!("Stopped detector: {}", detector.name());
                }
                Err(e) => {
                    warn!("Error stopping detector {}: {}", detector.name(), e);
                    // Continue with other detectors
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn process_event(&self, event: &Event) -> Result<()> {
        // Send event to all active detectors
        for detector in &self.detectors {
            if detector.is_running().await {
                if let Err(e) = detector.process_event(event).await {
                    error!("Error processing event in detector {}: {}", detector.name(), e);
                    // Continue with other detectors
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn get_status(&self) -> Vec<DetectorStatus> {
        let mut statuses = Vec::new();
        
        for detector in &self.detectors {
            statuses.push(detector.get_status().await);
        }
        
        statuses
    }
    
    pub async fn restart_detector(&self, detector_name: &str) -> Result<()> {
        info!("Restarting detector: {}", detector_name);
        
        for detector in &self.detectors {
            if detector.name() == detector_name {
                detector.stop().await?;
                detector.start().await?;
                info!("Restarted detector: {}", detector_name);
                return Ok(());
            }
        }
        
        anyhow::bail!("Detector not found: {}", detector_name);
    }
    
    pub async fn get_detector_names(&self) -> Vec<String> {
        self.detectors
            .iter()
            .map(|d| d.name().to_string())
            .collect()
    }
    
    pub fn get_alert_sender(&self) -> mpsc::Sender<DetectorAlert> {
        self.alert_sender.clone()
    }
}

// Helper trait for detectors that need periodic execution
#[async_trait::async_trait]
pub trait PeriodicDetector: Detector {
    async fn analyze(&self) -> Result<Vec<DetectorAlert>>;
    fn analysis_interval(&self) -> std::time::Duration;
    
    async fn run_periodic(&self) -> Result<()> {
        let mut interval = tokio::time::interval(self.analysis_interval());
        
        while self.is_running().await {
            interval.tick().await;
            
            match self.analyze().await {
                Ok(alerts) => {
                    for alert in alerts {
                        if let Err(e) = self.get_alert_sender().send(alert).await {
                            error!("Failed to send alert from {}: {}", self.name(), e);
                        }
                    }
                }
                Err(e) => {
                    error!("Analysis error in {}: {}", self.name(), e);
                }
            }
        }
        
        Ok(())
    }
    
    fn get_alert_sender(&self) -> &mpsc::Sender<DetectorAlert>;
}

// Helper trait for detectors that process events in real-time
#[async_trait::async_trait]
pub trait EventDetector: Detector {
    async fn analyze_event(&self, event: &Event) -> Result<Option<DetectorAlert>>;
    
    async fn process_event_stream(&self, event: &Event) -> Result<()> {
        if let Some(alert) = self.analyze_event(event).await? {
            if let Err(e) = self.get_alert_sender().send(alert).await {
                error!("Failed to send alert from {}: {}", self.name(), e);
            }
        }
        
        Ok(())
    }
    
    fn get_alert_sender(&self) -> &mpsc::Sender<DetectorAlert>;
}

impl DetectorAlert {
    pub fn new(
        detector_name: String,
        severity: AlertSeverity,
        title: String,
        description: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            detector_name,
            severity,
            title,
            description,
            affected_processes: Vec::new(),
            indicators: Vec::new(),
            recommended_actions: Vec::new(),
            risk_score: 0.0,
            timestamp: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
        }
    }
    
    pub fn with_process(mut self, pid: u32) -> Self {
        self.affected_processes.push(pid);
        self
    }
    
    pub fn with_indicator(mut self, indicator: String) -> Self {
        self.indicators.push(indicator);
        self
    }
    
    pub fn with_action(mut self, action: String) -> Self {
        self.recommended_actions.push(action);
        self
    }
    
    pub fn with_risk_score(mut self, score: f32) -> Self {
        self.risk_score = score;
        self
    }
    
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}
