use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::{error, info};
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;

use crate::events::{Event, EventData, RegistryEventData, AlertSeverity};
use crate::detectors::{Detector, DetectorAlert, DetectorStatus};
use crate::config::RegistryMonitorConfig;

#[derive(Debug)]
pub struct RegistryDetector {
    _config: RegistryMonitorConfig,
    alert_sender: mpsc::Sender<DetectorAlert>,
    registry_tracker: Arc<RwLock<RegistryTracker>>,
    detection_rules: RegistryDetectionRules,
    is_running: Arc<RwLock<bool>>,
    agent_id: String,
    hostname: String,
    stats: Arc<RwLock<RegistryDetectorStats>>,
}

#[derive(Debug, Default)]
struct RegistryDetectorStats {
    events_processed: u64,
    alerts_generated: u64,
    last_activity: Option<Instant>,
}

#[derive(Debug)]
pub struct RegistryTracker {
    key_states: HashMap<String, RegistryKeyState>,
    recent_events: VecDeque<RegistryEvent>,
    alert_frequency: HashMap<String, Vec<Instant>>,
    last_cleanup: Instant,
}

#[derive(Debug, Clone)]
pub struct RegistryKeyState {
    pub key_path: String,
    pub last_modified: Instant,
    pub modification_count: u32,
    pub suspicious_changes: u32,
    pub associated_processes: Vec<u32>,
    pub risk_score: f32,
    pub baseline_hash: Option<String>, // Hash of expected values
}

#[derive(Debug, Clone)]
pub struct RegistryEvent {
    pub timestamp: Instant,
    pub event_type: RegistryEventType,
    pub key_path: String,
    pub value_name: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub severity: AlertSeverity,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryEventType {
    PersistenceMechanism,
    SecurityBypass,
    SystemModification,
    MalwareIndicator,
    PolicyTampering,
    ServiceManipulation,
    StartupModification,
    ShellExtensionChange,
    UnauthorizedAccess,
    SuspiciousValueChange,
}


#[derive(Debug)]
pub struct RegistryDetectionRules {
    pub persistence_keys: HashMap<String, PersistenceRule>,
    pub security_keys: HashMap<String, SecurityRule>,
    pub system_keys: HashMap<String, SystemRule>,
    pub malware_indicators: Vec<MalwareIndicator>,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub baseline_values: HashMap<String, String>,
    pub alert_frequency_limits: HashMap<String, FrequencyLimit>,
}

#[derive(Debug, Clone)]
pub struct PersistenceRule {
    pub name: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub risk_score: f32,
    pub legitimate_processes: Vec<String>, // Processes that can legitimately modify this key
    pub alert_threshold: u32, // Number of changes before alerting
}

#[derive(Debug, Clone)]
pub struct SecurityRule {
    pub name: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub risk_score: f32,
    pub protected_values: Vec<String>, // Values that should never change
    pub whitelist_processes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SystemRule {
    pub name: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub risk_score: f32,
    pub change_window: Duration, // Legitimate changes should be infrequent
    pub max_changes_per_window: u32,
}

#[derive(Debug, Clone)]
pub struct MalwareIndicator {
    pub name: String,
    pub key_patterns: Vec<String>, // Regex patterns for suspicious keys
    pub value_patterns: Vec<String>, // Regex patterns for suspicious values
    pub severity: AlertSeverity,
    pub risk_score: f32,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct SuspiciousPattern {
    pub name: String,
    pub key_pattern: String,
    pub value_pattern: Option<String>,
    pub process_pattern: Option<String>,
    pub severity: AlertSeverity,
    pub risk_score: f32,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct FrequencyLimit {
    pub max_alerts_per_hour: u32,
    pub cooldown_multiplier: f32,
}

impl RegistryDetector {
    pub async fn new(
        config: RegistryMonitorConfig,
        alert_sender: mpsc::Sender<DetectorAlert>,
        agent_id: String,
        hostname: String,
    ) -> Result<Self> {
        let detection_rules = Self::create_detection_rules();
        
        Ok(Self {
            _config: config,
            alert_sender,
            registry_tracker: Arc::new(RwLock::new(RegistryTracker::new())),
            detection_rules,
            is_running: Arc::new(RwLock::new(false)),
            agent_id,
            hostname,
            stats: Arc::new(RwLock::new(RegistryDetectorStats::default())),
        })
    }

    fn create_detection_rules() -> RegistryDetectionRules {
        let mut persistence_keys = HashMap::new();
        let mut security_keys = HashMap::new();
        let mut system_keys = HashMap::new();
        let mut malware_indicators = Vec::new();
        let mut suspicious_patterns = Vec::new();
        let mut baseline_values = HashMap::new();
        let mut alert_frequency_limits = HashMap::new();

        // Persistence mechanism detection
        persistence_keys.insert(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            PersistenceRule {
                name: "Run Key Persistence".to_string(),
                description: "Modification to Run registry key - common persistence mechanism".to_string(),
                severity: AlertSeverity::High,
                risk_score: 0.8,
                legitimate_processes: vec!["installer.exe".to_string(), "setup.exe".to_string()],
                alert_threshold: 1,
            }
        );

        persistence_keys.insert(
            "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            PersistenceRule {
                name: "User Run Key Persistence".to_string(),
                description: "Modification to user Run registry key".to_string(),
                severity: AlertSeverity::Medium,
                risk_score: 0.7,
                legitimate_processes: vec!["installer.exe".to_string()],
                alert_threshold: 1,
            }
        );

        persistence_keys.insert(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".to_string(),
            PersistenceRule {
                name: "RunOnce Persistence".to_string(),
                description: "Modification to RunOnce registry key".to_string(),
                severity: AlertSeverity::High,
                risk_score: 0.8,
                legitimate_processes: vec!["installer.exe".to_string(), "setup.exe".to_string()],
                alert_threshold: 1,
            }
        );

        // Security-critical keys
        security_keys.insert(
            "HKEY_LOCAL_MACHINE\\SAM".to_string(),
            SecurityRule {
                name: "SAM Database Access".to_string(),
                description: "Unauthorized access to Security Account Manager database".to_string(),
                severity: AlertSeverity::Critical,
                risk_score: 0.95,
                protected_values: vec![],
                whitelist_processes: vec!["lsass.exe".to_string(), "winlogon.exe".to_string()],
            }
        );

        security_keys.insert(
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa".to_string(),
            SecurityRule {
                name: "LSA Security Settings".to_string(),
                description: "Modification to Local Security Authority settings".to_string(),
                severity: AlertSeverity::High,
                risk_score: 0.85,
                protected_values: vec!["Authentication Packages".to_string()],
                whitelist_processes: vec!["lsass.exe".to_string()],
            }
        );

        // System integrity keys
        system_keys.insert(
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services".to_string(),
            SystemRule {
                name: "Service Configuration".to_string(),
                description: "Modification to system services".to_string(),
                severity: AlertSeverity::Medium,
                risk_score: 0.6,
                change_window: Duration::from_secs(3600), // 1 hour
                max_changes_per_window: 5,
            }
        );

        // Malware indicators
        malware_indicators.push(MalwareIndicator {
            name: "Suspicious Executable in Run Key".to_string(),
            key_patterns: vec![
                r".*\\Run.*".to_string(),
                r".*\\RunOnce.*".to_string(),
            ],
            value_patterns: vec![
                r".*\.tmp.*".to_string(),
                r".*temp.*".to_string(),
                r".*\\AppData\\.*".to_string(),
                r".*powershell.*-enc.*".to_string(),
                r".*cmd.*\/c.*".to_string(),
            ],
            severity: AlertSeverity::High,
            risk_score: 0.9,
            description: "Suspicious executable path in startup registry key".to_string(),
        });

        malware_indicators.push(MalwareIndicator {
            name: "Base64 Encoded Command".to_string(),
            key_patterns: vec![r".*".to_string()],
            value_patterns: vec![
                r".*-enc[oded]*\s+[A-Za-z0-9+/]{20,}.*".to_string(),
                r".*[A-Za-z0-9+/]{50,}==?.*".to_string(),
            ],
            severity: AlertSeverity::High,
            risk_score: 0.85,
            description: "Base64 encoded command in registry value".to_string(),
        });

        // Suspicious patterns
        suspicious_patterns.push(SuspiciousPattern {
            name: "Unsigned Binary in Startup".to_string(),
            key_pattern: r".*\\(Run|RunOnce).*".to_string(),
            value_pattern: Some(r".*\.(exe|scr|bat|cmd|pif).*".to_string()),
            process_pattern: None,
            severity: AlertSeverity::Medium,
            risk_score: 0.6,
            description: "Executable file added to startup registry keys".to_string(),
        });

        suspicious_patterns.push(SuspiciousPattern {
            name: "Service DLL Hijacking".to_string(),
            key_pattern: r".*\\Services\\.*\\Parameters".to_string(),
            value_pattern: Some(r"ServiceDll".to_string()),
            process_pattern: None,
            severity: AlertSeverity::High,
            risk_score: 0.8,
            description: "Service DLL path modification - potential DLL hijacking".to_string(),
        });

        // Baseline values for critical settings
        baseline_values.insert(
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Authentication Packages".to_string(),
            "msv1_0".to_string()
        );

        // Alert frequency limits
        alert_frequency_limits.insert(
            "registry_persistence".to_string(),
            FrequencyLimit {
                max_alerts_per_hour: 10,
                cooldown_multiplier: 0.5,
            }
        );

        RegistryDetectionRules {
            persistence_keys,
            security_keys,
            system_keys,
            malware_indicators,
            suspicious_patterns,
            baseline_values,
            alert_frequency_limits,
        }
    }

    async fn analyze_registry_event(&self, registry_data: &RegistryEventData) -> Result<Option<RegistryEvent>> {
        let key_path = &registry_data.key_path;
        let mut risk_score = 0.0;
        let mut event_type = RegistryEventType::SuspiciousValueChange;
        let mut severity = AlertSeverity::Info;

        // Check against persistence rules
        if let Some(rule) = self.detection_rules.persistence_keys.get(key_path) {
            risk_score = rule.risk_score;
            event_type = RegistryEventType::PersistenceMechanism;
            severity = rule.severity.clone();
            
            // Check if process is legitimate
            if let Some(process_name) = &registry_data.process_name {
                if !rule.legitimate_processes.iter().any(|p| process_name.contains(p)) {
                    risk_score += 0.2; // Increase risk for non-legitimate processes
                }
            }
        }

        // Check against security rules
        if let Some(rule) = self.detection_rules.security_keys.get(key_path) {
            risk_score = f32::max(risk_score, rule.risk_score);
            event_type = RegistryEventType::SecurityBypass;
            severity = rule.severity.clone();
            
            // Critical security keys have maximum severity
            if matches!(rule.severity, AlertSeverity::Critical) {
                risk_score = 0.95;
            }
        }

        // Check against system rules
        if let Some(rule) = self.detection_rules.system_keys.get(key_path) {
            if risk_score < rule.risk_score {
                risk_score = rule.risk_score;
                event_type = RegistryEventType::SystemModification;
                severity = rule.severity.clone();
            }
        }

        // Check malware indicators
        for indicator in &self.detection_rules.malware_indicators {
            if Self::matches_patterns(&indicator.key_patterns, key_path) {
                if let Some(value_data) = &registry_data.value_data {
                    if Self::matches_patterns(&indicator.value_patterns, value_data) {
                        risk_score = f32::max(risk_score, indicator.risk_score);
                        event_type = RegistryEventType::MalwareIndicator;
                        severity = indicator.severity.clone();
                    }
                }
            }
        }

        // Check suspicious patterns
        for pattern in &self.detection_rules.suspicious_patterns {
            if Self::matches_pattern(&pattern.key_pattern, key_path) {
                let mut pattern_match = true;
                
                if let Some(value_pattern) = &pattern.value_pattern {
                    if let Some(value_data) = &registry_data.value_data {
                        pattern_match = Self::matches_pattern(value_pattern, value_data);
                    } else {
                        pattern_match = false;
                    }
                }
                
                if pattern_match {
                    risk_score = f32::max(risk_score, pattern.risk_score);
                    severity = pattern.severity.clone();
                }
            }
        }

        // Only create event if risk score is significant
        if risk_score > 0.3 {
            Ok(Some(RegistryEvent {
                timestamp: Instant::now(),
                event_type,
                key_path: key_path.clone(),
                value_name: registry_data.value_name.clone(),
                old_value: registry_data.old_value_data.clone(),
                new_value: registry_data.value_data.clone(),
                process_id: registry_data.process_id,
                process_name: registry_data.process_name.clone(),
                severity,
                risk_score,
            }))
        } else {
            Ok(None)
        }
    }

    fn matches_patterns(patterns: &[String], text: &str) -> bool {
        patterns.iter().any(|pattern| Self::matches_pattern(pattern, text))
    }

    fn matches_pattern(pattern: &str, text: &str) -> bool {
        // Simple pattern matching - in production, use regex crate
        if pattern.contains(".*") {
            // Basic wildcard matching
            let parts: Vec<&str> = pattern.split(".*").collect();
            if parts.len() == 2 {
                text.starts_with(parts[0]) && text.ends_with(parts[1])
            } else {
                text.contains(&pattern.replace(".*", ""))
            }
        } else {
            text.contains(pattern)
        }
    }

    async fn should_alert(&self, registry_event: &RegistryEvent) -> bool {
        let tracker = self.registry_tracker.read().await;
        
        // Check alert frequency limits
        if let Some(limit) = self.detection_rules.alert_frequency_limits.get("registry_persistence") {
            let alert_type = format!("{}_{}", registry_event.event_type.to_string(), registry_event.key_path);
            if let Some(recent_alerts) = tracker.alert_frequency.get(&alert_type) {
                let one_hour_ago = Instant::now() - Duration::from_secs(3600);
                let recent_count = recent_alerts.iter().filter(|&&t| t > one_hour_ago).count();
                
                if recent_count >= limit.max_alerts_per_hour as usize {
                    return false; // Too many alerts recently
                }
            }
        }
        
        // Always alert for critical severity
        if matches!(registry_event.severity, AlertSeverity::Critical) {
            return true;
        }
        
        // Alert based on risk score threshold
        registry_event.risk_score > 0.5
    }

    async fn create_alert(&self, registry_event: &RegistryEvent) -> DetectorAlert {
        let severity = registry_event.severity.clone();

        let title = match registry_event.event_type {
            RegistryEventType::PersistenceMechanism => "Registry Persistence Mechanism Detected",
            RegistryEventType::SecurityBypass => "Security Registry Modification",
            RegistryEventType::SystemModification => "System Registry Modification",
            RegistryEventType::MalwareIndicator => "Malware Registry Indicator",
            RegistryEventType::PolicyTampering => "Registry Policy Tampering",
            RegistryEventType::ServiceManipulation => "Service Registry Manipulation",
            RegistryEventType::StartupModification => "Startup Registry Modification",
            RegistryEventType::ShellExtensionChange => "Shell Extension Registry Change",
            RegistryEventType::UnauthorizedAccess => "Unauthorized Registry Access",
            RegistryEventType::SuspiciousValueChange => "Suspicious Registry Value Change",
        };

        let description = format!(
            "Registry modification detected in key: {} - {}",
            registry_event.key_path,
            match &registry_event.new_value {
                Some(value) => format!("New value: {}", value),
                None => "Key structure modified".to_string(),
            }
        );

        let mut indicators = vec![
            format!("Registry key: {}", registry_event.key_path),
            format!("Risk score: {:.2}", registry_event.risk_score),
        ];

        if let Some(process_name) = &registry_event.process_name {
            indicators.push(format!("Modifying process: {}", process_name));
        }

        if let Some(value_name) = &registry_event.value_name {
            indicators.push(format!("Value name: {}", value_name));
        }

        let recommended_actions = vec![
            "Investigate the modifying process".to_string(),
            "Verify if the registry change is legitimate".to_string(),
            "Check for additional persistence mechanisms".to_string(),
            "Review process execution timeline".to_string(),
        ];

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("detector_type".to_string(), "registry".to_string());
        metadata.insert("key_path".to_string(), registry_event.key_path.clone());
        
        if let Some(process_id) = registry_event.process_id {
            metadata.insert("process_id".to_string(), process_id.to_string());
        }

        let mut alert = DetectorAlert {
            id: Uuid::new_v4().to_string(),
            detector_name: "registry_detector".to_string(),
            severity,
            title: title.to_string(),
            description,
            affected_processes: registry_event.process_id.map(|pid| vec![pid]).unwrap_or_default(),
            indicators,
            recommended_actions,
            risk_score: registry_event.risk_score,
            timestamp: Utc::now(),
            metadata,
        };
        
        // Add agent_id and hostname to metadata
        alert.metadata.insert("agent_id".to_string(), self.agent_id.clone());
        alert.metadata.insert("hostname".to_string(), self.hostname.clone());
        
        alert
    }
}

impl RegistryTracker {
    fn new() -> Self {
        Self {
            key_states: HashMap::new(),
            recent_events: VecDeque::new(),
            alert_frequency: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    fn add_event(&mut self, event: RegistryEvent) {
        // Update key state
        let key_state = self.key_states
            .entry(event.key_path.clone())
            .or_insert_with(|| RegistryKeyState {
                key_path: event.key_path.clone(),
                last_modified: event.timestamp,
                modification_count: 0,
                suspicious_changes: 0,
                associated_processes: Vec::new(),
                risk_score: 0.0,
                baseline_hash: None,
            });

        key_state.last_modified = event.timestamp;
        key_state.modification_count += 1;
        key_state.risk_score = f32::max(key_state.risk_score, event.risk_score);

        if event.risk_score > 0.5 {
            key_state.suspicious_changes += 1;
        }

        if let Some(process_id) = event.process_id {
            if !key_state.associated_processes.contains(&process_id) {
                key_state.associated_processes.push(process_id);
            }
        }

        // Add to recent events
        self.recent_events.push_back(event);

        // Cleanup old events (keep last 1000)
        while self.recent_events.len() > 1000 {
            self.recent_events.pop_front();
        }
    }

    fn cleanup_old_data(&mut self) {
        let now = Instant::now();
        let one_hour_ago = now - Duration::from_secs(3600);
        
        // Cleanup alert frequency tracking
        for (_, timestamps) in self.alert_frequency.iter_mut() {
            timestamps.retain(|&t| t > one_hour_ago);
        }
        
        // Cleanup old events
        self.recent_events.retain(|event| event.timestamp > one_hour_ago);
        
        self.last_cleanup = now;
    }
}

impl ToString for RegistryEventType {
    fn to_string(&self) -> String {
        match self {
            RegistryEventType::PersistenceMechanism => "persistence_mechanism".to_string(),
            RegistryEventType::SecurityBypass => "security_bypass".to_string(),
            RegistryEventType::SystemModification => "system_modification".to_string(),
            RegistryEventType::MalwareIndicator => "malware_indicator".to_string(),
            RegistryEventType::PolicyTampering => "policy_tampering".to_string(),
            RegistryEventType::ServiceManipulation => "service_manipulation".to_string(),
            RegistryEventType::StartupModification => "startup_modification".to_string(),
            RegistryEventType::ShellExtensionChange => "shell_extension_change".to_string(),
            RegistryEventType::UnauthorizedAccess => "unauthorized_access".to_string(),
            RegistryEventType::SuspiciousValueChange => "suspicious_value_change".to_string(),
        }
    }
}

#[async_trait::async_trait]
impl Detector for RegistryDetector {
    async fn start(&self) -> Result<()> {
        info!("Starting registry detector");
        *self.is_running.write().await = true;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping registry detector");
        *self.is_running.write().await = false;
        Ok(())
    }

    async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    async fn get_status(&self) -> DetectorStatus {
        let stats = self.stats.read().await;
        let tracker = self.registry_tracker.read().await;
        
        DetectorStatus {
            name: "registry_detector".to_string(),
            is_running: self.is_running().await,
            events_processed: stats.events_processed,
            alerts_generated: stats.alerts_generated,
            processes_tracked: tracker.key_states.len() as u64,
            last_activity: stats.last_activity.unwrap_or_else(Instant::now),
            memory_usage_kb: 0, // TODO: Implement memory tracking
            cpu_usage_percent: 0.0, // TODO: Implement CPU tracking
        }
    }

    async fn process_event(&self, event: &Event) -> Result<()> {
        // Only process registry events
        if let EventData::Registry(registry_data) = &event.data {
            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.events_processed += 1;
                stats.last_activity = Some(Instant::now());
            }

            // Analyze the registry event
            if let Some(registry_event) = self.analyze_registry_event(registry_data).await? {
                // Check if we should alert
                if self.should_alert(&registry_event).await {
                    // Create and send alert
                    let alert = self.create_alert(&registry_event).await;
                    
                    if let Err(e) = self.alert_sender.send(alert).await {
                        error!("Failed to send registry alert: {}", e);
                    } else {
                        let mut stats = self.stats.write().await;
                        stats.alerts_generated += 1;
                    }
                }

                // Update tracker
                {
                    let mut tracker = self.registry_tracker.write().await;
                    tracker.add_event(registry_event);
                    
                    // Periodic cleanup
                    if tracker.last_cleanup.elapsed() > Duration::from_secs(3600) {
                        tracker.cleanup_old_data();
                    }
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "registry_detector"
    }
}

