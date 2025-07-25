use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use std::path::PathBuf;
use std::collections::HashMap;
use crate::deduplication::DeduplicationConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub collectors: CollectorsConfig,
    pub detectors: DetectorsConfig,
    pub deduplication: DeduplicationConfig,
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id: Option<String>,
    pub hostname: Option<String>,
    pub collection_interval_ms: u64,
    pub max_events_per_batch: usize,
    pub max_memory_usage_mb: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorsConfig {
    pub process_monitor: ProcessMonitorConfig,
    pub file_monitor: FileMonitorConfig,
    pub network_monitor: NetworkMonitorConfig,
    #[cfg(windows)]
    pub registry_monitor: RegistryMonitorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    pub enabled: bool,
    pub scan_interval_ms: u64,
    pub track_child_processes: bool,
    pub collect_command_line: bool,
    pub collect_environment: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitorConfig {
    pub enabled: bool,
    pub watched_paths: Vec<PathBuf>,
    pub ignored_extensions: Vec<String>,
    #[serde(default)]
    pub ignored_paths: Vec<PathBuf>,
    pub max_file_size_mb: u64,
    pub calculate_hashes: bool,
}

impl FileMonitorConfig {
    pub fn filter_watched_paths_for_platform(&mut self) {
        // Filter watched paths based on platform
        self.watched_paths.retain(|path| {
            let path_str = path.to_string_lossy();
            #[cfg(windows)]
            {
                !(path_str == "/")
            }
            #[cfg(not(windows))]
            {
                !(path_str == "C:\\")
            }
        });
        
        // Filter ignored paths based on platform
        self.ignored_paths.retain(|path| {
            let path_str = path.to_string_lossy();
            #[cfg(windows)]
            {
                // On Windows, keep Windows-style paths and reject Unix-style paths
                !path_str.starts_with("/")
            }
            #[cfg(not(windows))]
            {
                // On Unix/Linux/macOS, keep Unix-style paths and reject Windows-style paths
                !(path_str.starts_with("C:\\") || path_str.contains(":\\\\"))
            }
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    pub enabled: bool,
    pub monitor_connections: bool,
    pub monitor_dns: bool,
    pub capture_packets: bool,
    pub max_packet_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryMonitorConfig {
    pub enabled: bool,
    pub watched_keys: Vec<String>,
}

impl Default for RegistryMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: cfg!(windows),
            watched_keys: vec![
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectorsConfig {
    pub behavioral: BehavioralDetectorConfig,
    pub dns_anomaly: DnsAnomalyDetectorConfig,
    #[cfg(windows)]
    pub registry_monitor: RegistryMonitorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehavioralDetectorConfig {
    pub enabled: bool,
    pub scan_interval_ms: u64,
    pub alert_threshold: f32,
    pub prevention_threshold: f32,
    pub track_api_calls: bool,
    pub monitor_memory_operations: bool,
    pub monitor_thread_operations: bool,
    pub cross_platform_detection: bool,
    #[serde(default)]
    pub system_process_contexts: HashMap<String, SystemProcessContext>,
    #[serde(default)]
    pub alert_frequency_limits: HashMap<String, FrequencyLimit>,
    #[serde(default)]
    pub path_context_rules: HashMap<String, PathContextRule>,
    #[serde(default)]
    pub network_behavior_rules: HashMap<String, NetworkBehaviorRule>,
    #[serde(default)]
    pub time_based_risk_adjustment: TimeBasedRiskAdjustment,
    #[serde(default)]
    pub process_whitelist: ProcessWhitelist,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnomalyDetectorConfig {
    pub enabled: bool,
    pub max_queries_per_minute: u64,
    pub max_queries_per_hour: u64,
    pub max_unique_domains_per_hour: u64,
    pub entropy_threshold: f64,
    pub base64_detection_threshold: f64,
    pub data_exfiltration_threshold_mb_per_hour: u64,
    pub beaconing_detection_threshold: f64,
    pub txt_record_size_threshold: usize,
    pub monitor_dns_over_https: bool,
    pub monitor_dns_over_tls: bool,
    pub learning_period_hours: u64,
    #[serde(default)]
    pub suspicious_domain_patterns: Vec<String>,
    #[serde(default)]
    pub known_malicious_domains: Vec<String>,
    #[serde(default)]
    pub known_c2_domains: Vec<String>,
    #[serde(default)]
    pub dns_over_https_providers: Vec<String>,
    #[serde(default)]
    pub alert_frequency_limits: HashMap<String, FrequencyLimit>,
}

impl Default for DnsAnomalyDetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_queries_per_minute: 100,
            max_queries_per_hour: 1000,
            max_unique_domains_per_hour: 500,
            entropy_threshold: 4.5,
            base64_detection_threshold: 0.7,
            data_exfiltration_threshold_mb_per_hour: 100,
            beaconing_detection_threshold: 0.8,
            txt_record_size_threshold: 512,
            monitor_dns_over_https: true,
            monitor_dns_over_tls: true,
            learning_period_hours: 24,
            suspicious_domain_patterns: vec![
                r".*\.onion$".to_string(),
                r".*[0-9]{10,}.*".to_string(),
                r".*[a-fA-F0-9]{32,}.*".to_string(),
                r".*[A-Za-z0-9+/]{20,}=*.*".to_string(),
                r".*\.tk$".to_string(),
                r".*\.ml$".to_string(),
                r".*\.ga$".to_string(),
                r".*\.cf$".to_string(),
                r".*dyndns\..*".to_string(),
                r".*ddns\..*".to_string(),
                r".*ngrok\..*".to_string(),
            ],
            known_malicious_domains: vec![],
            known_c2_domains: vec![],
            dns_over_https_providers: vec![
                "1.1.1.1".to_string(),
                "1.0.0.1".to_string(),
                "8.8.8.8".to_string(),
                "8.8.4.4".to_string(),
                "9.9.9.9".to_string(),
                "149.112.112.112".to_string(),
            ],
            alert_frequency_limits: {
                let mut limits = HashMap::new();
                limits.insert("dns_tunneling".to_string(), FrequencyLimit {
                    max_alerts_per_hour: 5,
                    cooldown_multiplier: 0.5,
                });
                limits.insert("high_volume_dns".to_string(), FrequencyLimit {
                    max_alerts_per_hour: 3,
                    cooldown_multiplier: 0.7,
                });
                limits.insert("suspicious_domain".to_string(), FrequencyLimit {
                    max_alerts_per_hour: 10,
                    cooldown_multiplier: 0.3,
                });
                limits
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub local_storage: LocalStorageConfig,
    pub retention_days: u32,
    pub max_storage_size_gb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalStorageConfig {
    pub enabled: bool,
    pub data_directory: PathBuf,
    pub compress_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub enabled: bool,
    pub server_url: Option<String>,
    pub api_key: Option<String>,
    pub batch_upload_interval_s: u64,
    pub max_retries: u32,
    pub timeout_s: u64,
    pub use_tls: bool,
    pub verify_certificates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: PathBuf,
    pub max_file_size_mb: u64,
    pub max_files: u32,
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::find_config_file()?;
        
        let settings = config::Config::builder()
            .add_source(config::File::from(config_path))
            .add_source(config::Environment::with_prefix("EDR"))
            .build()
            .context("Failed to build configuration")?;
        
        let mut config: Config = settings
            .try_deserialize()
            .context("Failed to deserialize configuration")?;
        
        // Set defaults and validate
        config.set_defaults()?;
        config.set_platform_specifics()?;
        config.validate()?;
        
        Ok(config)
    }
    
    fn find_config_file() -> Result<PathBuf> {
        let possible_paths = vec![
            PathBuf::from("config.yaml"),
            PathBuf::from("config.yml"),
            PathBuf::from("/etc/edr-agent/config.yaml"),
            PathBuf::from("/usr/local/etc/edr-agent/config.yaml"),
        ];
        
        for path in possible_paths {
            if path.exists() {
                return Ok(path);
            }
        }
        
        // Create default config if none found
        let default_config = Self::default();
        let config_content = serde_yaml::to_string(&default_config)
            .context("Failed to serialize default config")?;
        
        std::fs::write("config.yaml", config_content)
            .context("Failed to write default config")?;
        
        Ok(PathBuf::from("config.yaml"))
    }
    
    fn set_defaults(&mut self) -> Result<()> {
        if self.agent.agent_id.is_none() {
            self.agent.agent_id = Some(uuid::Uuid::new_v4().to_string());
        }
        
        if self.agent.hostname.is_none() {
            self.agent.hostname = Some(
                hostname::get()
                    .context("Failed to get hostname")?
                    .to_string_lossy()
                    .to_string()
            );
        }
        
        Ok(())
    }
    
    fn set_platform_specifics(&mut self) -> Result<()> {
        let original_watched_paths = self.collectors.file_monitor.watched_paths.clone();
        let original_ignored_paths = self.collectors.file_monitor.ignored_paths.clone();
        
        self.collectors.file_monitor.filter_watched_paths_for_platform();
        
        // Log the filtering results for watched paths
        if original_watched_paths.len() != self.collectors.file_monitor.watched_paths.len() {
            let filtered_out: Vec<_> = original_watched_paths.iter()
                .filter(|p| !self.collectors.file_monitor.watched_paths.contains(p))
                .collect();
            println!("Platform-specific path filtering: Removed {} incompatible watched paths: {:?}", 
                     filtered_out.len(), 
                     filtered_out.iter().map(|p| p.display().to_string()).collect::<Vec<_>>());
        }
        
        // Log the filtering results for ignored paths
        if original_ignored_paths.len() != self.collectors.file_monitor.ignored_paths.len() {
            let filtered_out: Vec<_> = original_ignored_paths.iter()
                .filter(|p| !self.collectors.file_monitor.ignored_paths.contains(p))
                .collect();
            println!("Platform-specific path filtering: Removed {} incompatible ignored paths: {:?}", 
                     filtered_out.len(), 
                     filtered_out.iter().map(|p| p.display().to_string()).collect::<Vec<_>>());
        }
        
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.agent.collection_interval_ms == 0 {
            anyhow::bail!("Collection interval must be greater than 0");
        }

        if self.agent.max_events_per_batch == 0 {
            anyhow::bail!("Max events per batch must be greater than 0");
        }
        
        if self.storage.local_storage.enabled {
            let data_dir = &self.storage.local_storage.data_directory;
            if let Some(parent) = data_dir.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .context("Failed to create data directory")?;
                }
            }
        }
        
        Ok(())
    }
}

// Config-compatible types that match injection detector expectations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemProcessContext {
    pub expected_paths: Vec<String>,
    pub max_instances: u32,
    pub baseline_risk_reduction: f32,
    pub elevated_risk_multiplier: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyLimit {
    pub max_alerts_per_hour: u32,
    pub cooldown_multiplier: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertTimeWindows {
    pub short_term_seconds: u64,   // 5 minutes
    pub medium_term_seconds: u64,  // 30 minutes  
    pub long_term_seconds: u64,    // 1 hour
    pub max_alerts_short_term: u32,
    pub max_alerts_medium_term: u32,
    pub max_alerts_long_term: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathContextRule {
    pub patterns: Vec<String>,
    pub alert_threshold_multiplier: f32,
    pub max_alerts_per_hour: u32,
    pub context_type: PathContextType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PathContextType {
    BrowserData,
    SystemTemp,
    UserCache,
    SystemBinary,
    UserDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBehaviorRule {
    pub process_patterns: Vec<String>,
    pub suspicious_network_threshold: f32,
    pub max_network_alerts_per_hour: u32,
    pub whitelisted_ports: Vec<u16>,
    pub behavior_tolerance: NetworkToleranceLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkToleranceLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimeBasedRiskAdjustment {
    pub business_hours_multiplier: f32,
    pub after_hours_multiplier: f32,
    pub weekend_multiplier: f32,
    pub business_hours_start: u8,  // 24-hour format
    pub business_hours_end: u8,    // 24-hour format
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessWhitelist {
    pub enabled: bool,
    /// Process names to exclude from monitoring (exact matches)
    pub process_names: Vec<String>,
    /// Process path patterns to exclude from monitoring
    pub process_paths: Vec<String>,
    /// Command line patterns to exclude from monitoring
    pub command_line_patterns: Vec<String>,
    /// Parent process names that indicate child processes should be whitelisted
    pub parent_process_names: Vec<String>,
    /// Agent-specific processes to exclude (automatically populated)
    pub agent_processes: Vec<String>,
}

// Default implementations that extend existing architecture
impl Default for SystemProcessContext {
    fn default() -> Self {
        Self {
            expected_paths: vec![],
            max_instances: 5,
            baseline_risk_reduction: 0.3,
            elevated_risk_multiplier: 2.0,
        }
    }
}

impl Default for FrequencyLimit {
    fn default() -> Self {
        Self {
            max_alerts_per_hour: 10,
            cooldown_multiplier: 0.3,
        }
    }
}


impl Default for AlertTimeWindows {
    fn default() -> Self {
        Self {
            short_term_seconds: 300,    // 5 minutes
            medium_term_seconds: 1800,  // 30 minutes
            long_term_seconds: 3600,    // 1 hour
            max_alerts_short_term: 3,
            max_alerts_medium_term: 8,
            max_alerts_long_term: 15,
        }
    }
}

impl Default for PathContextRule {
    fn default() -> Self {
        Self {
            patterns: vec![],
            alert_threshold_multiplier: 1.0,
            max_alerts_per_hour: 10,
            context_type: PathContextType::UserDocument,
        }
    }
}

impl Default for NetworkBehaviorRule {
    fn default() -> Self {
        Self {
            process_patterns: vec![],
            suspicious_network_threshold: 0.5,
            max_network_alerts_per_hour: 10,
            whitelisted_ports: vec![80, 443, 53, 8080],
            behavior_tolerance: NetworkToleranceLevel::Medium,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: AgentConfig {
                agent_id: None,
                hostname: None,
                collection_interval_ms: 5000,
                max_events_per_batch: 1000,
                max_memory_usage_mb: 512,
            },
            collectors: CollectorsConfig {
                process_monitor: ProcessMonitorConfig {
                    enabled: true,
                    scan_interval_ms: 1000,
                    track_child_processes: true,
                    collect_command_line: true,
                    collect_environment: false,
                },
                file_monitor: FileMonitorConfig {
                    enabled: true,
                    watched_paths: vec![
                        PathBuf::from("/"),
                        PathBuf::from("C:\\"),
                    ],
                    ignored_extensions: vec![
                        ".tmp".to_string(),
                        ".log".to_string(),
                        ".cache".to_string(),
                    ],
                    ignored_paths: vec![
                        PathBuf::from("./data"),
                        PathBuf::from("./target"),
                        PathBuf::from("./logs"),
                    ],
                    max_file_size_mb: 100,
                    calculate_hashes: true,
                },
                network_monitor: NetworkMonitorConfig {
                    enabled: true,
                    monitor_connections: true,
                    monitor_dns: true,
                    capture_packets: false,
                    max_packet_size: 1500,
                },
                #[cfg(windows)]
                registry_monitor: RegistryMonitorConfig::default(),
            },
            detectors: DetectorsConfig {
                #[cfg(windows)]
                registry_monitor: RegistryMonitorConfig::default(),
                behavioral: BehavioralDetectorConfig {
                    enabled: true,
                    scan_interval_ms: 2000,
                    alert_threshold: 0.6,
                    prevention_threshold: 0.8,
                    track_api_calls: true,
                    monitor_memory_operations: true,
                    monitor_thread_operations: true,
                    cross_platform_detection: true,
                    system_process_contexts: HashMap::new(),
                    alert_frequency_limits: HashMap::new(),
                    path_context_rules: HashMap::new(),
                    network_behavior_rules: HashMap::new(),
                    time_based_risk_adjustment: TimeBasedRiskAdjustment::default(),
                    process_whitelist: ProcessWhitelist::default(),
                },
                dns_anomaly: DnsAnomalyDetectorConfig::default(),
            },
            deduplication: DeduplicationConfig::default(),
            storage: StorageConfig {
                local_storage: LocalStorageConfig {
                    enabled: true,
                    data_directory: PathBuf::from("./data"),
                    compress_events: true,
                },
                retention_days: 30,
                max_storage_size_gb: 10,
            },
            network: NetworkConfig {
                enabled: false,
                server_url: None,
                api_key: None,
                batch_upload_interval_s: 300,
                max_retries: 3,
                timeout_s: 30,
                use_tls: true,
                verify_certificates: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_path: PathBuf::from("./logs/edr-agent.log"),
                max_file_size_mb: 100,
                max_files: 10,
            },
        }
    }
}