use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub collectors: CollectorsConfig,
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
    pub max_file_size_mb: u64,
    pub calculate_hashes: bool,
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
                registry_monitor: RegistryMonitorConfig {
                    enabled: cfg!(windows),
                    watched_keys: vec![
                        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                        "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                    ],
                },
            },
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