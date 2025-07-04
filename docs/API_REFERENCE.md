# API Reference

## Core Module APIs

### Agent (`src/agent.rs`)

The main agent orchestrator responsible for coordinating all subsystems.

#### `Agent::new(config: Config) -> Result<Self>`
Creates a new agent instance with the specified configuration.

**Parameters:**
- `config`: Configuration object loaded from YAML

**Returns:**
- `Result<Agent>`: Initialized agent or error

**Example:**
```rust
let config = Config::load()?;
let agent = Agent::new(config).await?;
```

#### `Agent::run(&self) -> Result<()>`
Starts the agent and runs the main event processing loop.

**Features:**
- Starts all collectors and detectors
- Processes events in batches
- Handles graceful shutdown via SIGINT
- Manages event deduplication and storage

#### `Agent::shutdown(&self)`
Initiates graceful shutdown of all agent components.

### Configuration (`src/config.rs`)

Configuration management system supporting YAML-based configuration.

#### `Config::load() -> Result<Config>`
Loads configuration from `config.yaml` with fallback to defaults.

**Configuration Structure:**
```yaml
agent:
  agent_id: "unique-agent-id"
  hostname: "auto-detected"
  collection_interval_ms: 1000
  max_events_per_batch: 1000
  max_memory_usage_mb: 512

collectors:
  process_monitor:
    enabled: true
    scan_interval_ms: 1000
    track_child_processes: true
    collect_command_line: true
    collect_environment: false
  
  file_monitor:
    enabled: true
    watched_paths: ["/", "C:\\"]
    ignored_extensions: [".tmp", ".log"]
    max_file_size_mb: 100
    calculate_hashes: true
  
  network_monitor:
    enabled: true
    monitor_connections: true
    monitor_dns: true
    capture_packets: false

detectors:
  behavioral:
    enabled: true
    scan_interval_ms: 5000
    alert_threshold: 0.7
    prevention_threshold: 0.9
    cross_platform_detection: true
  
  dns_anomaly:
    enabled: true
    max_queries_per_minute: 100
    entropy_threshold: 4.5
    base64_detection_threshold: 0.7

storage:
  base_path: "./data"
  compression_enabled: true
  max_file_size_mb: 10
  retention_days: 30

logging:
  level: "info"
  file_rotation: "daily"
```

### Event System (`src/events.rs`)

Unified event format and processing system.

#### Event Types

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    // Process Events
    ProcessCreated,
    ProcessTerminated,
    ProcessModified,
    
    // File Events  
    FileCreated,
    FileModified,
    FileDeleted,
    FileRenamed,
    
    // Network Events
    NetworkConnectionEstablished,
    NetworkConnectionClosed,
    NetworkDnsQuery,
    
    // Security Events
    SecurityAlert,
    
    // Registry Events (Windows)
    #[cfg(windows)]
    RegistryKeyCreated,
    #[cfg(windows)]
    RegistryKeyModified,
    #[cfg(windows)]
    RegistryKeyDeleted,
}
```

#### `Event` Structure

```rust
pub struct Event {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub source: String,
    pub hostname: String,
    pub agent_id: String,
    pub data: EventData,
}
```

#### `EventBatch` API

```rust
impl EventBatch {
    pub fn new() -> Self
    pub fn add_event(&mut self, event: Event)
    pub fn len(&self) -> usize
    pub fn is_empty(&self) -> bool
    pub fn clear(&mut self)
}
```

## Collector APIs

### Process Collector (`src/collectors/process.rs`)

Monitors system processes for creation, termination, and modification events.

#### Key Features
- Real-time process monitoring via `sysinfo` crate
- CPU and memory usage tracking
- Command line and environment capture
- Parent-child process relationship tracking

#### Configuration Options
```rust
pub struct ProcessMonitorConfig {
    pub enabled: bool,
    pub scan_interval_ms: u64,
    pub track_child_processes: bool,
    pub collect_command_line: bool,
    pub collect_environment: bool,
}
```

### File Collector (`src/collectors/file.rs`)

Monitors file system events using the `notify` crate.

#### Key Features
- Real-time file change detection
- SHA-256 hash calculation
- Configurable path watching
- Extension and size filtering

#### Monitored Events
- File creation, modification, deletion
- File renaming and moving
- Directory structure changes

### Network Collector (`src/collectors/network.rs`)

Monitors network connections and DNS queries.

#### Key Features
- Connection state tracking
- DNS query monitoring
- Protocol detection
- Process correlation

#### Supported Protocols
- TCP/UDP connections
- DNS queries (UDP/TCP, DoH, DoT)
- ICMP monitoring (planned)

## Detector APIs

### Behavioral Detector (`src/detectors/behavioral.rs`)

Advanced behavioral threat detection engine with cross-platform support.

#### Detection Categories

**Process Injection Detection:**
- Ptrace-based injection (Linux)
- DLL injection patterns (Windows)
- Shared library injection (Linux/macOS)
- Memory manipulation techniques

**Suspicious Execution Patterns:**
- Shell execution from unusual locations
- Process execution from temporary directories
- Browser cache execution
- Command line injection patterns

**System Process Context:**
- Legitimate system process recognition
- Process location validation
- Privilege escalation detection

#### Risk Scoring Algorithm

```rust
pub struct RiskScore {
    pub base_risk: f32,
    pub context_multiplier: f32,
    pub frequency_reduction: f32,
    pub final_score: f32,
}
```

Risk factors:
- Process location (high risk for /tmp, /dev/shm)
- Parent process context
- Command line patterns
- API call sequences
- Time-based behavior

#### Platform-Specific Rules

**Linux:**
- Ptrace system call monitoring
- /proc filesystem manipulation
- Shared library injection via LD_PRELOAD
- Suspicious paths: /tmp, /dev/shm, /var/tmp

**Windows:**
- Registry-based persistence
- DLL injection via SetWindowsHookEx, CreateRemoteThread
- Process hollowing detection
- Suspicious paths: %TEMP%, %APPDATA%

**macOS:**
- Dylib injection monitoring
- Task port manipulation
- Suspicious paths: /tmp, ~/Downloads, cache directories

### DNS Anomaly Detector (`src/detectors/dns_anomaly.rs`)

Comprehensive DNS threat detection system.

#### Detection Types

**High-Frequency Queries:**
- Rate limiting per process/domain
- Threshold-based alerting
- Time-window analysis

**Suspicious Domain Patterns:**
- DGA (Domain Generation Algorithm) detection
- Base64 encoded subdomains
- Free TLD abuse (.tk, .ml, .ga, .cf)
- Suspicious domain length and entropy

**DNS Tunneling:**
- TXT record size analysis
- Unusual query patterns
- Data exfiltration volume detection
- Response size monitoring

**Command and Control:**
- Beaconing pattern detection
- Known C2 domain matching
- DNS over HTTPS/TLS monitoring

#### Alert Frequency Management

```rust
pub struct FrequencyLimit {
    pub max_alerts_per_hour: u32,
    pub cooldown_multiplier: f32,
}
```

**Default Limits:**
- DNS Tunneling: 5 alerts/hour
- High Volume DNS: 3 alerts/hour  
- Suspicious Domains: 10 alerts/hour

## Storage and Performance APIs

### Storage Manager (`src/storage.rs`)

Manages local event storage with compression and retention.

#### Key Features
- Gzip compression (90%+ reduction)
- Automatic file rotation
- Configurable retention policies
- Batch-based I/O optimization

#### API Methods

```rust
impl StorageManager {
    pub async fn new(config: StorageConfig) -> Result<Self>
    pub async fn store_events(&self, batch: EventBatch) -> Result<()>
    pub async fn cleanup_old_events(&self) -> Result<()>
    pub async fn get_storage_stats(&self) -> Result<StorageStats>
}
```

### Deduplication Engine (`src/deduplication.rs`)

Intelligent event deduplication to reduce noise while preserving security fidelity.

#### Security-First Approach
- **Never Deduplicates:** Process creation/termination, new connections, file creation/deletion
- **Conservative Deduplication:** Process modification events, repeated DNS queries
- **Aggressive Deduplication:** File system noise, connection state updates

#### Memory Management
- Maximum 300KB overhead for deduplication tracking
- Time-window based cleanup (hourly)
- Hard limits to prevent memory exhaustion

#### Configuration

```rust
pub struct DeduplicationConfig {
    pub enabled: bool,
    pub max_memory_usage_kb: usize,
    pub cleanup_interval_seconds: u64,
    pub event_type_rules: HashMap<EventType, DeduplicationRule>,
}
```

## Platform-Specific APIs

### Windows Registry Monitoring (`src/collectors/registry.rs`)

Windows-only registry change detection.

#### Features
- Real-time registry change monitoring
- Configurable key watching
- Registry threat detection integration

#### Configuration
```rust
pub struct RegistryMonitorConfig {
    pub enabled: bool,
    pub watched_keys: Vec<String>,
}
```

**Default Watched Keys:**
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

## Testing APIs

### Integration Tests

**Test Binaries:**
- `test_integration.rs`: Core functionality testing
- `test_linux_detection.rs`: Linux-specific detection validation
- `test_mac_detection.rs`: macOS-specific detection validation  
- `test_dns_anomaly_detection.rs`: DNS detection system testing

**Example Test Usage:**
```bash
# Run Linux detection tests
cargo run --bin test_linux_detection

# Run DNS anomaly detection tests  
cargo run --bin test_dns_anomaly_detection
```

## Error Handling

The crate uses comprehensive error handling with `anyhow` and `thiserror`:

```rust
use anyhow::{Result, Context};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),
    
    #[error("Storage error: {0}")]
    Storage(#[from] std::io::Error),
    
    #[error("Network error: {0}")]
    Network(String),
}
```

## Performance Considerations

### Memory Usage
- **Target**: 80-120 MB under normal load
- **Deduplication Overhead**: Max 300KB
- **Event Buffers**: Configurable batch sizes (default: 1000 events)

### CPU Usage
- **Collectors**: Configurable scan intervals (default: 1000ms)
- **Batch Processing**: Async I/O to minimize blocking
- **Compression**: Background gzip compression

### Storage
- **Compression**: 90%+ reduction with gzip
- **Retention**: Configurable cleanup (default: 30 days)
- **File Rotation**: Size-based and time-based rotation

## Best Practices

### Configuration
1. Adjust scan intervals based on system load
2. Use path filtering to reduce noise
3. Configure appropriate retention policies
4. Enable compression for production use

### Development
1. Use `RUST_LOG=debug` for development
2. Monitor memory usage with `max_memory_usage_mb`
3. Test platform-specific features on target platforms
4. Validate configuration before deployment

### Production Deployment
1. Run with minimal privileges
2. Monitor log file growth
3. Set up log rotation
4. Configure appropriate storage limits
5. Test backup and recovery procedures
