# Troubleshooting Guide

## Common Issues and Solutions

### Build and Compilation Issues

#### Error: "cargo: command not found"
**Problem:** Rust/Cargo not installed or not in PATH
**Solution:**
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
cargo --version
```

#### Error: "failed to compile with target feature" 
**Problem:** Missing system dependencies
**Solution:**
```bash
# Linux (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install build-essential pkg-config

# Linux (CentOS/RHEL)
sudo yum groupinstall "Development Tools"
sudo yum install pkgconfig

# macOS
xcode-select --install
```

#### Error: "linking with `cc` failed"
**Problem:** Missing C compiler or linker
**Solution:**
```bash
# Linux
sudo apt-get install gcc

# macOS
# Install Xcode Command Line Tools if not already done
xcode-select --install
```

### Runtime Issues

#### Error: "Permission denied" when accessing directories
**Problem:** Insufficient permissions to access system directories or create files
**Solution:**
```bash
# Ensure write permissions for data and logs directories
mkdir -p data logs
chmod 755 data logs

# Check current user permissions
ls -la data/ logs/

# For system-wide monitoring (advanced), run with appropriate privileges
# Note: Only for development/testing, not recommended for production
sudo ./target/release/edr-agent
```

#### Error: "No such file or directory: config.yaml"
**Problem:** Missing configuration file
**Solution:**
```bash
# Create default configuration
cat > config.yaml << 'EOF'
agent:
  agent_id: "test-agent"
  hostname: "localhost"
  collection_interval_ms: 5000
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
    watched_paths: ["/home", "/tmp"]
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

deduplication:
  enabled: true
  max_memory_usage_kb: 300
  cleanup_interval_seconds: 3600

storage:
  base_path: "./data"
  compression_enabled: true
  max_file_size_mb: 10
  retention_days: 30

network:
  enabled: false

logging:
  level: "info"
  file_rotation: "daily"
EOF
```

### Performance Issues

#### High Memory Usage
**Problem:** Agent consuming excessive memory
**Diagnosis:**
```bash
# Monitor memory usage
ps aux | grep edr-agent
top -p $(pgrep edr-agent)

# Check event batch sizes
grep "batch" logs/*.log
```

**Solutions:**
```yaml
# In config.yaml, reduce batch sizes
agent:
  max_events_per_batch: 500  # Reduce from 1000
  collection_interval_ms: 2000  # Increase interval

# Reduce collector frequency
collectors:
  process_monitor:
    scan_interval_ms: 2000  # Increase from 1000
```

#### High CPU Usage
**Problem:** Agent consuming too much CPU
**Diagnosis:**
```bash
# Monitor CPU usage
top -p $(pgrep edr-agent)
htop -p $(pgrep edr-agent)

# Check scan intervals
grep "scan_interval" config.yaml
```

**Solutions:**
```yaml
# Increase scan intervals to reduce CPU load
collectors:
  process_monitor:
    scan_interval_ms: 5000  # Increase interval
  file_monitor:
    enabled: false  # Temporarily disable if too noisy
```

#### Disk Space Issues
**Problem:** Event files consuming too much disk space
**Diagnosis:**
```bash
# Check data directory size
du -sh data/
ls -lah data/ | head -10

# Check compression status
file data/events_*.json.gz
```

**Solutions:**
```yaml
# Adjust retention and compression settings
storage:
  retention_days: 7  # Reduce from 30
  compression_enabled: true  # Ensure compression is enabled
  max_file_size_mb: 5  # Reduce file size
```

### Event Detection Issues

#### No Events Being Generated
**Problem:** Agent running but no event files created
**Diagnosis:**
```bash
# Check if collectors are enabled
grep "enabled: true" config.yaml

# Check if events are being processed
RUST_LOG=debug cargo run | grep "event"

# Check data directory
ls -la data/
```

**Solutions:**
1. **Enable collectors in config.yaml**
2. **Generate some activity:**
   ```bash
   # In another terminal
   ls -la
   ps aux
   touch /tmp/test_file
   ```
3. **Check permissions:**
   ```bash
   ls -la data/
   touch data/test.txt && rm data/test.txt
   ```

#### Too Many Events (Noise)
**Problem:** Agent generating excessive events
**Diagnosis:**
```bash
# Count events
gunzip -c data/*.json.gz | jq '.events | length' | paste -sd+ | bc

# Check event types
gunzip -c data/*.json.gz | jq -r '.events[].event_type' | sort | uniq -c
```

**Solutions:**
```yaml
# Enable deduplication
deduplication:
  enabled: true

# Reduce file monitoring noise
collectors:
  file_monitor:
    ignored_extensions: [".tmp", ".log", ".cache", ".swp"]
    watched_paths: ["/home/user/important"]  # Reduce scope
```

#### Behavioral Detection Not Working
**Problem:** No security alerts being generated
**Diagnosis:**
```bash
# Check if behavioral detector is enabled
grep -A 10 "behavioral:" config.yaml

# Look for security alerts
grep "SECURITY ALERT" logs/*.log
gunzip -c data/*.json.gz | jq '.events[] | select(.event_type == "SecurityAlert")'

# Test with detection binary
cargo run --bin test_linux_detection
```

**Solutions:**
1. **Enable behavioral detection:**
   ```yaml
   detectors:
     behavioral:
       enabled: true
       alert_threshold: 0.5  # Lower threshold for more sensitivity
   ```

2. **Generate test activity:**
   ```bash
   # Create suspicious activity
   cp /bin/bash /tmp/suspicious_shell
   /tmp/suspicious_shell -c "echo test"
   rm /tmp/suspicious_shell
   ```

### Platform-Specific Issues

#### Linux: "Permission denied" for /proc access
**Problem:** Cannot read process information
**Solution:**
```bash
# Check /proc access
ls -la /proc/

# For development, run with appropriate permissions
# Note: Consider security implications
sudo ./target/release/edr-agent
```

#### Windows: Registry monitoring not working
**Problem:** Registry events not being detected on Windows
**Solution:**
```yaml
# Enable registry monitoring in config.yaml
collectors:
  registry_monitor:
    enabled: true
    watched_keys:
      - "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
```

#### macOS: File monitoring permission issues
**Problem:** File system access denied on macOS
**Solution:**
1. Grant Full Disk Access to Terminal app
2. System Preferences → Security & Privacy → Privacy → Full Disk Access
3. Add Terminal or your IDE to the allowed applications

### Logging and Debugging

#### Enable Debug Logging
```bash
# Full debug logging
RUST_LOG=debug cargo run

# Module-specific debugging
RUST_LOG=edr_agent::collectors=debug cargo run
RUST_LOG=edr_agent::detectors::behavioral=debug cargo run
RUST_LOG=edr_agent::storage=debug cargo run
```

#### Common Log Messages and Meanings

**INFO Messages:**
- `"Starting EDR Agent"` - Normal startup
- `"Collectors started"` - All collectors initialized
- `"Stored events batch"` - Events saved successfully

**WARN Messages:**
- `"High memory usage detected"` - Consider reducing batch sizes
- `"Event processing queue full"` - Increase processing capacity

**ERROR Messages:**
- `"Failed to initialize collector"` - Check permissions and dependencies
- `"Storage error"` - Check disk space and permissions
- `"Configuration error"` - Validate config.yaml syntax

### Data Analysis Issues

#### Cannot Read Event Files
**Problem:** Event files are compressed and unreadable
**Solution:**
```bash
# Decompress and view events
gunzip -c data/events_*.json.gz | jq .

# View latest events
ls data/events_*.json.gz | tail -1 | xargs gunzip -c | jq '.events[-5:]'

# Install jq if missing
# Ubuntu/Debian: sudo apt-get install jq
# macOS: brew install jq
# CentOS/RHEL: sudo yum install jq
```

#### Cannot Parse JSON
**Problem:** JSON parsing errors when analyzing events
**Solution:**
```bash
# Validate JSON format
gunzip -c data/events_*.json.gz | jq . > /dev/null

# Check for truncated files
ls -la data/events_*.json.gz

# Check if agent shutdown properly
grep "shutdown" logs/*.log
```

### Testing and Validation

#### Integration Tests Failing
**Problem:** Test binaries not running correctly
**Solution:**
```bash
# Run individual tests
cargo run --bin test_integration
cargo run --bin test_linux_detection
cargo run --bin test_dns_anomaly_detection

# Check test output for specific errors
cargo run --bin test_linux_detection 2>&1 | grep -E "(ERROR|WARN)"
```

#### DNS Detection Tests Not Working
**Problem:** DNS anomaly detection tests failing
**Solution:**
```bash
# Check network connectivity
ping 8.8.8.8

# Run DNS tests with debug logging
RUST_LOG=debug cargo run --bin test_dns_anomaly_detection

# Generate manual DNS activity
for i in {1..10}; do nslookup test$i.example.com & done
```

## Getting Help

### Diagnostic Information Collection
When reporting issues, include:

```bash
# System information
uname -a
cargo --version
rustc --version

# Agent configuration
cat config.yaml

# Recent logs
tail -50 logs/*.log

# Data directory status
ls -la data/
du -sh data/

# Memory and CPU usage
ps aux | grep edr-agent
```

### Contact and Support
1. Check the [Development Guide](DEVELOPMENT.md) for implementation details
2. Review the [API Reference](API_REFERENCE.md) for module documentation
3. Check [TODO List](TODO.md) for known limitations
4. File issues with complete diagnostic information

### Performance Tuning Quick Reference
```yaml
# For high-performance systems
agent:
  collection_interval_ms: 500
  max_events_per_batch: 2000

# For resource-constrained systems
agent:
  collection_interval_ms: 5000
  max_events_per_batch: 100

collectors:
  process_monitor:
    scan_interval_ms: 2000
  file_monitor:
    enabled: false  # Disable if too noisy
```
