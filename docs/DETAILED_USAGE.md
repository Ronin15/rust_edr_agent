# Detailed Usage of EDR Agent

## Running the Agent

### Standard Operation
```bash
# Run in development mode (with debug logs)
RUST_LOG=debug cargo run

# Run with info level logging (recommended)
RUST_LOG=info cargo run

# Run the release build (production)
cargo build --release
./target/release/edr-agent
```

### Advanced Options
```bash
# Custom configuration file
EDR_CONFIG=/path/to/custom-config.yaml cargo run

# Module-specific logging
RUST_LOG=edr_agent::detectors::behavioral=debug cargo run

# Performance monitoring
RUST_LOG=info cargo run | grep -E '(memory|events|batch)'
```

## What the Agent Does

When running, the EDR agent performs these operations:

### Initialization Phase (0-2 seconds)
1. **Load configuration** from `config.yaml` with platform-specific defaults
2. **Initialize storage manager** with compression and retention settings
3. **Start collector manager** (process, file, network, registry on Windows)
4. **Start detector manager** (behavioral detection, DNS anomaly detection)
5. **Begin event processing pipeline** with batching and deduplication

### Runtime Operations (continuous)
1. **Monitor system activities** across multiple collectors simultaneously
2. **Generate structured events** with full metadata and context
3. **Apply behavioral detection** for threat identification
4. **Deduplicate events** to reduce noise while preserving security fidelity
5. **Compress and store events** as gzipped JSON with automatic rotation
6. **Log activities** with structured logging and daily rotation

## Where to Find Results

### 📊 Event Data
**Location:** `./data/` directory
- Files named: `events_<uuid>.json.gz`
- **Format:** Gzip-compressed JSON with structured event data
- **Content:** Process, file system, and network events
- **Compression:** ~90% size reduction for efficient storage
- **Example:**
  ```json
  {
    "events": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": "2025-06-29T16:47:11.123Z",
        "event_type": "ProcessCreated",
        "source": "process_monitor",
        "hostname": "your-hostname",
        "agent_id": "agent-uuid",
        "data": {
          "Process": {
            "pid": 1234,
            "name": "example_process",
            "path": "/path/to/executable",
            "command_line": "./example --arg",
            "user": "username",
            "start_time": "2025-06-29T16:47:11.000Z",
            "cpu_usage": 2.5,
            "memory_usage": 1048576
          }
        }
      }
    ]
  }
  ```

### 📝 Log Files
**Location:** `./logs/` directory
- Files named: `edr-agent.YYYY-MM-DD.log`
- **Format:** Structured logging with timestamps
- **Content:** Agent status, errors, debug information
- **Levels:** ERROR, WARN, INFO, DEBUG

### 🖥️ Console Output
Real-time logging shows:
- Agent startup status
- Collector initialization
- Event processing
- Error messages and warnings

## Understanding the Configuration

### Key Settings in `config.yaml`:
```yaml
agent:
  collection_interval_ms: 5000    # How often to process events
  max_events_per_batch: 1000      # Max events per JSON file
  max_memory_usage_mb: 512        # Memory limit

collectors:
  process_monitor:
    enabled: true                  # Enable process monitoring
    scan_interval_ms: 1000        # Process scan frequency
    collect_command_line: true     # Include command line args
    collect_environment: false     # Include env variables

storage:
  local_storage:
    enabled: true                  # Enable local JSON storage
    data_directory: "./data"      # Where to store events
    compress_events: true          # Compress event files
  retention_days: 30              # How long to keep events

logging:
  level: "info"                   # Log level (debug/info/warn/error)
  file_path: "./logs/edr-agent.log"
  max_file_size_mb: 100
```

## Monitoring Real Activity

To see the agent detect real system activity:

1. **Start the agent:**
   ```bash
   RUST_LOG=info cargo run
   ```

2. **In another terminal, create some activity:**
   ```bash
   # Start some processes to monitor
   ls -la
   ps aux
   top -l 1
   ```

3. **Check the results:**
   ```bash
   # View latest events
   ls -la data/ | tail -5
   
   # Examine an event file
   gunzip -c data/events_*.json.gz | jq .
   
   # Monitor logs
   tail -f logs/*.log
   ```

## Stopping the Agent
- **Ctrl+C** - Graceful shutdown
- Agent will process remaining events before exiting
- All data is automatically saved

## Troubleshooting

### Common Issues:
1. **Permission errors:** Ensure write access to `./data/` and `./logs/`
2. **High CPU usage:** Adjust `scan_interval_ms` in config
3. **Large files:** Monitor `data/` directory size
4. **No events:** Check if collectors are enabled in config

### Debug Mode:
```bash
# Run with maximum logging
RUST_LOG=debug cargo run

# Check specific module logs
RUST_LOG=edr_agent::collectors::process=debug cargo run
```
