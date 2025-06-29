# EDR Agent - Quick Usage Guide

## 🚀 Getting Started (30 seconds)

```bash
# 1. Clone and build
git clone https://github.com/Ronin15/rust_edr_agent.git
cd rust_edr_agent
cargo build

# 2. Run the agent
RUST_LOG=info cargo run

# 3. In another terminal, generate some activity
ls -la && ps aux && sleep 2

# 4. Check results
ls -la data/          # See event files
tail logs/*.log       # See log output
```

## 📁 Where to Find Results

| Data Type | Location | Format | Description |
|-----------|----------|--------|-------------|
| **Events** | `./data/*.json.gz` | Compressed JSON | All EDR events (file/network/process) |
| **Logs** | `./logs/*.log` | Text | Agent status & debug info |
| **Config** | `./config.yaml` | YAML | Agent configuration |

## 🔍 Quick Commands

### View Events
```bash
# List event files (newest first)
ls -lt data/

# View latest event file with pretty formatting
ls data/events_*.json.gz | tail -1 | xargs zcat | jq .

# Count total events
zcat data/*.json.gz | jq '.events | length' | paste -sd+ | bc

# Search for specific process
zcat data/*.json.gz | jq '.events[] | select(.data.Process.name == "cargo")'
```

### Monitor in Real-Time
```bash
# Watch agent logs live
tail -f logs/*.log

# Watch new event files being created
watch -n 1 'ls -la data/ | tail -5'

# Monitor specific log level
RUST_LOG=debug cargo run | grep ERROR
```

### Analyze Activity
```bash
# Find all process names seen
zcat data/*.json.gz | jq -r '.events[].data.Process.name' | sort | uniq

# Show events by type
zcat data/*.json.gz | jq -r '.events[].event_type' | sort | uniq -c

# Find high memory usage processes
zcat data/*.json.gz | jq '.events[] | select(.data.Process.memory_usage > 100000000)'
```

## ⚙️ Configuration Quick Reference

Edit `config.yaml` to change behavior:

```yaml
# Make it faster (scan every 500ms)
collectors:
  process_monitor:
    scan_interval_ms: 500

# Reduce storage (100 events per file)
agent:
  max_events_per_batch: 100

# Enable debug logging
logging:
  level: "debug"

# Disable file monitoring (reduce noise)
collectors:
  file_monitor:
    enabled: false
```

## 🐛 Troubleshooting

### No Events Generated?
```bash
# Check if collectors are running
grep "Started collector" logs/*.log

# Verify process monitoring is enabled
grep "process_monitor" config.yaml

# Run with debug logging
RUST_LOG=debug cargo run
```

### Too Many Events?
```bash
# Slow down scanning
# Edit config.yaml: scan_interval_ms: 5000

# Reduce batch size
# Edit config.yaml: max_events_per_batch: 100

# Check disk usage
du -sh data/
```

### Agent Won't Start?
```bash
# Check for permission issues
touch data/test.txt && rm data/test.txt
touch logs/test.log && rm logs/test.log

# Build with verbose output
cargo build --verbose

# Check dependencies
cargo check
```

## 📊 Example Output

### Console Output
```
2025-06-29T16:47:10.434Z  INFO edr_agent: Starting EDR Agent v0.1.0
2025-06-29T16:47:10.437Z  INFO edr_agent: Configuration loaded successfully
2025-06-29T16:47:10.441Z  INFO edr_agent::collectors: Starting 3 collectors
2025-06-29T16:47:10.441Z  INFO edr_agent::collectors: Started collector: process_monitor
```

### Event File Content
```json
{
  "events": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp": "2025-06-29T16:47:11.123456Z",
      "event_type": "ProcessCreated",
      "source": "process_monitor",
      "hostname": "MacBook-Pro",
      "agent_id": "agent-12345",
      "data": {
        "Process": {
          "pid": 1234,
          "name": "cargo",
          "path": "/usr/local/bin/cargo",
          "command_line": "cargo run",
          "cpu_usage": 15.2,
          "memory_usage": 52428800
        }
      }
    }
  ],
  "created_at": "2025-06-29T16:47:11.000000Z",
  "batch_id": "batch-uuid-here"
}
```

## 🎯 Testing Scenarios

### Generate Different Event Types
```bash
# Process events
cargo build &           # Background process
sleep 10 && killall cargo  # Process termination

# CPU intensive (will show in events)
yes > /dev/null &
sleep 5 && killall yes

# Memory intensive
python -c "x = ' ' * (100 * 1024 * 1024); input()" &
```

### Performance Testing
```bash
# High frequency scanning
# Edit config.yaml: scan_interval_ms: 100

# Large batch sizes  
# Edit config.yaml: max_events_per_batch: 5000

# Monitor resource usage
top -pid $(pgrep edr-agent)
```

## 📋 Common Use Cases

### Security Monitoring
- Watch for unusual process names
- Monitor high memory/CPU usage
- Track process command lines
- Detect rapid process creation

### Development Testing
- Monitor build processes
- Track test execution
- Analyze development tools
- Performance profiling

### System Analysis
- Process lifecycle tracking
- Resource usage patterns
- System activity baseline
- Performance bottlenecks

---

**Need help?** Check the full [README.md](../README.md) for detailed documentation!
