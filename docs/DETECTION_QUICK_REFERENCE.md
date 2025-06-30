# Detection Engine Quick Reference

## 🚀 Quick Start

### Enable Detection Engine
```yaml
# config.yaml
detectors:
  injection:
    enabled: true
    alert_threshold: 0.4
```

### View Real-time Alerts
```bash
# Console output
./target/release/edr-agent

# Log monitoring
tail -f logs/edr-agent.log | grep "SECURITY ALERT"
```

### Access Stored Alerts
```bash
# View all SecurityAlert events (structured data)
gunzip -c data/events_*.json.gz | jq '.events[] | select(.event_type == "SecurityAlert")'

# Filter alerts by risk score
gunzip -c data/events_*.json.gz | jq '.events[] | select(.event_type == "SecurityAlert" and (.metadata.risk_score | tonumber) > 0.5)'

# Count alerts by severity
gunzip -c data/events_*.json.gz | jq -r '.events[] | select(.event_type == "SecurityAlert") | .metadata.severity' | sort | uniq -c

# Search for specific alert types
gunzip -c data/events_*.json.gz | jq '.events[] | select(.event_type == "SecurityAlert" and (.data.System.description | contains("mdworker_shared")))'
```

## 🔍 Key Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Context-Aware Scoring** | Risk scores adjust based on process location | Reduces false positives |
| **Frequency Suppression** | Repeated alerts get progressively lower scores | Prevents alert fatigue |
| **System Process Profiling** | Known system processes get baseline treatment | Focuses on real threats |

## ⚙️ Quick Configuration

### Sensitivity Levels
```yaml
# High sensitivity (more alerts)
alert_threshold: 0.3

# Balanced (recommended)
alert_threshold: 0.4

# Low sensitivity (fewer alerts)
alert_threshold: 0.6
```

### Common Adjustments
```yaml
detectors:
  injection:
    scan_interval_ms: 2000      # Scan frequency
    alert_threshold: 0.4        # Sensitivity
    cross_platform_detection: true
```

## 📊 Alert Interpretation

### Risk Score Ranges
- **0.0-0.3**: 🟢 Low (Info only)
- **0.4-0.6**: 🟡 Medium (Investigate)
- **0.7-0.8**: 🟠 High (Priority)
- **0.9-1.0**: 🔴 Critical (Immediate)

### Example Alert
```
🔶 MEDIUM SECURITY ALERT: Suspicious process name: mdworker_shared (Risk: 0.3)
Process mdworker_shared (PID: 1234) has a suspicious name
Recommended Actions: ["Investigate process context", "Check for additional indicators"]
```

## 🔧 Troubleshooting

### Too Many Alerts?
```yaml
# Increase threshold
alert_threshold: 0.5

# Or check for legitimate processes
# (System automatically learns patterns)
```

### Missing Threats?
```yaml
# Decrease threshold
alert_threshold: 0.3

# Enable more monitoring
monitor_memory_operations: true
```

### Performance Issues?
```yaml
# Reduce scan frequency
scan_interval_ms: 5000
```

## 📈 Monitoring Commands

```bash
# Alert volume
grep "SECURITY ALERT" logs/*.log | wc -l

# Risk score distribution  
grep -o "Risk: [0-9.]*" logs/*.log | sort | uniq -c

# Suppressed alerts (frequency limiting working)
grep "Risk: 0\." logs/*.log | wc -l

# Process-specific alerts
grep "mdworker_shared" logs/*.log | grep "SECURITY ALERT"
```

## 🎯 Best Practices

1. **Start Conservative**: Use `alert_threshold: 0.5` initially
2. **Monitor for 24h**: Observe patterns before tuning
3. **Environment-Specific**: Adjust for development vs production
4. **Review Weekly**: Check alert patterns and adjust
5. **Document Changes**: Note what works for your environment

## 🔗 Full Documentation

- [Advanced Detection Engine](ADVANCED_DETECTION_ENGINE.md)
- [Configuration Guide](DETECTION_CONFIGURATION.md)
- [Main README](../README.md)
