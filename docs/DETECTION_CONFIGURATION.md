# Detection Engine Configuration Guide

## Overview

This guide covers configuration options for the advanced detection engine features.

## Detection Configuration

### Basic Settings
```yaml
detectors:
  injection:
    enabled: true                    # Enable detection engine
    scan_interval_ms: 2000          # How often to scan for threats
    alert_threshold: 0.4            # Minimum risk score to generate alerts
    prevention_threshold: 0.8       # Risk score for blocking (future feature)
    track_api_calls: true           # Monitor suspicious API usage
    monitor_memory_operations: true # Track memory modifications
    monitor_thread_operations: true # Monitor thread manipulations
    cross_platform_detection: true  # Enable cross-platform rules
```

## Context-Aware Risk Scoring

### How Risk Scoring Works
The system calculates risk based on:
- **Base Risk**: Initial assessment of suspicious activity
- **Context Adjustment**: Location, process ancestry, expected behavior
- **Frequency Reduction**: Progressive risk reduction for repeated alerts

### Risk Score Ranges
- `0.0 - 0.3`: Low risk (informational)
- `0.4 - 0.6`: Medium risk (investigation recommended)
- `0.7 - 0.8`: High risk (immediate attention)
- `0.9 - 1.0`: Critical risk (potential active threat)

## Frequency-Based Alert Tuning

### System Process Examples
The detection engine includes built-in profiles for common system processes:

#### macOS System Processes
```yaml
# These are handled automatically by the detection engine
mdworker_shared:
  max_alerts_per_hour: 5
  cooldown_multiplier: 0.5         # Each subsequent alert = 50% of previous
  expected_paths:
    - "/usr/libexec/"
    - "/System/Library/Frameworks/CoreServices.framework/"

sharingd:
  max_alerts_per_hour: 2
  cooldown_multiplier: 0.3
  expected_paths:
    - "/usr/libexec/"
    - "/System/Library/"
```

#### Windows System Processes (configured automatically)
- `svchost.exe`: Expected in `%SystemRoot%\System32\`
- `explorer.exe`: Expected in Windows directory
- `winlogon.exe`: Expected in System32

#### Linux System Processes (configured automatically)
- `systemd`: Expected in `/usr/lib/systemd/` or `/lib/systemd/`
- `kworker`: Kernel worker threads
- `ksoftirqd`: Kernel interrupt handlers

## Alert Severity Mapping

### Dynamic Severity Assignment
```yaml
# These thresholds are applied automatically
severity_thresholds:
  low: 0.0 - 0.39
  medium: 0.4 - 0.69
  high: 0.7 - 0.89
  critical: 0.9 - 1.0
```

## File Path Analysis

### Suspicious Path Detection
The engine monitors for suspicious file operations in:
- Temporary directories (`/tmp/`, `%TEMP%`)
- User-writable system locations
- Hidden directories and files
- Unusual executable locations

### Context-Aware File Analysis
```yaml
# Automatically configured path contexts
file_contexts:
  biome_tmp:                       # Code formatter temp files
    pattern: "/Library/Biome/tmp/"
    max_alerts_per_hour: 3
    risk_reduction: 0.6
  
  zsh_tmp:                         # Shell temporary files
    pattern: "/private/tmp/zsh*"
    max_alerts_per_hour: 5
    risk_reduction: 0.5
```

## Monitoring and Tuning

### Log Analysis
Monitor detection effectiveness:
```bash
# View risk score distribution
grep "SECURITY ALERT" logs/edr-agent.log | grep -o "Risk: [0-9.]*" | sort | uniq -c

# Count alerts by type
grep "SECURITY ALERT" logs/edr-agent.log | cut -d':' -f4 | sort | uniq -c

# Monitor frequency limiting effectiveness
grep "Risk: 0\." logs/edr-agent.log | wc -l  # Suppressed alerts
```

### Performance Tuning
```yaml
# Adjust these settings based on your environment
detectors:
  injection:
    scan_interval_ms: 1000    # More frequent scanning (higher CPU)
    alert_threshold: 0.3      # More sensitive (more alerts)
    alert_threshold: 0.6      # Less sensitive (fewer alerts)
```

## Environment-Specific Tuning

### Development Environment
```yaml
detectors:
  injection:
    alert_threshold: 0.5      # Reduce noise from dev tools
    scan_interval_ms: 5000    # Less frequent scanning
```

### Production Environment
```yaml
detectors:
  injection:
    alert_threshold: 0.3      # More sensitive detection
    scan_interval_ms: 1000    # Faster response time
```

### High-Security Environment
```yaml
detectors:
  injection:
    alert_threshold: 0.2      # Very sensitive
    prevention_threshold: 0.6 # Lower blocking threshold
    monitor_memory_operations: true
    monitor_thread_operations: true
```

## Troubleshooting

### Common Issues

#### Too Many False Positives
```yaml
# Increase threshold or add frequency limits
detectors:
  injection:
    alert_threshold: 0.5      # Raise from 0.4
```

#### Missing Real Threats
```yaml
# Lower threshold and review context rules
detectors:
  injection:
    alert_threshold: 0.3      # Lower from 0.4
```

#### High CPU Usage
```yaml
# Reduce scanning frequency
detectors:
  injection:
    scan_interval_ms: 3000    # Increase from 2000
```

### Validation Commands
```bash
# Test configuration syntax
./target/release/edr-agent --validate-config

# Monitor resource usage
top -p $(pgrep edr-agent)

# View detection statistics
grep "events processed" logs/edr-agent.log | tail -5
```

## Best Practices

1. **Start Conservative**: Begin with higher thresholds and adjust down
2. **Monitor Logs**: Regularly review alert patterns and adjust
3. **Environment-Specific**: Tune for your specific software stack
4. **Regular Review**: Update baselines as environment changes
5. **Test Changes**: Validate configuration changes in non-production first

## Advanced Configuration

### Custom Process Profiles
For custom applications, you can add similar profiling by monitoring the detection patterns and adjusting the built-in rules accordingly.

### Integration with SIEM
The structured JSON output integrates seamlessly with SIEM tools:
```bash
# Forward to syslog
tail -f logs/edr-agent.log | grep "SECURITY ALERT" | logger

# Export to JSON for analysis
grep "SECURITY ALERT" logs/edr-agent.log | jq '.' > security_alerts.json
```
