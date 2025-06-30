# Behavioral Detection Engine

## Overview

The EDR Agent features a sophisticated Behavioral Detection Engine that monitors threats across multiple dimensions using platform-aware detection rules. This engine replaced the previous "injection detector" to provide comprehensive behavioral threat analysis.

## Features

### 🔍 Multi-Vector Threat Detection
- **Process Injection Detection**: Linux ptrace sequences, Windows DLL injection, macOS task port manipulation
- **Malicious Shell Activity**: Shell execution from suspicious locations, browser-spawned shells, unusual parent processes
- **Library Loading Attacks**: .so injection on Linux, DLL sideloading on Windows, dylib attacks on macOS
- **Suspicious File Operations**: Executable files in temp directories, browser cache execution
- **Command Line Analysis**: Platform-specific suspicious command patterns

### 🐧 Linux-Specific Detection Capabilities
- **ptrace Injection Monitoring**: Detects `ptrace` → `mmap` → `mprotect` attack sequences
- **Shared Library Attacks**: Monitors for malicious `.so` file loading and `LD_PRELOAD` abuse
- **Shell Execution Analysis**: Detects shells running from `/tmp/`, `/dev/shm/`, browser cache directories
- **System Process Context**: Validates `systemd` and `init` process execution contexts
- **Command Line Patterns**: Monitors for suspicious patterns like `base64`, `ptrace`, `LD_PRELOAD`, `nc -l`

### 🧠 Context-Aware Risk Scoring
- **Dynamic risk adjustment** based on:
  - Process execution location and expected paths
  - Process ancestry and parent-child relationships
  - System process validation (legitimate vs impersonated)
- **Platform-adaptive scoring** that understands OS-specific behaviors
- Helps identify legitimate vs unauthorized system activities

### ⚡ Frequency-Based Alert Suppression
- **Progressive risk reduction** for repeated alerts to minimize false positives
- **Cooldown multipliers** that gradually reduce alert severity for known patterns
- **Per-process type limits** to prevent alert storms from legitimate system activity

### 🛡️ System Process Context Recognition
- **Cross-platform system process profiles**:
  - **Linux**: `systemd`, `init` with expected path validation
  - **macOS**: `mdworker_shared`, `sharingd`, `ReportCrash`
  - **Windows**: System processes (when running on Windows)
- **Expected path validation** with elevated risk for processes in wrong locations
- **Instance count monitoring** to detect process impersonation

## Configuration

### Baselines and Rules
```yaml
detectors:
  injection:
    enabled: true
    alert_threshold: 0.4
    prevention_threshold: 0.8
    track_api_calls: true
    cross_platform_detection: true

    # Frequency limits to prevent alert storms
    frequency_limits:
      mdworker_shared: 5  # max alerts per hour
      sharingd: 3
```

## Integration & Usage

### Integrating with Existing Systems
- Compatible with current EDR systems with JSON output.
- Easily integrates with SIEM tools via structured logs.

### Alert Storage Locations

#### Structured Event Data (Primary Storage)
- **Location**: `data/events_*.json.gz` files
- **Format**: Compressed JSON with complete SecurityAlert events
- **Usage**: Historical analysis, SIEM integration, audit trails
- **Retention**: 30 days (configurable)

#### Log Files (Human-Readable)
- **Location**: `logs/edr-agent.YYYY-MM-DD.log`
- **Format**: Structured JSON logging with emoji indicators
- **Usage**: Real-time monitoring, troubleshooting
- **Rotation**: Daily log files

### Accessing Alerts

#### Query Structured Data
```bash
# View all SecurityAlert events
gunzip -c data/events_*.json.gz | jq '.events[] | select(.event_type == "SecurityAlert")'

# Filter by risk score
gunzip -c data/events_*.json.gz | jq '.events[] | select(.event_type == "SecurityAlert" and (.metadata.risk_score | tonumber) > 0.5)'

# Count by severity
gunzip -c data/events_*.json.gz | jq -r '.events[] | select(.event_type == "SecurityAlert") | .metadata.severity' | sort | uniq -c
```

#### Monitor Real-time Alerts
```bash
# Real-time alert stream
tail -f logs/edr-agent.*.log | grep "SECURITY ALERT"

# Search historical alerts
grep "SECURITY ALERT" logs/edr-agent.*.log
```

## Best Practices

- **Tune baselines** regularly to match environment changes.
- **Monitor alert frequency** to adapt cooldown multipliers.
- **Validate context profiles** to ensure accuracy.

## Future Enhancements

- **Adaptive Machine Learning**: Real-time learning and adaptation based on new threats.
- **Deeper System Integration**: Enhanced visibility across subsystems.

