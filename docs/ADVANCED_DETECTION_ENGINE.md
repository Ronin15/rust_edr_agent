# Advanced Detection Engine

## Overview

The EDR Agent now includes advanced detection capabilities focused on reducing false positives and enhancing context-aware monitoring.

## Features

### 🔍 Cross-Platform Process Injection Detection
- **Real-time detection** of suspicious process names and file operations.
- Monitors for unusual process behavior and path anomalies.

### 🧠 Context-Aware Risk Scoring
- Dynamic risk adjustment based on:
  - Process execution location.
  - Ancestry and parent-child relationships.
- Helps identify legitimate vs unauthorized system activities.

### ⚡ Frequency-Based Alert Suppression
- Suppresses duplicate alerts for recurring benign activities.
- Reduces alert fatigue and highlights genuine threats.
- Utilizes a cooldown multiplier to gradually reduce alert risk.

### 🛡️ System Process Context Recognition
- Profiles known system processes to differentiate between normal and suspicious activity.
- Incorporates baseline rules for 
  - macOS (`mdworker_shared`, `sharingd`)
  - Windows (`svchost`, `explorer`)
  - Linux (`systemd`, `init`)

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

