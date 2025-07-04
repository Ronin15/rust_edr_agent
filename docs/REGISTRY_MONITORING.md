# Registry Monitoring Documentation

## Overview

The Registry Collector is part of our EDR agent's comprehensive monitoring capabilities, designed specifically to track changes within the Windows Registry in real-time. It integrates seamlessly with the agent's smart deduplication system to provide efficient, high-fidelity security monitoring.

**Platform Support**: This feature is **Windows-only** and will be automatically disabled on Linux and macOS systems.

## Features

- **Real-Time Detection**: Uses Windows `RegNotifyChangeKeyValue` API for immediate registry change notifications
- **Smart Deduplication**: Integrated with centralized deduplication system to reduce noise by 85-90% while preserving security fidelity
- **Registry-Specific Noise Filtering**: Intelligent rate limiting for known noisy registry keys (Services, Group Policy, etc.)
- **Comprehensive Monitoring**: Tracks key creation, modification, and deletion with detailed value enumeration
- **Asynchronous Processing**: Utilizes Tokio for non-blocking, efficient event handling and processing
- **Memory Bounded**: Efficient state tracking with automatic cleanup to prevent memory exhaustion
- **Configurable**: Easily extendable via the `config.yaml` file to support additional keys and customization

## Configuration

To enable and configure the Registry Collector, modify the `config.yaml` file under the `registry_monitor` section:

```yaml
registry_monitor:
  enabled: true
  watched_keys: []  # Empty = use security-focused defaults
  # Optional: Custom keys to monitor
  # watched_keys:
  #   - HKEY_LOCAL_MACHINE\SOFTWARE\Classes
  #   - HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  #   - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  #   - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
```

### Default Monitored Keys

When `watched_keys` is empty, the agent monitors these security-critical registry locations:

```yaml
Default Security Keys:
  - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  - HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
  - HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
  - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
  - HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
  - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
  - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
  - HKEY_LOCAL_MACHINE\SOFTWARE\Classes
  - HKEY_LOCAL_MACHINE\SAM
```

## Usage

Once configured, the registry monitoring will begin automatically upon starting the EDR agent. The collector actively monitors the specified registry keys and generates structured events for any modifications.

### Event Types Generated

- **RegistryKeyCreated**: New registry keys or subkeys detected
- **RegistryKeyModified**: Changes to existing registry values
- **RegistryKeyDeleted**: Registry key or value deletions

### Event Structure

```json
{
  "id": "69fd59ed-4ff0-469d-b01d-27a94a0f9742",
  "timestamp": "2025-07-04T22:53:44.181444900Z",
  "event_type": "RegistryKeyCreated",
  "source": "registry_monitor",
  "hostname": "WIN-HOSTNAME",
  "agent_id": "7356e5a9-eeea-45a8-ae61-3c184c3a182a",
  "data": {
    "Registry": {
      "key_path": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\ExampleService",
      "value_name": "ServiceType",
      "value_type": "REG_DWORD",
      "value_data": "32 (0x00000020)",
      "old_value_data": null,
      "process_id": 1234,
      "process_name": "services.exe"
    }
  }
}
```

## Smart Deduplication Integration

The registry collector integrates with the agent's centralized smart deduplication system:

### Deduplication Features
- **Registry-specific rate limiting**: 15 events per minute for registry changes
- **Windows noise filtering**: Automatic reduction for known noisy registry paths
- **Content-based deduplication**: Identical changes are deduplicated based on key path, value name, and data
- **Security-first preservation**: Critical registry changes are never suppressed

### Noise Reduction for Common Paths
```yaml
Windows Noisy Registry Paths (1/3 normal rate):
  - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
  - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy
  - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings
  - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager
  - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer
```

## Monitoring and Analysis

### View Registry Events
```bash
# Find registry events in data files
gunzip -c data/*.json.gz | jq '.events[] | select(.event_type | contains("Registry"))'

# Count registry events by type
gunzip -c data/*.json.gz | jq -r '.events[] | select(.event_type | contains("Registry")) | .event_type' | sort | uniq -c

# Monitor specific registry key
gunzip -c data/*.json.gz | jq '.events[] | select(.data.Registry.key_path | contains("Run"))'
```

### Real-time Monitoring
```bash
# Watch for registry changes in logs (debug level)
RUST_LOG=debug cargo run | grep -i registry

# Monitor registry events as they're generated
tail -f logs/*.log | grep "Registry"
```

## Performance Characteristics

### Resource Usage
- **Memory overhead**: Minimal (~100KB for state tracking)
- **CPU impact**: Low (Windows API-based notifications)
- **Event volume**: Typically 50-200 registry events per hour on active systems
- **Deduplication effectiveness**: 85-90% noise reduction while preserving security events

### Scalability
- **Monitored keys**: Supports monitoring 10+ registry keys simultaneously
- **Event throughput**: Handles high-frequency registry changes without data loss
- **Memory bounds**: Automatic cleanup prevents memory exhaustion

## Security Considerations

### Important Registry Areas Monitored
1. **Startup persistence**: Run/RunOnce keys for malware persistence
2. **Service installation**: Services key for new service creation
3. **File associations**: Classes key for malicious file type registration
4. **System configuration**: Critical system settings changes
5. **User account data**: SAM changes indicating account manipulation

### Threat Detection Capabilities
- **Persistence mechanisms**: Detects malware installing startup entries
- **Service installation**: Monitors for malicious service creation
- **File type hijacking**: Detects changes to file associations
- **Configuration tampering**: Alerts on critical system setting changes

## Troubleshooting

### Common Issues

1. **No registry events generated**:
   ```bash
   # Check if registry monitoring is enabled
   grep "registry_monitor" config.yaml
   
   # Verify Windows platform detection
   grep "Starting Windows registry monitoring" logs/*.log
   ```

2. **High event volume**:
   ```bash
   # Check deduplication effectiveness
   gunzip -c data/*.json.gz | jq '.events[] | select(.event_type | contains("Registry")) | .data.Registry.key_path' | sort | uniq -c
   
   # Adjust registry rate limiting in deduplication config
   ```

3. **Permission errors**:
   ```bash
   # Check Windows event logs for registry access denials
   # Ensure agent runs with appropriate privileges
   ```

### Debug Mode
```bash
# Enable detailed registry monitoring logs
RUST_LOG=edr_agent::collectors::registry=debug cargo run

# Watch registry change notifications
RUST_LOG=debug cargo run | grep -E "(Registry change detected|key created|key modified)"
```

For more detailed analysis and advanced configuration, refer to the [Smart Deduplication](SMART_DEDUPLICATION.md) and [Performance Analysis](PERFORMANCE.md) documentation.
