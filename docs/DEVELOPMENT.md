# Development Guide

## Prerequisites

- **Rust 1.60+** (2021 edition) - Uses modern async/await patterns
- **Cargo** (comes with Rust)
- Platform-specific requirements:
  - **Windows**: Windows SDK for registry monitoring and process APIs
  - **Linux**: procfs, ptrace, and system call monitoring capabilities
  - **macOS**: Full compatibility with all core features
- **System Dependencies**:
  - `pkg-config` (Linux/macOS)
  - Network access for DNS monitoring tests

## Quick Start

### Building
```bash
git clone <your-repo-url>
cd edr_agent
cargo build
```

### Running
```bash
# Run with default configuration
cargo run

# Or build release version
cargo build --release
./target/release/edr-agent
```

### Configuration
Edit `config.yaml` to customize the agent behavior:
- Adjust collection intervals
- Enable/disable specific collectors
- Configure storage settings (compression, retention)
- Adjust logging levels and file rotation

## Architecture

```
                          ┌──────────────────────────────┐
                          │           Agent Core         │
                          │    (Orchestration & Control) │
                          └───────────────┬──────────────┘
                                          │
          ┌───────────────────────────────┼─────────────────────────────┐
          │                               │                             │
          ▼                               ▼                             ▼
 ┌───────────────────┐          ┌───────────────────┐         ┌────────────────┐
 │ Collectors        │          │ Detectors         │         │ Events System  │
 │ Manager           │          │ Manager           │         │                │
 └──────┬────────────┘          └──────────┬────────┘         └───────┬────────┘
        │                                   │                          │
 ┌──────▼───────┐                  ┌────────▼─────────┐          ┌─────▼───────┐
 │Process       │                  │Injection         │          │Batch         │
 │Collector     │                  │Detector          │          │Processing    │
 │File Collector│                  │Registry          │          │Queue         │
 │Network       │                  │Detector          │          │              │
 │Collector     │                  └──────┬───────────┘          └──────────────┘
 │Registry      │                         │
 │Collector     │                 Other Detectors
 └──────────────┘                 (Planned)

 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Config Mgmt  │        │ Storage Mgmt │        │ Network Mgmt │
 │              │        │ (Compression)│        │ (Remote)     │
 │              │        │              │        │ [STUB]       │
 └──────────────┘        └──────────────┘        └──────────────┘
```

### Core Components

- **Agent Core**: Orchestrates all components and manages lifecycle
- **Collectors**: Modular monitoring components (process, file, network, registry)
- **Detectors**: Threat detection engines (behavioral, registry)
- **Events**: Unified event format and processing pipeline
- **Storage**: Local event storage with configurable retention and compression
- **Network**: Remote server communication (stub implementation)
- **Configuration**: YAML-based configuration management

## Project Structure

### Source Code (`src/`)
```
src/
├── bin/
│   ├── test_integration.rs          # Integration test binary
│   └── test_linux_detection.rs      # Linux detection test binary
├── collectors/                      # Data collection modules
│   ├── manager.rs                   # Collector orchestration (COMPLETE)
│   ├── process.rs                   # Process monitoring (COMPLETE)
│   ├── file.rs                      # File system monitoring (COMPLETE)
│   ├── network.rs                   # Network monitoring (COMPLETE)
│   └── registry.rs                  # Registry monitoring (COMPLETE)
├── detectors/                       # Threat detection modules
│   ├── manager.rs                   # Detection engine manager (COMPLETE)
│   ├── behavioral.rs                # Behavioral threat detection (COMPLETE)
│   └── registry.rs                  # Registry threat detection (COMPLETE)
├── edr_main.rs                      # Application entry point
├── lib.rs                           # Library exports and module definitions
├── agent.rs                         # Core agent implementation (COMPLETE)
├── config.rs                        # Configuration management (COMPLETE)
├── events.rs                        # Event types and handling (COMPLETE)
├── storage.rs                       # Local storage with compression (COMPLETE)
├── network.rs                       # Network communication (STUB)
├── utils.rs                         # Utility functions (COMPLETE)
└── config.yaml                      # Default configuration template
```

### Documentation (`docs/`)
```
docs/
├── ADVANCED_DETECTION_ENGINE.md      # Detection engine documentation
├── COMPRESSION.md                    # Storage compression guide
├── DETAILED_USAGE.md                 # Comprehensive usage guide
├── DETECTION_CONFIGURATION.md       # Detection system configuration
├── DETECTION_QUICK_REFERENCE.md     # Quick detection setup
├── DEVELOPMENT.md                    # This file - development guide
├── LINUX_DETECTION.md               # Linux-specific detection capabilities
├── PERFORMANCE.md                   # Performance analysis and benchmarks
├── REGISTRY_MONITORING.md           # Registry monitoring and detection guide
├── TODO.md                          # Development roadmap and planned features
└── USAGE.md                         # Basic usage guide
```

## Building for Development

```bash
# Debug build with logs
RUST_LOG=debug cargo run

# Check for issues
cargo clippy

# Format code
cargo fmt

# Run tests (when implemented)
cargo test

# Build release version
cargo build --release
```

## Implementation Status

### ✅ Fully Implemented Features

#### Core Architecture 
- **Agent Core (`agent.rs`)**: Complete async orchestration with tokio runtime
- **Event Processing Pipeline**: Batched event processing with configurable intervals
- **Graceful Shutdown**: SIGINT handling with proper resource cleanup
- **Error Handling**: Comprehensive error propagation with anyhow and thiserror

#### Data Collection System
- **Process Collector**: Real-time process monitoring with:
  - Process creation/termination/modification events
  - CPU and memory usage tracking
  - Command line and environment variable capture
  - Parent-child process relationships
- **File Collector**: File system monitoring with:
  - Real-time file change detection using `notify` crate
  - SHA-256 hash calculation for integrity monitoring
  - Platform-specific path filtering
  - Configurable file size limits and extension filtering
- **Network Collector**: Network monitoring with:
  - Connection tracking via system tools (netstat/lsof)
  - DNS query monitoring and correlation
  - Protocol detection and process mapping

#### Threat Detection Engines
- **Behavioral Detector**: Advanced threat detection with:
  - **Process Injection Detection**: Ptrace, DLL injection, memory manipulation
  - **Cross-Platform Rules**: Linux, Windows, macOS-specific detection patterns
  - **Risk Scoring**: Dynamic risk calculation with context awareness
  - **System Process Recognition**: Baseline understanding of legitimate processes
  - **Path-Based Analysis**: Suspicious location detection (/tmp, /dev/shm, cache dirs)
  - **Command Line Analysis**: Injection pattern and malicious command detection
- **DNS Anomaly Detector**: Comprehensive DNS threat detection with:
  - **High-Frequency Query Detection**: Rate limiting and threshold monitoring
  - **Suspicious Domain Patterns**: DGA, base64, free TLD detection
  - **DNS Tunneling Detection**: TXT record analysis, large response detection
  - **C2 Communication Detection**: Beaconing pattern analysis
  - **Data Exfiltration Monitoring**: Volume-based detection algorithms
  - **Smart Alert Deduplication**: Frequency-based alert suppression

#### Storage and Performance
- **Storage Manager**: Production-ready storage with:
  - **Gzip Compression**: 90%+ compression ratio
  - **Automatic Cleanup**: Configurable retention policies
  - **Batch Processing**: Efficient I/O with configurable batch sizes
- **Deduplication Engine**: Intelligent noise reduction with:
  - **Security-First Approach**: Never deduplicates critical security events
  - **Type-Based Rules**: Different limits for different event types
  - **Memory Bounded**: Hard limits prevent memory exhaustion (max 300KB)
  - **Time-Window Management**: Hourly tracking with automatic cleanup

#### Configuration and Logging
- **Configuration System**: YAML-based configuration with:
  - **Platform-Specific Defaults**: Automatic platform detection and filtering
  - **Validation**: Type checking and constraint validation
  - **Hot Reload Support**: Infrastructure ready for runtime updates
- **Logging System**: Production logging with:
  - **Structured JSON Logging**: Machine-readable log format
  - **File Rotation**: Daily rotation with automatic cleanup
  - **Console Output**: Real-time console logging with level filtering
  - **Environment-Based Filtering**: RUST_LOG support

### 🔄 Partially Implemented

#### Windows-Specific Features
- **Registry Monitoring**: Complete implementation with conditional compilation
  - Real-time registry change detection
  - Configurable key watching
  - Windows-only compilation via cfg attributes

#### Network Communication
- **Network Manager**: Stub implementation ready for:
  - Remote server communication
  - Event transmission
  - Configuration updates
  - Health reporting

#### Testing Framework
- **Integration Tests**: Basic test binaries for:
  - Linux detection capabilities (`test_linux_detection.rs`)
  - macOS detection capabilities (`test_mac_detection.rs`) 
  - DNS anomaly detection (`test_dns_anomaly_detection.rs`)
  - Core integration testing (`test_integration.rs`)

### 📋 Future Enhancements

#### Security Hardening
- Input validation and sanitization
- Privilege separation and capability-based security
- Event signing and tamper detection
- Anti-debugging and self-protection

#### Performance and Scale
- Adaptive batching based on system load
- Memory pressure detection and management
- High-throughput optimization for enterprise environments
- Streaming compression for large event volumes

#### Advanced Analytics
- Machine learning-based anomaly detection
- Event correlation and timeline analysis
- MITRE ATT&CK technique mapping
- Threat intelligence feed integration

## Development Workflow

### Setting Up Development Environment

1. **Clone Repository**
   ```bash
   git clone <repo-url>
   cd edr_agent
   ```

2. **Install Dependencies**
   ```bash
   # Dependencies are managed by Cargo
   cargo check
   ```

3. **Verify Setup**
   ```bash
   # Run in debug mode
   RUST_LOG=info cargo run
   ```

### Code Quality Tools

```bash
# Linting
cargo clippy -- -D warnings

# Formatting
cargo fmt --check

# Security audit (optional)
cargo audit

# Documentation generation
cargo doc --open
```

### Testing Approach

```bash
# Unit tests (when available)
cargo test

# Integration test
cargo run --bin test_integration

# Linux detection test
cargo run --bin test_linux_detection

# Manual testing with activity generation
ls -la && ps aux && sleep 2
```

## Contribution Guidelines

### Code Standards
- Follow Rust idioms and best practices
- Use `clippy` for linting compliance
- Format code with `rustfmt`
- Include proper error handling
- Add documentation for public APIs

### Development Process
1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Implement changes with proper error handling**
4. **Add tests** (when testing framework is available)
5. **Run quality checks**
   ```bash
   cargo clippy
   cargo fmt
   cargo test
   ```
6. **Submit a pull request**

### Performance Considerations
- Monitor memory usage during development
- Test with realistic workloads
- Profile CPU usage for hot paths
- Validate compression efficiency
- Check for memory leaks in long-running tests

## Debugging

### Debug Configuration
```bash
# Full debug logging
RUST_LOG=debug cargo run

# Module-specific logging
RUST_LOG=edr_agent::collectors::process=debug cargo run

# Trace-level logging (very verbose)
RUST_LOG=trace cargo run
```

### Common Debug Scenarios

1. **Event Processing Issues**
   - Check collector status in logs
   - Verify configuration is loaded correctly
   - Monitor event generation rates

2. **Performance Problems**
   - Use `cargo flamegraph` for profiling
   - Monitor memory with `htop` or Activity Monitor
   - Check disk I/O patterns

3. **Platform-Specific Issues**
   - Test on target platform
   - Check platform-specific dependencies
   - Validate file permissions

## Next Steps

- See [TODO.md](TODO.md) for planned enhancements
- Check [Performance Analysis](PERFORMANCE.md) for optimization opportunities
- Review [Advanced Detection Engine](ADVANCED_DETECTION_ENGINE.md) for threat detection capabilities

## Important Notes

- **Not Production Ready**: Missing security hardening and comprehensive testing
- **Limited Testing**: Testing framework needs expansion
- **Network Manager**: Remote transmission is stub implementation only
- **Registry Monitoring**: Windows-only, requires platform testing
- **Performance**: Optimized for development, needs high-throughput testing
