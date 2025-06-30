# EDR Agent

"Advanced EDR Prototype - Production Architecture, Educational Implementation"
This project demonstrates production-quality EDR architecture and engineering techniques in a controlled learning environment. While the implementation showcases real-world performance targets and design patterns, it's intentionally kept in educational status until comprehensive security auditing and testing are complete.

A high-performance EDR agent prototype written in Rust, demonstrating modern security monitoring concepts and Rust async programming patterns.

## 🎯 Project Purpose

This project serves as a:
- Learning exercise for Rust systems programming
- Prototype for EDR agent architecture design
- Demonstration of async/await patterns in security tools
- Test bed for cross-platform monitoring capabilities

## 🚀 Features

### Core Monitoring
- **Process Monitoring**: Track process creation, termination, and behavior changes
- **File System Monitoring**: Real-time file system event detection with file hashing
- **Network Monitoring**: Network connection and DNS query tracking
- **Registry Monitoring**: Windows registry change detection with real-time alerting
- **Cross-Platform Support**: Designed for Windows, Linux, and macOS
- **High Performance**: ~120 MB memory footprint with 90%+ event compression
- **Configurable**: YAML-based configuration with reasonable defaults

### 🎯 Behavioral Detection Engine (NEW)
- **🔍 Cross-Platform Threat Detection**: Real-time detection of process injection, suspicious shell execution, and malicious file operations
- **🐧 Linux-Specific Detection**: ptrace injection sequences, .so library attacks, shell execution from suspicious locations
- **🧠 Context-Aware Risk Scoring**: Dynamic risk adjustment based on process location, system context, and expected behavior
- **⚡ Frequency-Based Alert Suppression**: Progressive risk reduction for repeated alerts to minimize false positives
- **🛡️ System Process Context Recognition**: Baseline understanding of legitimate system processes (systemd, init, etc.)
- **📊 Platform-Adaptive Rules**: Automatically applies Linux, Windows, or macOS-specific detection patterns

## 📋 Current Implementation Status

### ✅ Fully Implemented
- **Core Architecture**: Agent orchestration, lifecycle management, async event processing
- **Configuration System**: YAML-based config with validation and defaults
- **Process Monitoring**: Real-time process creation/termination/modification tracking with CPU/memory metrics
- **File System Monitoring**: Live file change detection with hash calculation and metadata extraction
- **Network Monitoring**: Connection tracking via netstat/lsof with protocol and process mapping
- **Registry Monitoring**: Windows registry change detection with real-time alerting and threat detection
- **Event System**: Unified event format, batching, and structured data
- **Storage Management**: Compressed storage (90%+ compression), automatic cleanup, retention policies
- **Logging**: Structured logging with file rotation and console output
- **Cross-platform Support**: Works on Windows, macOS, and Linux

### 🔄 Partially Implemented
- **Network Manager**: Stub implementation for remote data transmission

### 📋 Planned/Missing
- **Testing Framework**: Unit and integration tests
- **Security Hardening**: Input validation, privilege separation
- **Performance Optimization**: High-throughput scenarios
- **Advanced Analytics**: Event correlation, threat detection

## 🛠️ Quick Start

### Prerequisites
- Rust 1.70+ (2021 edition)
- Cargo

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

## 📖 Documentation

For comprehensive documentation, see the `/docs` directory:

### Getting Started
- **[Quick Usage Guide](docs/USAGE.md)** - Get started in 30 seconds
- **[Detailed Usage](docs/DETAILED_USAGE.md)** - In-depth usage instructions

### Advanced Features
- **[Detection Quick Reference](docs/DETECTION_QUICK_REFERENCE.md)** - ⚡ Fast setup and troubleshooting
- **[Behavioral Detection Engine](docs/ADVANCED_DETECTION_ENGINE.md)** - Context-aware threat detection
- **[Linux Detection Capabilities](docs/LINUX_DETECTION.md)** - Linux-specific threat detection
- **[Detection Configuration](docs/DETECTION_CONFIGURATION.md)** - Tuning and customization guide

### System Management
- **[Storage Compression](docs/COMPRESSION.md)** - Compression and storage management
- **[Performance Analysis](docs/PERFORMANCE.md)** - Memory usage and performance metrics
- **[TODO List](docs/TODO.md)** - Future enhancements and planned features

### Quick Test Run
```bash
# 1. Build and run
cargo build
RUST_LOG=info cargo run

# 2. In another terminal, generate activity
ls -la && ps aux

# 3. Check results
ls data/          # Event files
tail logs/*.log   # Log output
```

### Detection Engine Test
```bash
# 1. Run agent with detection enabled
./target/release/edr-agent

# 2. Watch for security alerts in real-time
tail -f logs/edr-agent.log | grep "SECURITY ALERT"

# 3. View detection statistics
grep "SECURITY ALERT" logs/edr-agent.log | wc -l
grep -o "Risk: [0-9.]*" logs/edr-agent.log | sort | uniq -c
```

### Linux Detection Test
```bash
# Test Linux-specific detection capabilities
cargo run --bin test_linux_detection

# This test validates:
# • Linux process injection detection (ptrace, .so attacks)
# • System process context recognition (systemd, init)
# • Suspicious path detection (/tmp, /dev/shm, browser cache)
# • Shell execution monitoring
# • Command line pattern analysis
```

## 🏗️ Architecture

```
                          ┌──────────────────────────────┐
                          │           Agent Core         │
                          │    (Orchestration 6 Control) │
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
- **Events**: Unified event format and processing pipeline
- **Storage**: Local event storage with configurable retention
- **Network**: Remote server communication (stub)
- **Configuration**: YAML-based configuration management

## 🔧 Development

### Project Structure

#### Source Code (`src/`)
```
src/
├── bin/
│   └── test_integration.rs        # Integration test binary
├── collectors/                    # Data collection modules
│   ├── manager.rs                 # Collector orchestration (COMPLETE)
│   ├── process.rs                 # Process monitoring (COMPLETE)
│   ├── file.rs                    # File system monitoring (COMPLETE)
│   ├── network.rs                 # Network monitoring (COMPLETE)
│   └── registry.rs                # Registry monitoring (COMPLETE)
├── detectors/                     # Threat detection modules
│   ├── manager.rs                 # Detection engine manager (COMPLETE)
│   ├── behavioral.rs              # Behavioral threat detection (COMPLETE)
│   └── registry.rs                # Registry threat detection (COMPLETE)
├── edr_main.rs                    # Application entry point
├── lib.rs                         # Library exports and module definitions
├── agent.rs                       # Core agent implementation (COMPLETE)
├── config.rs                      # Configuration management (COMPLETE)
├── events.rs                      # Event types and handling (COMPLETE)
├── storage.rs                     # Local storage with compression (COMPLETE)
├── network.rs                     # Network communication (STUB)
├── utils.rs                       # Utility functions (COMPLETE)
└── config.yaml                    # Default configuration template
```

#### Documentation (`docs/`)
```
docs/
├── ADVANCED_DETECTION_ENGINE.md    # Detection engine documentation
├── COMPRESSION.md                  # Storage compression guide
├── DETAILED_USAGE.md              # Comprehensive usage guide
├── DETECTION_CONFIGURATION.md     # Detection system configuration
├── DETECTION_QUICK_REFERENCE.md   # Quick detection setup
├── PERFORMANCE.md                 # Performance analysis
├── REGISTRY_MONITORING.md         # Registry monitoring and detection guide
├── TODO.md                        # Development roadmap
└── USAGE.md                       # Basic usage guide
```

### Building for Development
```bash
# Debug build with logs
RUST_LOG=debug cargo run

# Check for issues
cargo clippy

# Format code
cargo fmt

# Run tests (when implemented)
cargo test
```

## ⚠️ Important Notes

- **Not Production Ready**: This is a test project and lacks many security and reliability features required for production use
- **Limited Testing**: Comprehensive testing suite is not yet implemented
- **Network Manager**: Remote data transmission is stub implementation only
- **Registry Monitoring**: Windows-only and requires testing
- **No Security Hardening**: Missing privilege separation, input validation, etc.
- **Performance**: Not optimized for high-throughput environments
- **Runtime Error**: Currently has a config deserialization issue that needs fixing

## 🤝 Contributing

This is a learning project, but contributions are welcome:
1. Fork the repository
2. Create a feature branch
3. Implement your changes with proper error handling
4. Add tests (when testing framework is available)
5. Submit a pull request

## 🎉 Project Achievements

This test project successfully demonstrates:

### Technical Implementation
- ✅ **Multi-threaded Architecture**: Tokio-based async runtime with concurrent collectors
- ✅ **Real-time Monitoring**: Live file system, process, and network event detection
- ✅ **Efficient Storage**: 90%+ compression with gzip, automatic cleanup
- ✅ **Cross-platform Support**: Works on Windows, macOS, and Linux
- ✅ **Low Resource Usage**: ~80 MB memory footprint, minimal CPU impact
- ✅ **Production-like Features**: Configuration management, structured logging, error handling
- ✅ **Event Processing**: Batched event processing with configurable intervals and sizes
- ✅ **File Hashing**: SHA-256 hash calculation for file integrity monitoring
- ✅ **Process Tracking**: CPU/memory usage tracking and process genealogy

### Learning Outcomes
- ✅ **Rust Systems Programming**: Advanced async/await, trait objects, error handling
- ✅ **Security Concepts**: EDR architecture, event correlation, monitoring strategies
- ✅ **Performance Optimization**: Memory management, compression, efficient I/O
- ✅ **Cross-platform Development**: Platform-specific APIs, conditional compilation
- ✅ **Project Organization**: Modular design, documentation, dependency management

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

- [Rust Async Book](https://rust-lang.github.io/async-book/)
- [Tokio Documentation](https://tokio.rs/)
- [EDR Concepts](https://en.wikipedia.org/wiki/Endpoint_detection_and_response)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

**Disclaimer**: This software is provided for educational and testing purposes only. Use at your own risk.
