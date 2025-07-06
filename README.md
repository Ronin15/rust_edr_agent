# Rust EDR Agent

**Advanced EDR Prototype - Production Architecture, Educational Implementation**

A high-performance EDR agent prototype written in Rust, demonstrating modern security monitoring concepts and cross-platform threat detection. This project showcases real-world EDR architecture patterns, async programming, and behavioral detection systems. This is mainly for rust practice. I have intentionally left networking/centeral management and kernel monitoring out of this time for now.

## 🎯 Project Purpose

This educational project demonstrates:
- **Advanced Rust Systems Programming**: Async/await patterns, tokio runtime, cross-platform compatibility
- **Production EDR Architecture**: Modular collector/detector design, event processing pipelines, storage management
- **Cross-Platform Security Monitoring**: Windows, Linux, and macOS support with platform-specific detectors
- **Real-Time Behavioral Detection**: Process injection detection, DNS anomaly detection, registry monitoring
- **Performance Engineering**: Event deduplication, compression, memory-efficient processing

## 🚀 Features

### Core Monitoring
- **Process Monitoring**: Track process creation, termination, and behavior changes
- **File System Monitoring**: Real-time file system event detection with file hashing
- **Network Monitoring**: Network connection and DNS query tracking with connection lifecycle tracking
- **DNS Anomaly Detection**: Real-time DNS threat detection with 6 threat types, and smart deduplication
- **Registry Monitoring**: Windows registry change detection with real-time alerting
- **Cross-Platform Support**: Designed for Windows, Linux, and macOS
- **High Performance**: ~80-120 MB memory footprint with 90%+ event compression
- **Intelligent Deduplication**: Production-ready event deduplication reducing noise by 85-90% while preserving 100% security fidelity
- **Configurable**: YAML-based configuration with reasonable defaults

### 🎯 Behavioral Detection Engine
- **🔍 Cross-Platform Threat Detection**: Real-time detection of process injection, suspicious shell execution, and malicious file operations
- **🧠 Context-Aware Risk Scoring**: Dynamic risk adjustment based on process location, system context, and expected behavior
- **⚡ Frequency-Based Alert Suppression**: Progressive risk reduction for repeated alerts to minimize false positives
- **🛡️ System Process Context Recognition**: Baseline understanding of legitimate system processes (systemd, init, etc.)
- **📊 Platform-Adaptive Rules**: Automatically applies Linux, Windows, or macOS-specific detection patterns

### 🧹 Intelligent Event Deduplication & Smart Alerting
- **🔒 Security-First**: Never deduplicates security-critical events (process creation/termination, new connections, file creation/deletion)
- **📡 Connection Lifecycle Tracking**: Full network connection duration monitoring with state change detection
- **🎯 Smart Process Monitoring**: Conservative deduplication of ProcessModified events while preserving all creation/termination events
- **📁 File System Intelligence**: Rate-limiting for noisy file systems while preserving all security-relevant file operations
- **🚨 Type-Based Alert Limits**: Different deduplication rules for DNS tunneling (5/hour), high-volume DNS (3/hour), suspicious domains (10/hour)
- **⏰ Time-Window Management**: Hourly alert tracking with automatic cleanup of old timestamps
- **💾 Memory-Bounded**: Hard limits prevent memory exhaustion on high-throughput servers (max 300KB overhead)
- **🚀 Production-Ready**: Handles thousands of connections and rapid process churn without data loss

## 📋 Implementation Status

**✅ Fully Implemented**: 
- Core agent architecture with tokio async runtime
- Event collection system (process, file, network)
- Behavioral detection engine with cross-platform support
- DNS anomaly detection with 6+ threat detection types
- Storage management with gzip compression
- Intelligent event deduplication (85-90% noise reduction)
- Configuration system with YAML support
- Structured logging with file rotation
- Event batching and processing pipelines

**🔄 Partially Implemented**: 
- Network manager (stub implementation)
- Windows registry monitoring (conditional compilation)
- Testing framework (basic integration tests)

**📋 Future Enhancements**: 
- Advanced threat intelligence integration
- Machine learning-based anomaly detection
- Enterprise management console
- SIEM integrations

📖 **Complete implementation details in [Development Guide](docs/DEVELOPMENT.md)**

## 🛠️ Quick Start

### Prerequisites
- Rust 1.60+ (2021 edition)
- Cargo

### Building
```bash
git clone https://github.com/Ronin15/rust_edr_agent.git
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
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Common issues and solutions
- **[API Reference](docs/API_REFERENCE.md)** - Complete module and API documentation

### Advanced Features
- **[Detection Quick Reference](docs/DETECTION_QUICK_REFERENCE.md)** - ⚡ Fast setup and troubleshooting
- **[Behavioral Detection Engine](docs/ADVANCED_DETECTION_ENGINE.md)** - Context-aware threat detection
- **[DNS Anomaly Detection](docs/DNS_ANOMALY_DETECTION.md)** - Real-time DNS threat detection and monitoring
- **[Linux Detection Capabilities](docs/LINUX_DETECTION.md)** - Linux-specific threat detection
- **[Detection Configuration](docs/DETECTION_CONFIGURATION.md)** - Tuning and customization guide

### System Management & Development
- **[Development Guide](docs/DEVELOPMENT.md)** - Architecture, implementation status, and build instructions
- **[Smart Deduplication](docs/SMART_DEDUPLICATION.md)** - Intelligent alert deduplication system
- **[Storage Compression](docs/COMPRESSION.md)** - Compression and storage management
- **[Performance Analysis](docs/PERFORMANCE.md)** - Memory usage and performance metrics
- **[TODO List](docs/TODO.md)** - Future enhancements and planned features

### Quick Test Run
```bash
# 1. Build and run
cargo build
cargo run

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

### Integration Test
```bash
# Test core functionality and integration
cargo run --bin test_integration

# This test validates:
# • Core agent functionality
# • Cross-platform compatibility
# • Event processing pipeline
# • Configuration loading
# • Storage operations
```

### Mac Detection Test
```bash
# Test macOS-specific detection capabilities
cargo run --bin test_mac_detection

# This test validates:
# • macOS system process context recognition (mdworker, sharingd, ReportCrash)
# • Suspicious path detection (/tmp, Downloads, dylib injection)
# • Shell execution monitoring with browser-spawned detection
# • macOS task port manipulation (task_for_pid patterns)
# • macOS dylib injection monitoring (dlopen/dlsym)
# • Command line pattern analysis for macOS-specific threats
# • Memory operation tracking indicators
# • Risk scoring and alert generation
```

### DNS Anomaly Detection Test
```bash
# Test comprehensive DNS anomaly detection capabilities
cargo run --bin test_dns_anomaly_detection

# This test validates:
# ✅ High-frequency DNS queries detection (>5 queries/minute)
# ✅ Suspicious domain pattern recognition (.tk, base64 patterns)
# ✅ DNS tunneling detection (TXT records, large responses)
# ✅ Command and control communication detection
# ✅ Data exfiltration monitoring (volume-based detection)
# ✅ Smart alert deduplication (prevents alert spam)
# ✅ Process-to-DNS query correlation
# ✅ Multiple DNS protocol support (UDP/TCP, DoT, DoH, DoQ)
# ✅ Real-time threat detection with EDR-friendly monitoring

# Expected test output:
# 🔍 Testing DNS Anomaly Detection System
# ✅ High-frequency DNS alert detected
# ✅ Suspicious domain alert detected  
# 🧠 Testing DNS Baseline Learning
# 🔒 Testing DNS Protocol Detection

# Manual DNS testing
# Generate high-frequency DNS queries
for i in {1..10}; do nslookup test-domain-$i.com & done

# Query suspicious domains (test patterns)
nslookup evil-domain.tk  # Free TLD abuse
nslookup dGVzdA==.example.com  # Base64 subdomain
```

## 🏧 Architecture Overview

### Core Components

- **Agent Core (`agent.rs`)**: Main orchestration layer managing all subsystems
- **Collector Manager**: Coordinates multiple data collection modules
  - **Process Collector**: System process monitoring and tracking
  - **File Collector**: File system event monitoring with hashing
  - **Network Collector**: Network connection and DNS monitoring
  - **Registry Collector**: Windows registry change detection (Windows only)
- **Detector Manager**: Threat detection and analysis engines
  - **Behavioral Detector**: Process injection, suspicious execution patterns
  - **DNS Anomaly Detector**: Malicious domain detection, tunneling, C2 communication
- **Event System**: Unified event format, batching, and processing pipeline
- **Storage Manager**: Compressed storage with automatic retention and cleanup
- **Deduplication Engine**: Intelligent noise reduction preserving security fidelity
- **Configuration System**: YAML-based configuration with platform-specific defaults

### Data Flow
```
System Events → Collectors → Event Processing → Detectors → Alerts
                     ↓                ↓
              Deduplication → Storage (Compressed)
```

📖 **Detailed architecture and module documentation in [Development Guide](docs/DEVELOPMENT.md)**

## 🔧 Development

**Building**: `cargo build`, then `cargo run` or `./target/release/edr-agent`

📖 **Complete development guide, project structure, and build instructions in [Development Guide](docs/DEVELOPMENT.md)**

## ⚠️ Important Notes

- **Educational Project**: This is a learning/demonstration project showcasing production EDR concepts
- **Limited Testing**: Comprehensive testing suite is not yet implemented
- **Network Manager**: Phone-home networking functionality is a stub and not implemented
- **No Security Hardening**: Missing privilege separation, input validation, etc.
- **✅ Performance**: Now optimized for high-throughput environments with intelligent deduplication

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
- ✅ **Low Resource Usage**: ~80-120 MB memory footprint, minimal CPU impact
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
