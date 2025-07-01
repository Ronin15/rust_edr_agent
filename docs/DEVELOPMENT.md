# Development Guide

## Prerequisites

- Rust 1.70+ (2021 edition)
- Cargo (comes with Rust)
- Platform-specific requirements:
  - **Windows**: For registry monitoring features
  - **Linux**: For ptrace and system call monitoring
  - **macOS**: Full compatibility with all features

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

### ✅ Fully Implemented
- **Core Architecture**: Agent orchestration, lifecycle management, async event processing
- **Configuration System**: YAML-based config with validation and defaults
- **Process Monitoring**: Real-time process creation/termination/modification tracking with CPU/memory metrics
- **File System Monitoring**: Live file change detection with hash calculation and metadata extraction
- **Network Monitoring**: Connection tracking via netstat/lsof with protocol and process mapping
- **Registry Monitoring**: Windows registry change detection with real-time alerting and threat detection
- **Behavioral Detection Engine**: Context-aware threat detection with platform-specific rules
- **Event System**: Unified event format, batching, and structured data
- **Storage Management**: Compressed storage (90%+ compression), automatic cleanup, retention policies
- **Logging**: Structured logging with file rotation and console output
- **Cross-platform Support**: Works on Windows, macOS, and Linux

### 🔄 Partially Implemented
- **Network Manager**: Stub implementation for remote data transmission
- **Testing Framework**: Basic structure exists, comprehensive tests needed

### 📋 Planned/Missing
- **Security Hardening**: Input validation, privilege separation
- **Performance Optimization**: High-throughput scenarios
- **Advanced Analytics**: Event correlation, threat intelligence integration

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
