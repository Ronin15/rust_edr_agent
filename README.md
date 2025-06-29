# EDR Agent (Test Project)

> **⚠️ Test/Learning Project**: This is a test implementation of an Endpoint Detection and Response (EDR) agent built for learning and experimentation purposes. It is not intended for production use.

A high-performance EDR agent prototype written in Rust, demonstrating modern security monitoring concepts and Rust async programming patterns.

## 🎯 Project Purpose

This project serves as a:
- Learning exercise for Rust systems programming
- Prototype for EDR agent architecture design
- Demonstration of async/await patterns in security tools
- Test bed for cross-platform monitoring capabilities

## 🚀 Features (In Development)

- **Process Monitoring**: Track process creation, termination, and behavior changes
- **File System Monitoring**: Real-time file system event detection (planned)
- **Network Monitoring**: Network connection and DNS query tracking (planned)
- **Registry Monitoring**: Windows registry change detection (Windows only, planned)
- **Cross-Platform Support**: Designed for Windows, Linux, and macOS
- **Configurable**: YAML-based configuration with reasonable defaults

## 📋 Current Status

- ✅ Core architecture implemented
- ✅ Configuration system working
- ✅ Basic process monitoring functional
- ✅ Event system and storage framework
- 🔄 File monitoring (stub implementation)
- 🔄 Network monitoring (stub implementation)
- 🔄 Registry monitoring (stub implementation)
- 📋 Testing framework (planned)
- 📋 Documentation (in progress)

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
- Configure storage and logging settings

## 🏗️ Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Agent     │────│  Collectors  │────│   Events    │
│   Core      │    │              │    │   System    │
└─────────────┘    └──────────────┘    └─────────────┘
       │                    │                   │
       │                    │                   │
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│ Config Mgmt │    │   Storage    │    │  Network    │
│             │    │   Manager    │    │  Manager    │
└─────────────┘    └──────────────┘    └─────────────┘
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
```
src/
├── edr_main.rs          # Application entry point
├── agent.rs             # Core agent implementation
├── config.rs            # Configuration management
├── events.rs            # Event types and handling
├── storage.rs           # Local storage implementation
├── network.rs           # Network communication (stub)
├── utils.rs             # Utility functions
└── collectors/          # Monitoring modules
    ├── mod.rs
    ├── process.rs       # Process monitoring
    ├── file.rs          # File system monitoring (stub)
    ├── network.rs       # Network monitoring (stub)
    └── registry.rs      # Registry monitoring (stub)
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
- **Incomplete Features**: Many collectors are stub implementations
- **No Security Hardening**: Missing privilege separation, input validation, etc.
- **Performance**: Not optimized for high-throughput environments

## 🤝 Contributing

This is a learning project, but contributions are welcome:
1. Fork the repository
2. Create a feature branch
3. Implement your changes with proper error handling
4. Add tests (when testing framework is available)
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

- [Rust Async Book](https://rust-lang.github.io/async-book/)
- [Tokio Documentation](https://tokio.rs/)
- [EDR Concepts](https://en.wikipedia.org/wiki/Endpoint_detection_and_response)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

**Disclaimer**: This software is provided for educational and testing purposes only. Use at your own risk.
