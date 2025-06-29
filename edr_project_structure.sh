# Create the complete project structure
mkdir -p edr-agent/{src,tests,docs,examples,scripts}
cd edr-agent

# Create the main source files
touch src/{lib.rs,agent.rs,events.rs,storage.rs,network.rs,utils.rs}
mkdir -p src/collectors
touch src/collectors/{mod.rs,process.rs,file.rs,network.rs,registry.rs}

# Create test files
mkdir -p tests/{integration,unit}
touch tests/integration/test_agent.rs
touch tests/unit/test_config.rs

# Create configuration files
cat > config.yaml << 'EOF'
agent:
  collection_interval_ms: 5000
  max_events_per_batch: 1000
  max_memory_usage_mb: 512

collectors:
  process_monitor:
    enabled: true
    scan_interval_ms: 1000
    track_child_processes: true
    collect_command_line: true
    collect_environment: false
  
  file_monitor:
    enabled: true
    watched_paths:
      - "/"
      - "C:\\"
    ignored_extensions:
      - ".tmp"
      - ".log"
      - ".cache"
    max_file_size_mb: 100
    calculate_hashes: true
  
  network_monitor:
    enabled: true
    monitor_connections: true
    monitor_dns: true
    capture_packets: false
    max_packet_size: 1500

storage:
  local_storage:
    enabled: true
    data_directory: "./data"
    compress_events: true
  retention_days: 30
  max_storage_size_gb: 10

network:
  enabled: false
  batch_upload_interval_s: 300
  max_retries: 3
  timeout_s: 30
  use_tls: true
  verify_certificates: true

logging:
  level: "info"
  file_path: "./logs/edr-agent.log"
  max_file_size_mb: 100
  max_files: 10
EOF

# Create .gitignore
cat > .gitignore << 'EOF'
# Rust
/target/
**/*.rs.bk
*.pdb
Cargo.lock

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Logs and data
/logs/
/data/
*.log

# Build artifacts
/dist/
/build/

# Configuration (if containing secrets)
config.local.yaml
.env
EOF

# Create README.md
cat > README.md << 'EOF'
# EDR Agent

A high-performance Endpoint Detection and Response (EDR) agent written in Rust.

## Features

- **Process Monitoring**: Track process creation, termination, and behavior
- **File System Monitoring**: Real-time file system event monitoring
- **Network Monitoring**: Network connection and DNS query tracking
- **Registry Monitoring**: Windows registry change detection (Windows only)
- **Cross-Platform**: Support for Windows, Linux, and macOS
- **High Performance**: Low resource overhead with configurable limits
- **Secure**: Memory-safe implementation with comprehensive error handling

## Quick Start

1. **Build the agent:**
   ```bash
   cargo build --release
   ```

2. **Configure the agent:**
   Edit `config.yaml` to match your environment and requirements.

3. **Run the agent:**
   ```bash
   ./target/release/edr-agent
   ```

## Configuration

The agent uses a YAML configuration file (`config.yaml`) with the following sections:

- `agent`: Core agent settings
- `collectors`: Individual collector configurations
- `storage`: Local storage and retention settings
- `network`: Remote server communication settings
- `logging`: Logging configuration

See the default `config.yaml` for detailed options.

## Development

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Running in Development Mode

```bash
cargo run
```

## Architecture

The EDR agent is built using a modular architecture:

- **Agent Core**: Orchestrates all components and manages lifecycle
- **Collectors**: Individual monitoring modules for different data sources
- **Events**: Unified event format and processing
- **Storage**: Local event storage and retention management
- **Network**: Remote server communication and data upload
- **Configuration**: Centralized configuration management

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
EOF

# Create LICENSE file
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2025 EDR Agent Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

# Create build script for cross-compilation
cat > scripts/build.sh << 'EOF'
#!/bin/bash
set -e

echo "Building EDR Agent..."

# Build for current platform
cargo build --release

# Optional: Build for other platforms
# cargo build --release --target x86_64-pc-windows-gnu
# cargo build --release --target x86_64-apple-darwin
# cargo build --release --target aarch64-apple-darwin

echo "Build complete!"
echo "Binary location: ./target/release/edr-agent"
EOF

chmod +x scripts/build.sh

echo "Project structure created successfully!"
echo ""
echo "Next steps:"
echo "1. cd edr-agent"
echo "2. cargo build"
echo "3. Edit config.yaml as needed"
echo "4. cargo run"