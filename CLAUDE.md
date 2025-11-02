# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based EDR (Endpoint Detection and Response) agent prototype demonstrating production-grade security monitoring architecture. It's an **educational/demonstration project** showcasing real-world EDR patterns, not a production security tool. The codebase emphasizes cross-platform compatibility (Windows, Linux, macOS), async programming with Tokio, and behavioral threat detection.

## Build & Development Commands

### Building
```bash
# Development build
cargo build

# Release build (with optimizations: LTO, strip, single codegen unit)
cargo build --release

# Run the agent
cargo run
./target/release/edr-agent
```

### Testing
The project uses binary test executables rather than traditional `cargo test`:

```bash
# Integration test (core functionality)
cargo run --bin test_integration

# Platform-specific detection tests
cargo run --bin test_linux_detection      # Linux threat detection
cargo run --bin test_mac_detection        # macOS threat detection
cargo run --bin test_dns_anomaly_detection # DNS anomaly detection
```

### Running & Monitoring
```bash
# Run agent and watch security alerts
./target/release/edr-agent &
tail -f logs/edr-agent.log | grep "SECURITY ALERT"

# Generate test activity
ls -la && ps aux

# Check collected events
ls data/
tail logs/*.log
```

## Architecture Overview

### Core Design Pattern: Manager-Worker with Async Channels

The agent uses a **producer-consumer pattern** with Tokio's async channels:

```
Agent Core (Orchestrator)
    ├── CollectorManager → [Event channel] → DetectorManager → [Alert channel] → Agent
    ├── StorageManager (persists events with gzip compression)
    └── NetworkManager (stub - phone-home functionality not implemented)
```

### Key Architectural Concepts

1. **Event Flow Pipeline**: System events → Collectors → Deduplication → Detectors → Storage/Alerts
   - Events flow through `mpsc::channel<Event>` with 10,000 capacity
   - Alerts flow through `mpsc::channel<DetectorAlert>` with 1,000 capacity
   - **Deduplication is fully integrated** in the agent's process_batch pipeline (as of latest fixes)

2. **Deduplication System** (`src/deduplication.rs`):
   - **Security-first**: NEVER deduplicates critical events (ProcessCreated/Terminated, new connections, file creation/deletion)
   - Uses SHA256 content hashing for exact duplicate detection
   - Multi-phase: exact duplicates (2min window) → burst detection → type-based rate limiting
   - Preserves 100% security fidelity while reducing noise by 85-90%
   - Memory-bounded: max 300KB overhead with hard limits on cache sizes

3. **Collector Architecture** (`src/collectors/`):
   - Each collector is a long-running async task spawned by CollectorManager
   - **Process Collector**: Uses `sysinfo` crate, tracks CPU/memory, SHA-256 hashing
   - **File Collector**: Uses `notify` crate for filesystem watching, respects ignored paths/extensions
   - **Network Collector**: Uses `pnet` for network monitoring, tracks connection lifecycle
   - **Registry Collector**: Windows-only (`#[cfg(windows)]`), monitors registry changes via WinAPI

4. **Detector Architecture** (`src/detectors/`):
   - **Behavioral Detector**: Cross-platform threat detection (process injection, shell execution, suspicious paths)
   - **DNS Anomaly Detector**: 6+ threat types (tunneling, C2, high-frequency, suspicious domains)
   - Platform-adaptive rules: automatically applies OS-specific patterns

5. **Event System** (`src/events.rs`):
   - Unified `Event` struct with `EventType` enum (Process/File/Network/Registry/System/User)
   - Each event has: id, timestamp, event_type, source, hostname, agent_id, data, metadata
   - `EventData` enum wraps type-specific structs (ProcessEventData, FileEventData, etc.)
   - Security-aware fields: `security_critical` flag, `content_hash` for deduplication

### Module Dependency Map

```
src/edr_main.rs (binary entry point)
    ↓
src/agent.rs (orchestration)
    ↓
├── config.rs → loads config.yaml
├── collectors/manager.rs
│   ├── collectors/process.rs
│   ├── collectors/file.rs
│   ├── collectors/network.rs
│   └── collectors/registry.rs (Windows only)
├── detectors/manager.rs
│   ├── detectors/behavioral.rs
│   └── detectors/dns_anomaly.rs
├── deduplication.rs
├── storage.rs → flate2 compression
└── network.rs (stub)
```

## Critical Implementation Details

### Configuration (`config.yaml`)
- **Ignored paths**: The agent MUST exclude its own `data/`, `logs/`, and `target/` directories to prevent recursive event loops
- Platform-specific paths are included (e.g., `/private/var/folders/`, `/proc/`, `/sys/`)
- File size limit: 50MB (balanced for security coverage and performance)
- Collection interval: 5000ms, max 1000 events per batch

### Cross-Platform Compilation
```rust
// Registry collector only on Windows
#[cfg(windows)]
pub mod registry;

// Platform-specific dependencies in Cargo.toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.52", features = [...] }

[target.'cfg(unix)'.dependencies]
libc = "0.2"
nix = { version = "0.27", features = ["process", "signal", "fs"] }
```

### Storage & Compression
- Events stored in `data/` as gzipped JSON files
- Automatic retention cleanup based on config
- File naming: `{timestamp}_{batch_number}.json.gz`
- StorageManager handles compression with `flate2::write::GzEncoder`

### Logging
- Uses `tracing` crate with file rotation (`tracing-appender`)
- Log files in `logs/` directory
- Important: Look for "SECURITY ALERT" prefix in logs for threat detections

### Error Handling
- Uses `anyhow::Result` for propagating errors
- Uses `thiserror` for custom error types
- `.context()` extensively for error chain context

## Common Development Patterns

### Adding a New Collector
1. Create `src/collectors/new_collector.rs` implementing data collection logic
2. Add module to `src/lib.rs`: `pub mod new_collector;` inside `collectors` block
3. Add collector initialization in `src/collectors/manager.rs::new()`
4. Add corresponding config struct in `src/config.rs`
5. Spawn collection task in `manager.rs::start()`

### Adding a New Event Type
1. Add variant to `EventType` enum in `src/events.rs`
2. Create corresponding data struct (e.g., `NewEventData`)
3. Add variant to `EventData` enum
4. Mark security-critical events in `Event::new()` or collector code
5. Update deduplication rules in `src/deduplication.rs` if needed

### Adding a New Detector
1. Create `src/detectors/new_detector.rs` with detection logic
2. Add module to `src/lib.rs`: `pub mod new_detector;` inside `detectors` block
3. Register in `src/detectors/manager.rs::new()`
4. Add config struct in `src/config.rs`
5. Spawn detector task in `manager.rs::start()`

## Important Constraints & Known Issues

1. **Network Manager is a Stub**: Phone-home functionality is not implemented. The NetworkManager exists but does nothing.

2. **Limited Testing**: The project uses binary test executables (`test_*.rs` in root and `src/bin/`) rather than unit tests. No comprehensive test suite exists.

3. **No Security Hardening**: This is an educational project. Missing:
   - Privilege separation
   - Input validation/sanitization
   - Secure credential management
   - Anti-tampering protections

4. **Platform-Specific Code**: Registry monitoring is Windows-only. When modifying, ensure proper `#[cfg(windows)]` guards.

5. **Async Runtime**: All long-running tasks must be Tokio async. Blocking operations should use `tokio::task::spawn_blocking`.

6. **Shutdown Handling**: The agent responds to Ctrl-C via `tokio::signal::ctrl_c()`. Collectors and detectors must respect shutdown signals.

7. **Deduplication is Security-Critical**: When modifying event types or deduplication logic, ensure `security_critical` events are NEVER suppressed:
   - ProcessCreated/ProcessTerminated
   - FileCreated/FileDeleted
   - NetworkConnection (new connections only)
   - RegistryKeyCreated/Deleted
   - SecurityAlert

## Performance Characteristics

- Memory footprint: ~80-120 MB typical
- Event compression: 90%+ with gzip
- Noise reduction: 85-90% through deduplication
- Event throughput: Handles thousands of connections and rapid process churn
- Channel capacities: 10,000 events, 1,000 alerts

## Documentation Structure

The `docs/` directory contains extensive documentation:
- `DEVELOPMENT.md` - Detailed architecture and implementation status
- `DETECTION_*.md` - Detection engine documentation
- `SMART_DEDUPLICATION.md` - Deduplication system deep dive
- `COMPRESSION.md`, `PERFORMANCE.md` - Performance analysis
- `USAGE.md`, `TROUBLESHOOTING.md` - User-facing docs

When making significant architectural changes, update relevant docs.
