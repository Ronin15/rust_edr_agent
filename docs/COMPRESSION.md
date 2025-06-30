# EDR Agent - Storage Compression Features

## Overview

The EDR Agent now includes automatic event compression and cleanup features to efficiently manage storage space while maintaining data integrity.

## Compression

### How It Works
- **Format**: Gzip compression using the `flate2` crate
- **Trigger**: Configurable via `storage.local_storage.compress_events` in `config.yaml`
- **File Extension**: Compressed files use `.json.gz` extension
- **Compression Ratio**: Typically 85-95% size reduction

### Configuration
```yaml
storage:
  local_storage:
    enabled: true
    data_directory: "./data"
    compress_events: true  # Enable compression
  retention_days: 30
```

### Performance Benefits
- **Disk Space**: ~90% reduction in storage requirements
- **I/O Performance**: Faster writes due to smaller file sizes
- **Network Transfer**: Reduced bandwidth if uploading to remote servers

## Automatic Cleanup

### Retention Policy
- **Default**: 30 days retention
- **Configurable**: Via `storage.retention_days` setting
- **File Types**: Only removes event files (`events_*.json` and `events_*.json.gz`)
- **Safe**: Preserves logs and configuration files

### Cleanup Process
1. Scans data directory for event files
2. Checks file modification time
3. Removes files older than retention period
4. Logs cleanup activity (files removed, bytes freed)

## File Format Examples

### Compressed Event File
```bash
# File: events_572de6e0-726b-4592-80ff-90e16d3667a0.json.gz
# Size: 45,248 bytes (compressed from 573,820 bytes)

# To view content:
gunzip -c data/events_*.json.gz | jq .
# Alternative (Linux/some systems): zcat data/events_*.json.gz | jq .
```

### Log Output
```
INFO edr_agent::storage: Stored compressed batch 572de6e0-726b-4592-80ff-90e16d3667a0 (573820 -> 45248 bytes)
INFO edr_agent::storage: Cleanup completed: removed 5 files, freed 2048000 bytes
```

## Working with Compressed Files

### Command Line Tools
```bash
# View compressed file (cross-platform)
gunzip -c data/events_*.json.gz | jq .

# Search across all compressed files
gunzip -c data/*.json.gz | jq '.events[] | select(.event_type == "ProcessCreated")'

# Count total events in all files
gunzip -c data/*.json.gz | jq '.events | length' | paste -sd+ | bc

# Extract specific data
gunzip -c data/*.json.gz | jq -r '.events[].data.Process.name' | sort | uniq

# Note: On Linux systems, you can also use 'zcat' instead of 'gunzip -c'
```

### Programming Integration
```rust
use flate2::read::GzDecoder;
use std::io::Read;

// Read compressed event file
let file = std::fs::File::open("data/events_xyz.json.gz")?;
let mut decoder = GzDecoder::new(file);
let mut contents = String::new();
decoder.read_to_string(&mut contents)?;
let events: EventBatch = serde_json::from_str(&contents)?;
```

## Cross-Platform Support

### Unix/Linux/macOS
- Uses standard `gzip` compression
- Compatible with system tools (`gunzip -c`, `zcat` on Linux)
- Preserves file permissions and timestamps

### Windows
- Same compression format
- Can be opened with tools like 7-Zip, WinRAR
- PowerShell can handle gzip files natively

## Monitoring Storage Usage

### Disk Space Monitoring
```bash
# Check total data directory size
du -sh data/

# Compare compressed vs uncompressed
ls -lh data/*.json.gz     # Compressed files
du -sh data/              # Total usage

# Monitor in real-time
watch -n 5 'du -sh data/ && ls -la data/ | tail -3'
```

### Performance Metrics
```bash
# Time compression performance
time gunzip -c data/events_*.json.gz > /dev/null

# Check compression ratio
for f in data/*.json.gz; do
    original=$(gunzip -c "$f" | wc -c)
    compressed=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f")
    ratio=$(echo "scale=2; (1 - $compressed/$original) * 100" | bc)
    echo "$f: ${ratio}% compression"
done
```

## Best Practices

### Storage Management
1. **Monitor Disk Usage**: Regularly check data directory size
2. **Adjust Retention**: Tune `retention_days` based on requirements
3. **Backup Strategy**: Consider backing up compressed files before cleanup
4. **Performance Testing**: Test compression impact on your specific workload

### Troubleshooting
1. **High Disk Usage**: Reduce `retention_days` or `max_events_per_batch`
2. **Slow Performance**: Disable compression if I/O is bottleneck
3. **Corruption**: Verify files with `gzip -t data/*.json.gz`
4. **Access Issues**: Ensure proper file permissions on data directory

## Future Enhancements

- **Multiple Compression Levels**: Configurable compression levels
- **Encryption**: Optional encryption of compressed files
- **Remote Storage**: Upload compressed files to cloud storage
- **Streaming Compression**: Real-time compression during event generation
