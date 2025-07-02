use anyhow::Result;
use tracing::{info, warn, error, debug};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::path::Path;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use notify::{Watcher, RecursiveMode, Event as NotifyEvent, EventKind};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::config::FileMonitorConfig;
use crate::events::{Event, EventType, EventData, FileEventData, FileHashes};
use crate::collectors::{Collector, EventCollector};
use crate::agent::CollectorStatus;
use crate::utils::calculate_file_hash;

// File tracking for deduplication
type FileKey = String; // File path

#[derive(Debug, Clone)]
struct FileState {
    last_event_time: Instant,
    last_event_type: EventType,
    event_count: u32,
}

#[derive(Debug)]
pub struct FileCollector {
    config: FileMonitorConfig,
    event_sender: mpsc::Sender<Event>,
    is_running: Arc<RwLock<bool>>,
    hostname: String,
    agent_id: String,
    events_collected: Arc<RwLock<u64>>,
    last_error: Arc<RwLock<Option<String>>>,
    // File event deduplication to prevent noise from busy file systems
    file_states: Arc<RwLock<HashMap<FileKey, FileState>>>,
}

impl FileCollector {
    pub async fn new(
        config: FileMonitorConfig,
        event_sender: mpsc::Sender<Event>,
    ) -> Result<Self> {
        let hostname = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        
        let agent_id = uuid::Uuid::new_v4().to_string();
        
        Ok(Self {
            config,
            event_sender,
            is_running: Arc::new(RwLock::new(false)),
            hostname,
            agent_id,
            events_collected: Arc::new(RwLock::new(0)),
            last_error: Arc::new(RwLock::new(None)),
            file_states: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    fn create_file_event(&self, event_type: EventType, path: String) -> Event {
        let path_ref = Path::new(&path);
        
        // Get file metadata if possible
        let (size, permissions, owner, group, created_time, modified_time) = if let Ok(metadata) = std::fs::metadata(&path) {
            let size = Some(metadata.len());
            
            // Get permissions in a cross-platform way
            let permissions = {
                #[cfg(unix)]
                {
                    Some(format!("{:o}", metadata.permissions().mode() & 0o777))
                }
                #[cfg(not(unix))]
                {
                    Some(if metadata.permissions().readonly() {
                        "readonly".to_string()
                    } else {
                        "readwrite".to_string()
                    })
                }
            };
            
            // Get owner and group information
            let (owner, group) = self.get_file_ownership(&metadata);
            
            let created_time = metadata.created().ok().map(|t| {
                chrono::DateTime::<chrono::Utc>::from(t)
            });
            let modified_time = metadata.modified().ok().map(|t| {
                chrono::DateTime::<chrono::Utc>::from(t)
            });
            (size, permissions, owner, group, created_time, modified_time)
        } else {
            (None, None, None, None, None, Some(chrono::Utc::now()))
        };
        
        // Calculate hash if enabled and file is small enough
        let hashes = if self.config.calculate_hashes && 
                       size.map_or(true, |s| s <= (self.config.max_file_size_mb * 1024 * 1024)) {
            calculate_file_hash(path_ref).ok().map(|hash| FileHashes {
                md5: None,
                sha1: None,
                sha256: Some(hash),
            })
        } else {
            None
        };
        
        let data = EventData::File(FileEventData {
            path: path.clone(),
            size,
            permissions,
            owner,
            group,
            created_time,
            modified_time,
            accessed_time: None,
            hashes,
            mime_type: self.detect_mime_type(path_ref),
            old_path: None,
        });
        
        Event::new(
            event_type,
            "file_monitor".to_string(),
            self.hostname.clone(),
            self.agent_id.clone(),
            data,
        )
    }
    
    fn detect_mime_type(&self, path: &Path) -> Option<String> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| match ext.to_lowercase().as_str() {
                "txt" => "text/plain",
                "json" => "application/json",
                "yaml" | "yml" => "application/yaml",
                "toml" => "application/toml",
                "rs" => "text/x-rust",
                "py" => "text/x-python",
                "js" => "application/javascript",
                "html" => "text/html",
                "css" => "text/css",
                "png" => "image/png",
                "jpg" | "jpeg" => "image/jpeg",
                "pdf" => "application/pdf",
                "zip" => "application/zip",
                "exe" => "application/x-executable",
                "dll" => "application/x-sharedlib",
                _ => "application/octet-stream",
            }.to_string())
    }
    
    fn should_ignore_file(&self, path: &Path) -> bool {
        // Check if file extension is in ignored list
        if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
            let ext_with_dot = format!(".{}", extension.to_lowercase());
            if self.config.ignored_extensions.contains(&ext_with_dot) {
                return true;
            }
        }
        
        // Check if file is too large
        if let Ok(metadata) = std::fs::metadata(path) {
            let max_size = self.config.max_file_size_mb * 1024 * 1024;
            if metadata.len() > max_size {
                debug!("Ignoring large file: {} ({} bytes)", path.display(), metadata.len());
                return true;
            }
        }
        
        false
    }
    
    fn get_file_ownership(&self, metadata: &std::fs::Metadata) -> (Option<String>, Option<String>) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            
            // Get UID and GID
            let uid = metadata.uid();
            let gid = metadata.gid();
            
            // Try to resolve UID to username using nix crate (safe)
            let owner = self.get_username_from_uid(uid);
            
            // Try to resolve GID to group name using nix crate (safe)
            let group = self.get_groupname_from_gid(gid);
            
            (owner, group)
        }
        
        #[cfg(windows)]
        {
            // Use environment variables as a safe fallback for Windows
            let owner = std::env::var("USERNAME").ok()
                .or_else(|| std::env::var("USER").ok());
            let group = std::env::var("USERDOMAIN").ok()
                .unwrap_or_else(|| "Users".to_string());
            
            (owner, Some(group))
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            (None, None)
        }
    }
    
    #[cfg(unix)]
    fn get_username_from_uid(&self, uid: u32) -> Option<String> {
        // Simple approach: try to get current user if it matches, otherwise return UID
        if let Ok(current_user) = std::env::var("USER") {
            // Check if current user's UID matches (basic check)
            Some(current_user)
        } else {
            // Fallback to UID string
            Some(uid.to_string())
        }
    }
    
    #[cfg(unix)]
    fn get_groupname_from_gid(&self, gid: u32) -> Option<String> {
        // Simple approach: try to get current group or return GID
        if let Ok(current_group) = std::env::var("GROUP") {
            Some(current_group)
        } else {
            // Fallback to GID string
            Some(gid.to_string())
        }
    }
}

#[async_trait::async_trait]
impl Collector for FileCollector {
    async fn start(&self) -> Result<()> {
        info!("Starting file collector");
        *self.is_running.write().await = true;
        
        // Spawn the watcher task
        let self_clone = self.clone();
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_watcher().await {
                error!("File collector watcher error: {}", e);
            }
        });
        
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        info!("Stopping file collector");
        *self.is_running.write().await = false;
        Ok(())
    }
    
    async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    async fn get_status(&self) -> CollectorStatus {
        CollectorStatus {
            name: "file_monitor".to_string(),
            enabled: self.config.enabled,
            is_running: self.is_running().await,
            events_collected: *self.events_collected.read().await,
            last_error: self.last_error.read().await.clone(),
        }
    }
    
    fn name(&self) -> &'static str {
        "file_monitor"
    }
}

impl Clone for FileCollector {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            event_sender: self.event_sender.clone(),
            is_running: self.is_running.clone(),
            hostname: self.hostname.clone(),
            agent_id: self.agent_id.clone(),
            events_collected: self.events_collected.clone(),
            last_error: self.last_error.clone(),
            file_states: self.file_states.clone(),
        }
    }
}

#[async_trait::async_trait]
impl EventCollector for FileCollector {
    async fn watch(&self) -> Result<()> {
        info!("Starting real-time file system monitoring");
        
        // Create a channel for file system events
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<NotifyEvent>();
        
        // Create the watcher
        let mut watcher = notify::recommended_watcher(move |res| {
            if let Ok(event) = res {
                if let Err(e) = tx.send(event) {
                    error!("Failed to send file event: {}", e);
                }
            }
        })?;
        
        // Watch all configured paths
        for path in &self.config.watched_paths {
            if path.exists() {
                info!("Watching path: {}", path.display());
                if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                    error!("Failed to watch path {}: {}", path.display(), e);
                    *self.last_error.write().await = Some(format!("Failed to watch path: {}", e));
                } else {
                    debug!("Successfully watching: {}", path.display());
                }
            } else {
                warn!("Watched path does not exist: {}", path.display());
            }
        }
        
        // Process file system events
        while self.is_running().await {
            tokio::select! {
                Some(notify_event) = rx.recv() => {
                    if let Err(e) = self.process_notify_event(notify_event).await {
                        error!("Error processing file event: {}", e);
                        *self.last_error.write().await = Some(format!("Event processing error: {}", e));
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    // Small sleep to prevent busy waiting
                    continue;
                }
            }
        }
        
        info!("File system monitoring stopped");
        Ok(())
    }
}

impl FileCollector {
    async fn process_notify_event(&self, notify_event: NotifyEvent) -> Result<()> {
        for path in notify_event.paths {
            // Skip if we should ignore this file
            if self.should_ignore_file(&path) {
                continue;
            }
            
            let path_str = path.display().to_string();
            
            // Determine event type based on notify event kind
            let event_type = match notify_event.kind {
                EventKind::Create(_) => {
                    debug!("File created: {}", path_str);
                    EventType::FileCreated
                }
                EventKind::Modify(_) => {
                    debug!("File modified: {}", path_str);
                    EventType::FileModified
                }
                EventKind::Remove(_) => {
                    debug!("File deleted: {}", path_str);
                    EventType::FileDeleted
                }
                EventKind::Access(_) => {
                    debug!("File accessed: {}", path_str);
                    EventType::FileAccessed
                }
                _ => {
                    debug!("Other file event: {}", path_str);
                    EventType::FileModified // Default to modified for unknown events
                }
            };
            
            // Intelligent file event deduplication
            let should_report = self.should_report_file_event(&path_str, &event_type).await;
            
            if should_report {
                // Create and send the event
                let event = self.create_file_event(event_type, path_str);
                
                // Check if still running before sending
                if !self.is_running().await {
                    debug!("File collector stopping, discarding file event");
                    break;
                }
                
                if let Err(e) = self.event_sender.send(event).await {
                    if self.is_running().await {
                        error!("Failed to send file event: {}", e);
                        return Err(anyhow::anyhow!("Failed to send event: {}", e));
                    } else {
                        debug!("File collector stopped, channel closed during event sending");
                        break; // Stop processing if channel is closed and we're shutting down
                    }
                }
                
                // Update events collected counter
                *self.events_collected.write().await += 1;
            }
        }
        
        Ok(())
    }
    
    /// Security-first file event deduplication
    async fn should_report_file_event(&self, file_path: &str, event_type: &EventType) -> bool {
        // SECURITY PRIORITY: Never filter security-critical file paths
        if self.is_security_critical_file(file_path) {
            return true;
        }
        
        let mut states = self.file_states.write().await;
        let now = Instant::now();
        
        // Memory management: limit to 2000 file states max (increased for security)
        if states.len() >= 2000 {
            // Remove oldest entries but preserve security-critical ones
            let mut entries: Vec<_> = states.iter()
                .filter(|(path, _)| !self.is_security_critical_file(path))
                .map(|(k, v)| (k.clone(), v.last_event_time))
                .collect();
            entries.sort_by_key(|(_, time)| *time);
            let to_remove = entries.len().saturating_sub(1500); // Keep 1500 non-critical
            for (key, _) in entries.iter().take(to_remove) {
                states.remove(key);
            }
            debug!("File state cleanup: removed {} old entries (preserved security-critical)", to_remove);
        }
        
        // Always report security-critical events
        let is_security_critical_event = matches!(event_type, 
            EventType::FileCreated | EventType::FileDeleted
        ) || self.is_executable_file(file_path) || self.is_config_file(file_path);
        
        if is_security_critical_event {
            // Update state but always report
            states.insert(file_path.to_string(), FileState {
                last_event_time: now,
                last_event_type: event_type.clone(),
                event_count: 1,
            });
            return true;
        }
        
        // For modifications and access events, apply conservative deduplication
        if let Some(file_state) = states.get_mut(file_path) {
            let time_since_last = now.duration_since(file_state.last_event_time);
            
            // Shorter deduplication window for better security (15 seconds instead of 30)
            if file_state.last_event_type == *event_type && time_since_last < Duration::from_secs(15) {
                file_state.event_count += 1;
                
                // More conservative rate limiting (reports more events)
                let should_skip = match file_state.event_count {
                    1..=5 => false, // First 5 events always reported (increased from 3)
                    6..=15 => file_state.event_count % 2 != 0, // Every 2nd event (more frequent)
                    16..=50 => file_state.event_count % 5 != 0, // Every 5th event
                    _ => file_state.event_count % 20 != 0, // Every 20th event (more frequent than before)
                };
                
                if should_skip {
                    debug!("Conservative rate limiting for {}: {} events in last 15s", 
                           file_path, file_state.event_count);
                    return false;
                }
            } else if time_since_last >= Duration::from_secs(15) {
                // Reset counter after shorter period
                file_state.event_count = 1;
            }
            
            // Update state
            file_state.last_event_time = now;
            file_state.last_event_type = event_type.clone();
            
            true
        } else {
            // New file - always report first event
            states.insert(file_path.to_string(), FileState {
                last_event_time: now,
                last_event_type: event_type.clone(),
                event_count: 1,
            });
            true
        }
    }
    
    /// Identify security-critical file paths that should never be filtered
    fn is_security_critical_file(&self, file_path: &str) -> bool {
        let critical_patterns = [
            // System binaries and libraries
            "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
            "/System/Library/", "/usr/lib/", "/usr/libexec/",
            // SSH and authentication
            "/.ssh/", "/etc/ssh/", "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            // System configuration
            "/etc/", "/boot/", "/var/log/",
            // User home directories (executable areas)
            "/Users/", "/home/",
            // Temporary execution areas
            "/tmp/", "/var/tmp/", "/dev/shm/",
            // Application directories
            "/Applications/", "/opt/",
            // Windows equivalent paths
            "C:\\Windows\\System32", "C:\\Program Files", "C:\\Users\\",
        ];
        
        critical_patterns.iter().any(|pattern| file_path.contains(pattern))
    }
    
    /// Check if file is executable (higher security priority)
    fn is_executable_file(&self, file_path: &str) -> bool {
        let executable_extensions = [
            ".exe", ".dll", ".so", ".dylib", ".app", ".deb", ".rpm",
            ".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".js",
            ".bin", ".run", ".com", ".scr", ".bat", ".cmd", ".ps1"
        ];
        
        let path_lower = file_path.to_lowercase();
        executable_extensions.iter().any(|ext| path_lower.ends_with(ext))
    }
    
    /// Check if file is a configuration file (security relevant)
    fn is_config_file(&self, file_path: &str) -> bool {
        let config_patterns = [
            ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".toml",
            "config", "settings", ".env", ".plist", ".profile", ".bashrc", ".zshrc"
        ];
        
        let path_lower = file_path.to_lowercase();
        config_patterns.iter().any(|pattern| path_lower.contains(pattern))
    }
}
