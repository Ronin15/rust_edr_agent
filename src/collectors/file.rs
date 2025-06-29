use anyhow::Result;
use tracing::{info, warn, error, debug};
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::path::Path;
use std::time::SystemTime;
use notify::{Watcher, RecursiveMode, Event as NotifyEvent, EventKind, RecommendedWatcher};
use tokio::sync::mpsc::UnboundedSender;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::config::FileMonitorConfig;
use crate::events::{Event, EventType, EventData, FileEventData, FileHashes};
use crate::collectors::{Collector, EventCollector};
use crate::agent::CollectorStatus;
use crate::utils::calculate_file_hash;

#[derive(Debug)]
pub struct FileCollector {
    config: FileMonitorConfig,
    event_sender: mpsc::Sender<Event>,
    is_running: Arc<RwLock<bool>>,
    hostname: String,
    agent_id: String,
    events_collected: Arc<RwLock<u64>>,
    last_error: Arc<RwLock<Option<String>>>,
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
        })
    }
    
    fn create_file_event(&self, event_type: EventType, path: String) -> Event {
        let path_ref = Path::new(&path);
        
        // Get file metadata if possible
        let (size, permissions, created_time, modified_time) = if let Ok(metadata) = std::fs::metadata(&path) {
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
            
            let created_time = metadata.created().ok().map(|t| {
                chrono::DateTime::<chrono::Utc>::from(t)
            });
            let modified_time = metadata.modified().ok().map(|t| {
                chrono::DateTime::<chrono::Utc>::from(t)
            });
            (size, permissions, created_time, modified_time)
        } else {
            (None, None, None, Some(chrono::Utc::now()))
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
            owner: None, // TODO: Get owner info
            group: None, // TODO: Get group info
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
            
            // Create and send the event
            let event = self.create_file_event(event_type, path_str);
            
            if let Err(e) = self.event_sender.send(event).await {
                error!("Failed to send file event: {}", e);
                return Err(anyhow::anyhow!("Failed to send event: {}", e));
            }
            
            // Update events collected counter
            *self.events_collected.write().await += 1;
        }
        
        Ok(())
    }
}
