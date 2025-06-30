use anyhow::Result;
use tracing::{info, error};
use std::path::PathBuf;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use chrono::{DateTime, Utc, Duration};

use crate::config::StorageConfig;
use crate::events::EventBatch;

pub struct StorageManager {
    config: StorageConfig,
    data_directory: PathBuf,
}

impl StorageManager {
    pub async fn new(config: StorageConfig) -> Result<Self> {
        let data_directory = config.local_storage.data_directory.clone();
        
        // Create data directory if it doesn't exist
        if config.local_storage.enabled {
            std::fs::create_dir_all(&data_directory)?;
        }
        
        info!("Storage manager initialized with directory: {:?}", data_directory);
        
        Ok(Self {
            config,
            data_directory,
        })
    }
    
    pub async fn store_batch(&self, batch: &EventBatch) -> Result<()> {
        if !self.config.local_storage.enabled {
            return Ok(());
        }
        
        let json_data = serde_json::to_string_pretty(batch)?;
        
        if self.config.local_storage.compress_events {
            let filename = format!("events_{}.json.gz", batch.batch_id);
            let file_path = self.data_directory.join(filename);
            
            // Compress data using gzip
            let compressed_data = self.compress_data(&json_data)?;
            tokio::fs::write(file_path, compressed_data.clone()).await?;
            
            info!("Stored compressed batch {} ({} -> {} bytes)", 
                  batch.batch_id, json_data.len(), compressed_data.len());
        } else {
            let filename = format!("events_{}.json", batch.batch_id);
            let file_path = self.data_directory.join(filename);
            
            tokio::fs::write(file_path, json_data.clone()).await?;
            
            info!("Stored uncompressed batch {} ({} bytes)", 
                  batch.batch_id, json_data.len());
        }
        
        Ok(())
    }
    
    pub async fn cleanup_old_events(&self) -> Result<()> {
        if !self.config.local_storage.enabled {
            return Ok(());
        }
        
        let retention_days = self.config.retention_days;
        let cutoff_time = Utc::now() - Duration::days(retention_days as i64);
        
        let mut entries = tokio::fs::read_dir(&self.data_directory).await?;
        let mut files_removed = 0;
        let mut bytes_freed = 0u64;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            
            // Only process event files (json or json.gz)
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                if filename.starts_with("events_") && 
                   (filename.ends_with(".json") || filename.ends_with(".json.gz")) {
                    
                    // Get file metadata
                    if let Ok(metadata) = entry.metadata().await {
                        if let Ok(modified) = metadata.modified() {
                            let modified_time: DateTime<Utc> = modified.into();
                            
                            if modified_time < cutoff_time {
                                let file_size = metadata.len();
                                
                                match tokio::fs::remove_file(&path).await {
                                    Ok(()) => {
                                        files_removed += 1;
                                        bytes_freed += file_size;
                                        info!("Removed old event file: {:?}", path);
                                    }
                                    Err(e) => {
                                        error!("Failed to remove file {:?}: {}", path, e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if files_removed > 0 {
            info!("Cleanup completed: removed {} files, freed {} bytes", 
                  files_removed, bytes_freed);
        } else {
            info!("Cleanup completed: no files older than {} days found", retention_days);
        }
        
        Ok(())
    }
    
    fn compress_data(&self, data: &str) -> Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data.as_bytes())?;
        let compressed = encoder.finish()?;
        Ok(compressed)
    }
}
