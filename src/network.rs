use anyhow::Result;
use tracing::{info, warn, error};
use reqwest::Client;

use crate::config::NetworkConfig;
use crate::events::EventBatch;

pub struct NetworkManager {
    config: NetworkConfig,
    client: Client,
}

impl NetworkManager {
    pub async fn new(config: NetworkConfig) -> Result<Self> {
        let client = if config.use_tls {
            Client::builder()
                .danger_accept_invalid_certs(!config.verify_certificates)
                .build()?
        } else {
            Client::new()
        };
        
        info!("Network manager initialized with TLS: {}", config.use_tls);
        
        Ok(Self {
            config,
            client,
        })
    }
    
    pub async fn send_batch(&self, batch: &EventBatch) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let server_url = match &self.config.server_url {
            Some(url) => url,
            None => {
                warn!("No server URL configured for network manager");
                return Ok(());
            }
        };
        
        let json_data = serde_json::to_string(batch)?;
        
        let mut request = self.client
            .post(format!("{}/events", server_url))
            .header("Content-Type", "application/json")
            .body(json_data);
        
        if let Some(api_key) = &self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }
        
        let response = request.send().await?;
        
        if response.status().is_success() {
            info!("Successfully sent batch {} with {} events", batch.batch_id, batch.len());
        } else {
            error!("Failed to send batch: HTTP {}", response.status());
            anyhow::bail!("HTTP error: {}", response.status());
        }
        
        Ok(())
    }
    
    pub async fn test_connection(&self) -> Result<()> {
        if let Some(server_url) = &self.config.server_url {
            let response = self.client
                .get(format!("{}/health", server_url))
                .send()
                .await?;
            
            if response.status().is_success() {
                info!("Network connection test successful");
            } else {
                error!("Network connection test failed: HTTP {}", response.status());
                anyhow::bail!("Connection test failed");
            }
        }
        
        Ok(())
    }
}
