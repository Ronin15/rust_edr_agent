use anyhow::Result;
use tracing::{info, error};
use std::sync::Arc;
use tokio::signal;

mod config;
mod agent;
mod collectors;
mod detectors;
mod events;
mod storage;
mod network;
mod utils;

use config::Config;
use agent::Agent;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    init_logging()?;
    
    info!("Starting EDR Agent v{}", env!("CARGO_PKG_VERSION"));
    
    // Load configuration
    let config = Config::load()?;
    info!("Configuration loaded successfully");
    
    // Create and start the agent
    let agent = Arc::new(Agent::new(config).await?);
    let agent_clone = agent.clone();
    
    // Handle shutdown signals
    let shutdown_handle = tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Received shutdown signal");
                agent_clone.shutdown().await;
            }
            Err(err) => {
                error!("Failed to listen for shutdown signal: {}", err);
            }
        }
    });
    
    // Start the agent
    let agent_handle = {
        let agent = agent.clone();
        tokio::spawn(async move {
            if let Err(e) = agent.run().await {
                error!("Agent error: {}", e);
            }
        })
    };
    
    // Wait for either the agent to complete or shutdown signal
    tokio::select! {
        _ = agent_handle => {
            info!("Agent completed");
        }
        _ = shutdown_handle => {
            info!("Shutdown initiated");
        }
    }
    
    info!("EDR Agent shutting down");
    Ok(())
}

fn init_logging() -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    
    // Create log directory if it doesn't exist
    std::fs::create_dir_all("logs")?;
    
    // File appender for logs
    let file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("edr-agent")
        .filename_suffix("log")
        .build("logs")
        .expect("Failed to create file appender");
    
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_appender)
        .json();
    
    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout);
    
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(file_layer)
        .with(console_layer)
        .init();
    
    Ok(())
}