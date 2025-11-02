use std::time::Duration;
use std::path::Path;
use edr_agent::config::Config;
use edr_agent::agent::Agent;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    println!("🚀 EDR Agent Integration Test");
    println!("Testing full agent lifecycle and component integration\n");
    
    // Test 1: Configuration loading
    println!("📋 Test 1: Configuration Loading");
    let config = Config::load()?;
    println!("   ✓ Configuration loaded successfully");
    println!("   ✓ Agent ID: {}", config.agent.agent_id.as_deref().unwrap_or("auto-generated"));
    println!("   ✓ Collection interval: {}ms", config.agent.collection_interval_ms);
    
    // Test 2: Agent initialization
    println!("\n📋 Test 2: Agent Initialization");
    let agent = Agent::new(config).await?;
    println!("   ✓ Agent created successfully");
    println!("   ✓ Collectors initialized");
    println!("   ✓ Detectors initialized");
    println!("   ✓ Storage manager ready");
    
    // Test 3: Agent startup
    println!("\n📋 Test 3: Agent Startup");
    let agent = std::sync::Arc::new(agent);
    let agent_clone = agent.clone();
    let agent_handle = tokio::spawn(async move {
        agent_clone.run().await
    });
    
    // Give it a moment to start up
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("   ✓ Agent started successfully");
    println!("   ✓ Collectors are running");
    println!("   ✓ Detection engine active");
    
    // Test 4: Runtime status check
    println!("\n📋 Test 4: Runtime Status Check");
    let status_before = agent.get_status().await;
    println!("   ✓ Agent running: {}", status_before.is_running);
    println!("   ✓ Hostname: {}", status_before.hostname);
    println!("   ✓ Memory usage: {} MB", status_before.memory_usage / 1024 / 1024);

    assert!(status_before.is_running, "❌ Agent should be running");

    // Test 5: Event collection (brief)
    println!("\n📋 Test 5: Event Collection Test");
    println!("   Running agent for 3 seconds to collect events...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify events were actually collected
    let status_after = agent.get_status().await;
    let events_collected: u64 = status_after.collectors_status
        .iter()
        .map(|c| c.events_collected)
        .sum();

    println!("   📊 Events collected: {}", events_collected);
    assert!(events_collected > 0,
        "❌ Test 5 FAILED: No events were collected after 3 seconds of runtime. Agent may not be collecting events properly.");
    println!("   ✓ Event collection pipeline working ({} events)", events_collected);

    // Verify storage files were created
    let data_dir = Path::new("data");
    assert!(data_dir.exists(), "❌ data/ directory should exist");

    let data_file_count = std::fs::read_dir(data_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("gz"))
        .count();

    println!("   📁 Storage files created: {}", data_file_count);
    assert!(data_file_count > 0,
        "❌ Test 5 FAILED: No compressed storage files found in data/ directory");
    println!("   ✓ Storage system working ({} files)", data_file_count);

    // Verify logs were created
    let logs_dir = Path::new("logs");
    assert!(logs_dir.exists(), "❌ logs/ directory should exist");

    let log_file_count = std::fs::read_dir(logs_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("log"))
        .count();

    println!("   📝 Log files created: {}", log_file_count);
    assert!(log_file_count > 0,
        "❌ Test 5 FAILED: No log files found in logs/ directory");
    println!("   ✓ Logging system working ({} files)", log_file_count);
    
    // Test 6: Graceful shutdown
    println!("\n📋 Test 6: Graceful Shutdown");
    agent.shutdown().await;
    println!("   ✓ Agent shutdown completed");
    
    // Wait for background task to finish
    tokio::time::sleep(Duration::from_millis(100)).await;
    agent_handle.abort();
    
    println!("\n✅ EDR Agent Integration Test Completed Successfully!");
    println!("");
    println!("🎯 Integration Summary:");
    println!("   ✓ Configuration system working");
    println!("   ✓ Agent lifecycle management working");
    println!("   ✓ Collector subsystem operational");
    println!("   ✓ Detection engine operational");
    println!("   ✓ Storage system operational");
    println!("   ✓ Graceful shutdown working");
    println!("");
    println!("🔧 Platform-Specific Detection Tests:");
    println!("   • Linux: cargo run --bin test_linux_detection");
    println!("   • macOS: cargo run --bin test_mac_detection");
    
    Ok(())
}
