use edr_agent::config::DnsAnomalyDetectorConfig;
use edr_agent::detectors::dns_anomaly::DnsAnomalyDetector;
use edr_agent::detectors::{Detector, DetectorAlert};
use edr_agent::events::{Event, EventType, EventData, NetworkEventData, NetworkDirection};
use tokio::sync::mpsc;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    test_dns_anomaly_detection().await?;
    test_dns_baseline_learning().await?;
    test_dns_protocol_detection().await?;
    Ok(())
}

async fn test_dns_anomaly_detection() -> anyhow::Result<()> {
    // Create a channel for alerts
    let (alert_sender, mut alert_receiver) = mpsc::channel::<DetectorAlert>(100);
    
    // Create DNS anomaly detector with low thresholds for testing
    let mut config = DnsAnomalyDetectorConfig::default();
    config.max_queries_per_minute = 5; // Low threshold for testing
    config.data_exfiltration_threshold_mb_per_hour = 1; // 1MB threshold for testing
    config.known_c2_domains = vec!["evil-domain.tk".to_string()];
    config.suspicious_domain_patterns = vec![
        r".*\.tk$".to_string(),
        r".*[A-Za-z0-9+/]{20,}=*.*".to_string(), // Base64 pattern
    ];
    
    let detector = DnsAnomalyDetector::new(
        config,
        alert_sender,
        "test-agent".to_string(),
        "test-host".to_string(),
    ).await.expect("Failed to create DNS anomaly detector");
    
    // Start the detector
    detector.start().await.expect("Failed to start detector");
    assert!(detector.is_running().await);
    
    println!("🔍 Testing DNS Anomaly Detection System");
    
    // Test 1: High-frequency DNS queries
    println!("\n📊 Test 1: High-frequency DNS queries");
    for i in 0..10 {
        let dns_event = create_dns_event(
            &format!("test-domain-{}.com", i),
            "standard-udp",
            Some(1234),
            Some("test_process".to_string()),
        );
        
        detector.process_event(&dns_event).await.expect("Failed to process DNS event");
        tokio::time::sleep(Duration::from_millis(100)).await; // Small delay
    }
    
    // Check for high-frequency alert - receive multiple alerts and check if any match
    let mut high_freq_alert_received = false;
    let mut alerts_received = Vec::new();
    
    // Collect alerts for up to 2 seconds
    let start_time = tokio::time::Instant::now();
    while start_time.elapsed() < Duration::from_secs(2) {
        if let Ok(alert) = tokio::time::timeout(Duration::from_millis(100), alert_receiver.recv()).await {
            if let Some(alert) = alert {
                println!("📨 Received alert: {}", alert.title);
                if alert.title.contains("High-Frequency DNS Queries") {
                    println!("✅ High-frequency DNS alert detected: {}", alert.title);
                    println!("   Severity: {:?}", alert.severity);
                    println!("   Risk Score: {:.2}", alert.risk_score);
                    high_freq_alert_received = true;
                }
                alerts_received.push(alert);
            }
        }
        if high_freq_alert_received {
            break;
        }
    }
    
    println!("📊 Total alerts received: {}", alerts_received.len());
    for (i, alert) in alerts_received.iter().enumerate() {
        println!("   Alert {}: {}", i + 1, alert.title);
    }
    assert!(high_freq_alert_received, "High-frequency DNS alert should have been generated");
    
    // Test 2: Suspicious domain detection
    println!("\n🚨 Test 2: Suspicious domain detection");
    let suspicious_dns_event = create_dns_event(
        "evil-domain.tk",
        "standard-udp", 
        Some(1234),
        Some("malware_process".to_string()),
    );
    
    detector.process_event(&suspicious_dns_event).await.expect("Failed to process suspicious DNS event");
    
    // Check for suspicious domain alert
    let mut suspicious_domain_alert_received = false;
    for _ in 0..3 {
        if let Ok(alert) = tokio::time::timeout(Duration::from_millis(500), alert_receiver.recv()).await {
            if let Some(alert) = alert {
                if alert.title.contains("Suspicious Domain Query") {
                    println!("✅ Suspicious domain alert detected: {}", alert.title);
                    println!("   Domain: {}", alert.metadata.get("domain").unwrap_or(&"unknown".to_string()));
                    println!("   Severity: {:?}", alert.severity);
                    suspicious_domain_alert_received = true;
                    break;
                }
            }
        }
    }
    assert!(suspicious_domain_alert_received, "Suspicious domain alert should have been generated");
    
    // Test 3: DNS tunneling detection (TXT record queries)
    println!("\n🕳️  Test 3: DNS tunneling detection");
    for i in 0..15 {
        let txt_query_event = create_dns_event(
            &format!("dGVzdGRhdGE{}.tunnel-domain.com", i), // Base64-like subdomain
            "dns-txt",
            Some(1234),
            Some("tunneling_process".to_string()),
        );
        
        detector.process_event(&txt_query_event).await.expect("Failed to process TXT DNS event");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    
    // Check for DNS tunneling alert
    let mut tunneling_alert_received = false;
    for _ in 0..5 {
        if let Ok(alert) = tokio::time::timeout(Duration::from_millis(500), alert_receiver.recv()).await {
            if let Some(alert) = alert {
                if alert.title.contains("DNS Tunneling") {
                    println!("✅ DNS tunneling alert detected: {}", alert.title);
                    println!("   Attack Technique: {}", alert.metadata.get("attack_technique").unwrap_or(&"unknown".to_string()));
                    println!("   Severity: {:?}", alert.severity);
                    tunneling_alert_received = true;
                    break;
                } else if alert.title.contains("Suspicious Domain") {
                    println!("📝 Also detected suspicious domain: {}", alert.metadata.get("domain").unwrap_or(&"unknown".to_string()));
                }
            }
        }
    }
    // Note: Tunneling detection requires building up statistics
    assert!(tunneling_alert_received,
        "❌ Test 3 FAILED: DNS tunneling detection should trigger after 15 TXT queries with base64-like subdomains");
    println!("✅ Test 3 PASSED: DNS tunneling detection working");
    
    // Test 4: Command and Control communication
    println!("\n🎯 Test 4: Command and Control communication");
    // Send multiple queries to simulate beaconing pattern
    for _ in 0..15 {
        let c2_event = create_dns_event(
            "evil-domain.tk", // This is in our known_c2_domains config
            "standard-udp",
            Some(6666),
            Some("malware_c2".to_string()),
        );
        detector.process_event(&c2_event).await.expect("Failed to process C2 DNS event");
        tokio::time::sleep(Duration::from_millis(50)).await; // Faster interval for testing
    }
    
    // Check for C2 communication alert
    let mut c2_alert_received = false;
    for _ in 0..3 {
        if let Ok(alert) = tokio::time::timeout(Duration::from_millis(500), alert_receiver.recv()).await {
            if let Some(alert) = alert {
                if alert.title.contains("Command and Control") {
                    println!("✅ C2 communication alert detected: {}", alert.title);
                    println!("   C2 Domain: {}", alert.metadata.get("c2_domain").unwrap_or(&"unknown".to_string()));
                    println!("   Severity: {:?}", alert.severity);
                    c2_alert_received = true;
                    break;
                } else if alert.title.contains("Suspicious Domain") {
                    println!("📝 Also detected suspicious domain pattern");
                }
            }
        }
    }
    assert!(c2_alert_received,
        "❌ Test 4 FAILED: C2 communication detection should trigger for evil-domain.tk with beaconing pattern");
    println!("✅ Test 4 PASSED: C2 communication detection working");
    
    // Test 5: Data exfiltration simulation
    println!("\n💾 Test 5: Data exfiltration detection");
    
    // Send a batch of data exfiltration events
    // Send data exfiltration events sequentially
    for i in 0..20 {
        let large_response_event = create_dns_event_with_response(
            &format!("data-exfil-{}.com", i),
            "standard-udp",
            Some(7777),
            Some("exfil_process".to_string()),
            200_000, // 200KB per response * 20 = 4MB total
        );
        detector.process_event(&large_response_event).await.expect("Failed to process data exfil event");
        tokio::time::sleep(Duration::from_millis(10)).await; // Small delay between events
    }
    
    // Give a small window for alert processing
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Check for data exfiltration alert with timeout
    let mut exfil_alert_received = false;
    let check_timeout = tokio::time::timeout(Duration::from_millis(500), async {
        while let Some(alert) = alert_receiver.recv().await {
            if alert.title.contains("Data Exfiltration") {
                println!("✅ Data exfiltration alert detected: {}", alert.title);
                println!("   Data Transferred: {} MB", alert.metadata.get("data_transferred_mb").unwrap_or(&"unknown".to_string()));
                println!("   Severity: {:?}", alert.severity);
                return true;
            }
        }
        false
    }).await;
    
    match check_timeout {
        Ok(received) => exfil_alert_received = received,
        Err(_) => println!("⚠️  Timeout while waiting for data exfiltration alert")
    }
    
    assert!(exfil_alert_received,
        "❌ Test 5 FAILED: Data exfiltration detection should trigger for 20 events * 200KB = 4MB transfer");
    println!("✅ Test 5 PASSED: Data exfiltration detection working");
    
    // Get detector status
    let status = detector.get_status().await;
    println!("\n📈 Detector Status:");
    println!("   Events Processed: {}", status.events_processed);
    println!("   Alerts Generated: {}", status.alerts_generated);
    println!("   Processes Tracked: {}", status.processes_tracked);
    println!("   Running: {}", status.is_running);
    
    // Stop the detector
    detector.stop().await.expect("Failed to stop detector");
    assert!(!detector.is_running().await);
    
    println!("\n✅ DNS Anomaly Detection Test Completed Successfully!");
    println!("   The DNS anomaly detection system is working and capable of detecting:");
    println!("   • High-frequency DNS queries");
    println!("   • Suspicious domain patterns");
    println!("   • Potential DNS tunneling attempts");
    println!("   • Command and control communication");
    println!("   • Data exfiltration via DNS");
    
    Ok(())
}

fn create_dns_event(domain: &str, dns_type: &str, process_id: Option<u32>, process_name: Option<String>) -> Event {
    Event::new(
        EventType::NetworkDnsQuery,
        "network_monitor".to_string(),
        "test-host".to_string(),
        "test-agent".to_string(),
        EventData::Network(NetworkEventData {
            protocol: "udp".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            source_port: Some(12345),
            destination_ip: Some("8.8.8.8".to_string()),
            destination_port: Some(53),
            direction: NetworkDirection::Outbound,
            bytes_sent: Some(64),
            bytes_received: Some(128),
            connection_state: None,
            dns_query: Some(format!("{}:{}", dns_type, domain)),
            dns_response: Some(vec!["192.168.1.1".to_string()]),
            process_id,
            process_name,
        }),
    )
}

fn create_dns_event_with_response(
    domain: &str, 
    dns_type: &str, 
    process_id: Option<u32>, 
    process_name: Option<String>,
    response_bytes: u64,
) -> Event {
    Event::new(
        EventType::NetworkDnsQuery,
        "network_monitor".to_string(),
        "test-host".to_string(),
        "test-agent".to_string(),
        EventData::Network(NetworkEventData {
            protocol: "udp".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            source_port: Some(12345),
            destination_ip: Some("8.8.8.8".to_string()),
            destination_port: Some(53),
            direction: NetworkDirection::Outbound,
            bytes_sent: Some(64),
            bytes_received: Some(response_bytes),
            connection_state: None,
            dns_query: Some(format!("{}:{}", dns_type, domain)),
            dns_response: Some(vec!["192.168.1.1".to_string()]),
            process_id,
            process_name,
        }),
    )
}

async fn test_dns_baseline_learning() -> anyhow::Result<()> {
    println!("\n🧠 Testing DNS Baseline Learning");
    
    let (alert_sender, _alert_receiver) = mpsc::channel::<DetectorAlert>(100);
    
    let config = DnsAnomalyDetectorConfig {
        enabled: true,
        learning_period_hours: 1, // Short learning period for testing
        max_queries_per_minute: 1000, // High threshold during learning
        ..Default::default()
    };
    
    let detector = DnsAnomalyDetector::new(
        config,
        alert_sender,
        "test-agent".to_string(),
        "test-host".to_string(),
    ).await.expect("Failed to create DNS detector");
    
    detector.start().await.expect("Failed to start detector");
    
    // Simulate normal DNS activity during learning phase
    let normal_domains = [
        "google.com",
        "github.com", 
        "stackoverflow.com",
        "rust-lang.org",
        "crates.io",
    ];
    
    for domain in &normal_domains {
        for _ in 0..5 {
            let event = create_dns_event(domain, "standard-udp", Some(1234), Some("browser".to_string()));
            detector.process_event(&event).await.expect("Failed to process normal DNS event");
        }
    }
    
    let status = detector.get_status().await;
    println!("✅ Baseline learning completed. Events processed: {}", status.events_processed);
    
    detector.stop().await.expect("Failed to stop detector");
    Ok(())
}

async fn test_dns_protocol_detection() -> anyhow::Result<()> {
    println!("\n🔒 Testing DNS Protocol Detection");
    
    let (alert_sender, mut _alert_receiver) = mpsc::channel::<DetectorAlert>(100);
    
    let detector = DnsAnomalyDetector::new(
        DnsAnomalyDetectorConfig::default(),
        alert_sender,
        "test-agent".to_string(),
        "test-host".to_string(),
    ).await.expect("Failed to create DNS detector");
    
    detector.start().await.expect("Failed to start detector");
    
    // Test different DNS protocols
    let dns_protocols = [
        ("dns-over-https", 443, "tcp"),
        ("dns-over-tls", 853, "tcp"), 
        ("dns-over-quic", 443, "udp"),
        ("standard-udp", 53, "udp"),
        ("standard-tcp", 53, "tcp"),
    ];
    
    for (dns_type, port, protocol) in &dns_protocols {
        let event = Event::new(
            EventType::NetworkDnsQuery,
            "network_monitor".to_string(),
            "test-host".to_string(),
            "test-agent".to_string(),
            EventData::Network(NetworkEventData {
                protocol: protocol.to_string(),
                source_ip: Some("192.168.1.100".to_string()),
                source_port: Some(12345),
                destination_ip: Some("1.1.1.1".to_string()),
                destination_port: Some(*port),
                direction: NetworkDirection::Outbound,
                bytes_sent: Some(64),
                bytes_received: Some(128),
                connection_state: None,
                dns_query: Some(format!("{}:example.com", dns_type)),
                dns_response: Some(vec!["192.168.1.1".to_string()]),
                process_id: Some(1234),
                process_name: Some("dns_client".to_string()),
            }),
        );
        
        detector.process_event(&event).await.expect("Failed to process DNS protocol event");
        println!("📡 Processed {} DNS query on port {}", dns_type, port);
    }
    
    let status = detector.get_status().await;
    println!("✅ DNS protocol detection test completed. Events processed: {}", status.events_processed);
    
    detector.stop().await.expect("Failed to stop detector");
    Ok(())
}
