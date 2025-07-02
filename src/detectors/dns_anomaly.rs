use std::collections::{HashMap, VecDeque, HashSet};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::{info, error};
use tokio::sync::mpsc;
use uuid::Uuid;
use chrono::Utc;

use crate::events::{Event, EventData, NetworkEventData};
use crate::detectors::{Detector, DetectorAlert, AlertSeverity, DetectorStatus};
use crate::config::DnsAnomalyDetectorConfig;

#[derive(Debug)]
pub struct DnsAnomalyDetector {
    config: DnsAnomalyDetectorConfig,
    alert_sender: mpsc::Sender<DetectorAlert>,
    dns_tracker: Arc<RwLock<DnsTracker>>,
    detection_rules: DnsDetectionRules,
    is_running: Arc<RwLock<bool>>,
    agent_id: String,
    hostname: String,
    stats: Arc<RwLock<DnsDetectorStats>>,
}

#[derive(Debug, Default)]
struct DnsDetectorStats {
    events_processed: u64,
    alerts_generated: u64,
    domains_tracked: u64,
    last_activity: Option<Instant>,
    dns_queries_analyzed: u64,
    tunneling_attempts_detected: u64,
    high_volume_alerts: u64,
    base64_encoded_domains: u64,
}

#[derive(Debug)]
pub struct DnsTracker {
    domain_stats: HashMap<String, DomainStats>,
    process_dns_usage: HashMap<u32, ProcessDnsUsage>,
    recent_queries: VecDeque<DnsQuery>,
    baseline_metrics: DnsBaseline,
    alert_frequency: HashMap<String, Vec<Instant>>,
    last_cleanup: Instant,
    time_window_stats: HashMap<String, TimeWindowStats>,
}

#[derive(Debug, Clone)]
pub struct DomainStats {
    pub domain: String,
    pub first_query: Instant,
    pub last_query: Instant,
    pub query_count: u64,
    pub unique_query_types: HashSet<String>,
    pub requesting_processes: HashSet<u32>,
    pub total_request_bytes: u64,
    pub total_response_bytes: u64,
    pub average_response_time: Duration,
    pub query_frequency_per_hour: f64,
    pub suspicious_patterns: Vec<DnsSuspiciousPattern>,
    pub is_known_malicious: bool,
    pub entropy_score: f64,
    pub subdomain_count: u32,
    pub txt_record_queries: u32,
    pub large_response_count: u32,
}

#[derive(Debug, Clone)]
pub struct ProcessDnsUsage {
    pub process_id: u32,
    pub process_name: Option<String>,
    pub first_dns_query: Instant,
    pub last_dns_query: Instant,
    pub total_queries: u64,
    pub unique_domains: HashSet<String>,
    pub query_types: HashMap<String, u64>,
    pub hourly_query_rate: f64,
    pub data_transferred: u64,
    pub suspicious_domains: Vec<String>,
    pub risk_score: f64,
}

#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub timestamp: Instant,
    pub domain: String,
    pub query_type: String,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub response_size: Option<u64>,
    pub response_time: Option<Duration>,
    pub dns_server: Option<String>,
    pub protocol_type: DnsProtocolType,
    pub response_code: Option<String>,
}

#[derive(Debug, Clone)]
pub enum DnsProtocolType {
    StandardUdp,
    StandardTcp,
    DnsOverHttps,
    DnsOverTls,
    DnsOverQuic,
    Multicast,
    CustomPort(u16),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsSuspiciousPattern {
    HighFrequency { queries_per_minute: f64 },
    LargePayload { avg_size_bytes: u64 },
    UnusualTiming { intervals: Vec<Duration> },
    Base64Subdomain { encoded_content: String },
    TxtRecordTunneling { record_size: usize },
    SubdomainGeneration { entropy_score: f64 },
    C2Communication { communication_pattern: String },
    DataExfiltration { bytes_per_hour: u64 },
    BeaconingPattern { interval_regularity: f64 },
    UnusualQueryTypes { query_types: Vec<String> },
}

#[derive(Debug, Clone)]
pub struct DnsBaseline {
    pub normal_query_rate_per_hour: f64,
    pub normal_domains_per_hour: f64,
    pub common_query_types: HashMap<String, f64>,
    pub known_legitimate_domains: HashSet<String>,
    pub baseline_established: bool,
    pub baseline_start_time: Instant,
    pub learning_period_hours: u64,
}

#[derive(Debug, Clone)]
pub struct TimeWindowStats {
    pub five_minute_queries: VecDeque<(Instant, u64)>,
    pub hourly_queries: VecDeque<(Instant, u64)>,
    pub daily_unique_domains: HashSet<String>,
    pub peak_query_rate: f64,
    pub anomalous_spikes: u32,
}

#[derive(Debug)]
pub struct DnsDetectionRules {
    pub max_queries_per_minute: u64,
    pub max_queries_per_hour: u64,
    pub max_unique_domains_per_hour: u64,
    pub suspicious_domain_patterns: Vec<String>,
    pub known_malicious_domains: HashSet<String>,
    pub known_c2_domains: HashSet<String>,
    pub base64_detection_threshold: f64,
    pub entropy_threshold: f64,
    pub max_subdomain_length: usize,
    pub txt_record_size_threshold: usize,
    pub beaconing_detection_threshold: f64,
    pub data_exfiltration_threshold_mb_per_hour: u64,
    pub alert_frequency_limits: HashMap<String, FrequencyLimit>,
    pub dns_over_https_providers: HashSet<String>,
    pub suspicious_query_types: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FrequencyLimit {
    pub max_alerts_per_hour: u32,
    pub cooldown_multiplier: f32,
}

impl DnsAnomalyDetector {
    pub async fn new(
        config: DnsAnomalyDetectorConfig,
        alert_sender: mpsc::Sender<DetectorAlert>,
        agent_id: String,
        hostname: String,
    ) -> Result<Self> {
        let detection_rules = Self::create_detection_rules_from_config(&config);
        
        Ok(Self {
            config,
            alert_sender,
            dns_tracker: Arc::new(RwLock::new(DnsTracker::new())),
            detection_rules,
            is_running: Arc::new(RwLock::new(false)),
            agent_id,
            hostname,
            stats: Arc::new(RwLock::new(DnsDetectorStats::default())),
        })
    }

    fn create_detection_rules_from_config(config: &DnsAnomalyDetectorConfig) -> DnsDetectionRules {
        let mut alert_frequency_limits = HashMap::new();

        // Use config values to populate frequency limits
        for (key, limit) in &config.alert_frequency_limits {
            alert_frequency_limits.insert(key.clone(), FrequencyLimit {
                max_alerts_per_hour: limit.max_alerts_per_hour,
                cooldown_multiplier: limit.cooldown_multiplier,
            });
        }

        // Convert Vec<String> to HashSet<String> for domains and providers
        let known_malicious_domains: HashSet<String> = config.known_malicious_domains.iter().cloned().collect();
        let known_c2_domains: HashSet<String> = config.known_c2_domains.iter().cloned().collect();
        let dns_over_https_providers: HashSet<String> = config.dns_over_https_providers.iter().cloned().collect();

        // Default suspicious query types if not configured
        let suspicious_query_types = if config.suspicious_domain_patterns.is_empty() {
            vec![
                "TXT".to_string(),
                "NULL".to_string(),
                "PRIVATE".to_string(),
                "UNASSIGNED".to_string(),
            ]
        } else {
            vec![
                "TXT".to_string(),
                "NULL".to_string(),
                "PRIVATE".to_string(),
                "UNASSIGNED".to_string(),
            ]
        };

        DnsDetectionRules {
            max_queries_per_minute: config.max_queries_per_minute,
            max_queries_per_hour: config.max_queries_per_hour,
            max_unique_domains_per_hour: config.max_unique_domains_per_hour,
            suspicious_domain_patterns: config.suspicious_domain_patterns.clone(),
            known_malicious_domains,
            known_c2_domains,
            base64_detection_threshold: config.base64_detection_threshold,
            entropy_threshold: config.entropy_threshold,
            max_subdomain_length: 63, // DNS spec limit
            txt_record_size_threshold: config.txt_record_size_threshold,
            beaconing_detection_threshold: config.beaconing_detection_threshold,
            data_exfiltration_threshold_mb_per_hour: config.data_exfiltration_threshold_mb_per_hour,
            alert_frequency_limits,
            dns_over_https_providers,
            suspicious_query_types,
        }
    }

    fn create_detection_rules() -> DnsDetectionRules {
        let mut suspicious_domain_patterns = Vec::new();
        let known_malicious_domains = HashSet::new();
        let mut known_c2_domains = HashSet::new();
        let mut alert_frequency_limits = HashMap::new();
        let mut dns_over_https_providers = HashSet::new();
        let mut suspicious_query_types = Vec::new();

        // Suspicious domain patterns (regex-like patterns)
        suspicious_domain_patterns.extend([
            r".*\.onion$".to_string(),                          // Tor domains
            r".*[0-9]{10,}.*".to_string(),                      // Long numeric sequences
            r".*[a-fA-F0-9]{32,}.*".to_string(),               // Long hex sequences
            r".*[A-Za-z0-9+/]{20,}=*.*".to_string(),           // Base64 patterns
            r".*\.tk$".to_string(),                             // Free TLD often used maliciously
            r".*\.ml$".to_string(),                             // Free TLD often used maliciously
            r".*\.ga$".to_string(),                             // Free TLD often used maliciously
            r".*\.cf$".to_string(),                             // Free TLD often used maliciously
            r".*dyndns\..*".to_string(),                        // Dynamic DNS
            r".*ddns\..*".to_string(),                          // Dynamic DNS
            r".*ngrok\..*".to_string(),                         // Tunneling service
        ]);

        // Known C2 domains (examples - in real deployment, use threat intelligence)
        known_c2_domains.extend([
            "malware-c2.example.com".to_string(),
            "evil-domain.tk".to_string(),
            "suspicious-beacon.ml".to_string(),
        ]);

        // DNS over HTTPS providers
        dns_over_https_providers.extend([
            "1.1.1.1".to_string(),                              // Cloudflare
            "1.0.0.1".to_string(),                              // Cloudflare
            "8.8.8.8".to_string(),                              // Google
            "8.8.4.4".to_string(),                              // Google
            "9.9.9.9".to_string(),                              // Quad9
            "149.112.112.112".to_string(),                      // Quad9
            "208.67.222.222".to_string(),                       // OpenDNS
            "208.67.220.220".to_string(),                       // OpenDNS
            "94.140.14.14".to_string(),                         // AdGuard
            "94.140.15.15".to_string(),                         // AdGuard
        ]);

        // Suspicious query types that might indicate tunneling
        suspicious_query_types.extend([
            "TXT".to_string(),                                  // Often used for data exfiltration
            "NULL".to_string(),                                 // Unusual query type
            "PRIVATE".to_string(),                              // Unusual query type
            "UNASSIGNED".to_string(),                           // Unusual query type
        ]);

        // Alert frequency limits to prevent spam
        alert_frequency_limits.insert("dns_tunneling".to_string(), FrequencyLimit {
            max_alerts_per_hour: 5,
            cooldown_multiplier: 0.5,
        });

        alert_frequency_limits.insert("high_volume_dns".to_string(), FrequencyLimit {
            max_alerts_per_hour: 3,
            cooldown_multiplier: 0.7,
        });

        alert_frequency_limits.insert("suspicious_domain".to_string(), FrequencyLimit {
            max_alerts_per_hour: 10,
            cooldown_multiplier: 0.3,
        });

        DnsDetectionRules {
            max_queries_per_minute: 100,
            max_queries_per_hour: 1000,
            max_unique_domains_per_hour: 500,
            suspicious_domain_patterns,
            known_malicious_domains,
            known_c2_domains,
            base64_detection_threshold: 0.7,        // 70% base64 characters
            entropy_threshold: 4.5,                 // High entropy indicates randomness
            max_subdomain_length: 63,               // DNS spec limit
            txt_record_size_threshold: 512,         // Large TXT records are suspicious
            beaconing_detection_threshold: 0.8,     // 80% regular intervals
            data_exfiltration_threshold_mb_per_hour: 100, // 100MB/hour threshold
            alert_frequency_limits,
            dns_over_https_providers,
            suspicious_query_types,
        }
    }

    async fn analyze_dns_event(
        &self,
        tracker: &mut DnsTracker,
        network_data: &NetworkEventData,
    ) -> Result<Vec<DetectorAlert>> {
        let mut alerts = Vec::new();

        // Extract DNS query information
        if let Some(ref dns_query) = network_data.dns_query {
            let domain = self.extract_domain_from_query(dns_query);
            let query_type = self.extract_query_type_from_query(dns_query);
            
            let dns_query_obj = DnsQuery {
                timestamp: Instant::now(),
                domain: domain.clone(),
                query_type: query_type.clone(),
                process_id: network_data.process_id,
                process_name: network_data.process_name.clone(),
                response_size: network_data.bytes_received,
                response_time: None, // Could be calculated if we track request/response pairs
                dns_server: network_data.destination_ip.clone(),
                protocol_type: self.determine_dns_protocol_type(network_data),
                response_code: None, // Would need to parse actual DNS response
            };

            // Update tracking statistics
            self.update_domain_stats(tracker, &dns_query_obj).await;
            self.update_process_dns_usage(tracker, &dns_query_obj).await;
            self.update_time_window_stats(tracker, &dns_query_obj).await;

            // Perform anomaly detection
            alerts.extend(self.detect_dns_anomalies(tracker, &dns_query_obj).await?);

            // Add to recent queries for pattern analysis
            tracker.recent_queries.push_back(dns_query_obj);

            // Cleanup old queries (keep last 10000)
            while tracker.recent_queries.len() > 10000 {
                tracker.recent_queries.pop_front();
            }
        }

        Ok(alerts)
    }

    fn extract_domain_from_query(&self, dns_query: &str) -> String {
        // Parse the DNS query to extract the domain
        // Format is typically "type:domain" (e.g., "standard-udp:example.com")
        if let Some(colon_pos) = dns_query.find(':') {
            // Extract domain part after the colon
            dns_query[colon_pos + 1..].to_string()
        } else {
            // Fallback: use the entire string as domain
            dns_query.to_string()
        }
    }

    fn extract_query_type_from_query(&self, dns_query: &str) -> String {
        // Extract query type (A, AAAA, TXT, etc.)
        // Simplified - in reality, parse from DNS packet
        if dns_query.contains("txt") {
            "TXT".to_string()
        } else if dns_query.contains("aaaa") {
            "AAAA".to_string()
        } else {
            "A".to_string() // Default assumption
        }
    }

    fn determine_dns_protocol_type(&self, network_data: &NetworkEventData) -> DnsProtocolType {
        match (network_data.protocol.as_str(), network_data.destination_port) {
            ("udp", Some(53)) => DnsProtocolType::StandardUdp,
            ("tcp", Some(53)) => DnsProtocolType::StandardTcp,
            ("tcp", Some(853)) => DnsProtocolType::DnsOverTls,
            ("tcp", Some(443)) => DnsProtocolType::DnsOverHttps,
            ("udp", Some(443)) => DnsProtocolType::DnsOverQuic,
            ("udp", Some(5353)) => DnsProtocolType::Multicast,
            (_, Some(port)) => DnsProtocolType::CustomPort(port),
            _ => DnsProtocolType::StandardUdp,
        }
    }

    async fn update_domain_stats(&self, tracker: &mut DnsTracker, query: &DnsQuery) {
        // Update domains tracked stat
        {
            let mut detector_stats = self.stats.write().await;
            detector_stats.domains_tracked = tracker.domain_stats.len() as u64;
        }
        let stats = tracker.domain_stats.entry(query.domain.clone()).or_insert_with(|| DomainStats {
            domain: query.domain.clone(),
            first_query: query.timestamp,
            last_query: query.timestamp,
            query_count: 0,
            unique_query_types: HashSet::new(),
            requesting_processes: HashSet::new(),
            total_request_bytes: 0,
            total_response_bytes: 0,
            average_response_time: Duration::from_millis(0),
            query_frequency_per_hour: 0.0,
            suspicious_patterns: Vec::new(),
            is_known_malicious: false,
            entropy_score: self.calculate_domain_entropy(&query.domain),
            subdomain_count: query.domain.split('.').count() as u32,
            txt_record_queries: 0,
            large_response_count: 0,
        });

        stats.last_query = query.timestamp;
        stats.query_count += 1;
        stats.unique_query_types.insert(query.query_type.clone());
        
        if let Some(pid) = query.process_id {
            stats.requesting_processes.insert(pid);
        }

        // Update TXT record count
        if query.query_type == "TXT" {
            stats.txt_record_queries += 1;
        }

        // Update large response count
        if let Some(response_size) = query.response_size {
            stats.total_response_bytes += response_size;
            if response_size > 1024 { // Responses > 1KB are considered large
                stats.large_response_count += 1;
            }
        }

        // Calculate query frequency per hour
        let duration_hours = query.timestamp.duration_since(stats.first_query).as_secs_f64() / 3600.0;
        if duration_hours > 0.0 {
            stats.query_frequency_per_hour = stats.query_count as f64 / duration_hours;
        }

        // Check for malicious domains
        stats.is_known_malicious = self.detection_rules.known_malicious_domains.contains(&query.domain) ||
                                  self.detection_rules.known_c2_domains.contains(&query.domain);
                                  
        // Update baseline metrics learning
        if !tracker.baseline_metrics.baseline_established {
            tracker.baseline_metrics.known_legitimate_domains.insert(query.domain.clone());
        }
    }

    async fn update_process_dns_usage(&self, tracker: &mut DnsTracker, query: &DnsQuery) {
        if let Some(pid) = query.process_id {
            let usage = tracker.process_dns_usage.entry(pid).or_insert_with(|| ProcessDnsUsage {
                process_id: pid,
                process_name: query.process_name.clone(),
                first_dns_query: query.timestamp,
                last_dns_query: query.timestamp,
                total_queries: 0,
                unique_domains: HashSet::new(),
                query_types: HashMap::new(),
                hourly_query_rate: 0.0,
                data_transferred: 0,
                suspicious_domains: Vec::new(),
                risk_score: 0.0,
            });

            usage.last_dns_query = query.timestamp;
            usage.total_queries += 1;
            usage.unique_domains.insert(query.domain.clone());
            *usage.query_types.entry(query.query_type.clone()).or_insert(0) += 1;

            if let Some(response_size) = query.response_size {
                usage.data_transferred += response_size;
            }

            // Calculate hourly query rate
            let duration_hours = query.timestamp.duration_since(usage.first_dns_query).as_secs_f64() / 3600.0;
            if duration_hours > 0.0 {
                usage.hourly_query_rate = usage.total_queries as f64 / duration_hours;
            }

            // Check for suspicious domains
            if self.is_domain_suspicious(&query.domain) {
                if !usage.suspicious_domains.contains(&query.domain) {
                    usage.suspicious_domains.push(query.domain.clone());
                }
            }

            // Calculate risk score based on various factors
            usage.risk_score = self.calculate_process_risk_score(usage);
        }
    }

    async fn update_time_window_stats(&self, tracker: &mut DnsTracker, query: &DnsQuery) {
        let stats = tracker.time_window_stats.entry("global".to_string()).or_insert_with(|| TimeWindowStats {
            five_minute_queries: VecDeque::new(),
            hourly_queries: VecDeque::new(),
            daily_unique_domains: HashSet::new(),
            peak_query_rate: 0.0,
            anomalous_spikes: 0,
        });

        let now = query.timestamp;
        
        // Update 5-minute window
        stats.five_minute_queries.push_back((now, 1));
        let five_minutes_ago = now - Duration::from_secs(300);
        while let Some(&(timestamp, _)) = stats.five_minute_queries.front() {
            if timestamp < five_minutes_ago {
                stats.five_minute_queries.pop_front();
            } else {
                break;
            }
        }

        // Update hourly window
        stats.hourly_queries.push_back((now, 1));
        let one_hour_ago = now - Duration::from_secs(3600);
        while let Some(&(timestamp, _)) = stats.hourly_queries.front() {
            if timestamp < one_hour_ago {
                stats.hourly_queries.pop_front();
            } else {
                break;
            }
        }

        // Update daily unique domains
        stats.daily_unique_domains.insert(query.domain.clone());
        
        // Clean up daily domains (keep only last 24 hours worth)
        // This is simplified - in practice you'd track timestamps per domain

        // Calculate current query rate (queries per minute)
        let one_minute_ago = now - Duration::from_secs(60);
        let queries_last_minute = stats.five_minute_queries.iter()
            .filter(|(timestamp, _)| *timestamp > one_minute_ago)
            .count();
        let current_rate = queries_last_minute as f64;
        
        if current_rate > stats.peak_query_rate {
            stats.peak_query_rate = current_rate;
        }

        // Detect anomalous spikes
        if current_rate > self.detection_rules.max_queries_per_minute as f64 {
            stats.anomalous_spikes += 1;
        }
    }

    async fn detect_dns_anomalies(
        &self,
        tracker: &DnsTracker,
        query: &DnsQuery,
    ) -> Result<Vec<DetectorAlert>> {
        let mut alerts = Vec::new();

        // 1. High-frequency DNS queries
        if let Some(stats) = tracker.time_window_stats.get("global") {
            let one_minute_ago = query.timestamp - Duration::from_secs(60);
            let queries_last_minute = stats.five_minute_queries.iter()
                .filter(|(timestamp, _)| *timestamp > one_minute_ago)
                .count();
            let one_min_rate = queries_last_minute as f64;
            if one_min_rate > self.detection_rules.max_queries_per_minute as f64 {
                alerts.push(self.create_high_frequency_alert(one_min_rate, query).await);
            }
        }

        // 2. Suspicious domain patterns
        if self.is_domain_suspicious(&query.domain) {
            alerts.push(self.create_suspicious_domain_alert(&query.domain, query).await);
        }

        // 3. DNS tunneling detection
        if self.detect_dns_tunneling(tracker, query).await {
            alerts.push(self.create_tunneling_alert(query).await);
        }

        // 4. Data exfiltration detection
        if let Some(process_usage) = tracker.process_dns_usage.get(&query.process_id.unwrap_or(0)) {
            let hourly_data_mb = process_usage.data_transferred as f64 / 1024.0 / 1024.0;
            if hourly_data_mb > self.detection_rules.data_exfiltration_threshold_mb_per_hour as f64 {
                alerts.push(self.create_data_exfiltration_alert(process_usage, query).await);
            }
        }

        // 5. C2 communication detection
        if self.detect_c2_communication(tracker, query).await {
            alerts.push(self.create_c2_communication_alert(query).await);
        }

        // 6. Beaconing detection
        if self.detect_beaconing_pattern(tracker, query).await {
            alerts.push(self.create_beaconing_alert(query).await);
        }

        // Filter alerts based on frequency limits
        alerts.retain(|alert| self.should_send_alert(tracker, alert));

        Ok(alerts)
    }

    fn is_domain_suspicious(&self, domain: &str) -> bool {
        // Check against known malicious domains
        if self.detection_rules.known_malicious_domains.contains(domain) ||
           self.detection_rules.known_c2_domains.contains(domain) {
            return true;
        }

        // Check against suspicious patterns
        for pattern in &self.detection_rules.suspicious_domain_patterns {
            if self.matches_pattern(pattern, domain) {
                return true;
            }
        }

        // Check entropy (high entropy suggests domain generation algorithm)
        let entropy = self.calculate_domain_entropy(domain);
        if entropy > self.detection_rules.entropy_threshold {
            return true;
        }

        // Check for base64 patterns
        if self.contains_base64_pattern(domain) {
            return true;
        }

        false
    }

    async fn detect_dns_tunneling(&self, tracker: &DnsTracker, query: &DnsQuery) -> bool {
        if let Some(domain_stats) = tracker.domain_stats.get(&query.domain) {
            // Multiple indicators of DNS tunneling:
            
            // 1. High frequency of TXT record queries
            if domain_stats.txt_record_queries > 10 && 
               domain_stats.txt_record_queries as f64 / domain_stats.query_count as f64 > 0.5 {
                return true;
            }

            // 2. Large response sizes consistently
            if domain_stats.large_response_count > 5 &&
               domain_stats.large_response_count as f64 / domain_stats.query_count as f64 > 0.3 {
                return true;
            }

            // 3. High subdomain count with random patterns
            if domain_stats.subdomain_count > 5 && domain_stats.entropy_score > 4.0 {
                return true;
            }

            // 4. Consistent high-frequency queries to the same domain
            if domain_stats.query_frequency_per_hour > 60.0 { // More than 1 query per minute
                return true;
            }
        }

        false
    }

    async fn detect_c2_communication(&self, tracker: &DnsTracker, query: &DnsQuery) -> bool {
        // Check if domain is in known C2 list
        if self.detection_rules.known_c2_domains.contains(&query.domain) {
            return true;
        }

        // Check for beaconing to specific domains
        if let Some(domain_stats) = tracker.domain_stats.get(&query.domain) {
            // Regular intervals might indicate C2 beaconing
            if domain_stats.query_count > 10 {
                let regularity = self.calculate_query_interval_regularity(domain_stats);
                if regularity > self.detection_rules.beaconing_detection_threshold {
                    return true;
                }
            }
        }

        false
    }

    async fn detect_beaconing_pattern(&self, tracker: &DnsTracker, query: &DnsQuery) -> bool {
        if let Some(process_usage) = tracker.process_dns_usage.get(&query.process_id.unwrap_or(0)) {
            // Check if process is making regular DNS queries
            if process_usage.total_queries > 20 {
                let time_span = query.timestamp.duration_since(process_usage.first_dns_query);
                let average_interval = time_span.as_secs_f64() / process_usage.total_queries as f64;
                
                // Check if intervals are suspiciously regular (typical of automated beaconing)
                if average_interval > 60.0 && average_interval < 3600.0 { // Between 1 minute and 1 hour
                    // Calculate regularity - this would need more sophisticated analysis
                    // For now, flag if there's consistent querying
                    return true;
                }
            }
        }

        false
    }

    fn calculate_domain_entropy(&self, domain: &str) -> f64 {
        let mut char_counts = HashMap::new();
        for c in domain.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        let length = domain.len() as f64;
        let mut entropy = 0.0;

        for &count in char_counts.values() {
            let probability = count as f64 / length;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    fn contains_base64_pattern(&self, domain: &str) -> bool {
        let base64_chars = domain.chars()
            .filter(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .count();
        
        let total_chars = domain.len();
        if total_chars == 0 {
            return false;
        }

        let base64_ratio = base64_chars as f64 / total_chars as f64;
        base64_ratio > self.detection_rules.base64_detection_threshold
    }

    fn matches_pattern(&self, pattern: &str, text: &str) -> bool {
        // Simplified pattern matching - in production, use regex
        if pattern.starts_with(".*") && pattern.ends_with("$") {
            let suffix = &pattern[2..pattern.len()-1];
            text.ends_with(suffix)
        } else if pattern.contains(".*") {
            let parts: Vec<&str> = pattern.split(".*").collect();
            if parts.len() == 2 {
                text.starts_with(parts[0]) && text.ends_with(parts[1])
            } else {
                text.contains(&pattern.replace(".*", ""))
            }
        } else {
            text.contains(pattern)
        }
    }

    fn calculate_process_risk_score(&self, usage: &ProcessDnsUsage) -> f64 {
        let mut risk_score = 0.0;

        // High query rate increases risk
        if usage.hourly_query_rate > 100.0 {
            risk_score += 0.3;
        }

        // Many unique domains increases risk
        if usage.unique_domains.len() > 100 {
            risk_score += 0.2;
        }

        // Suspicious domains significantly increase risk
        risk_score += usage.suspicious_domains.len() as f64 * 0.1;

        // High data transfer increases risk
        let hourly_data_mb = usage.data_transferred as f64 / 1024.0 / 1024.0;
        if hourly_data_mb > 50.0 {
            risk_score += 0.4;
        }

        // TXT queries increase risk (potential tunneling)
        if let Some(&txt_count) = usage.query_types.get("TXT") {
            if txt_count > 10 {
                risk_score += 0.3;
            }
        }

        risk_score.min(1.0) // Cap at 1.0
    }

    fn calculate_query_interval_regularity(&self, domain_stats: &DomainStats) -> f64 {
        // This would need access to timestamp history to calculate properly
        // For now, return a simplified calculation based on frequency
        if domain_stats.query_frequency_per_hour > 0.0 {
            let expected_interval = 3600.0 / domain_stats.query_frequency_per_hour;
            if expected_interval > 60.0 && expected_interval < 3600.0 {
                0.8 // High regularity score
            } else {
                0.2 // Low regularity score
            }
        } else {
            0.0
        }
    }

    fn should_send_alert(&self, tracker: &DnsTracker, alert: &DetectorAlert) -> bool {
        // Check frequency limits based on alert type
        let alert_type = alert.metadata.get("alert_type").unwrap_or(&"general".to_string()).clone();
        
        if let Some(limit) = self.detection_rules.alert_frequency_limits.get(&alert_type) {
            if let Some(recent_alerts) = tracker.alert_frequency.get(&alert_type) {
                let one_hour_ago = Instant::now() - Duration::from_secs(3600);
                let recent_count = recent_alerts.iter().filter(|&&t| t > one_hour_ago).count();
                
                return recent_count < limit.max_alerts_per_hour as usize;
            }
        }

        true // Send alert if no limits configured
    }

    // Alert creation methods
    async fn create_high_frequency_alert(&self, rate: f64, query: &DnsQuery) -> DetectorAlert {
        DetectorAlert {
            id: Uuid::new_v4().to_string(),
            detector_name: "dns_anomaly_detector".to_string(),
            severity: AlertSeverity::High,
            title: "High-Frequency DNS Queries Detected".to_string(),
            description: format!(
                "Detected {} DNS queries per minute, exceeding threshold of {}. Domain: {}",
                rate, self.detection_rules.max_queries_per_minute, query.domain
            ),
            affected_processes: query.process_id.map(|pid| vec![pid]).unwrap_or_default(),
            indicators: vec![
                format!("Query rate: {:.1} queries/minute", rate),
                format!("Domain: {}", query.domain),
                format!("Process: {:?}", query.process_name),
            ],
            recommended_actions: vec![
                "Investigate the process making high-frequency DNS queries".to_string(),
                "Check if this is legitimate application behavior".to_string(),
                "Monitor for data exfiltration patterns".to_string(),
            ],
            risk_score: (rate / self.detection_rules.max_queries_per_minute as f64).min(1.0) as f32,
            timestamp: Utc::now(),
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("alert_type".to_string(), "high_volume_dns".to_string());
                metadata.insert("query_rate".to_string(), rate.to_string());
                metadata.insert("domain".to_string(), query.domain.clone());
                metadata.insert("agent_id".to_string(), self.agent_id.clone());
                metadata.insert("hostname".to_string(), self.hostname.clone());
                metadata
            },
        }
    }

    async fn create_suspicious_domain_alert(&self, domain: &str, query: &DnsQuery) -> DetectorAlert {
        DetectorAlert {
            id: Uuid::new_v4().to_string(),
            detector_name: "dns_anomaly_detector".to_string(),
            severity: AlertSeverity::High,
            title: "Suspicious Domain Query Detected".to_string(),
            description: format!(
                "DNS query to suspicious domain: {}. This domain matches known malicious patterns.",
                domain
            ),
            affected_processes: query.process_id.map(|pid| vec![pid]).unwrap_or_default(),
            indicators: vec![
                format!("Suspicious domain: {}", domain),
                format!("Process: {:?}", query.process_name),
                format!("Query type: {}", query.query_type),
            ],
            recommended_actions: vec![
                "Block the suspicious domain immediately".to_string(),
                "Investigate the process making the query".to_string(),
                "Check for malware infection".to_string(),
                "Review other DNS queries from this process".to_string(),
            ],
            risk_score: 0.9,
            timestamp: Utc::now(),
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("alert_type".to_string(), "suspicious_domain".to_string());
                metadata.insert("domain".to_string(), domain.to_string());
                metadata.insert("query_type".to_string(), query.query_type.clone());
                metadata.insert("agent_id".to_string(), self.agent_id.clone());
                metadata.insert("hostname".to_string(), self.hostname.clone());
                metadata
            },
        }
    }

    async fn create_tunneling_alert(&self, query: &DnsQuery) -> DetectorAlert {
        DetectorAlert {
            id: Uuid::new_v4().to_string(),
            detector_name: "dns_anomaly_detector".to_string(),
            severity: AlertSeverity::Critical,
            title: "DNS Tunneling Detected".to_string(),
            description: format!(
                "Detected potential DNS tunneling activity to domain: {}. This may indicate data exfiltration or command and control communication.",
                query.domain
            ),
            affected_processes: query.process_id.map(|pid| vec![pid]).unwrap_or_default(),
            indicators: vec![
                format!("Domain: {}", query.domain),
                format!("Process: {:?}", query.process_name),
                "High frequency TXT record queries".to_string(),
                "Large DNS response sizes".to_string(),
                "High entropy domain names".to_string(),
            ],
            recommended_actions: vec![
                "Immediately block the domain".to_string(),
                "Isolate the affected system".to_string(),
                "Perform forensic analysis".to_string(),
                "Check for data breach".to_string(),
                "Review firewall logs for related activity".to_string(),
            ],
            risk_score: 0.95,
            timestamp: Utc::now(),
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("alert_type".to_string(), "dns_tunneling".to_string());
                metadata.insert("domain".to_string(), query.domain.clone());
                metadata.insert("attack_technique".to_string(), "T1048.003".to_string()); // MITRE ATT&CK
                metadata.insert("agent_id".to_string(), self.agent_id.clone());
                metadata.insert("hostname".to_string(), self.hostname.clone());
                metadata
            },
        }
    }

    async fn create_data_exfiltration_alert(&self, process_usage: &ProcessDnsUsage, _query: &DnsQuery) -> DetectorAlert {
        let hourly_data_mb = process_usage.data_transferred as f64 / 1024.0 / 1024.0;
        
        DetectorAlert {
            id: Uuid::new_v4().to_string(),
            detector_name: "dns_anomaly_detector".to_string(),
            severity: AlertSeverity::Critical,
            title: "Potential Data Exfiltration via DNS".to_string(),
            description: format!(
                "Process {} has transferred {:.2} MB of data via DNS queries in the last hour, exceeding the threshold of {} MB.",
                process_usage.process_name.as_ref().unwrap_or(&"Unknown".to_string()),
                hourly_data_mb,
                self.detection_rules.data_exfiltration_threshold_mb_per_hour
            ),
            affected_processes: vec![process_usage.process_id],
            indicators: vec![
                format!("Data transferred: {:.2} MB/hour", hourly_data_mb),
                format!("Process: {:?}", process_usage.process_name),
                format!("Unique domains: {}", process_usage.unique_domains.len()),
                format!("Total queries: {}", process_usage.total_queries),
            ],
            recommended_actions: vec![
                "Immediately isolate the affected system".to_string(),
                "Block DNS queries from the process".to_string(),
                "Investigate what data may have been exfiltrated".to_string(),
                "Check for unauthorized access".to_string(),
                "Perform incident response procedures".to_string(),
            ],
            risk_score: 0.9,
            timestamp: Utc::now(),
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("alert_type".to_string(), "data_exfiltration".to_string());
                metadata.insert("data_transferred_mb".to_string(), hourly_data_mb.to_string());
                metadata.insert("process_id".to_string(), process_usage.process_id.to_string());
                metadata.insert("attack_technique".to_string(), "T1041".to_string()); // MITRE ATT&CK
                metadata.insert("agent_id".to_string(), self.agent_id.clone());
                metadata.insert("hostname".to_string(), self.hostname.clone());
                metadata
            },
        }
    }

    async fn create_c2_communication_alert(&self, query: &DnsQuery) -> DetectorAlert {
        DetectorAlert {
            id: Uuid::new_v4().to_string(),
            detector_name: "dns_anomaly_detector".to_string(),
            severity: AlertSeverity::Critical,
            title: "Command and Control Communication Detected".to_string(),
            description: format!(
                "Detected DNS queries to known command and control domain: {}. This indicates potential malware infection.",
                query.domain
            ),
            affected_processes: query.process_id.map(|pid| vec![pid]).unwrap_or_default(),
            indicators: vec![
                format!("C2 domain: {}", query.domain),
                format!("Process: {:?}", query.process_name),
                "Regular beaconing pattern detected".to_string(),
                "Known malicious domain".to_string(),
            ],
            recommended_actions: vec![
                "Immediately isolate the infected system".to_string(),
                "Block the C2 domain at firewall level".to_string(),
                "Run full malware scan".to_string(),
                "Check for lateral movement".to_string(),
                "Initiate incident response procedures".to_string(),
            ],
            risk_score: 1.0,
            timestamp: Utc::now(),
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("alert_type".to_string(), "c2_communication".to_string());
                metadata.insert("c2_domain".to_string(), query.domain.clone());
                metadata.insert("attack_technique".to_string(), "T1071.004".to_string()); // MITRE ATT&CK
                metadata.insert("agent_id".to_string(), self.agent_id.clone());
                metadata.insert("hostname".to_string(), self.hostname.clone());
                metadata
            },
        }
    }

    async fn create_beaconing_alert(&self, query: &DnsQuery) -> DetectorAlert {
        DetectorAlert {
            id: Uuid::new_v4().to_string(),
            detector_name: "dns_anomaly_detector".to_string(),
            severity: AlertSeverity::High,
            title: "DNS Beaconing Pattern Detected".to_string(),
            description: format!(
                "Detected regular DNS beaconing pattern to domain: {}. This may indicate malware communication.",
                query.domain
            ),
            affected_processes: query.process_id.map(|pid| vec![pid]).unwrap_or_default(),
            indicators: vec![
                format!("Beaconing domain: {}", query.domain),
                format!("Process: {:?}", query.process_name),
                "Regular query intervals detected".to_string(),
                "Automated communication pattern".to_string(),
            ],
            recommended_actions: vec![
                "Monitor the beaconing process closely".to_string(),
                "Investigate the domain reputation".to_string(),
                "Check for malware infection".to_string(),
                "Consider blocking the domain".to_string(),
            ],
            risk_score: 0.8,
            timestamp: Utc::now(),
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("alert_type".to_string(), "beaconing".to_string());
                metadata.insert("domain".to_string(), query.domain.clone());
                metadata.insert("attack_technique".to_string(), "T1071.004".to_string()); // MITRE ATT&CK
                metadata.insert("agent_id".to_string(), self.agent_id.clone());
                metadata.insert("hostname".to_string(), self.hostname.clone());
                metadata
            },
        }
    }
}

impl DnsTracker {
    fn new() -> Self {
        Self {
            domain_stats: HashMap::new(),
            process_dns_usage: HashMap::new(),
            recent_queries: VecDeque::new(),
            baseline_metrics: DnsBaseline {
                normal_query_rate_per_hour: 0.0,
                normal_domains_per_hour: 0.0,
                common_query_types: HashMap::new(),
                known_legitimate_domains: HashSet::new(),
                baseline_established: false,
                baseline_start_time: Instant::now(),
                learning_period_hours: 24, // Learn for 24 hours
            },
            alert_frequency: HashMap::new(),
            last_cleanup: Instant::now(),
            time_window_stats: HashMap::new(),
        }
    }

    fn cleanup_old_data(&mut self) {
        let now = Instant::now();
        let one_hour_ago = now - Duration::from_secs(3600);
        let one_day_ago = now - Duration::from_secs(86400);

        // Cleanup alert frequency tracking
        for (_, timestamps) in self.alert_frequency.iter_mut() {
            timestamps.retain(|&t| t > one_hour_ago);
        }

        // Cleanup old queries
        self.recent_queries.retain(|query| query.timestamp > one_day_ago);

        // Cleanup old domain stats (keep only active domains from last 24 hours)
        self.domain_stats.retain(|_, stats| stats.last_query > one_day_ago);

        // Cleanup old process usage (keep only active processes from last 24 hours)
        self.process_dns_usage.retain(|_, usage| usage.last_dns_query > one_day_ago);

        self.last_cleanup = now;
    }
}

#[async_trait::async_trait]
impl Detector for DnsAnomalyDetector {
    async fn start(&self) -> Result<()> {
        info!("Starting DNS anomaly detector");
        *self.is_running.write().await = true;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping DNS anomaly detector");
        *self.is_running.write().await = false;
        Ok(())
    }

    async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    async fn get_status(&self) -> DetectorStatus {
        let stats = self.stats.read().await;
        let tracker = self.dns_tracker.read().await;
        
        DetectorStatus {
            name: "dns_anomaly_detector".to_string(),
            is_running: self.is_running().await,
            events_processed: stats.events_processed,
            alerts_generated: stats.alerts_generated,
            processes_tracked: tracker.process_dns_usage.len() as u64,
            last_activity: stats.last_activity.unwrap_or_else(Instant::now),
            memory_usage_kb: 0, // TODO: Implement memory tracking
            cpu_usage_percent: 0.0, // TODO: Implement CPU tracking
        }
    }

    async fn process_event(&self, event: &Event) -> Result<()> {
        // Only process DNS-related network events
        if let EventData::Network(network_data) = &event.data {
            if network_data.dns_query.is_some() || 
               network_data.destination_port == Some(53) ||
               network_data.destination_port == Some(853) ||
               (network_data.destination_port == Some(443) && 
                network_data.protocol.to_lowercase().contains("dns")) {
                
                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    stats.events_processed += 1;
                    stats.last_activity = Some(Instant::now());
                    stats.dns_queries_analyzed += 1;
                }

                // Analyze the DNS event
                let mut tracker = self.dns_tracker.write().await;
                let alerts = self.analyze_dns_event(&mut tracker, network_data).await?;

                // Periodic cleanup
                if tracker.last_cleanup.elapsed() > Duration::from_secs(3600) {
                    tracker.cleanup_old_data();
                }

                drop(tracker);

                // Send alerts
                for alert in alerts {
                    {
                        let mut stats = self.stats.write().await;
                        stats.alerts_generated += 1;
                        
                        // Update specific stats based on alert type
                        if let Some(alert_type) = alert.metadata.get("alert_type") {
                            match alert_type.as_str() {
                                "dns_tunneling" => stats.tunneling_attempts_detected += 1,
                                "high_volume_dns" => stats.high_volume_alerts += 1,
                                "suspicious_domain" if alert.description.contains("base64") => {
                                    stats.base64_encoded_domains += 1;
                                }
                                _ => {}
                            }
                        }
                    }

                    if let Err(e) = self.alert_sender.send(alert).await {
                        error!("Failed to send DNS anomaly alert: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "dns_anomaly_detector"
    }
}

impl DnsAnomalyDetector {
    pub fn get_config(&self) -> &DnsAnomalyDetectorConfig {
        &self.config
    }
}
