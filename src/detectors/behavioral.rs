use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::sync::Arc;

#[cfg(windows)]
const WINDOWS_SYSTEM32: &str = "C:/Windows/System32";
#[cfg(windows)]
const WINDOWS_SYSWOW64: &str = "C:/Windows/SysWOW64";
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use tracing::{debug, info};
use tokio::sync::mpsc;

use crate::events::{Event, EventData, ProcessEventData, FileEventData, NetworkEventData};
use crate::detectors::{Detector, EventDetector, DetectorAlert};
use crate::events::AlertSeverity;
use crate::detectors::DetectorStatus;
use crate::config::{BehavioralDetectorConfig, ProcessWhitelist};

// Cross-platform behavioral threat detector
#[derive(Debug)]
pub struct BehavioralDetector {
    config: BehavioralDetectorConfig,
    alert_sender: mpsc::Sender<DetectorAlert>,
    process_tracker: Arc<RwLock<ProcessTracker>>,
    detection_rules: DetectionRules,
    is_running: Arc<RwLock<bool>>,
    agent_id: String,
    hostname: String,
    stats: Arc<RwLock<DetectorStats>>,
}

#[derive(Debug, Default)]
struct DetectorStats {
    events_processed: u64,
    alerts_generated: u64,
    last_activity: Option<Instant>,
}

// Process tracking state
#[derive(Debug)]
pub struct ProcessTracker {
    processes: HashMap<u32, ProcessState>,
    recent_events: VecDeque<SuspiciousEvent>,
    blocked_processes: HashMap<u32, Instant>,
    alert_frequency: HashMap<String, Vec<Instant>>, // Track alert frequency by type
    last_cleanup: Instant,
}

// Per-process injection indicators
#[derive(Debug, Clone)]
pub struct ProcessState {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub parent_pid: u32,
    pub creation_time: Instant,
    pub handles_opened: u32,
    pub memory_operations: u32,
    pub thread_operations: u32,
    pub dll_operations: u32,
    pub file_operations: u32,
    pub network_operations: u32,
    pub suspicious_api_calls: Vec<ApiCall>,
    pub risk_score: f32,
    pub last_update: Instant,
}

// Suspicious event tracking
#[derive(Debug, Clone)]
pub struct SuspiciousEvent {
    pub timestamp: Instant,
    pub event_type: InjectionEventType,
    pub source_pid: u32,
    pub target_pid: Option<u32>,
    pub severity: InjectionSeverity,
    pub details: String,
    pub risk_score: f32,
    pub platform_specific: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionEventType {
    SuspiciousHandleAccess,
    CrossProcessMemoryOp,
    RemoteThreadCreation,
    MemoryProtectionChange,
    ProcessHollowing,
    ApiHooking,
    DllInjection,
    ApcQueueing,
    SuspiciousFileAccess,
    ShellcodeDetection,
    UnusualNetworkBehavior,
    // Cross-platform events
    PtraceUsage,      // Linux/macOS
    MachPortUsage,    // macOS
    DebuggerAttach,   // All platforms
    SuspiciousLibrary, // All platforms
    SuspiciousProcess, // All platforms
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct ApiCall {
    pub function: String,
    pub timestamp: Instant,
    pub parameters: HashMap<String, String>,
    pub risk_weight: f32,
    pub platform: String,
}

// Detection rules and weights
#[derive(Debug)]
struct DetectionRules {
    pub system_process_contexts: HashMap<String, SystemProcessContext>,
    pub alert_frequency_limits: HashMap<String, FrequencyLimit>,
    pub process_whitelist: ProcessWhitelist,
    pub suspicious_paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SystemProcessContext {
    pub expected_paths: Vec<String>,
    pub max_instances: u32,
    pub baseline_risk_reduction: f32, // Reduce risk when in expected context
    pub elevated_risk_multiplier: f32, // Increase risk when in unexpected context
}

#[derive(Debug, Clone)]
pub struct FrequencyLimit {
    pub max_alerts_per_hour: u32,
    pub cooldown_multiplier: f32, // Reduce subsequent alert severity
}


impl BehavioralDetector {
    fn should_whitelist(&self, process_data: &ProcessEventData, tracker: &ProcessTracker) -> bool {
        let whitelist = &self.detection_rules.process_whitelist;
        if !whitelist.enabled {
            return false;
        }

        // Check against whitelisted process names
        if whitelist.process_names.contains(&process_data.name) {
            return true;
        }

        // Check against whitelisted process paths
        if whitelist.process_paths.iter().any(|pattern| process_data.path.contains(pattern)) {
            return true;
        }

        // Check against whitelisted command lines
        if let Some(command_line) = &process_data.command_line {
            if whitelist.command_line_patterns.iter().any(|pattern| command_line.contains(pattern)) {
                return true;
            }
        }

        // Check if parent process is whitelisted
        if let Some(ppid) = process_data.ppid {
            if let Some(parent) = tracker.processes.get(&ppid) {
                if whitelist.parent_process_names.contains(&parent.name) {
                    return true;
                }
            }
        }

        false
    }
    pub async fn new(
        config: BehavioralDetectorConfig,
        alert_sender: mpsc::Sender<DetectorAlert>,
        agent_id: String,
        hostname: String,
    ) -> Result<Self> {
        let detection_rules = Self::create_platform_rules_with_config(config.process_whitelist.clone());
        
        Ok(Self {
            config,
            alert_sender,
            process_tracker: Arc::new(RwLock::new(ProcessTracker::new())),
            detection_rules,
            is_running: Arc::new(RwLock::new(false)),
            agent_id,
            hostname,
            stats: Arc::new(RwLock::new(DetectorStats::default())),
        })
    }

    fn create_platform_rules_with_config(whitelist: ProcessWhitelist) -> DetectionRules {
        let mut suspicious_paths = Vec::new();
        
        // Cross-platform suspicious paths
        suspicious_paths.extend([
            "/tmp/".to_string(),
            "/dev/shm/".to_string(),
            "/var/tmp/".to_string(),
        ]);
        
        #[cfg(windows)]
        {
            // Windows suspicious paths
            suspicious_paths.extend([
                "\\Windows\\Temp\\".to_string(),
                "\\Users\\Public\\".to_string(),
                "\\AppData\\Local\\Temp\\".to_string(),
                "\\ProgramData\\".to_string(),
            ]);
        }
        
        // System process context definitions
        let mut system_process_contexts = HashMap::new();
        
        // macOS system processes
        system_process_contexts.insert("mdworker_shared".to_string(), SystemProcessContext {
            expected_paths: vec![
                "/System/Library/Frameworks/CoreServices.framework/".to_string(),
                "/usr/libexec/".to_string(),
            ],
            max_instances: 20, // Spotlight can spawn many workers
            baseline_risk_reduction: 0.7, // 70% risk reduction when in expected context
            elevated_risk_multiplier: 2.5, // 2.5x risk when in unexpected context
        });
        
        system_process_contexts.insert("sharingd".to_string(), SystemProcessContext {
            expected_paths: vec![
                "/usr/libexec/".to_string(),
                "/System/Library/".to_string(),
            ],
            max_instances: 1,
            baseline_risk_reduction: 0.8,
            elevated_risk_multiplier: 3.0,
        });
        
        system_process_contexts.insert("ReportCrash".to_string(), SystemProcessContext {
            expected_paths: vec![
                "/System/Library/CoreServices/".to_string(),
            ],
            max_instances: 5,
            baseline_risk_reduction: 0.9,
            elevated_risk_multiplier: 4.0, // Very suspicious if in wrong location
        });
        
        // Linux system processes
        system_process_contexts.insert("systemd".to_string(), SystemProcessContext {
            expected_paths: vec![
                "/lib/systemd/".to_string(),
                "/usr/lib/systemd/".to_string(),
                "/bin/".to_string(),
                "/sbin/".to_string(),
            ],
            max_instances: 50, // systemd can have many processes
            baseline_risk_reduction: 0.8, // 80% risk reduction when in expected context
            elevated_risk_multiplier: 3.0, // 3x risk when in unexpected context
        });
        
        system_process_contexts.insert("init".to_string(), SystemProcessContext {
            expected_paths: vec![
                "/sbin/".to_string(),
                "/bin/".to_string(),
                "/usr/sbin/".to_string(),
            ],
            max_instances: 1, // Only one init process should exist
            baseline_risk_reduction: 0.9, // 90% risk reduction when in expected context
            elevated_risk_multiplier: 5.0, // Very suspicious if in wrong location
        });
        
        // Alert frequency limits
        let mut alert_frequency_limits = HashMap::new();
        
        alert_frequency_limits.insert("mdworker_shared".to_string(), FrequencyLimit {
            max_alerts_per_hour: 5, // Limit mdworker alerts to 5 per hour
            cooldown_multiplier: 0.5, // Reduce subsequent alert severity by 50%
        });
        
        alert_frequency_limits.insert("sharingd".to_string(), FrequencyLimit {
            max_alerts_per_hour: 2,
            cooldown_multiplier: 0.3,
        });
        
        alert_frequency_limits.insert("biome_tmp".to_string(), FrequencyLimit {
            max_alerts_per_hour: 3, // Limit Biome temp file alerts
            cooldown_multiplier: 0.4,
        });

        // Mail operation frequency limits
        alert_frequency_limits.insert("mail_tmp".to_string(), FrequencyLimit {
            max_alerts_per_hour: 15, // Allow more temp file operations for Mail
            cooldown_multiplier: 0.3, // Reduce subsequent alert severity by 70%
        });

        alert_frequency_limits.insert("mail_group".to_string(), FrequencyLimit {
            max_alerts_per_hour: 10, // Group container operations
            cooldown_multiplier: 0.3,
        });

        // Messages app limits
        alert_frequency_limits.insert("messages_tmp".to_string(), FrequencyLimit {
            max_alerts_per_hour: 20, // Messages can create many temp files for attachments
            cooldown_multiplier: 0.3,
        });

        // News widget limits
        alert_frequency_limits.insert("news_widget_tmp".to_string(), FrequencyLimit {
            max_alerts_per_hour: 10, // News widget temp files
            cooldown_multiplier: 0.3,
        });

        // PersonalizationPortrait limits
        alert_frequency_limits.insert("personalization_portrait".to_string(), FrequencyLimit {
            max_alerts_per_hour: 30, // High frequency for social ranking updates
            cooldown_multiplier: 0.3,
        });
        
        DetectionRules {
            system_process_contexts,
            alert_frequency_limits,
            process_whitelist: whitelist,
            suspicious_paths,
        }
    }

async fn analyze_process_event(
    &self,
    tracker: &mut ProcessTracker,
    _event: &Event,
    process_data: &ProcessEventData,
) -> Result<Option<DetectorAlert>> {
    let pid = process_data.pid;

    // Check if the process should be whitelisted
    if self.should_whitelist(process_data, tracker) {
        return Ok(None);
    }

    // Update or create process state
    let process_state = tracker.processes.entry(pid).or_insert_with(|| ProcessState {
        pid,
        name: process_data.name.clone(),
        path: process_data.path.clone(),
        parent_pid: process_data.ppid.unwrap_or(0),
        creation_time: Instant::now(),
        handles_opened: 0,
        memory_operations: 0,
        thread_operations: 0,
        dll_operations: 0,
        file_operations: 0,
        network_operations: 0,
        suspicious_api_calls: Vec::new(),
        risk_score: 0.0,
        last_update: Instant::now(),
    });
    process_state.last_update = Instant::now();
    
    // Move mutable usage of tracker here
    let process_name = process_state.name.clone();
    let process_path = process_state.path.clone();
    let parent_pid = process_state.parent_pid;
    
    // Check for suspicious process characteristics using context-aware scoring
    let mut alerts = Vec::new();
    
    // Implement parent process hierarchy analysis for injection detection
    if let Some(parent_alert) = self.analyze_parent_process_hierarchy(
        tracker, pid, parent_pid, &process_name, &process_path
    ).await {
        alerts.push(parent_alert);
    }

        // Linux-specific behavioral detection
        #[cfg(target_os = "linux")]
        {
            // Check for shells/interpreters launched from unexpected parents or locations
            if self.is_shell_or_interpreter(&process_name) {
                if let Some(alert) = self.check_suspicious_shell_execution(
                    tracker, pid, &process_name, &process_path, parent_pid
                ) {
                    alerts.push(alert);
                }
            }
            
            // Check for processes running from browser cache/temp directories
            if self.is_browser_cache_execution(&process_path) {
                alerts.push(self.create_alert(
                    InjectionEventType::SuspiciousProcess,
                    AlertSeverity::High,
                    "Process execution from browser cache".to_string(),
                    format!("Process {} (PID: {}) executed from browser cache: {}", 
                        process_name, pid, process_path),
                    0.8,
                    vec![pid],
                ));
            }
        }
        
        // Windows detection (kept for reference)
        #[cfg(windows)]
        {
            // For Windows, check process name against known suspicious patterns
            let suspicious_patterns = [
                "rundll32", "regsvr32", "powershell", "cmd", "wscript",
                "cscript", "mshta", "certutil", "bitsadmin", "net",
                "sc", "at", "schtasks", "reg", "whoami",
            ];
            
            let name_lower = process_name.to_lowercase();
            if suspicious_patterns.iter().any(|pattern| name_lower.contains(*pattern)) {
                let base_risk = 0.5;
                
                // Calculate risk based on process context
                let mut risk_multiplier = 1.0;
                
                // Check process path - higher risk if in suspicious locations
                if self.is_suspicious_process_path(&process_path) {
                    risk_multiplier *= 1.5;
                }
                
                // Check parent process - higher risk if parent is unusual
                if let Some(parent) = tracker.processes.get(&parent_pid) {
                    if self.is_browser_process(&parent.name) {
                        risk_multiplier *= 2.0; // Very suspicious if launched from browser
                    }
                }
                
                let adjusted_risk = base_risk * risk_multiplier;
                
                let (should_suppress, severity_multiplier) = self.should_suppress_alert(
                    tracker, 
                    &process_name
                );
                
                if !should_suppress {
                    let final_risk = adjusted_risk * severity_multiplier;
            let severity = if final_risk >= 0.85 {
                AlertSeverity::High
            } else if final_risk >= 0.65 {
                AlertSeverity::Medium
            } else {
                AlertSeverity::Low
            };
                    
                    alerts.push(self.create_alert(
                        InjectionEventType::SuspiciousProcess,
                        severity,
                        format!("Suspicious Windows process: {}", process_name),
                        format!("Process {} (PID: {}) matches known suspicious pattern", process_name, pid),
                        final_risk,
                        vec![pid],
                    ));
                }
            }
        }
        
        if self.is_suspicious_process_path(&process_path) {
            alerts.push(self.create_alert(
                InjectionEventType::SuspiciousProcess,
                AlertSeverity::Medium,
                format!("Suspicious process path: {}", process_path),
                format!("Process {} running from suspicious location: {}", process_name, process_path),
                0.6,
                vec![pid],
            ));
        }
        
        // Check command line patterns
        if let Some(command_line) = &process_data.command_line {
            if let Some(alert) = self.check_command_line_patterns(pid, &process_name, command_line) {
                alerts.push(alert);
            }
        }
        
        // For now, return the first alert (if any)
        Ok(alerts.into_iter().next())
    }

    async fn analyze_file_event(
        &self,
        tracker: &mut ProcessTracker,
        _event: &Event,
        file_data: &FileEventData,
    ) -> Result<Option<DetectorAlert>> {
        // Get operation type context first - assuming we use modification time as a proxy for write operations
        let is_write = file_data.modified_time.is_some();

        // Use enhanced file path analysis with context
        let (mut is_suspicious, alert_key, _risk_score) = self.analyze_file_path_context(&file_data.path);

        // Only warn on write operations for certain paths
        if alert_key == "mail_tmp" || alert_key == "news_widget_tmp" || alert_key == "personalization_portrait" {
            is_suspicious = is_suspicious && is_write;
        }
        
        if is_suspicious {
            // Check frequency limits for this type of file alert
            let (should_suppress, severity_multiplier) = self.should_suppress_alert(
                tracker, 
                &alert_key
            );
            
            if !should_suppress {
            let base_risk = 0.3;
            let final_risk = base_risk * severity_multiplier;
                
                let severity = if final_risk >= 0.6 {
                    AlertSeverity::High
                } else if final_risk >= 0.3 {
                    AlertSeverity::Medium
                } else {
                    AlertSeverity::Low
                };
                
                return Ok(Some(self.create_alert(
                    InjectionEventType::SuspiciousFileAccess,
                    severity,
                    "Suspicious file access".to_string(),
                    format!("Suspicious file operation detected: {}", file_data.path),
                    final_risk,
                    vec![],
                )));
            }
        }
        
        // Check for executable files in suspicious locations
        if self.is_executable_file(&file_data.path) && self.is_suspicious_file_location(&file_data.path) {
            // Use frequency limiting for executable files too
            let (should_suppress, severity_multiplier) = self.should_suppress_alert(
                tracker, 
                "suspicious_executable"
            );
            
            if !should_suppress {
                let base_risk = 0.7;
                let final_risk = base_risk * severity_multiplier;
                
                return Ok(Some(self.create_alert(
                    InjectionEventType::SuspiciousLibrary,
                    AlertSeverity::High,
                    "Executable in suspicious location".to_string(),
                    format!("Executable file created/modified in suspicious location: {}", file_data.path),
                    final_risk,
                    vec![],
                )));
            }
        }
        
        Ok(None)
    }

    async fn analyze_network_event(
        &self,
        tracker: &mut ProcessTracker,
        _event: &Event,
        network_data: &NetworkEventData,
    ) -> Result<Option<DetectorAlert>> {
        // Check for suspicious network patterns
        if let Some(pid) = network_data.process_id {
            if let Some(process_state) = tracker.processes.get_mut(&pid) {
                process_state.network_operations += 1;
                
                // Check for suspicious destinations or patterns
                if self.is_suspicious_network_behavior(network_data) {
                    return Ok(Some(self.create_alert(
                        InjectionEventType::UnusualNetworkBehavior,
                        AlertSeverity::Medium,
                        "Unusual network behavior".to_string(),
                        format!("Unusual network behavior from process {} (PID: {})", 
                            process_state.name, pid),
                        0.5,
                        vec![pid],
                    )));
                }
            }
        }
        
        Ok(None)
    }

    fn is_suspicious_file_location(&self, path: &str) -> bool {
        #[cfg(target_os = "linux")]
        let suspicious_locations = [
            "/tmp/",
            "/dev/shm/",
            "/var/tmp/",
            "/run/user/*/",  // User runtime directories
        ];
        
        #[cfg(windows)]
        let suspicious_locations = [
            "\\Windows\\Temp\\",
            "\\Users\\Public\\",
            "\\AppData\\Local\\Temp\\",
            "\\ProgramData\\",
        ];
        
        #[cfg(target_os = "macos")]
        let suspicious_locations = [
            "/tmp/",
            "/var/tmp/",
            "/private/tmp/",
        ];
        
        suspicious_locations.iter().any(|&location| path.contains(location))
    }

    fn is_executable_file(&self, path: &str) -> bool {
        #[cfg(target_os = "linux")]
        let executable_extensions = [".so", ".bin", ".out", ".elf"];
        
        #[cfg(windows)]
        let executable_extensions = [".exe", ".dll", ".com", ".scr", ".bat", ".cmd"];
        
        #[cfg(target_os = "macos")]
        let executable_extensions = [".dylib", ".bin", ".out", ".app"];
        
        executable_extensions.iter().any(|&ext| path.to_lowercase().ends_with(ext)) ||
        // Also check for files without extensions that might be executable
        (cfg!(target_os = "linux") && !path.contains('.') && path.starts_with("/"))
    }

    fn check_command_line_patterns(&self, pid: u32, process_name: &str, command_line: &str) -> Option<DetectorAlert> {
        // Platform-specific suspicious command line patterns
        #[cfg(target_os = "linux")]
        let suspicious_patterns = [
            ("base64", 0.5),
            ("encoded", 0.5),
            ("/dev/shm", 0.8),
            ("/tmp/", 0.6),
            ("chmod +x", 0.7),
            ("curl", 0.4),
            ("wget", 0.4),
            ("ptrace", 0.7),
            ("LD_PRELOAD", 0.8),
            ("dd if=", 0.5),
            ("nc -l", 0.6),  // netcat listener
            ("python -c", 0.5),
            ("perl -e", 0.5),
            ("bash -i", 0.6),  // interactive bash
        ];
        
        #[cfg(windows)]
        let suspicious_patterns = [
            ("powershell", 0.6),
            ("rundll32", 0.7),
            ("regsvr32", 0.7),
            ("mshta", 0.8),
            ("wscript", 0.6),
            ("cscript", 0.6),
            ("certutil", 0.7),
            ("base64", 0.5),
            ("encoded", 0.5),
        ];
        
        #[cfg(target_os = "macos")]
        let suspicious_patterns = [
            ("base64", 0.5),
            ("encoded", 0.5),
            ("/tmp/", 0.6),
            ("chmod +x", 0.7),
            ("curl", 0.4),
            ("python -c", 0.5),
            ("perl -e", 0.5),
            ("bash -i", 0.6),
        ];
        
        let cmd_lower = command_line.to_lowercase();
        for (pattern, risk_score) in &suspicious_patterns {
            if cmd_lower.contains(pattern) {
                return Some(self.create_alert(
                    InjectionEventType::SuspiciousProcess,
                    if *risk_score >= 0.7 { AlertSeverity::High } else { AlertSeverity::Medium },
                    format!("Suspicious command line pattern: {}", pattern),
                    format!("Process {} (PID: {}) executed suspicious command: {}", 
                        process_name, pid, command_line),
                    *risk_score,
                    vec![pid],
                ));
            }
        }
        
        None
    }

    fn is_suspicious_process_path(&self, path: &str) -> bool {
        self.detection_rules.suspicious_paths.iter()
            .any(|sus_path| path.contains(sus_path))
    }

    fn is_suspicious_network_behavior(&self, network_data: &NetworkEventData) -> bool {
        let mut risk_score = 0.0;
        
        // Check suspicious patterns
        if let Some(port) = network_data.destination_port {
            match port {
                1..=1023 => risk_score += 0.1, // Privileged port access
                4444 | 9999 | 31337 => risk_score += 0.5, // Commonly associated with malicious activity
                _ => {}
            }
        }
        
        // Check for suspicious protocols or patterns
        if network_data.protocol.to_lowercase().contains("unknown") {
            risk_score += 0.4;
        }
        
        // Check for suspicious volume using bytes_sent and bytes_received if available
        let total_bytes = network_data.bytes_sent.unwrap_or(0) + network_data.bytes_received.unwrap_or(0);
        if total_bytes > 5_000_000 { // Arbitrary threshold for high traffic
            risk_score += 0.3;
        }
        
        risk_score >= 0.5 // Overall risk threshold for triggering an alert
    }

    // Check if we should suppress alert due to frequency limits
    fn should_suppress_alert(&self, tracker: &mut ProcessTracker, alert_key: &str) -> (bool, f32) {
        if let Some(frequency_limit) = self.detection_rules.alert_frequency_limits.get(alert_key) {
            let now = Instant::now();
            let one_hour_ago = now - Duration::from_secs(3600);
            
            // Get or create alert history for this key
            let alert_history = tracker.alert_frequency.entry(alert_key.to_string())
                .or_insert_with(Vec::new);
            
            // Clean up old alerts (older than 1 hour)
            alert_history.retain(|&timestamp| timestamp > one_hour_ago);
            
            let recent_alert_count = alert_history.len() as u32;
            
            if recent_alert_count >= frequency_limit.max_alerts_per_hour {
                // Suppress this alert
                (true, 0.0)
            } else {
                // Allow alert, but reduce severity based on frequency
                let severity_multiplier = if recent_alert_count > 0 {
                    frequency_limit.cooldown_multiplier.powi(recent_alert_count as i32)
                } else {
                    1.0
                };
                
                // Record this alert
                alert_history.push(now);
                
                (false, severity_multiplier)
            }
        } else {
            // No frequency limits for this alert type
            (false, 1.0)
        }
    }
    
    // Enhanced file path analysis
    fn analyze_file_path_context(&self, path: &str) -> (bool, String, f32) {
        #[cfg(windows)] 
        {
            let mut risk_score = 0.0;
            let mut context_type = "unknown";

            // PowerShell Script Policy Testing - Only flag when combined with suspicious patterns
            if path.contains("__PSScriptPolicyTest_") && path.contains(".ps1") {
                // Check the context of script policy testing
                if !path.contains("\\AppData\\Local\\Temp\\") {
                    risk_score += 0.4; // Unusual location for policy testing
                    context_type = "powershell_policy_suspicious";
                } else {
                    // Additional checks for policy test files
                    let suspicious_patterns = [
                        "download", "http", "invoke", "iex", "bypass",
                        "hidden", "encode", "encrypted", "base64"
                    ];
                    if suspicious_patterns.iter().any(|&pattern| path.to_lowercase().contains(pattern)) {
                        risk_score += 0.5;
                        context_type = "powershell_policy_malicious";
                    } else {
                        context_type = "powershell_policy_normal";
                        return (false, context_type.to_string(), 0.0);
                    }
                }
            }

            // Windows System File Access Analysis
            if path.contains("\\Windows\\System32\\") || path.contains("\\Windows\\SysWOW64\\") {
                context_type = "windows_system";
                
                // Check for system database access
                if path.ends_with(".db") || path.ends_with(".db-wal") || path.ends_with(".db-journal") {
                    if path.contains("CapabilityAccessManager") {
                        // Normal Windows capability access
                        return (false, "system_db_normal".to_string(), 0.0);
                    }
                    risk_score += 0.3;
                }
            }

            // Driver and Network Analysis
            if path.contains("\\RivetNetworks\\Killer\\") {
                context_type = "network_driver";
                if path.contains("\\ActivityLog\\") || path.contains("\\ConfigurationFiles\\") {
                    // Normal driver activity
                    return (false, "driver_logs_normal".to_string(), 0.0);
                }
                // Suspicious driver file operations
                if path.contains(".sys") || path.contains(".dll") {
                    risk_score += 0.6;
                }
            }

            // Analyze path depth and character patterns
            let depth = path.matches("\\").count();
            if depth > 10 {
                risk_score += 0.2; // Unusually nested paths
            }

            // Check for suspicious characters or patterns
            let suspicious_patterns = [
                "\u{200B}", "\u{FEFF}", // Unicode zero-width spaces
                "..\\..", "....",      // Directory traversal attempts
                "%temp%", "%appdata%"   // Environment variable injection attempts
            ];
            if suspicious_patterns.iter().any(|&pattern| path.contains(pattern)) {
                risk_score += 0.4;
            }

            (risk_score >= 0.5, context_type.to_string(), risk_score)
        }
        #[cfg(target_os = "macos")] 
        {
            // [existing macOS code remains unchanged]
            if path.starts_with("/System/Library/") || 
               path.starts_with("/Library/Apple/") || 
               path.starts_with("/Library/Application Support/") {
                return (false, "system_files".to_string(), 0.0);
            }
            if path.contains("/Library/Containers/") {
                let (is_suspicious, context) = self.analyze_macos_container_path(path);
                return (is_suspicious, context, if is_suspicious { 0.6 } else { 0.0 });
            }
            if path.contains("/Library/Group Containers/group.com.apple.") {
                return (false, "group_container".to_string(), 0.0);
            }
            if path.contains("/private/var/folders/") || 
               path.starts_with("/private/tmp/") || 
               path.starts_with("/tmp/") {
                let (is_suspicious, context) = self.analyze_macos_temp_path(path);
                return (is_suspicious, context, if is_suspicious { 0.7 } else { 0.0 });
            }
            if path.contains("/Library/") {
                let (is_suspicious, context) = self.analyze_macos_library_path(path);
                return (is_suspicious, context, if is_suspicious { 0.6 } else { 0.0 });
            }

            // Default behavior for macOS unhandled paths
            let is_suspicious = self.is_suspicious_process_path(path);
            (is_suspicious, "general_suspicious_file".to_string(), if is_suspicious { 0.6 } else { 0.0 })
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            // Default behavior for other platforms
            let is_suspicious = self.is_suspicious_process_path(path);
            (is_suspicious, "general_suspicious_file".to_string(), if is_suspicious { 0.6 } else { 0.0 })
        }
    }

    #[cfg(target_os = "macos")]
    fn analyze_macos_container_path(&self, path: &str) -> (bool, String) {
        // Mail paths
        if path.contains("com.apple.mail") {
            if path.contains("/Data/tmp/") && (
                path.contains("/TemporaryItems/NSIRD_Mail_") || 
                path.contains("/tmp/etilqs_") || 
                path.contains("/tmp/TemporaryItems/")
            ) {
                return (false, "mail_tmp".to_string());
            }
            if path.contains("/Library/Preferences/") {
                return (false, "mail_group".to_string());
            }
            return (false, "mail_other".to_string());
        }

        // Messages app
        if path.contains("com.apple.MobileSMS/Data/tmp/.LINKS/") {
            return (false, "messages_tmp".to_string());
        }

        // News widget
        if path.contains("com.apple.news.widget/Data/tmp/TemporaryItems/NSIRD_NewsToday2_") {
            return (false, "news_widget_tmp".to_string());
        }

        // Default container paths are generally safe
        (false, "app_container".to_string())
    }

    #[cfg(target_os = "macos")]
    fn analyze_macos_temp_path(&self, path: &str) -> (bool, String) {
        // Handle known temp patterns
        if path.contains("/TemporaryItems/") || 
           path.contains("/T/") || 
           path.contains("/Cleanup At Startup/") {
            // Mail config files
            if path.contains("group.com.apple.mail.plist") {
                return (false, "mail_group".to_string());
            }
            return (false, "system_tmp".to_string());
        }

        // ZSH temp files
        if path.contains("/zsh") && (path.contains(".zsh") || path.contains("zsh-")) {
            return (false, "zsh_tmp".to_string());
        }

        // Apple and system temp files
        if path.contains("/com.apple.") || 
           path.contains("/CoreSimulator/") || 
           path.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '/').count() >= 28 {
            return (false, "system_tmp".to_string());
        }

        // Any other temp files are potentially suspicious
        (true, "suspicious_tmp".to_string())
    }

    #[cfg(target_os = "macos")]
fn analyze_macos_library_path(&self, path: &str) -> (bool, String) {
        // Add logic to handle analysis or return default for unhandled cases
        if path.contains("/Library/PersonalizationPortrait/") {
            if path.contains("/streams/rankedSocialHighlights/") ||
               path.contains("/Contacts/name_records/") &&
               path.contains("/tmp/") {
                return (false, "personalization_portrait".to_string());
            }
        }
        // Default behavior
        (false, "general_library".to_string())
    }

    fn create_alert(
        &self,
        event_type: InjectionEventType,
        severity: AlertSeverity,
        title: String,
        description: String,
        risk_score: f32,
        affected_processes: Vec<u32>,
    ) -> DetectorAlert {
        let mut alert = DetectorAlert::new(
            self.name().to_string(),
            severity,
            title,
            description,
        )
        .with_risk_score(risk_score)
        .with_metadata("platform".to_string(), std::env::consts::OS.to_string())
        .with_metadata("event_type".to_string(), format!("{:?}", event_type))
        .with_metadata("agent_id".to_string(), self.agent_id.clone())
        .with_metadata("hostname".to_string(), self.hostname.clone());
        
        for pid in affected_processes {
            alert = alert.with_process(pid);
        }
        
        // Add recommended actions based on severity
        match alert.severity {
            AlertSeverity::Critical => {
                alert = alert
                    .with_action("Immediately isolate the affected process".to_string())
                    .with_action("Perform memory dump for analysis".to_string())
                    .with_action("Check for persistence mechanisms".to_string());
            }
            AlertSeverity::High => {
                alert = alert
                    .with_action("Monitor process behavior closely".to_string())
                    .with_action("Check process ancestry and children".to_string())
                    .with_action("Validate process legitimacy".to_string());
            }
            AlertSeverity::Medium => {
                alert = alert
                    .with_action("Investigate process context".to_string())
                    .with_action("Check for additional indicators".to_string());
            }
            _ => {
                alert = alert.with_action("Continue monitoring".to_string());
            }
        }
        
        alert
    }

    // Linux-specific helper functions
    #[cfg(target_os = "linux")]
    fn is_shell_or_interpreter(&self, process_name: &str) -> bool {
        let shells_and_interpreters = ["sh", "bash", "zsh", "fish", "dash", "python", "python3", "perl", "ruby", "node", "php"];
        let name_lower = process_name.to_lowercase();
        
        // Check for exact matches or common naming patterns
        shells_and_interpreters.iter().any(|&shell| {
            name_lower == shell || 
            name_lower.ends_with(&format!("/{}", shell)) ||
            name_lower.starts_with(&format!("{}_", shell)) ||
            name_lower.starts_with(&format!("{}-", shell))
        })
    }
    
    #[cfg(target_os = "linux")]
    fn check_suspicious_shell_execution(
        &self, 
        tracker: &mut ProcessTracker, 
        pid: u32, 
        process_name: &str, 
        process_path: &str, 
        parent_pid: u32
    ) -> Option<DetectorAlert> {
        // Check if shell is launched from browser or unusual parent
        if let Some(parent_process) = tracker.processes.get(&parent_pid) {
            let parent_name = &parent_process.name;
            
            // Check for browsers launching shells
            let browser_processes = ["firefox", "chrome", "chromium", "safari", "edge", "opera"];
            if browser_processes.iter().any(|&browser| parent_name.to_lowercase().contains(browser)) {
                return Some(self.create_alert(
                    InjectionEventType::SuspiciousProcess,
                    AlertSeverity::High,
                    "Shell launched by browser".to_string(),
                    format!("Shell {} (PID: {}) launched by browser process {} (PID: {})", 
                        process_name, pid, parent_name, parent_pid),
                    0.9,
                    vec![pid, parent_pid],
                ));
            }
            
            // Check for unexpected parent processes
            let unexpected_parents = ["steamwebhelper", "discord", "slack", "teams"];
            if unexpected_parents.iter().any(|&parent| parent_name.to_lowercase().contains(parent)) {
                return Some(self.create_alert(
                    InjectionEventType::SuspiciousProcess,
                    AlertSeverity::Medium,
                    "Shell launched by unexpected parent".to_string(),
                    format!("Shell {} (PID: {}) launched by {} (PID: {})", 
                        process_name, pid, parent_name, parent_pid),
                    0.7,
                    vec![pid, parent_pid],
                ));
            }
        }
        
        // Check for shells running from unusual locations
        let suspicious_locations = ["/tmp/", "/dev/shm/", "/var/tmp/", "/.cache/", "/home/*/Downloads/"];
        if suspicious_locations.iter().any(|&location| process_path.contains(location)) {
            return Some(self.create_alert(
                InjectionEventType::SuspiciousProcess,
                AlertSeverity::High,
                "Shell execution from suspicious location".to_string(),
                format!("Shell {} (PID: {}) executing from suspicious location: {}", 
                    process_name, pid, process_path),
                0.8,
                vec![pid],
            ));
        }
        
        None
    }
    
    #[cfg(target_os = "linux")]
    fn is_browser_cache_execution(&self, process_path: &str) -> bool {
        let browser_cache_patterns = [
            "/.cache/",
            "/.mozilla/firefox/",
            "/.config/google-chrome/",
            "/.config/chromium/",
            "/snap/firefox/common/.cache/",
            "/tmp/mozilla_",
            "/tmp/chrome_"
        ];
        
        browser_cache_patterns.iter().any(|&pattern| process_path.contains(pattern))
    }

    // Analyze parent process hierarchy for injection detection
    async fn analyze_parent_process_hierarchy(
        &self,
        tracker: &mut ProcessTracker,
        pid: u32,
        parent_pid: u32,
        process_name: &str,
        process_path: &str,
    ) -> Option<DetectorAlert> {
        if parent_pid == 0 {
            return None; // No parent to analyze
        }

        // Check if this process should be whitelisted
        let process_data = ProcessEventData {
            pid,
            ppid: Some(parent_pid),
            name: process_name.to_string(),
            path: process_path.to_string(),
            command_line: None,
            user: None,
            session_id: None,
            start_time: None,
            end_time: None,
            exit_code: None,
            cpu_usage: None,
            memory_usage: None,
            environment: None,
            hashes: None,
        };
        
        if self.should_whitelist(&process_data, tracker) {
            return None;
        }
        
        // Get parent process information
        if let Some(parent_process) = tracker.processes.get(&parent_pid) {
            let parent_name = &parent_process.name;
            let parent_path = &parent_process.path;
            
            // Check for suspicious parent-child relationships
            
            // 1. System processes spawning from unexpected locations
            if self.is_system_process_name(process_name) {
                if let Some(expected_context) = self.detection_rules.system_process_contexts.get(process_name) {
                    let is_in_expected_path = expected_context.expected_paths.iter()
                        .any(|expected_path| process_path.starts_with(expected_path));
                    
                    if !is_in_expected_path {
                        return Some(self.create_alert(
                            InjectionEventType::SuspiciousProcess,
                            AlertSeverity::High,
                            "System process in unexpected location".to_string(),
                            format!(
                                "System process {} (PID: {}) running from unexpected location: {}. Expected paths: {:?}",
                                process_name, pid, process_path, expected_context.expected_paths
                            ),
                            0.8,
                            vec![pid, parent_pid],
                        ));
                    }
                }
            }
            
            // 2. Processes spawned by browsers or other applications that shouldn't spawn system utilities
            if self.is_browser_process(parent_name) && self.is_system_utility(process_name) {
                return Some(self.create_alert(
                    InjectionEventType::SuspiciousProcess,
                    AlertSeverity::High,
                    "System utility spawned by browser".to_string(),
                    format!(
                        "System utility {} (PID: {}) spawned by browser process {} (PID: {})",
                        process_name, pid, parent_name, parent_pid
                    ),
                    0.9,
                    vec![pid, parent_pid],
                ));
            }
            
            // 3. Check for process hollowing patterns (process name mismatch with parent expectations)
            #[cfg(target_os = "macos")]
            let is_hollow = self.is_potential_process_hollowing(process_name, process_path, parent_name, parent_path);
            #[cfg(not(target_os = "macos"))]
            let is_hollow = self.is_potential_process_hollowing(process_name, process_path, parent_path);

            if is_hollow {
                return Some(self.create_alert(
                    InjectionEventType::ProcessHollowing,
                    AlertSeverity::Critical,
                    "Potential process hollowing detected".to_string(),
                    format!(
                        "Process {} (PID: {}) may be hollowed. Parent: {} (PID: {}). Path: {}",
                        process_name, pid, parent_name, parent_pid, process_path
                    ),
                    0.95,
                    vec![pid, parent_pid],
                ));
            }
            
            // 4. Check for unusual process chains (deep nesting or circular references)
            let chain_depth = self.calculate_process_chain_depth(tracker, pid, 0);
            if chain_depth > 10 {
                return Some(self.create_alert(
                    InjectionEventType::SuspiciousProcess,
                    AlertSeverity::Medium,
                    "Unusual process chain depth".to_string(),
                    format!(
                        "Process {} (PID: {}) has unusual chain depth: {}. This may indicate process injection or malware activity.",
                        process_name, pid, chain_depth
                    ),
                    0.6,
                    vec![pid],
                ));
            }
        }
        
        None
    }
    
    fn is_system_process_name(&self, process_name: &str) -> bool {
        self.detection_rules.system_process_contexts.contains_key(process_name)
    }
    
    fn is_browser_process(&self, process_name: &str) -> bool {
        let browser_names = [
            "firefox", "chrome", "chromium", "safari", "edge", "opera", "brave",
            "webkit", "electron", "discord", "slack", "teams", "zoom"
        ];
        let name_lower = process_name.to_lowercase();
        browser_names.iter().any(|&browser| name_lower.contains(browser))
    }
    
    fn is_system_utility(&self, process_name: &str) -> bool {
        let system_utilities = [
            "sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh",
            "python", "python3", "perl", "ruby", "node", "php",
            "curl", "wget", "nc", "netcat", "ssh", "scp", "rsync",
            "sudo", "su", "doas", "systemctl", "service",
            "grep", "awk", "sed", "find", "locate", "which"
        ];
        let name_lower = process_name.to_lowercase();
        system_utilities.iter().any(|&util| name_lower == util || name_lower.ends_with(&format!("/{}", util)))
    }
    
    #[cfg(target_os = "macos")]
    fn is_legitimate_macos_process(&self, process_name: &str, process_path: &str, parent_name: &str, parent_path: &str) -> bool {
        // Early return for mdworker_shared - macOS metadata worker process
        if process_name == "mdworker_shared" {
            const MDWORKER_PATH: &str = "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared";
            // mdworker_shared is legitimate if it's running from the correct path and parent is launchd
            return process_path == MDWORKER_PATH && parent_name == "launchd" && parent_path == "/sbin/launchd";
        }
        // Special case for mdworker_shared - part of macOS Spotlight indexing
        let legitimate_processes = [
            // Launchd processes
            ("launchd", "/sbin/launchd", "", ""), // Main launchd (no parent)
            ("launchd", "/sbin/launchd", "launchd", "/sbin/launchd"), // Self-parent
            ("launchd.system", "/usr/libexec/launchd.system", "launchd", "/sbin/launchd"),
            ("launchd_helper", "/usr/libexec/launchd_helper", "launchd", "/sbin/launchd"),
            ("launchd.peruser", "/usr/libexec/launchd.peruser", "launchd", "/sbin/launchd"),
            // Other system processes
            ("Spotlight", "/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight", "launchd", "/sbin/launchd"),
            ("securityd", "/usr/sbin/securityd", "launchd", "/sbin/launchd"),
            ("WindowServer", "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer", "launchd", "/sbin/launchd"),
            ("cfprefsd", "/usr/sbin/cfprefsd", "launchd", "/sbin/launchd"),
            ("trustd", "/usr/libexec/trustd", "launchd", "/sbin/launchd"),
            ("opendirectoryd", "/usr/libexec/opendirectoryd", "launchd", "/sbin/launchd"),
        ];

        // Find matching process configuration
        if let Some(&(name, expected_path, expected_parent, expected_parent_path)) = 
            legitimate_processes.iter().find(|&&(name, _, _, _)| name == process_name) {
            // Must match exact path
            if process_path != expected_path {
                return false;
            }

            // Handle special case for main launchd (PID 1)
            if name == "launchd" && expected_path == "/sbin/launchd" && expected_parent.is_empty() {
                return parent_name.is_empty() || (parent_name == "launchd" && parent_path == "/sbin/launchd");
            }

            // For all other processes, must match expected parent
            return parent_name == expected_parent && parent_path == expected_parent_path;
        }

        // Not a critical system process we strictly validate
        true
    }

    #[cfg(not(target_os = "macos"))]
    fn is_potential_process_hollowing(&self, process_name: &str, process_path: &str, parent_path: &str) -> bool {
        let mut risk_score = 0.0;
        let path_separator = if cfg!(windows) { '\\' } else { '/' };
        
        // 1. Path integrity checks
        if let Some(path_filename) = process_path.split(path_separator).last() {
            let path_basename = path_filename.split('.').next().unwrap_or(path_filename);
            if process_name != path_basename && !process_name.starts_with(path_basename) {
                // Mismatched name/path is highly suspicious
                risk_score += 0.4;
            }
        }

        // 2. Protected directory verification
        #[cfg(windows)]
        {
            let protected_dirs = [
                "Windows\\System32",
                "Windows\\SysWOW64",
                "Program Files",
                "Program Files (x86)",
            ];
            
            // If claiming to be from protected dir but in wrong location
            if protected_dirs.iter().any(|dir| process_name.to_lowercase().contains(&dir.to_lowercase())) 
                && !protected_dirs.iter().any(|dir| process_path.contains(dir)) {
                risk_score += 0.5; // High risk - pretending to be system file
            }
        }

        // 3. Enhanced path depth analysis
        let process_depth = process_path.matches(path_separator).count();
        let parent_depth = parent_path.matches(path_separator).count();
        let depth_diff = process_depth.saturating_sub(parent_depth);
        
        if depth_diff > 5 {
            risk_score += 0.3; // Suspicious nesting level
        }

        // 4. Check for suspicious characters and patterns
        let suspicious_chars = if cfg!(windows) {
            vec!["  ", "...", "\u{200B}", "\u{FEFF}", // Unicode zero-width spaces
                 "\\\\\\\\" // Multiple backslashes
            ]
        } else {
            vec!["  ", "...", "//", "\u{200B}", "\u{FEFF}"]
        };

        if suspicious_chars.iter().any(|c| process_path.contains(c)) {
            risk_score += 0.3;
        }

        // 5. Binary replacement detection
        #[cfg(windows)]
        {
            // Check if process is running from a temp or download location
            let temp_locations = [
                "\\Temp\\",
                "\\Downloads\\"
            ];
            
            if temp_locations.iter().any(|loc| process_path.contains(loc)) {
                risk_score += 0.2;
            }

            // Additional check for system processes in non-system locations
            let system_processes = [
                "svchost", "lsass", "csrss", "winlogon",
                "services", "smss", "wininit"
            ];

            if system_processes.iter().any(|&proc| process_name.eq_ignore_ascii_case(proc)) 
                && !process_path.contains(WINDOWS_SYSTEM32) 
                && !process_path.contains(WINDOWS_SYSWOW64) {
                risk_score += 0.6; // Very high risk for system processes in wrong location
            }
        }

        // 6. Parent-child relationship analysis
        #[cfg(windows)]
        {
            let suspicious_parent_patterns = [
                ("svchost", vec!["Users", "Temp", "Downloads"]),
                ("services", vec!["Users", "Temp", "Downloads"]),
                ("lsass", vec!["Users", "Temp", "Downloads"])
            ];

            for (parent_name, suspicious_paths) in suspicious_parent_patterns {
                if parent_path.ends_with(parent_name) {
                    if suspicious_paths.iter().any(|p| process_path.contains(p)) {
                        risk_score += 0.4;
                    }
                }
            }
        }

        // Final decision based on cumulative risk score
        risk_score >= 0.7 // Threshold for considering it a hollow process
    }

    #[cfg(target_os = "macos")]
    fn is_potential_process_hollowing(&self, process_name: &str, process_path: &str, parent_name: &str, parent_path: &str) -> bool {
        // Special case for mdworker_shared - we handle it in is_legitimate_macos_process
        #[cfg(target_os = "macos")]
        if process_name == "mdworker_shared" {
            return !self.is_legitimate_macos_process(process_name, process_path, parent_name, parent_path);
        }
        // Check macOS specific processes first - macOS process validation handles mdworker_shared
        // Check macOS specific processes first
        #[cfg(target_os = "macos")]
        if !self.is_legitimate_macos_process(process_name, process_path, parent_name, parent_path) {
            return true;
        }

        // Generic checks for all platforms
        let mut is_hollow = false;

        // Process name/path mismatch detection
        if let Some(path_filename) = process_path.split('/').last() {
            let path_basename = path_filename.split('.').next().unwrap_or(path_filename);
            if process_name != path_basename && !process_name.starts_with(path_basename) {
                // Known legitimate cases where name doesn't match path
                let legitimate_renames = [
                    ("chrome", "google_chrome"),
                    ("firefox", "mozilla_firefox"),
                ];
                
                if !legitimate_renames.iter().any(|(orig, renamed)| 
                    (process_name.contains(orig) && path_basename.contains(renamed)) ||
                    (process_name.contains(renamed) && path_basename.contains(orig))) {
                    is_hollow = true;
                }
            }
        }

        // System process location checks
        if self.is_system_process_name(process_name) {
            let user_writable_dirs = [
                "/home/", "/Users/", "/tmp/", "/var/tmp/",
                "/dev/shm/", "AppData", "Local", "Temp", "Downloads",
            ];
            
            if user_writable_dirs.iter().any(|dir| process_path.to_lowercase().contains(dir)) {
                is_hollow = true;
            }

            // Path depth check for system processes - allow more nesting
            let process_depth = process_path.matches('/').count();
            let parent_depth = parent_path.matches('/').count();
            if process_depth > parent_depth + 4 { // Increased from 2 to 4
                is_hollow = true;
            }
        }

        // Check for suspicious characters in paths
        if self.is_system_process_name(process_name) {
            let suspicious_chars = [" ", "  ", ".", "..", "...", "7f8a0", "7f0a00"];
            if suspicious_chars.iter().any(|c| process_path.contains(c)) {
                is_hollow = true;
            }
        }

        is_hollow
    }
    fn calculate_process_chain_depth(&self, tracker: &ProcessTracker, pid: u32, current_depth: u32) -> u32 {
        if current_depth > 20 {
            return current_depth; // Prevent infinite recursion
        }
        
        if let Some(process) = tracker.processes.get(&pid) {
            let parent_pid = process.parent_pid;
            if parent_pid == 0 || parent_pid == pid {
                return current_depth;
            }
            
            return self.calculate_process_chain_depth(tracker, parent_pid, current_depth + 1);
        }
        
        current_depth
    }
    
    fn cleanup_old_events(&self, tracker: &mut ProcessTracker) {
        let cutoff_time = Instant::now() - Duration::from_secs(3600); // Keep 1 hour of events
        
        tracker.recent_events.retain(|event| event.timestamp > cutoff_time);
        tracker.blocked_processes.retain(|_, &mut time| time > cutoff_time);
        tracker.processes.retain(|_, process| process.last_update > cutoff_time);
        
        tracker.last_cleanup = Instant::now();
        
        debug!("Cleaned");
    }
}

#[async_trait::async_trait]
impl Detector for BehavioralDetector {
    async fn start(&self) -> Result<()> {
        info!("Started");
        *self.is_running.write().await = true;
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        info!("Stopped");
        *self.is_running.write().await = false;
        Ok(())
    }
    
    async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    async fn get_status(&self) -> DetectorStatus {
        let (events_processed, alerts_generated, last_activity) = {
            let stats = self.stats.read().await;
            (stats.events_processed, stats.alerts_generated, stats.last_activity)
        };
        
        let processes_tracked = {
            let tracker = self.process_tracker.read().await;
            tracker.processes.len() as u64
        };
        
        let is_running = self.is_running().await;
        
        DetectorStatus {
            name: self.name().to_string(),
            is_running,
            events_processed,
            alerts_generated,
            processes_tracked,
            last_activity: last_activity.unwrap_or_else(Instant::now),
            memory_usage_kb: 0, // TODO: Implement memory tracking
            cpu_usage_percent: 0.0, // TODO: Implement CPU tracking
        }
    }
    
    async fn process_event(&self, event: &Event) -> Result<()> {
        if !self.is_running().await {
            return Ok(());
        }
        
        {
            let mut stats = self.stats.write().await;
            stats.events_processed += 1;
            stats.last_activity = Some(Instant::now());
        }
        
        let mut tracker = self.process_tracker.write().await;
        
        let alert = match &event.data {
            EventData::Process(process_data) => {
                self.analyze_process_event(&mut tracker, event, process_data).await?
            }
            EventData::File(file_data) => {
                self.analyze_file_event(&mut tracker, event, file_data).await?
            }
            EventData::Network(network_data) => {
                self.analyze_network_event(&mut tracker, event, network_data).await?
            }
            _ => None,
        };
        
        // Cleanup old events periodically
        if tracker.last_cleanup.elapsed() > Duration::from_secs(300) {
            self.cleanup_old_events(&mut tracker);
        }
        
        drop(tracker);
        
        // Send alert if generated
        if let Some(alert) = alert {
            {
                let mut stats = self.stats.write().await;
                stats.alerts_generated += 1;
            }
            
            self.alert_sender.send(alert).await
                .context("AlertError")?;
        }
        
        Ok(())
    }
    
    fn name(&self) -> &'static str {
        "behavioral_detector"
    }
}

impl BehavioralDetector {
    pub fn get_config(&self) -> &BehavioralDetectorConfig {
        &self.config
    }
}

#[async_trait::async_trait]
impl EventDetector for BehavioralDetector {
    async fn analyze_event(&self, event: &Event) -> Result<Option<DetectorAlert>> {
        if !self.is_running().await {
            return Ok(None);
        }
        
        let mut tracker = self.process_tracker.write().await;
        
        match &event.data {
            EventData::Process(process_data) => {
                self.analyze_process_event(&mut tracker, event, process_data).await
            }
            EventData::File(file_data) => {
                self.analyze_file_event(&mut tracker, event, file_data).await
            }
            EventData::Network(network_data) => {
                self.analyze_network_event(&mut tracker, event, network_data).await
            }
            _ => Ok(None),
        }
    }
    
    fn get_alert_sender(&self) -> &mpsc::Sender<DetectorAlert> {
        &self.alert_sender
    }
}

impl ProcessTracker {
    fn new() -> Self {
        Self {
            processes: HashMap::new(),
            recent_events: VecDeque::new(),
            blocked_processes: HashMap::new(),
            alert_frequency: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use crate::config::BehavioralDetectorConfig;
    use crate::events::builders;
    
    #[tokio::test]
    async fn test_behavioral_detector_creation() {
        let config = BehavioralDetectorConfig {
            enabled: true,
            scan_interval_ms: 1000,
            alert_threshold: 0.6,
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
        
        let (alert_sender, _) = mpsc::channel(100);
        
        let detector = BehavioralDetector::new(
            config,
            alert_sender,
            String::from("test_agent"),
            String::from("test_host"),
        ).await;
        
        assert!(detector.is_ok());
    }
    
    #[tokio::test]
    async fn test_suspicious_process_detection() {
        let config = BehavioralDetectorConfig {
            enabled: true,
            scan_interval_ms: 1000,
            alert_threshold: 0.6,
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
        
        let detector = BehavioralDetector::new(
            config,
            alert_sender,
            String::from("test_agent"),
            String::from("test_host"),
        ).await.unwrap();
        
        detector.start().await.unwrap();
        
        // Create a suspicious process event (Linux path)
        let event = builders::create_process_event(
            1234,
            "bash".to_string(),
            String::from("/alpha/sample "),
            String::from("host123"),
            String::from("agent456"),
        );

        // Process the event
        detector.process_event(&event).await.unwrap();

        // Check if an alert was generated
        let alert = tokio::time::timeout(Duration::from_millis(100), alert_receiver.recv()).await;
        assert!(alert.is_ok() && alert.unwrap().is_some());
    }
}
