use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use tracing::{debug, info};
use tokio::sync::mpsc;

use crate::events::{Event, EventData, ProcessEventData, FileEventData, NetworkEventData};
use crate::detectors::{Detector, EventDetector, DetectorAlert, AlertSeverity};
use crate::detectors::DetectorStatus;
use crate::config::BehavioralDetectorConfig;

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
pub struct DetectionRules {
    pub api_weights: HashMap<String, f32>,
    pub sequence_patterns: Vec<SequencePattern>,
    pub time_window_rules: Vec<TimeWindowRule>,
    pub suspicious_paths: Vec<String>,
    pub suspicious_processes: Vec<String>,
    pub system_process_contexts: HashMap<String, SystemProcessContext>,
    pub alert_frequency_limits: HashMap<String, FrequencyLimit>,
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

#[derive(Debug, Clone)]
pub struct SequencePattern {
    pub name: String,
    pub apis: Vec<String>,
    pub max_time_between: Duration,
    pub risk_multiplier: f32,
    pub platform: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TimeWindowRule {
    pub event_type: InjectionEventType,
    pub max_count: u32,
    pub time_window: Duration,
    pub risk_score: f32,
}

impl BehavioralDetector {
    pub async fn new(
        config: BehavioralDetectorConfig,
        alert_sender: mpsc::Sender<DetectorAlert>,
        agent_id: String,
        hostname: String,
    ) -> Result<Self> {
        let detection_rules = Self::create_platform_rules();
        
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

    // Create platform-specific detection rules
    fn create_platform_rules() -> DetectionRules {
        let mut api_weights = HashMap::new();
        let mut sequence_patterns = Vec::new();
        let mut suspicious_paths = Vec::new();
        let suspicious_processes = Vec::new();
        
        // Cross-platform suspicious APIs and patterns
        api_weights.insert("dlopen".to_string(), 0.3);
        api_weights.insert("dlsym".to_string(), 0.4);
        api_weights.insert("mmap".to_string(), 0.3);
        api_weights.insert("mprotect".to_string(), 0.5);
        api_weights.insert("ptrace".to_string(), 0.7);
        
        // Cross-platform suspicious paths
        suspicious_paths.extend([
            "/tmp/".to_string(),
            "/dev/shm/".to_string(),
            "/var/tmp/".to_string(),
        ]);
        
        // Focus on truly suspicious execution contexts rather than common process names
        // We'll check these in behavioral context analysis instead
        
        #[cfg(windows)]
        {
            // Windows-specific APIs
            api_weights.insert("OpenProcess".to_string(), 0.3);
            api_weights.insert("VirtualAllocEx".to_string(), 0.4);
            api_weights.insert("WriteProcessMemory".to_string(), 0.5);
            api_weights.insert("CreateRemoteThread".to_string(), 0.7);
            api_weights.insert("SetThreadContext".to_string(), 0.6);
            api_weights.insert("QueueUserAPC".to_string(), 0.6);
            api_weights.insert("LoadLibrary".to_string(), 0.3);
            api_weights.insert("GetProcAddress".to_string(), 0.4);
            
            // Windows suspicious paths
            suspicious_paths.extend([
                "\\Windows\\Temp\\".to_string(),
                "\\Users\\Public\\".to_string(),
                "\\AppData\\Local\\Temp\\".to_string(),
                "\\ProgramData\\".to_string(),
            ]);
            
            // Windows suspicious processes
            suspicious_processes.extend([
                "powershell.exe".to_string(),
                "cmd.exe".to_string(),
                "rundll32.exe".to_string(),
                "regsvr32.exe".to_string(),
                "mshta.exe".to_string(),
                "wscript.exe".to_string(),
                "cscript.exe".to_string(),
            ]);
            
            // Classic injection pattern
            sequence_patterns.push(SequencePattern {
                name: "Windows DLL Injection".to_string(),
                apis: vec![
                    "OpenProcess".to_string(),
                    "VirtualAllocEx".to_string(),
                    "WriteProcessMemory".to_string(),
                    "CreateRemoteThread".to_string(),
                ],
                max_time_between: Duration::from_secs(30),
                risk_multiplier: 2.0,
                platform: Some("windows".to_string()),
            });
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS-specific APIs
            api_weights.insert("task_for_pid".to_string(), 0.6);
            api_weights.insert("vm_allocate".to_string(), 0.4);
            api_weights.insert("vm_write".to_string(), 0.5);
            api_weights.insert("thread_create_running".to_string(), 0.7);
            api_weights.insert("mach_port_allocate".to_string(), 0.3);
            
            // macOS injection pattern
            sequence_patterns.push(SequencePattern {
                name: "macOS Task Port Injection".to_string(),
                apis: vec![
                    "task_for_pid".to_string(),
                    "vm_allocate".to_string(),
                    "vm_write".to_string(),
                    "thread_create_running".to_string(),
                ],
                max_time_between: Duration::from_secs(30),
                risk_multiplier: 2.0,
                platform: Some("macos".to_string()),
            });
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux-specific patterns
            sequence_patterns.push(SequencePattern {
                name: "Linux ptrace Injection".to_string(),
                apis: vec![
                    "ptrace".to_string(),
                    "mmap".to_string(),
                    "mprotect".to_string(),
                ],
                max_time_between: Duration::from_secs(30),
                risk_multiplier: 1.8,
                platform: Some("linux".to_string()),
            });
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
        
        DetectionRules {
            api_weights,
            sequence_patterns,
            suspicious_paths,
            suspicious_processes,
            system_process_contexts,
            alert_frequency_limits,
            time_window_rules: vec![
                TimeWindowRule {
                    event_type: InjectionEventType::CrossProcessMemoryOp,
                    max_count: 5,
                    time_window: Duration::from_secs(60),
                    risk_score: 0.6,
                },
                TimeWindowRule {
                    event_type: InjectionEventType::DllInjection,
                    max_count: 3,
                    time_window: Duration::from_secs(30),
                    risk_score: 0.7,
                },
            ],
        }
    }

    async fn analyze_process_event(
        &self,
        tracker: &mut ProcessTracker,
        _event: &Event,
        process_data: &ProcessEventData,
    ) -> Result<Option<DetectorAlert>> {
        let pid = process_data.pid;
        
        // Update or create process state
        let process_state = tracker.processes.entry(pid).or_insert_with(|| {
            ProcessState {
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
            }
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
            if self.is_suspicious_process_name(&process_name) {
                let base_risk = 0.5;
                let adjusted_risk = self.calculate_context_aware_risk(
                    &process_name, 
                    &process_path, 
                    base_risk
                );
                
                let (should_suppress, severity_multiplier) = self.should_suppress_alert(
                    tracker, 
                    &process_name
                );

                if !should_suppress {
                    let final_risk = adjusted_risk * severity_multiplier;
                    let severity = if final_risk >= 0.7 {
                        AlertSeverity::High
                    } else if final_risk >= 0.4 {
                        AlertSeverity::Medium
                    } else {
                        AlertSeverity::Low
                    };

                    alerts.push(self.create_alert(
                        InjectionEventType::SuspiciousProcess,
                        severity,
                        format!("Suspicious process name: {}", process_name),
                        format!("Process {} (PID: {}) has a suspicious name", process_name, pid),
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
        // Use enhanced file path analysis with context
        let (is_suspicious, alert_key) = self.analyze_file_path_context(&file_data.path);
        
        if is_suspicious {
            // Check frequency limits for this type of file alert
            let (should_suppress, severity_multiplier) = self.should_suppress_alert(
                tracker, 
                &alert_key
            );
            
            if !should_suppress {
                let base_risk = 0.4;
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

    fn is_suspicious_file_path(&self, path: &str) -> bool {
        self.detection_rules.suspicious_paths.iter()
            .any(|suspicious_path| path.contains(suspicious_path))
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

    fn is_suspicious_network_behavior(&self, network_data: &NetworkEventData) -> bool {
        // Check for suspicious ports
        if let Some(port) = network_data.destination_port {
            let suspicious_ports = [4444, 8080, 9999, 31337, 1337, 6666, 6667, 443, 80];
            if suspicious_ports.contains(&port) {
                return true;
            }
        }
        
        // Check for suspicious protocols or patterns
        if network_data.protocol.to_lowercase().contains("unknown") {
            return true;
        }
        
        false
    }


    fn is_suspicious_process_path(&self, path: &str) -> bool {
        self.detection_rules.suspicious_paths.iter()
            .any(|sus_path| path.contains(sus_path))
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
    fn analyze_file_path_context(&self, path: &str) -> (bool, String) {
        // Check for specific patterns that might be false positives
        if path.contains("/Library/Biome/tmp/") {
            return (true, "biome_tmp".to_string());
        }
        
        if path.contains("/Library/PersonalizationPortrait/") {
            return (true, "personalization_tmp".to_string());
        }
        
        if path.starts_with("/private/tmp/zsh") {
            return (true, "zsh_tmp".to_string());
        }
        
        // Default suspicious file check
        (self.is_suspicious_file_path(path), "general_suspicious_file".to_string())
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
            if self.is_potential_process_hollowing(process_name, process_path, parent_name, parent_path) {
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
    
    fn is_potential_process_hollowing(&self, process_name: &str, process_path: &str, parent_name: &str, parent_path: &str) -> bool {
        // Check for mismatched process names and paths
        // This is a simplified heuristic - real process hollowing detection would be more complex
        
        // 1. Process name doesn't match the executable name in the path
        if let Some(path_filename) = process_path.split('/').last() {
            let path_basename = path_filename.split('.').next().unwrap_or(path_filename);
            if process_name != path_basename && !process_name.starts_with(path_basename) {
                return true;
            }
        }
        
        // 2. Child process in same directory as parent but different expected behavior
        if process_path.starts_with(&parent_path[..parent_path.rfind('/').unwrap_or(0)]) {
            // Same directory, check if this is expected behavior
            if parent_name == "explorer.exe" && process_name != "explorer.exe" {
                return true; // Suspicious: non-explorer process in explorer directory
            }
        }
        
        // 3. System processes in user directories
        if self.is_system_process_name(process_name) {
            let user_directories = ["/home/", "/Users/", "C:\\Users\\", "/tmp/", "/var/tmp/"];
            if user_directories.iter().any(|&dir| process_path.contains(dir)) {
                return true;
            }
        }
        
        false
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
        
        debug!("Cleaned up old injection detection events and processes");
    }
}

#[async_trait::async_trait]
impl Detector for BehavioralDetector {
    async fn start(&self) -> Result<()> {
        info!("Starting behavioral detector");
        *self.is_running.write().await = true;
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        info!("Stopping behavioral detector");
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
                .context("Failed to send injection detection alert")?;
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
        };
        
        let (alert_sender, _) = mpsc::channel(100);
        
        let detector = BehavioralDetector::new(
            config,
            alert_sender,
            "test-agent".to_string(),
            "test-host".to_string(),
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
        };
        
        let (alert_sender, mut alert_receiver) = mpsc::channel(100);
        
        let detector = BehavioralDetector::new(
            config,
            alert_sender,
            "test-agent".to_string(),
            "test-host".to_string(),
        ).await.unwrap();
        
        detector.start().await.unwrap();
        
        // Create a suspicious process event (Linux path)
        let event = builders::create_process_event(
            1234,
            "bash".to_string(),
            "/tmp/suspicious_bash".to_string(),
            "test-host".to_string(),
            "test-agent".to_string(),
        );
        
        detector.process_event(&event).await.unwrap();
        
        // Check if an alert was generated
        let alert = tokio::time::timeout(Duration::from_millis(100), alert_receiver.recv()).await;
        assert!(alert.is_ok() && alert.unwrap().is_some());
    }
}
