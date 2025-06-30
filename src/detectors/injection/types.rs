use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

// Cross-platform injection events
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

// Process tracking state
#[derive(Debug)]
pub struct ProcessTracker {
    pub processes: HashMap<u32, ProcessState>,
    pub recent_events: VecDeque<SuspiciousEvent>,
    pub blocked_processes: HashMap<u32, Instant>,
    pub alert_frequency: HashMap<String, Vec<Instant>>, // Track alert frequency by type
    pub last_cleanup: Instant,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            recent_events: VecDeque::new(),
            blocked_processes: HashMap::new(),
            alert_frequency: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }
}

#[derive(Debug, Default)]
pub struct DetectorStats {
    pub events_processed: u64,
    pub alerts_generated: u64,
    pub last_activity: Option<Instant>,
}
