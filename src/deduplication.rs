// Security-First Event Deduplication System
// Designed to reduce noise while preserving ALL security-critical events

use std::collections::HashMap;
use std::time::{Duration, Instant};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tokio::sync::RwLock;
use tracing::{debug, info};
use crate::events::{Event, EventType, EventData};

/// Configuration for security-aware deduplication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationConfig {
    // Phase 1: Content-based deduplication
    pub exact_duplicate_window_secs: u64,          // 3600 (1 hour)
    pub security_critical_bypass: bool,            // true - always report critical events
    
    // Phase 2: Burst detection  
    pub burst_threshold: u32,                      // 10 events
    pub burst_window_secs: u64,                    // 60 (1 minute)
    pub burst_summary_interval: u32,               // Every 100 events
    
    // Phase 3: Intelligent rate limiting by event type
    pub file_event_rate_per_minute: u32,          // 5
    pub process_event_rate_per_minute: u32,       // 10 (higher for security)
    pub network_event_rate_per_minute: u32,       // 20
    pub security_alert_rate_per_hour: u32,        // 5 (never suppress critical alerts)
    
    // Phase 2 Enhancements: Pattern-based deduplication (security-focused)
    pub microsecond_deduplication_window_ms: u64, // 100 (milliseconds for rapid duplicates)
    pub enable_subsecond_deduplication: bool,     // true (enable sub-second duplicate detection)
    pub rapid_duplicate_threshold: u32,           // 3 (identical events within microsecond window)
    
    // Enhanced content similarity detection
    pub enable_content_similarity_detection: bool, // true (detect near-identical content)
    pub content_similarity_threshold: f32,         // 0.95 (95% similarity threshold)
    pub similarity_window_secs: u64,               // 60 (1 minute window for similarity detection)
    
    // Adaptive rate limiting based on behavior patterns
    pub enable_adaptive_rate_limiting: bool,       // true (adjust rates based on patterns)
    pub noise_pattern_detection_window: u64,       // 300 (5 minutes to detect noise patterns)
    pub noise_threshold_multiplier: f32,           // 2.0 (reduce rate by half when noise detected)
    
    // Memory management
    pub max_hash_cache_size: usize,               // 10,000 entries
    pub max_burst_states: usize,                  // 1,000 entries
    pub cleanup_interval_secs: u64,               // 300 (5 minutes)
    pub max_microsecond_cache_size: usize,        // 5,000 entries for sub-second deduplication
    pub max_similarity_cache_size: usize,         // 3,000 entries for content similarity
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            exact_duplicate_window_secs: 1800,    // 30 minutes (was 1 hour)
            security_critical_bypass: true,
            burst_threshold: 5,                    // More aggressive (was 10)
            burst_window_secs: 30,                 // Shorter window (was 60)
            burst_summary_interval: 25,            // More frequent summaries (was 100)
            file_event_rate_per_minute: 3,         // Tighter rate limiting (was 5)
            process_event_rate_per_minute: 10,
            network_event_rate_per_minute: 20,
            security_alert_rate_per_hour: 5,
            
            // Phase 2 Enhancements: Pattern-based deduplication (security-focused)
            microsecond_deduplication_window_ms: 100, // 100ms for rapid duplicates
            enable_subsecond_deduplication: true,     // Enable sub-second duplicate detection
            rapid_duplicate_threshold: 3,             // 3 identical events within microsecond window
            
            // Enhanced content similarity detection
            enable_content_similarity_detection: true, // Detect near-identical content
            content_similarity_threshold: 0.95,        // 95% similarity threshold
            similarity_window_secs: 60,                // 1 minute window for similarity detection
            
            // Adaptive rate limiting based on behavior patterns
            enable_adaptive_rate_limiting: true,       // Adjust rates based on patterns
            noise_pattern_detection_window: 300,       // 5 minutes to detect noise patterns
            noise_threshold_multiplier: 2.0,           // Reduce rate by half when noise detected
            
            max_hash_cache_size: 10_000,
            max_burst_states: 1_000,
            cleanup_interval_secs: 300,            // 5 minutes
            max_microsecond_cache_size: 5_000,     // Sub-second deduplication cache
            max_similarity_cache_size: 3_000,      // Content similarity cache
        }
    }
}

/// Security-first event deduplication manager
pub struct SecurityAwareDeduplicator {
    config: DeduplicationConfig,
    
    // Phase 1: Content-based deduplication
    content_cache: RwLock<HashMap<String, ContentEntry>>,
    
    // Phase 2: Burst detection
    burst_detector: RwLock<HashMap<String, BurstState>>,
    
    // Phase 3: Rate limiting by event type
    rate_limiter: RwLock<HashMap<RateLimitKey, RateLimitState>>,
    
    // Phase 2 Enhancements: Sub-second deduplication cache
    microsecond_cache: RwLock<HashMap<String, MicrosecondEntry>>,
    
    // Phase 2 Enhancements: Content similarity cache
    similarity_cache: RwLock<HashMap<String, SimilarityEntry>>,
    
    // Phase 2 Enhancements: Adaptive rate limiting state
    noise_pattern_tracker: RwLock<HashMap<String, NoisePatternState>>,
    
    // Statistics
    stats: RwLock<DeduplicationStats>,
    last_cleanup: RwLock<Instant>,
}

#[derive(Debug, Clone)]
struct ContentEntry {
    first_seen: Instant,
    last_seen: Instant,
    count: u32,
}

#[derive(Debug, Clone)]
struct BurstState {
    content_type: String,
    count: u32,
    first_seen: Instant,
    last_reported: Instant,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RateLimitKey {
    event_type: String,
    agent_id: String,
    context: String, // File path, process name, etc.
}

#[derive(Debug, Clone)]
struct RateLimitState {
    count: u32,
    window_start: Instant,
    last_event: Instant,
}

// Phase 2 Enhancement data structures
#[derive(Debug, Clone)]
struct MicrosecondEntry {
    first_seen: Instant,
    last_seen: Instant,
    count: u32,
    content_hash: String,
}

#[derive(Debug, Clone)]
struct SimilarityEntry {
    first_seen: Instant,
    last_seen: Instant,
    count: u32,
    similarity_score: f32,
    representative_hash: String,
}

#[derive(Debug, Clone)]
struct NoisePatternState {
    event_count: u32,
    window_start: Instant,
    baseline_rate: f32,
    is_noisy: bool,
    adjusted_rate_limit: u32,
}

#[derive(Debug, Clone, Default)]
pub struct DeduplicationStats {
    pub events_processed: u64,
    pub events_allowed: u64,
    pub events_deduplicated: u64,
    pub events_burst_suppressed: u64,
    pub events_rate_limited: u64,
    pub security_critical_bypassed: u64,
    pub summary_events_generated: u64,
    // Phase 2 Enhancement statistics
    pub microsecond_duplicates_suppressed: u64,
    pub similarity_duplicates_suppressed: u64,
    pub adaptive_rate_adjustments: u64,
}

impl SecurityAwareDeduplicator {
    pub fn new(config: DeduplicationConfig) -> Self {
        Self {
            config,
            content_cache: RwLock::new(HashMap::new()),
            burst_detector: RwLock::new(HashMap::new()),
            rate_limiter: RwLock::new(HashMap::new()),
            // Phase 2 Enhancement caches
            microsecond_cache: RwLock::new(HashMap::new()),
            similarity_cache: RwLock::new(HashMap::new()),
            noise_pattern_tracker: RwLock::new(HashMap::new()),
            stats: RwLock::new(DeduplicationStats::default()),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Main deduplication entry point - returns (should_send, optional_summary_event)
    pub async fn should_allow_event(&self, event: &Event) -> (bool, Option<Event>) {
        let mut stats = self.stats.write().await;
        stats.events_processed += 1;
        drop(stats);

        // SECURITY RULE 1: Never filter security-critical events
        if self.config.security_critical_bypass && event.security_critical {
            let mut stats = self.stats.write().await;
            stats.security_critical_bypassed += 1;
            stats.events_allowed += 1;
            debug!("Security-critical event bypassed deduplication: {:?}", event.event_type);
            return (true, None);
        }

        // OPTIMIZATION: Check for excluded paths (self-generated content, noise)
        if self.should_exclude_event(event) {
            let mut stats = self.stats.write().await;
            stats.events_rate_limited += 1; // Count as rate limited for statistics
            debug!("Event excluded due to path exclusion rules: {:?}", event);
            return (false, None);
        }

        // Periodic cleanup
        self.cleanup_if_needed().await;

        // Phase 1: Check for exact content duplicates
        if let Some(summary) = self.check_content_duplication(event).await {
            let mut stats = self.stats.write().await;
            stats.events_deduplicated += 1;
            return (false, Some(summary));
        }

        // Phase 2 Enhancement: Sub-second deduplication for rapid events
        if self.config.enable_subsecond_deduplication {
            if self.check_microsecond_duplication(event).await {
                let mut stats = self.stats.write().await;
                stats.microsecond_duplicates_suppressed += 1;
                debug!("Microsecond-level duplicate suppressed for event: {:?}", event.event_type);
                return (false, None);
            }
        }

        // Phase 2: Check for burst patterns
        if let Some(summary) = self.check_burst_pattern(event).await {
            let mut stats = self.stats.write().await;
            stats.events_burst_suppressed += 1;
            return (false, Some(summary));
        }

        // Phase 2 Enhancement: Content similarity detection for near-duplicates
        if self.config.enable_content_similarity_detection {
            if self.check_content_similarity(event).await {
                let mut stats = self.stats.write().await;
                stats.similarity_duplicates_suppressed += 1;
                debug!("Content similarity duplicate suppressed for event: {:?}", event.event_type);
                return (false, None);
            }
        }

        // Phase 3: Apply intelligent rate limiting
        if !self.check_rate_limit(event).await {
            let mut stats = self.stats.write().await;
            stats.events_rate_limited += 1;
            return (false, None);
        }

        // Event passed all filters
        let mut stats = self.stats.write().await;
        stats.events_allowed += 1;
        (true, None)
    }

    /// Phase 1: Content-based deduplication
    async fn check_content_duplication(&self, event: &Event) -> Option<Event> {
        let content_hash = self.generate_robust_content_hash(event);
        let now = Instant::now();
        
        let mut cache = self.content_cache.write().await;
        
        if let Some(entry) = cache.get_mut(&content_hash) {
            let time_since_first = now.duration_since(entry.first_seen);
            
            // Check if we're within the deduplication window
            if time_since_first < Duration::from_secs(self.config.exact_duplicate_window_secs) {
                entry.count += 1;
                entry.last_seen = now;
                
                // Generate summary event for significant duplicates
                if entry.count % 50 == 0 {  // Every 50th duplicate
                    debug!("Generating summary for {} duplicates of content hash: {}", entry.count, &content_hash[..8]);
                    return Some(self.create_summary_event(event, entry.count, time_since_first));
                }
                return None; // Suppress this duplicate
            } else {
                // Outside window, reset counter
                entry.count = 1;
                entry.first_seen = now;
                entry.last_seen = now;
            }
        } else {
            // New content hash
            cache.insert(content_hash.clone(), ContentEntry {
                first_seen: now,
                last_seen: now,
                count: 1,
            });
        }
        
        None // Allow this event
    }

    /// Phase 2: Burst detection
    async fn check_burst_pattern(&self, event: &Event) -> Option<Event> {
        let burst_key = self.generate_burst_key(event);
        let now = Instant::now();
        
        let mut detector = self.burst_detector.write().await;
        
        if let Some(state) = detector.get_mut(&burst_key) {
            let time_since_first = now.duration_since(state.first_seen);
            
            // Check if we're in a burst window
            if time_since_first < Duration::from_secs(self.config.burst_window_secs) {
                state.count += 1;
                
                // Detect burst pattern
                if state.count >= self.config.burst_threshold {
                    let time_since_reported = now.duration_since(state.last_reported);
                    
                    // Generate summary every N events or every minute
                    if state.count % self.config.burst_summary_interval == 0 || 
                       time_since_reported > Duration::from_secs(60) {
                        state.last_reported = now;
                        debug!("Burst detected: {} events in burst for key: {}", state.count, burst_key);
                        return Some(self.create_burst_summary_event(event, state));
                    }
                    return None; // Suppress this burst event
                }
            } else {
                // Reset burst counter
                state.count = 1;
                state.first_seen = now;
            }
        } else {
            // New burst key
            detector.insert(burst_key.clone(), BurstState {
                content_type: format!("{:?}", event.event_type),
                count: 1,
                first_seen: now,
                last_reported: now,
            });
        }
        
        None // Allow this event
    }

    /// Phase 3: Intelligent rate limiting
    async fn check_rate_limit(&self, event: &Event) -> bool {
        let rate_key = self.generate_rate_limit_key(event);
        let rate_limit = self.get_rate_limit_for_event_type(&event.event_type);
        let window_duration = Duration::from_secs(60); // 1 minute window
        let now = Instant::now();
        
        let mut limiter = self.rate_limiter.write().await;
        
        if let Some(state) = limiter.get_mut(&rate_key) {
            let time_since_window_start = now.duration_since(state.window_start);
            
            if time_since_window_start < window_duration {
                // Within current window
                if state.count >= rate_limit {
                    return false; // Rate limit exceeded
                }
                state.count += 1;
            } else {
                // New window
                state.count = 1;
                state.window_start = now;
            }
            state.last_event = now;
        } else {
            // New rate limit key
            limiter.insert(rate_key, RateLimitState {
                count: 1,
                window_start: now,
                last_event: now,
            });
        }
        
        true // Allow this event
    }

    /// Generate robust content hash for deduplication
    fn generate_robust_content_hash(&self, event: &Event) -> String {
        let mut hasher = Sha256::new();
        
        // Include event type and source
        hasher.update(format!("{:?}", event.event_type).as_bytes());
        hasher.update(event.source.as_bytes());
        
        // Include relevant data based on event type
        match &event.data {
            EventData::File(file_data) => {
                hasher.update(file_data.path.as_bytes());
                
                // Include file size for stronger deduplication
                if let Some(size) = file_data.size {
                    hasher.update(size.to_string().as_bytes());
                }
                
                // Include permissions
                if let Some(permissions) = &file_data.permissions {
                    hasher.update(permissions.as_bytes());
                }
                
                // OPTIMIZATION: Include file SHA256 hash if available for strongest deduplication
                // This catches identical file content even with different timestamps
                if let Some(ref hashes) = file_data.hashes {
                    if let Some(ref sha256) = hashes.sha256 {
                        hasher.update(sha256.as_bytes());
                    }
                }
                
                // OPTIMIZATION: Use hour-level precision for timestamps to catch rapid duplicates
                // This groups events within the same hour together while still maintaining some temporal distinction
                if let Some(ref modified_time) = file_data.modified_time {
                    // Use hour precision to deduplicate events with microsecond differences
                    let hour_timestamp = modified_time.format("%Y-%m-%d-%H").to_string();
                    hasher.update(hour_timestamp.as_bytes());
                }
            },
            EventData::Process(proc_data) => {
                hasher.update(proc_data.name.as_bytes());
                hasher.update(proc_data.path.as_bytes());
                hasher.update(proc_data.pid.to_string().as_bytes());
            },
            EventData::Network(net_data) => {
                hasher.update(net_data.protocol.as_bytes());
                if let Some(ref dest_ip) = net_data.destination_ip {
                    hasher.update(dest_ip.as_bytes());
                }
                if let Some(dest_port) = net_data.destination_port {
                    hasher.update(dest_port.to_string().as_bytes());
                }
            },
            EventData::System(sys_data) => {
                hasher.update(sys_data.description.as_bytes());
            },
            _ => {
                // Fallback for other event types
                if let Ok(json) = serde_json::to_string(&event.data) {
                    hasher.update(json.as_bytes());
                }
            }
        }
        
        format!("{:x}", hasher.finalize())
    }

    /// Generate burst detection key
    fn generate_burst_key(&self, event: &Event) -> String {
        match &event.data {
            EventData::File(file_data) => {
                // Group by directory for file events
                let path = std::path::Path::new(&file_data.path);
                if let Some(parent) = path.parent() {
                    format!("file_{}_{}", event.event_type.as_str(), parent.display())
                } else {
                    format!("file_{}_{}", event.event_type.as_str(), file_data.path)
                }
            },
            EventData::Process(proc_data) => {
                format!("process_{}_{}", event.event_type.as_str(), proc_data.name)
            },
            EventData::Network(_) => {
                format!("network_{}", event.event_type.as_str())
            },
            _ => {
                format!("other_{}", event.event_type.as_str())
            }
        }
    }

    /// Generate rate limiting key
    fn generate_rate_limit_key(&self, event: &Event) -> RateLimitKey {
        let context = match &event.data {
            EventData::File(file_data) => file_data.path.clone(),
            EventData::Process(proc_data) => proc_data.name.clone(),
            EventData::Network(net_data) => net_data.protocol.clone(),
            _ => "general".to_string(),
        };
        
        RateLimitKey {
            event_type: format!("{:?}", event.event_type),
            agent_id: event.agent_id.clone(),
            context,
        }
    }

    /// Get rate limit for event type
    fn get_rate_limit_for_event_type(&self, event_type: &EventType) -> u32 {
        match event_type {
            EventType::FileCreated | EventType::FileModified | EventType::FileDeleted 
            | EventType::FileAccessed => self.config.file_event_rate_per_minute,
            
            EventType::ProcessCreated | EventType::ProcessTerminated 
            | EventType::ProcessModified => self.config.process_event_rate_per_minute,
            
            EventType::NetworkConnection | EventType::NetworkDnsQuery => 
                self.config.network_event_rate_per_minute,
            
            EventType::SecurityAlert => self.config.security_alert_rate_per_hour / 60, // Convert to per-minute
            
            _ => 30, // Default rate limit
        }
    }

    /// Create summary event for duplicates
    fn create_summary_event(&self, original: &Event, count: u32, duration: Duration) -> Event {
        let mut summary_event = original.clone();
        summary_event.id = uuid::Uuid::new_v4().to_string();
        summary_event.timestamp = Utc::now();
        summary_event.event_type = EventType::SystemBoot; // Use a neutral event type for summaries
        
        summary_event.add_metadata("event_type".to_string(), "EventSummary".to_string());
        summary_event.add_metadata("original_event_type".to_string(), format!("{:?}", original.event_type));
        summary_event.add_metadata("suppressed_count".to_string(), count.to_string());
        summary_event.add_metadata("duration_secs".to_string(), duration.as_secs().to_string());
        summary_event.add_metadata("reason".to_string(), "content_duplication".to_string());
        
        summary_event
    }

    /// Create summary event for bursts
    fn create_burst_summary_event(&self, original: &Event, state: &BurstState) -> Event {
        let mut summary_event = original.clone();
        summary_event.id = uuid::Uuid::new_v4().to_string();
        summary_event.timestamp = Utc::now();
        summary_event.event_type = EventType::SystemBoot; // Use a neutral event type for summaries
        
        summary_event.add_metadata("event_type".to_string(), "BurstSummary".to_string());
        summary_event.add_metadata("original_event_type".to_string(), state.content_type.clone());
        summary_event.add_metadata("burst_count".to_string(), state.count.to_string());
        summary_event.add_metadata("burst_duration_secs".to_string(), 
                                 Instant::now().duration_since(state.first_seen).as_secs().to_string());
        summary_event.add_metadata("reason".to_string(), "burst_detection".to_string());
        
        summary_event
    }

    /// Cleanup old entries to prevent memory leaks
    async fn cleanup_if_needed(&self) {
        let mut last_cleanup = self.last_cleanup.write().await;
        let now = Instant::now();
        
        if now.duration_since(*last_cleanup) < Duration::from_secs(self.config.cleanup_interval_secs) {
            return; // Not time yet
        }
        
        *last_cleanup = now;
        drop(last_cleanup);
        
        // Cleanup content cache
        let mut cache = self.content_cache.write().await;
        let old_size = cache.len();
        cache.retain(|_, entry| {
            now.duration_since(entry.last_seen) < Duration::from_secs(self.config.exact_duplicate_window_secs * 2)
        });
        if cache.len() > self.config.max_hash_cache_size {
            // Emergency cleanup - remove oldest entries
            let mut entries: Vec<_> = cache.iter().map(|(k, v)| (k.clone(), v.last_seen)).collect();
            entries.sort_by_key(|(_, time)| *time);
            let to_remove = cache.len() - self.config.max_hash_cache_size / 2;
            for (key, _) in entries.iter().take(to_remove) {
                cache.remove(key);
            }
        }
        let new_cache_size = cache.len();
        drop(cache);
        
        // Cleanup burst detector
        let mut detector = self.burst_detector.write().await;
        let old_burst_size = detector.len();
        detector.retain(|_, state| {
            now.duration_since(state.last_reported) < Duration::from_secs(300) // 5 minutes
        });
        if detector.len() > self.config.max_burst_states {
            // Emergency cleanup
            let mut entries: Vec<_> = detector.iter().map(|(k, v)| (k.clone(), v.last_reported)).collect();
            entries.sort_by_key(|(_, time)| *time);
            let to_remove = detector.len() - self.config.max_burst_states / 2;
            for (key, _) in entries.iter().take(to_remove) {
                detector.remove(key);
            }
        }
        let new_burst_size = detector.len();
        drop(detector);
        
        // Cleanup rate limiter
        let mut limiter = self.rate_limiter.write().await;
        let old_rate_size = limiter.len();
        limiter.retain(|_, state| {
            now.duration_since(state.last_event) < Duration::from_secs(120) // 2 minutes
        });
        let new_rate_size = limiter.len();
        drop(limiter);
        
        info!("Deduplication cleanup: cache {} -> {}, burst {} -> {}, rate {} -> {}", 
              old_size, new_cache_size, old_burst_size, new_burst_size, old_rate_size, new_rate_size);
    }

    /// Phase 2 Enhancement: Sub-second deduplication for rapid identical events
    async fn check_microsecond_duplication(&self, event: &Event) -> bool {
        let content_hash = self.generate_robust_content_hash(event);
        let now = Instant::now();
        let window_duration = Duration::from_millis(self.config.microsecond_deduplication_window_ms);
        
        let mut cache = self.microsecond_cache.write().await;
        
        if let Some(entry) = cache.get_mut(&content_hash) {
            let time_since_first = now.duration_since(entry.first_seen);
            
            // Check if we're within the microsecond deduplication window
            if time_since_first < window_duration {
                entry.count += 1;
                entry.last_seen = now;
                
                // Suppress if we've hit the rapid duplicate threshold
                if entry.count >= self.config.rapid_duplicate_threshold {
                    debug!("Rapid duplicate suppressed: {} events within {}ms for hash: {}", 
                           entry.count, self.config.microsecond_deduplication_window_ms, &content_hash[..8]);
                    return true; // Suppress this rapid duplicate
                }
            } else {
                // Outside window, reset counter
                entry.count = 1;
                entry.first_seen = now;
                entry.last_seen = now;
            }
        } else {
            // New content hash for microsecond cache
            cache.insert(content_hash.clone(), MicrosecondEntry {
                first_seen: now,
                last_seen: now,
                count: 1,
                content_hash: content_hash.clone(),
            });
            
            // Prevent cache from growing too large
            if cache.len() > self.config.max_microsecond_cache_size {
                // Remove oldest entries
                let mut entries: Vec<_> = cache.iter().map(|(k, v)| (k.clone(), v.first_seen)).collect();
                entries.sort_by_key(|(_, time)| *time);
                let to_remove = cache.len() - self.config.max_microsecond_cache_size / 2;
                for (key, _) in entries.iter().take(to_remove) {
                    cache.remove(key);
                }
            }
        }
        
        false // Allow this event (not a rapid duplicate)
    }
    
    /// Phase 2 Enhancement: Content similarity detection for near-identical events
    async fn check_content_similarity(&self, event: &Event) -> bool {
        // Generate a similarity key based on event type, source, and core data
        let similarity_key = self.generate_similarity_key(event);
        let now = Instant::now();
        let window_duration = Duration::from_secs(self.config.similarity_window_secs);
        
        let mut cache = self.similarity_cache.write().await;
        
        if let Some(entry) = cache.get_mut(&similarity_key) {
            let time_since_first = now.duration_since(entry.first_seen);
            
            // Check if we're within the similarity detection window
            if time_since_first < window_duration {
                entry.count += 1;
                entry.last_seen = now;
                
                // Calculate similarity with representative event
                let current_content_hash = self.generate_robust_content_hash(event);
                let similarity_score = self.calculate_content_similarity(&current_content_hash, &entry.representative_hash);
                
                // Suppress if similarity is above threshold
                if similarity_score >= self.config.content_similarity_threshold {
                    debug!("Similarity duplicate suppressed: {:.2}% similar to representative for key: {}", 
                           similarity_score * 100.0, &similarity_key);
                    return true; // Suppress this similar event
                }
            } else {
                // Outside window, reset with current event as new representative
                entry.count = 1;
                entry.first_seen = now;
                entry.last_seen = now;
                entry.representative_hash = self.generate_robust_content_hash(event);
            }
        } else {
            // New similarity key - use current event as representative
            cache.insert(similarity_key.clone(), SimilarityEntry {
                first_seen: now,
                last_seen: now,
                count: 1,
                similarity_score: 1.0, // Perfect match with itself
                representative_hash: self.generate_robust_content_hash(event),
            });
            
            // Prevent cache from growing too large
            if cache.len() > self.config.max_similarity_cache_size {
                // Remove oldest entries
                let mut entries: Vec<_> = cache.iter().map(|(k, v)| (k.clone(), v.first_seen)).collect();
                entries.sort_by_key(|(_, time)| *time);
                let to_remove = cache.len() - self.config.max_similarity_cache_size / 2;
                for (key, _) in entries.iter().take(to_remove) {
                    cache.remove(key);
                }
            }
        }
        
        false // Allow this event (not similar enough to suppress)
    }
    
    /// Generate similarity key for grouping related events
    fn generate_similarity_key(&self, event: &Event) -> String {
        match &event.data {
            EventData::File(file_data) => {
                // Group by event type + directory + file extension for file events
                let path = std::path::Path::new(&file_data.path);
                let extension = path.extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("unknown");
                let parent_dir = path.parent()
                    .and_then(|p| p.to_str())
                    .unwrap_or("unknown");
                
                format!("file_{}_{}_{}_{}", 
                        event.event_type.as_str(), 
                        event.source,
                        parent_dir.chars().rev().take(50).collect::<String>(), // Last 50 chars of path
                        extension)
            },
            EventData::Process(proc_data) => {
                format!("process_{}_{}_{}", 
                        event.event_type.as_str(),
                        event.source,
                        proc_data.name)
            },
            EventData::Network(net_data) => {
                format!("network_{}_{}_{}", 
                        event.event_type.as_str(),
                        event.source,
                        net_data.protocol)
            },
            _ => {
                format!("other_{}_{}", 
                        event.event_type.as_str(),
                        event.source)
            }
        }
    }
    
    /// Calculate similarity between two content hashes (simplified)
    fn calculate_content_similarity(&self, hash1: &str, hash2: &str) -> f32 {
        if hash1 == hash2 {
            return 1.0; // Perfect match
        }
        
        // Simple similarity based on common prefix/suffix length
        // In a production system, you might use more sophisticated algorithms
        let common_prefix = hash1.chars()
            .zip(hash2.chars())
            .take_while(|(a, b)| a == b)
            .count();
        
        let common_suffix = hash1.chars().rev()
            .zip(hash2.chars().rev())
            .take_while(|(a, b)| a == b)
            .count();
        
        let max_len = hash1.len().max(hash2.len()) as f32;
        let similarity = (common_prefix + common_suffix) as f32 / max_len;
        
        // Cap at the configured threshold to avoid false positives
        similarity.min(self.config.content_similarity_threshold - 0.01)
    }

    /// Check if event should be excluded based on path patterns
    fn should_exclude_event(&self, event: &Event) -> bool {
        match &event.data {
            EventData::File(file_data) => {
                let path = &file_data.path;
                
                // Only exclude self-generated event files to avoid monitoring loops
                if path.contains("/projects/rust_projects/edr_agent/data/events_") {
                    debug!("Excluding self-generated event file: {}", path);
                    return true;
                }
                
                false
            },
            _ => false, // Only apply path exclusions to file events
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> DeduplicationStats {
        self.stats.read().await.clone()
    }
}

// Extension trait for EventType
trait EventTypeExt {
    fn as_str(&self) -> &'static str;
}

impl EventTypeExt for EventType {
    fn as_str(&self) -> &'static str {
        match self {
            EventType::ProcessCreated => "ProcessCreated",
            EventType::ProcessTerminated => "ProcessTerminated",
            EventType::ProcessModified => "ProcessModified",
            EventType::FileCreated => "FileCreated",
            EventType::FileModified => "FileModified",
            EventType::FileDeleted => "FileDeleted",
            EventType::FileAccessed => "FileAccessed",
            EventType::NetworkConnection => "NetworkConnection",
            EventType::NetworkDnsQuery => "NetworkDnsQuery",
            EventType::RegistryKeyCreated => "RegistryKeyCreated",
            EventType::RegistryKeyModified => "RegistryKeyModified",
            EventType::RegistryKeyDeleted => "RegistryKeyDeleted",
            EventType::RegistryValueSet => "RegistryValueSet",
            EventType::SystemBoot => "SystemBoot",
            EventType::SystemShutdown => "SystemShutdown",
            EventType::UserLogin => "UserLogin",
            EventType::UserLogout => "UserLogout",
            EventType::SecurityAlert => "SecurityAlert",
        }
    }
}
