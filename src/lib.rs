// EDR Agent Library
pub mod config;
pub mod agent;
pub mod deduplication;
pub mod events;
pub mod storage;
pub mod network;
pub mod utils;

// Modules with submodules
pub mod collectors {
    pub mod process;
    pub mod file;
    pub mod network;
    
    #[cfg(windows)]
    pub mod registry;
    
    // Re-export the manager and related types
    mod manager;
    pub use manager::*;
}

pub mod detectors {
    pub mod behavioral;
    pub mod dns_anomaly;
    
    #[cfg(windows)]
    pub mod registry;
    
    // Re-export the manager and related types
    mod manager;
    pub use manager::*;
}
