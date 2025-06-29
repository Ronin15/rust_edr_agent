use anyhow::Result;
use sha2::{Sha256, Digest};
use std::path::Path;

pub fn calculate_file_hash(file_path: &Path) -> Result<String> {
    let contents = std::fs::read(file_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&contents);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;
    
    if bytes < THRESHOLD {
        return format!("{} B", bytes);
    }
    
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }
    
    format!("{:.2} {}", size, UNITS[unit_index])
}

pub fn get_current_username() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
}

pub fn is_admin() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    
    #[cfg(windows)]
    {
        // TODO: Implement Windows admin check
        false
    }
    
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
    }
}
