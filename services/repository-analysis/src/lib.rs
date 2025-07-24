pub mod config;
pub mod storage;
pub mod analysis;
pub mod api;
pub mod server;
pub mod error;
pub mod events;
pub mod auth;
pub mod forensics;
pub mod temporal;
pub mod proto;

#[cfg(test)]
pub mod tests;

pub use config::Config;
pub use error::{Error, Result};
pub use server::Server;

/// Repository Analysis Service version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Service description
pub const DESCRIPTION: &str = "Universal repository forensic analysis service with AI-powered intelligence";

#[cfg(test)]
mod service_tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_description() {
        assert!(DESCRIPTION.contains("repository"));
        assert!(DESCRIPTION.contains("forensic"));
    }
}