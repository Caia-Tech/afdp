use thiserror::Error;

/// Repository Analysis Service error types
#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Storage error: {0}")]
    Storage(#[from] sqlx::Error),

    #[error("Object storage error: {0}")]
    ObjectStorage(#[from] object_store::Error),

    #[error("Vector storage error: {0}")]
    VectorStorage(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

/// Result type for Repository Analysis Service
pub type Result<T> = std::result::Result<T, Error>;

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(anyhow::anyhow!(s))
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(anyhow::anyhow!(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = Error::Config("Invalid configuration".to_string());
        assert_eq!(error.to_string(), "Configuration error: Invalid configuration");

        let error = Error::NotFound("Job not found".to_string());
        assert_eq!(error.to_string(), "Not found: Job not found");
    }

    #[test]
    fn test_error_conversion() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let error: Error = io_error.into();
        assert!(matches!(error, Error::Io(_)));

        let string_error: Error = "Test error".into();
        assert!(matches!(string_error, Error::Other(_)));
    }
}