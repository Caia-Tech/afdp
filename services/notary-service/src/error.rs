//! Error types for the AFDP Notary Service

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NotaryError {
    #[error("Vault error: {0}")]
    VaultError(String),

    #[error("Rekor error: {0}")]
    RekorError(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("HTTP request error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Transport error: {0}")]
    TransportError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Temporal error: {0}")]
    TemporalError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

pub type Result<T> = std::result::Result<T, NotaryError>;