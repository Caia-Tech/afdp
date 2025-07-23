//! AFDP Notary Service Core Library
//! 
//! This library provides the core functionality for cryptographic notarization
//! of evidence packages in the AI-Ready Forensic Deployment Pipeline.

pub mod error;
pub mod evidence;
pub mod notary;
pub mod rekor;
pub mod vault;
pub mod config;

// Temporal workflow integration
pub mod temporal;

// AFDP-specific implementations  
pub mod afdp;

// REST API implementation
pub mod rest;

// gRPC server implementation
pub mod grpc;

// Apache Pulsar integration (requires Rust 1.85+ for compatibility)
// pub mod pulsar;

pub use error::{NotaryError, Result};
pub use evidence::{Actor, Artifact, EvidencePackage};
pub use notary::{NotaryClient, NotarizationReceipt, VaultRekorNotary};

// Re-export Temporal integration
pub use temporal::{TemporalNotaryClient, TemporalNotaryConfig};
pub use afdp::{AFDPEvidencePackage, AFDPWorkflows};

// Re-export server implementations
pub use rest::NotaryRestServer;
pub use grpc::NotaryGrpcServer;
// pub use pulsar::{PulsarConsumer, PulsarProducer, PulsarConfig};

// Re-export commonly used types
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;