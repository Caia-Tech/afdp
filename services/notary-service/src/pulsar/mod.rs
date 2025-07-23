//! Apache Pulsar integration for AFDP Notary Service
//!
//! This module provides event streaming capabilities using Apache Pulsar,
//! enabling the notary service to:
//!
//! - Consume events from AI deployment pipelines
//! - Automatically trigger notarization workflows
//! - Publish notarization results and status updates
//! - Integrate with existing event-driven architectures
//!
//! # Architecture
//!
//! The Pulsar integration follows an event-driven pattern:
//!
//! ```text
//! AI Pipeline → Pulsar Topic → Notary Consumer → Temporal Workflow → Pulsar Topic
//!     ↓              ↓              ↓                ↓                  ↓
//! Event Data → afdp.events → Auto Processing → Signing/Approval → afdp.results
//! ```
//!
//! # Topics
//!
//! - `afdp.pipeline.events`: Incoming events from AI deployment pipeline
//! - `afdp.notary.results`: Notarization results and receipts
//! - `afdp.notary.status`: Workflow status updates and notifications
//! - `afdp.notary.errors`: Error events and processing failures
//!
//! # Message Formats
//!
//! All messages use JSON encoding with standardized schemas for interoperability
//! across different components of the AFDP ecosystem.

pub mod consumer;
pub mod producer;
pub mod config;
pub mod messages;
pub mod handlers;

pub use consumer::PulsarConsumer;
pub use producer::PulsarProducer;
pub use config::PulsarConfig;
pub use messages::{
    PipelineEvent, NotaryResult, NotaryStatus, NotaryError,
    EventType, WorkflowStatusUpdate,
};
pub use handlers::{EventHandler, DefaultEventHandler};