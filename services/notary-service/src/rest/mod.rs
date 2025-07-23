//! REST API implementation for AFDP Notary Service

pub mod server;
pub mod handlers;
pub mod models;

pub use server::NotaryRestServer;