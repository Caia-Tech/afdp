use anyhow::Result;
use crate::config::TemporalConfig;

#[derive(Clone)]
pub struct TemporalClient {
    config: TemporalConfig,
}

impl TemporalClient {
    pub async fn new(config: TemporalConfig) -> Result<Self> {
        // TODO: Connect to Temporal server
        Ok(Self { config })
    }

    pub async fn start_workflow(&self, workflow_id: &str, params: serde_json::Value) -> Result<String> {
        // TODO: Start Temporal workflow
        Ok(workflow_id.to_string())
    }

    pub async fn get_workflow_status(&self, workflow_id: &str) -> Result<WorkflowStatus> {
        // TODO: Get workflow status
        Ok(WorkflowStatus::Running)
    }
}

#[derive(Debug, Clone)]
pub enum WorkflowStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}