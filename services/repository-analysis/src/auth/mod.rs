use anyhow::Result;
use crate::config::AuthConfig;
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthManager {
    config: AuthConfig,
}

impl AuthManager {
    pub async fn new(config: AuthConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn validate_token(&self, token: &str) -> Result<Claims> {
        // TODO: Implement JWT validation
        Ok(Claims {
            sub: "test-user".to_string(),
            exp: 0,
            permissions: vec![],
        })
    }

    pub async fn check_permission(&self, claims: &Claims, permission: &str) -> Result<bool> {
        // TODO: Implement permission checking
        Ok(true)
    }
}

#[derive(Debug, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub permissions: Vec<String>,
}