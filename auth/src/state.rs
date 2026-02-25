use std::sync::Arc;

use crate::services::auth::token_issuer::AuthService;

#[derive(Clone)]
pub struct AppState {
    pub auth: Arc<AuthService>,
}

impl AppState {
    pub fn new(auth: Arc<AuthService>) -> Self {
        Self { auth }
    }
}
