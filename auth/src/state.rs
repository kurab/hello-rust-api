use std::sync::Arc;

use crate::services::auth::token_service::TokenService;

#[derive(Clone)]
pub struct AppState {
    pub auth: Arc<TokenService>,
}

impl AppState {
    pub fn new(auth: Arc<TokenService>) -> Self {
        Self { auth }
    }
}
