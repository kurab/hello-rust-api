/// Factory: build `AuthService` from application `Config`.
use std::sync::Arc;

use crate::config::Config;
use crate::error::AppError;
use crate::services::auth::AuthService;
pub fn build_auth_service(config: &Config) -> Result<Arc<AuthService>, AppError> {
    let auth = AuthService::new(
        &config.access_jwt_public_key_pem,
        &config.auth_issuer,
        &config.auth_audience,
        config.access_token_leeway_seconds,
    )
    .map_err(|_| AppError::Internal)?;

    Ok(Arc::new(auth))
}
