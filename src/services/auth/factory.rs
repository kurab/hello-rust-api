use std::convert::TryFrom;
/// Factory: build `AuthService` from application `Config`.
use std::sync::Arc;

use crate::config::Config;
use crate::error::AppError;
use crate::services::auth::AuthService;
use crate::services::auth::dpop::core::DpopPolicy;

fn u64_to_i64(v: u64) -> Result<i64, AppError> {
    i64::try_from(v).map_err(|_| AppError::Internal)
}

pub fn build_auth_service(config: &Config) -> Result<Arc<AuthService>, AppError> {
    let iat_leeway_seconds = u64_to_i64(config.dpop_iat_leeway_seconds)?;
    let max_age_seconds = u64_to_i64(config.dpop_max_age_seconds)?;

    let dpop_policy = DpopPolicy {
        required: config.dpop_required,
        iat_leeway_seconds,
        max_age_seconds,
        require_ath: config.dpop_required_ath,
        require_nonce: config.dpop_require_nonce,
    };

    let auth = AuthService::new(
        &config.access_jwt_public_key_pem,
        &config.auth_issuer,
        &config.auth_audience,
        config.access_token_leeway_seconds,
        dpop_policy,
        config.public_base_url.clone(),
    )
    .map_err(|_| AppError::Internal)?;

    Ok(Arc::new(auth))
}
