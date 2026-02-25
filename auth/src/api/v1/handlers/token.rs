use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub sub: String,         // UUID (string)
    pub jkt: Option<String>, // cnf.jkt later
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

pub async fn issue_token(
    State(state): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> Result<(StatusCode, Json<TokenResponse>), AppError> {
    let token = state.auth.issue_access_token(&req.sub, req.jkt)?;

    Ok((
        StatusCode::OK,
        Json(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: state.auth.access_token_ttl_seconds(),
        }),
    ))
}
