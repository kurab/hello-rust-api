use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use crate::api::v1::dto::{token_request::TokenRequest, token_response::TokenResponse};
use crate::error::AppError;
use crate::state::AppState;

pub async fn token(
    State(state): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> Result<(StatusCode, Json<TokenResponse>), AppError> {
    match req.grant_type.as_deref() {
        Some("refresh_token") => {
            // Minimal refresh (without DPoP)
            let refresh_token = req.refresh_token.ok_or(AppError::Internal)?;

            // Expected: TokenService validates the refresh token, issues a new access token,
            // and may optionally rotate the refresh token in later steps.
            let out = state.auth.refresh(&refresh_token).await?;

            Ok((
                StatusCode::OK,
                Json(TokenResponse {
                    access_token: out.access_token,
                    token_type: "Bearer".to_string(),
                    expires_in: out.expires_in,
                    refresh_token: out.refresh_token,
                    session_id: Some(out.session_id),
                }),
            ))
        }
        _ => {
            // Issue access token + refresh token (minimal refresh, no DPoP binding yet)
            let sub = req.sub.ok_or(AppError::Internal)?;
            let out = state.auth.issue_token_pair(sub, req.jkt).await?;

            Ok((
                StatusCode::OK,
                Json(TokenResponse {
                    access_token: out.access_token,
                    token_type: "Bearer".to_string(),
                    expires_in: out.expires_in,
                    refresh_token: out.refresh_token,
                    session_id: Some(out.session_id),
                }),
            ))
        }
    }
}
