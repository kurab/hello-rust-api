use axum::Json;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};

use crate::api::v1::dto::{token_request::TokenRequest, token_response::TokenResponse};
use crate::error::AppError;
use crate::state::AppState;

pub async fn token(
    State(state): State<AppState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Json(req): Json<TokenRequest>,
) -> Result<(StatusCode, Json<TokenResponse>), AppError> {
    match req.grant_type.as_deref() {
        Some("refresh_token") => {
            let refresh_token = req.refresh_token.ok_or(AppError::Internal)?;

            // DPoP header
            let dpop = headers
                .get("DPoP")
                .and_then(|v| v.to_str().ok())
                .ok_or(AppError::Unauthorized)?;

            let url = uri.to_string();
            let out = state
                .auth
                .refresh(&refresh_token, dpop, method.as_str(), &url)
                .await?;

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
            // Issue access token + refresh token (DPoP-bound session from the start)
            let sub = req.sub.ok_or(AppError::Internal)?;

            // DPoP header (required)
            let dpop = headers
                .get("DPoP")
                .and_then(|v| v.to_str().ok())
                .ok_or(AppError::Unauthorized)?;

            let url = uri.to_string();
            let out = state
                .auth
                .issue_token_pair(sub, dpop, method.as_str(), &url)
                .await?;

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
