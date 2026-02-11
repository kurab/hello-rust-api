use axum::extract::FromRequestParts;
use axum::http::{StatusCode, request::Parts};

use crate::state::AppState;

use super::AuthCtx;

/// Handler で、 AuthCtx を受け取るための extractor
/// middleware が AuthCtx を request.extensions() に insert 済みである前提
/// 見つからない場合は 401 を返す（認証がかかってない・ミドルウェア未設定）
pub struct AuthCtxExtractor(pub AuthCtx);

impl FromRequestParts<AppState> for AuthCtxExtractor
where
    AppState: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthCtx>()
            .cloned()
            .map(AuthCtxExtractor)
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}
