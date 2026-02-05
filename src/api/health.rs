/*
 * Responsibility
 * - GET /health (疎通用)
 * - middleware を通す/通さない方針の確認用
 */
use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}
