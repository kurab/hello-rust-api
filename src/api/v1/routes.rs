/*
 * Responsibility
 * - v1 の URL 構造を定義
 * - /health, /users, /posts, /bookmarks を next/merge
 * - Bearer が必要な範囲を route_layer などで適用する設計もここで決める
 */
use axum::{Router, routing::get};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/health", get(crate::api::v1::handlers::health::health))
}
