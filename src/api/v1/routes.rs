/*
 * Responsibility
 * - v1 の URL 構造を定義
 * - /health, /users, /posts, /bookmarks を next/merge
 * - Bearer が必要な範囲を route_layer などで適用する設計もここで決める
 */
use axum::{Router, routing::get};

use crate::state::AppState;

use crate::api::v1::handlers::{
    health::health,
    users::{create_user, delete_user, get_user, list_users, update_user},
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/users", get(list_users).post(create_user))
        .route(
            "/users/{user_id}",
            get(get_user).put(update_user).delete(delete_user),
        )
}
