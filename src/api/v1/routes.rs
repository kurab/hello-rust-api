/*
 * Responsibility
 * - v1 の URL 構造を定義
 * - /users, /posts, /bookmarks を next/merge
 * - Bearer が必要な範囲を route_layer などで適用する設計もここで決める
 */
use axum::{Router, routing::get};

use crate::api::v1::handlers::{posts, users};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        // users
        .route("/users", get(users::list_users).post(users::create_user))
        .route(
            "/users/{user_id}",
            get(users::get_user)
                .put(users::update_user)
                .delete(users::delete_user),
        )
        // posts
        .route("/posts", get(posts::list_posts).post(posts::create_post))
        .route(
            "/posts/{post_id}",
            get(posts::get_post)
                .put(posts::update_post)
                .delete(posts::delete_post),
        )
}
