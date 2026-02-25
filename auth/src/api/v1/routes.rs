use axum::{Router, routing::post};

use crate::api::v1::handlers::token::issue_token;
use crate::state::AppState;

pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/token", post(issue_token))
        .with_state(state)
}
