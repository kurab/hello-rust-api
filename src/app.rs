/*
 * Responsibility
 * - Config読み込み → 依存生成 → Router 組み立て
 * - Middleware の適用 (CORS/Bearer など)
 * - axum::serve() で起動
 */
use anyhow::Result;
use axum::Router;

use crate::{api, config::Config, state::AppState};

pub async fn run() -> Result<()> {
    let config = Config::from_env()?;
    let state = AppState::new();

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .nest("/api/v1", api::v1::routes())
        .with_state(state)
}
