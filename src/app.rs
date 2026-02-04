/*
 * Responsibility
 * - Config読み込み → 依存生成 → Router 組み立て
 * - Middleware の適用 (CORS/Bearer など)
 * - axum::serve() で起動
 */
use anyhow::Result;
use axum::Router;
use sqlx::postgres::PgPoolOptions;

use crate::{api, config::Config, state::AppState};

pub async fn run() -> Result<()> {
    let config = Config::from_env()?;
    let state = build_state(&config).await?;

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/**
 * Config: immutable reference (borrow)
 */
async fn build_state(config: &Config) -> Result<AppState> {
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    Ok(AppState::new(db))
}

/**
 * AppState: owned (move)
 */
fn build_router(state: AppState) -> Router {
    Router::new()
        .nest("/api/v1", api::v1::routes())
        .with_state(state)
}
