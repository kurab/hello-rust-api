/*
 * Responsibility
 * - Config読み込み → 依存生成 → Router 組み立て
 * - Middleware の適用 (CORS/Bearer など)
 * - axum::serve() で起動
 */
use anyhow::Result;
use axum::{Router, routing::get};
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{api, config::Config, middleware, services::id_codec::IdCodec, state::AppState};

fn init_tracing() {
    // Prefer RUST_LOG if set; otherwise use a sensible default.
    // Ex:
    // RUST_LOG=info,hello_rust=debug,tower_http=debug cargo run
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,tower_http=info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

pub async fn run() -> Result<()> {
    init_tracing();

    let config = Config::from_env()?;
    tracing::info!(
        "starting API in {:?} mode on {}",
        config.app_env,
        config.addr
    );

    let state = build_state(&config).await?;

    let app = build_router(state, &config);

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

    let id_codec = IdCodec::new(config.sqids_min_length, &config.sqids_alphabet)?;

    Ok(AppState::new(db, id_codec))
}

/**
 * AppState: owned (move)
 */
fn build_router(state: AppState, config: &Config) -> Router {
    let router = Router::new()
        .route("/health", get(api::health::health))
        .nest("/api/v1", api::v1::routes())
        .with_state(state);

    // Cross-cutting middleware (policy/infrastructure)
    let router = middleware::security_headers::apply(router);
    let router = middleware::cors::apply(router, config);

    middleware::http::apply(router)
}
