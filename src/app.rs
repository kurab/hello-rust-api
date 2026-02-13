/*
 * Responsibility
 * - Config読み込み → 依存生成 → Router 組み立て
 * - Middleware の適用 (CORS/Bearer など)
 * - axum::serve() で起動
 */
use anyhow::Result;
use axum::{Router, routing::get};
use sqlx::postgres::PgPoolOptions;
use std::{panic, process};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    api,
    config::Config,
    middleware,
    services::{auth::build_auth_service, id_codec::IdCodec},
    state::AppState,
};

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

fn init_panic_hook(abort_on_panic: bool) {
    // Keep the default hook as a fallback (prints to stderr with location/palyload).
    let default_hook = panic::take_hook();

    panic::set_hook(Box::new(move |info| {
        // Always surface panic via tracing so they don't get "lost"
        // (stderr can be hidden depending on how the process is launched.)
        tracing::error!(?info, "panic");

        // In development, fail fast: crash the whole process so we notice immediately.
        // In production, prefer the default behavior (stderr) and let the server keep running.
        if abort_on_panic {
            process::abort();
        } else {
            default_hook(info);
        }
    }))
}

pub async fn run() -> Result<()> {
    init_tracing();

    let config = Config::from_env()?;

    // Decide behavior from config without assuming the exact enum/string shape.
    let abort_on_panic = !config.app_env.is_production();
    init_panic_hook(abort_on_panic);

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

    let auth = build_auth_service(config).await?;

    Ok(AppState::new(db, id_codec, auth))
}

/**
 * AppState: owned (move)
 */
fn build_router(state: AppState, config: &Config) -> Router {
    let router = Router::new()
        .route("/health", get(api::health::health))
        .nest("/api/v1", api::v1::routes(state.clone()))
        .with_state(state);

    // Cross-cutting middleware (policy/infrastructure)
    let router = middleware::security_headers::apply(router);
    let router = middleware::cors::apply(router, config);

    middleware::http::apply(router)
}
