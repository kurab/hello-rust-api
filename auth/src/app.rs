use axum::{Router, routing::get};
use std::{panic, process, sync::Arc};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::api;
use crate::config::Config;
use crate::error::AppError;
use crate::services::auth::{jwt::JwtIssuer, token_issuer::AuthService};
use crate::state::AppState;

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

pub async fn run() -> Result<(), AppError> {
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
    let listener = tokio::net::TcpListener::bind(config.addr)
        .await
        .map_err(|_| AppError::Internal)?;
    axum::serve(listener, app)
        .await
        .map_err(|_| AppError::Internal)?;

    Ok(())
}

async fn build_state(config: &Config) -> Result<AppState, AppError> {
    // Build process-level services here and inject them into the shared application state.
    // JwtIssuer signs access/refresh tokens using AS private key.
    let jwt = JwtIssuer::new(
        &config.access_jwt_private_key_pem,
        config.issuer.clone(),
        config.audience.clone(),
        config.access_token_ttl_seconds,
    )?;

    let auth = Arc::new(AuthService::new(jwt));

    Ok(AppState::new(auth))
}

fn build_router(state: AppState, config: &Config) -> Router {
    async fn health() -> &'static str {
        "ok"
    }

    let router = Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api::v1::routes(state.clone()))
        .with_state(state);

    router
}
