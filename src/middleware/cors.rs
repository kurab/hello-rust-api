//! CORS policy for browser clients.
//!
//! Note:
//! - CORS is enforced by browsers. Native mobile apps and server-to-server calls are not
//!   restricted by CORS.
//! - This middleware should be applied at the Router level (not inside handlers).
//!
//! Responsibility:
//! - Provide a consistent CORS policy for this API.
//! - Keep `app.rs` clean and scaffolding-friendly.
//!
//! Policy:
//! - Development: permissive (Allow-Origin: *), WITHOUT credentials.
//! - Production: allowlist origins from Config (comma-separated env var), WITHOUT credentials.

use axum::Router;
use axum::http::{HeaderName, HeaderValue, Method, header};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use crate::config::Config;

/// Apply CORS policy to the given Router.
///
/// IMPORTANT:
/// - Do not combine wildcard origin (`Any`) with `allow_credentials(true)`.
pub fn apply(router: Router, config: &Config) -> Router {
    let cors = if config.app_env.is_production() {
        // Production: allow only configured origins (exact match).
        // If the allowlist is empty, we intentionally allow none (no CORS headers),
        // which is safer than accidentally allowing all.
        let allowed: Vec<HeaderValue> = config
            .cors_allowed_origins
            .iter()
            .filter_map(|s| HeaderValue::from_str(s).ok())
            .collect();

        let allow_origin = AllowOrigin::predicate(move |origin: &HeaderValue, _req| {
            allowed.iter().any(|v| v == origin)
        });

        CorsLayer::new().allow_origin(allow_origin)
    } else {
        // Development: permissive (no credentials)
        CorsLayer::new().allow_origin(Any)
    }
    .allow_methods([
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ])
    .allow_headers([
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::ACCEPT,
        HeaderName::from_static("x-request-id"),
    ])
    .max_age(std::time::Duration::from_secs(60 * 10));

    router.layer(cors)
}
