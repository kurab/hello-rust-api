//! HTTP-level middleware (cross-cutting concerns).
//!
//! This module is for transport/infrastructure concerns that should apply to
//! most (or all) routes, regardless of API version.
//!
//! Responsibility:
//! - Request-Id generation + propagation (X-Request-Id)
//! - Access logging / request tracing (TraceLayer)
//! - Body size limits
//! - Global timeouts
//!
//! Notes:
//! - Defaults are intentionally conservative for production-ish behavior.
//! - Later, we can make these configurable via `Config` without changing call sites.

use std::time::Duration;

use axum::Router;
use axum::error_handling::HandleErrorLayer;
use axum::http::{StatusCode, header::HeaderName};
use tower::timeout::TimeoutLayer;
use tower::{BoxError, ServiceBuilder};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

/// Apply HTTP-level middleware to the given Router.
///
/// Defaults:
/// - Request-Id header: `x-request-id`
/// - Body limit: 1 MiB
/// - Timeout: 30 seconds
pub fn apply(router: Router) -> Router {
    let request_id_header = HeaderName::from_static("x-request-id");

    let layers = ServiceBuilder::new()
        // Make the service error `Infallible` by converting errors into responses.
        .layer(HandleErrorLayer::new(|err: BoxError| async move {
            if err.is::<tower::timeout::error::Elapsed>() {
                StatusCode::REQUEST_TIMEOUT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }))
        // Generate a request id if missing, then propagate it to the response.
        .layer(SetRequestIdLayer::new(
            request_id_header.clone(),
            MakeRequestUuid,
        ))
        .layer(PropagateRequestIdLayer::new(request_id_header))
        // Limit request body size (protects against accidental/hostile large payloads).
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        // Bound request time (protects against hanging upstreams / slow clients).
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        // Access log / tracing for all requests.
        .layer(TraceLayer::new_for_http());

    router.layer(layers)
}
