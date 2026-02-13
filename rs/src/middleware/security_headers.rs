//! Security-related response headers for browser clients.
//!
//! This middleware is intended to be applied at the Router level
//! (not inside individual handlers).
//!
//! Responsibility:
//! - Clickjacking protection
//! - MIME sniffing protection
//! - Referrer leakage control
//! - Browser feature restrictions
//!
//! This is intentionally configuration-free for now.
//! If needed later, it can be extended to accept Config.

use axum::Router;
use axum::http::header::{HeaderName, HeaderValue};
use tower_http::set_header::SetResponseHeaderLayer;

/// Apply common security headers to all responses.
///
/// This function returns a new Router with header-setting layers applied.
/// Keeping this logic here allows `app.rs` to stay clean and
/// makes future scaffolding trivial.
pub fn apply(router: Router) -> Router {
    router
        // Clickjacking protection (legacy + modern)
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("frame-ancestors 'none'"),
        ))
        // Prevent MIME sniffing
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        // Limit referrer leakage
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        // Disable powerful browser features by default
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ))
}
