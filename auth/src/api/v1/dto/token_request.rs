use serde::Deserialize;
use uuid::Uuid;

/// Request body for `/token`.
///
/// We keep a single endpoint and branch by `grant_type`.
///
/// - Issue (default): omit `grant_type` (or set it to a non-refresh value)
///   and provide `sub` (+ optional `jkt`).
/// - Refresh: set `grant_type` to `"refresh_token"` and provide `refresh_token`.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    /// OAuth2-style grant type.
    ///
    /// When `Some("refresh_token")`, this request is treated as a refresh request.
    /// Otherwise, it's treated as an issue request.
    pub grant_type: Option<String>,

    /// Subject (user id). Required for issuing a new access token.
    pub sub: Option<Uuid>,

    /// Optional cnf.jkt for sender-constrained access tokens.
    pub jkt: Option<String>,

    /// Opaque refresh token. Required when `grant_type == "refresh_token"`.
    pub refresh_token: Option<String>,
}
