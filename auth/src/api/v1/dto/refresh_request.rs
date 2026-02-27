use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RefreshRequest {
    /// OAuth2-style grant type. Must be "refresh_token".
    pub grant_type: String,
    pub refresh_token: String,
}
