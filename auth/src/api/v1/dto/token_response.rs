use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    /// Usually "Bearer"
    pub token_type: String,
    /// Seconds until expiry.
    pub expires_in: u64,

    /// Present when the server returns a refresh token.
    pub refresh_token: String,

    /// Present when the server chooses to retrun a session id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
}
