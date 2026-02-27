use chrono::{DateTime, Utc};
use tracing::error;
use uuid::Uuid;

use crate::error::AppError;
use crate::repos::auth_session_repo::AuthSessionRepo;
use crate::services::auth::{
    access_token_issuer::AccessTokenService, refresh_token_issuer::RefreshTokenService,
};

/// Service that orchestrates access-token issuance and refresh-token issuance/rotation.
///
/// - AccessTokenService is responsible for JWT issuance (access tokens).
/// - RefreshTokenService is responsible for opaque refresh token issuance/rotation and DB persistence.
#[derive(Clone)]
pub struct TokenService {
    access_issuer: AccessTokenService,
    refresh_issuer: RefreshTokenService,
    auth_session_repo: AuthSessionRepo,
}

impl TokenService {
    pub fn new(
        access_issuer: AccessTokenService,
        refresh_issuer: RefreshTokenService,
        auth_session_repo: AuthSessionRepo,
    ) -> Self {
        Self {
            access_issuer,
            refresh_issuer,
            auth_session_repo,
        }
    }

    /// Issue a new token pair for an authenticated subject.
    ///
    /// This creates a new session_id, issues an access token, and issues a refresh token bound to
    /// that session.
    pub async fn issue_token_pair(
        &self,
        sub: Uuid,
        jkt: Option<String>,
    ) -> Result<IssuedTokenPair, AppError> {
        //let session_id = Uuid::new_v4();
        let session = self
            .auth_session_repo
            .create(sub, None)
            .await
            .map_err(|e| {
                error!(user_id = %sub, error = %e, "Failed to create auth session");
                AppError::Internal
            })?;
        let session_id = session.id;

        // Access token (JWT)
        let access_token = self
            .access_issuer
            .issue_access_token(&sub.to_string(), jkt)
            .await?;

        // Refresh token (opaque)
        let refresh_token = self.refresh_issuer.issue_refresh_token(session_id).await?;

        Ok(IssuedTokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer",
            expires_in: self.access_issuer.access_token_ttl_seconds(),
            session_id,
        })
    }

    /// Refresh an access token using a refresh token.
    ///
    /// Step 1 (minimal refresh / no DPoP binding):
    /// - validate the refresh token (active + not expired + not revoked)
    /// - issue a new access token for the same subject
    /// - return the same refresh token (no rotation yet; rotation is step 3)
    pub async fn refresh(&self, refresh_token: &str) -> Result<IssuedTokenPair, AppError> {
        // NOTE:
        // RefreshTokenService must provide validate_refresh_token that returns the
        // subject and session_id bound to this refresh token.
        let now: DateTime<Utc> = Utc::now();

        let v = self
            .refresh_issuer
            .validate_refresh_token(refresh_token, now)
            .await?
            .ok_or(AppError::Unauthorized)?;

        // Access token (JWT)
        let access_token = self
            .access_issuer
            .issue_access_token(&v.user_id.to_string(), v.jkt)
            .await?;

        Ok(IssuedTokenPair {
            access_token,
            refresh_token: refresh_token.to_string(),
            token_type: "Bearer",
            expires_in: self.access_issuer.access_token_ttl_seconds(),
            session_id: v.session_id,
        })
    }
}

/// Service-level return type to keep handlers thin.
///
/// Handlers can map this into the HTTP DTO (TokenResponse).
#[derive(Clone, Debug)]
pub struct IssuedTokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub session_id: Uuid,
}

/// Return type for refresh rotation.
///
/// RefreshTokenService::rotate should return this.
#[derive(Clone, Debug)]
pub struct RotatedRefreshToken {
    pub refresh_token: String,
    pub session_id: Uuid,
    pub sub: String,

    // Reserved for later steps (DPoP-bound refresh, etc.).
    pub jkt: Option<String>,
}
