use chrono::{DateTime, Utc};
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use crate::error::AppError;
use crate::repos::auth_session_repo::AuthSessionRepo;
use crate::services::auth::{
    access_token_issuer::AccessTokenService, dpop::verifier::DpopVerifier,
    refresh_token_issuer::RefreshTokenService,
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
    dpop_verifier: Arc<DpopVerifier>,
}

impl TokenService {
    pub fn new(
        access_issuer: AccessTokenService,
        refresh_issuer: RefreshTokenService,
        auth_session_repo: AuthSessionRepo,
        dpop_verifier: Arc<DpopVerifier>,
    ) -> Self {
        Self {
            access_issuer,
            refresh_issuer,
            auth_session_repo,
            dpop_verifier,
        }
    }

    /// Issue a new token pair for an authenticated subject.
    ///
    /// This creates a new session_id, issues an access token, and issues a refresh token bound to
    /// that session.
    pub async fn issue_token_pair(
        &self,
        sub: Uuid,
        dpop_proof: &str,
        method: &str,
        url: &str,
    ) -> Result<IssuedTokenPair, AppError> {
        if dpop_proof.trim().is_empty() {
            return Err(AppError::Unauthorized);
        }

        let now: DateTime<Utc> = Utc::now();
        let verified = self
            .dpop_verifier
            .verify_proof(dpop_proof, method, url, None, None, now)
            .map_err(|e| {
                error!(user_id = %sub, error = ?e, "DPoP proof verification failed (issue)");
                AppError::Unauthorized
            })?;

        // Issue-side: bind jkt immediately (no BOFU).
        let jkt = verified.jkt;

        let session = self
            .auth_session_repo
            .create(sub, Some(jkt))
            .await
            .map_err(|e| {
                error!(user_id = %sub, error = %e, "Failed to create auth session");
                AppError::Internal
            })?;
        let session_id = session.id;

        // Access token (JWT)
        let access_token = self
            .access_issuer
            .issue_access_token(&sub.to_string(), session.dpop_jkt.clone())
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
    /// Step 2 (DPoP-bound refresh):
    /// - validate the refresh token (active + not expired + not revoked)
    /// - (later) verify the DPoP proof and enforce binding (session.dpop_jkt)
    /// - issue a new access token for the same subject
    /// - return the same refresh token (no rotation yet; rotation is step 3)
    pub async fn refresh(
        &self,
        refresh_token: &str,
        dpop_proof: &str,
        method: &str,
        url: &str,
    ) -> Result<IssuedTokenPair, AppError> {
        let now: DateTime<Utc> = Utc::now();
        // Step2: require DPoP header to be present (full cryptographic verification is done later).
        if dpop_proof.trim().is_empty() {
            return Err(AppError::Unauthorized);
        }

        let v = self
            .refresh_issuer
            .validate_refresh_token(refresh_token, now, dpop_proof, method, url)
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
