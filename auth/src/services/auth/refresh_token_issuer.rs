use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin, sync::Arc};
use tracing::{debug, error};
use uuid::Uuid;

use crate::error::AppError;
use crate::repos::auth_session_repo::AuthSessionRepo;
use crate::repos::refresh_token_repo::{RefreshTokenRepo, RefreshTokenRow};

/// Service-layer representation of a refresh token that has been validated
/// and enriched with the data required to mint a new access token.
///
/// NOTE: This type is intentionally decoupled from DB schema (RefreshTokenRow)
#[derive(Clone, Debug)]
pub struct ValidatedRefreshToken {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub jkt: Option<String>,
}

type SessionUserAndJkt = Option<(Uuid, Option<String>)>;
type SessionLookupOutput = Result<SessionUserAndJkt, AppError>;
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Minimal lookup interface for resolving session-bound data.
///
/// Step1 (no DPoP binding): implementations may return Ok(None) for jkt
/// Step2/3: implementations should return the bound jkt stored for the session.
pub trait SessionLookup: Send + Sync {
    fn get_user_and_jkt_by_session_id(
        &self,
        session_id: Uuid,
    ) -> BoxFuture<'_, SessionLookupOutput>;
}

impl SessionLookup for AuthSessionRepo {
    fn get_user_and_jkt_by_session_id(
        &self,
        session_id: Uuid,
    ) -> BoxFuture<'_, SessionLookupOutput> {
        Box::pin(async move {
            let ctx_opt = self.lookup_refresh_context(session_id).await.map_err(|e| {
                error!(session_id = %session_id, error = %e, "Failed to lookup refresh context");
                AppError::Internal
            })?;
            Ok(ctx_opt.map(|c| (c.user_id, c.dpop_jkt)))
        })
    }
}

#[derive(Clone)]
pub struct RefreshTokenService {
    repo: Arc<RefreshTokenRepo>,
    sessions: Arc<dyn SessionLookup>,
    ttl_seconds: u64,
}

impl std::fmt::Debug for RefreshTokenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenService")
            .field("ttl_seconds", &self.ttl_seconds)
            .finish()
    }
}

impl RefreshTokenService {
    pub fn new(
        repo: Arc<RefreshTokenRepo>,
        sessions: Arc<dyn SessionLookup>,
        ttl_seconds: u64,
    ) -> Self {
        Self {
            repo,
            sessions,
            ttl_seconds,
        }
    }

    /// Issue a new refresh token for (user_id, session_id) and store it.
    ///
    /// Returns the opaque refresh token string.
    pub async fn issue_refresh_token(&self, session_id: Uuid) -> Result<String, AppError> {
        let refresh_token = generate_refresh_token();
        let token_hash = hash_refresh_token(&refresh_token);

        let expires_at = Utc::now() + ChronoDuration::seconds(self.ttl_seconds as i64);

        debug!(
            session_id = %session_id,
            ttl_seconds = self.ttl_seconds,
            expires_at = %expires_at,
            "Issuing refresh token"
        );

        self.repo
            .insert(session_id, token_hash, expires_at)
            .await
            .map_err(|e| {
                error!(
                    session_id = %session_id,
                    error = ?e,
                    "Failed to insert refresh token"
                );
                AppError::Internal
            })?;

        Ok(refresh_token)
    }

    /// Validate the presented refresh token and return the data required for refresh.
    ///
    /// - Verifies the token exists and is active (not expired/revoked)
    /// - Resolves user_id and optional jkt from the session
    pub async fn validate_refresh_token(
        &self,
        refresh_token: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ValidatedRefreshToken>, AppError> {
        let row_opt = self.find_active_by_token(refresh_token, now).await?;

        let row = match row_opt {
            Some(r) => r,
            None => {
                debug!("Refresh token not found or inactive");
                return Ok(None);
            }
        };

        let sess_opt = self
            .sessions
            .get_user_and_jkt_by_session_id(row.session_id)
            .await?;

        let (user_id, jkt) = match sess_opt {
            Some(v) => v,
            None => {
                // Token exists but session is missing/inactive -> treat as invalid.
                debug!(session_id = %row.session_id, "Session not found for refresh token");
                return Ok(None);
            }
        };

        Ok(Some(ValidatedRefreshToken {
            user_id,
            session_id: row.session_id,
            jkt,
        }))
    }

    /// Look up an active refresh token by the raw token.
    ///
    /// This is intended for the refresh endpoint to validate presented tokens.
    pub async fn find_active_by_token(
        &self,
        refresh_token: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<RefreshTokenRow>, AppError> {
        let token_hash = hash_refresh_token(refresh_token);

        debug!(now = %now, "Looking up refresh token");

        self.repo
            .find_active_by_hash(token_hash, now)
            .await
            .map_err(|e| {
                error!(error = ?e, now = %now, "Failed to find refresh token");
                AppError::Internal
            })
    }

    /// Revoke a refresh token by the raw token.
    pub async fn revoke_by_token(
        &self,
        refresh_token: &str,
        revoked_at: DateTime<Utc>,
    ) -> Result<u64, AppError> {
        let now = revoked_at;
        let row_opt = self.find_active_by_token(refresh_token, now).await?;

        let row = match row_opt {
            Some(r) => r,
            None => {
                debug!("Refresh token not found or already inactive");
                return Ok(0);
            }
        };

        debug!(id = %row.id, session_id = %row.session_id, revoked_at = %revoked_at, "Revoking refresh token");

        self.repo
            .revoke(row.id, None, revoked_at)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to revoke refresh token");
                AppError::Internal
            })
    }
}

fn generate_refresh_token() -> String {
    // 32 bytes of entropy -> URL-safe base64 without padding.
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("getrandom failed");

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_refresh_token(token: &str) -> Vec<u8> {
    // sha256(token) -> raw 32 bytes (stored as BYTEA)
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}
