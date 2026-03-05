use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{Value as JsonValue, from_slice};
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin, sync::Arc};
use tracing::{debug, error};
use uuid::Uuid;

use crate::error::AppError;
use crate::repos::auth_session_repo::AuthSessionRepo;
use crate::repos::refresh_token_repo::{RefreshTokenRepo, RefreshTokenRow};
use crate::services::auth::dpop::verifier::DpopVerifier;

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

    fn bind_dpop_jkt_if_empty(
        &self,
        session_id: Uuid,
        jkt: String,
        now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<(), AppError>>;
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

    fn bind_dpop_jkt_if_empty(
        &self,
        session_id: Uuid,
        jkt: String,
        now: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<(), AppError>> {
        Box::pin(async move {
            AuthSessionRepo::bind_dpop_jkt_if_empty(self, session_id, jkt, now)
                .await
                .map_err(|e| {
                    error!(session_id = %session_id, error = ?e, "Failed to bind dpop_jkt (BOFU)");
                    AppError::Internal
                })?;
            Ok(())
        })
    }
}

#[derive(Clone)]
pub struct RefreshTokenService {
    repo: Arc<RefreshTokenRepo>,
    sessions: Arc<dyn SessionLookup>,
    // Optional in Step1, Set in Step2+ to enforce DPoP binding on refresh.
    dpop_verifier: Option<Arc<DpopVerifier>>,
    ttl_seconds: u64,
}

impl std::fmt::Debug for RefreshTokenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshTokenService")
            .field("has_dpop_verifier", &self.dpop_verifier.is_some())
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
            dpop_verifier: None,
            ttl_seconds,
        }
    }

    // Enable DPoP verification for refresh flows (Step2+).
    pub fn with_dpop_verifier(mut self, verifier: Arc<DpopVerifier>) -> Self {
        self.dpop_verifier = Some(verifier);
        self
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
    /// Step2+: This requires a valid DPoP proof for this request and enforces the
    /// session-bound DPoP key binding (cnf.jkt).
    pub async fn validate_refresh_token(
        &self,
        refresh_token: &str,
        now: DateTime<Utc>,
        dpop_proof: &str,
        method: &str,
        url: &str,
    ) -> Result<Option<ValidatedRefreshToken>, AppError> {
        let row_opt = self.find_active_by_token(refresh_token, now).await?;

        let row = match row_opt {
            Some(r) => r,
            None => {
                debug!(now = %now, "Refresh token not found or inactive");
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

        // Step2+: enforce DPoP binding on refresh.
        // - We expect the session to have a bound `jkt`.
        // - We expect the caller to present a valid DPoP proof for this refresh request.
        // - The proof's JWK thumbprint must match the stored `jkt`.
        match (&self.dpop_verifier, &jkt) {
            (Some(verifier), Some(expected_jkt)) => {
                // Verify the DPoP proof and enforce the expected JWK thumbprint (jkt).
                verifier
                    // Refresh requests do not carry an access token, so `ath` is not applicable.
                    .verify_proof(
                        dpop_proof,
                        method,
                        url,
                        None,
                        Some(expected_jkt.as_str()),
                        now,
                    )
                    .map_err(|e| {
                        error!(
                            session_id = %row.session_id,
                            error = ?e,
                            "DPoP proof verification failed for refresh"
                        );
                        AppError::Internal
                    })?;
            }

            (Some(verifier), None) => {
                // Bind-on-first-use (BOFU): verify proof, then bind the proof's JWK thumbprint to the session.
                let presented_jkt = presented_jkt_from_dpop_proof(dpop_proof)?;

                verifier
                    .verify_proof(
                        dpop_proof,
                        method,
                        url,
                        None,
                        Some(presented_jkt.as_str()),
                        now,
                    )
                    .map_err(|e| {
                        error!(
                            session_id = %row.session_id,
                            error = ?e,
                            "DPoP proof verification failed for refresh (BOFU)"
                        );
                        AppError::Internal
                    })?;

                // Try to bind; then re-read to confirm we didn't race or bind a different key.
                self.sessions
                    .bind_dpop_jkt_if_empty(row.session_id, presented_jkt.clone(), now)
                    .await?;

                let after = self
                    .sessions
                    .get_user_and_jkt_by_session_id(row.session_id)
                    .await?;

                let (_, bound_jkt) = match after {
                    Some(v) => v,
                    None => return Ok(None),
                };

                match bound_jkt {
                    Some(b) if b == presented_jkt => {
                        // Update local jkt so the returned ValidatedRefreshToken carries it.
                        // (We shadow `jkt` by returning with `Some(...)` below.)
                        return Ok(Some(ValidatedRefreshToken {
                            user_id,
                            session_id: row.session_id,
                            jkt: Some(presented_jkt),
                        }));
                    }
                    _ => {
                        debug!(session_id = %row.session_id, "BOFU binding mismatch");
                        return Ok(None);
                    }
                }
            }

            (None, _) => {
                // Misconfiguration: validate_refresh_token in Step2+ requires DPoP verification.
                error!(
                    session_id = %row.session_id,
                    "DPoP verifier is not configured (expected in Step2+)"
                );
                return Err(AppError::Internal);
            }
        }

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

fn presented_jkt_from_dpop_proof(dpop_proof: &str) -> Result<String, AppError> {
    // Parse JWT header (first segment) and compute RFC7638 thumbprint for OKP/Ed25519.
    let header_b64 = dpop_proof.split('.').next().ok_or(AppError::Internal)?;

    let header_json = URL_SAFE_NO_PAD.decode(header_b64).map_err(|e| {
        error!(error = ?e, "Failed to base64url-decode DPoP header");
        AppError::Internal
    })?;

    let v: JsonValue = from_slice(&header_json).map_err(|e| {
        error!(error = ?e, "Failed to parse DPoP header JSON");
        AppError::Internal
    })?;

    let jwk = v.get("jwk").ok_or_else(|| {
        error!("DPoP header missing jwk");
        AppError::Internal
    })?;

    let kty = jwk.get("kty").and_then(|x| x.as_str()).ok_or_else(|| {
        error!("DPoP jwk missing/invalid kty");
        AppError::Internal
    })?;

    let crv = jwk.get("crv").and_then(|x| x.as_str()).ok_or_else(|| {
        error!("DPoP jwk missing/invalid crv");
        AppError::Internal
    })?;

    let x = jwk.get("x").and_then(|x| x.as_str()).ok_or_else(|| {
        error!("DPoP jwk missing/invalid x");
        AppError::Internal
    })?;

    // We only support OKP/Ed25519 for now.
    if kty != "OKP" || crv != "Ed25519" {
        debug!(kty = %kty, crv = %crv, "Unsupported JWK for DPoP");
        return Err(AppError::Internal);
    }

    // Validate x is base64url (decode succeeds).
    URL_SAFE_NO_PAD.decode(x).map_err(|e| {
        error!(error = ?e, "Invalid base64url in jwk.x");
        AppError::Internal
    })?;

    // FRC7638 canonical JSON with lexicographically sorted member names.
    let canonical = format!(
        "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\"}}",
        crv, kty, x
    );

    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

fn generate_refresh_token() -> String {
    // 32 bytes of entropy -> URL-safe base64 without padding.
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("getrandom failed");

    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_refresh_token(token: &str) -> Vec<u8> {
    // sha256(token) -> raw 32 bytes (stored as BYTEA)
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}
