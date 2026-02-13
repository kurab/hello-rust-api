use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::{error::Error as StdError, fmt, sync::Arc};
use uuid::Uuid;

use crate::services::auth::dpop::core::DpopPolicy;
use crate::services::auth::replay::store::ReplayStore;

// Errors returned by access-token verification + strict claim validation.
#[derive(Debug)]
pub enum AccessJwtError {
    Jwt(jsonwebtoken::errors::Error),
    MissingOrInvalidAud,
    EmptyClaim(&'static str),
    InvalidSubUuid,
}

impl fmt::Display for AccessJwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Jwt(e) => write!(f, "jwt verification failed: {}", e),
            Self::MissingOrInvalidAud => write!(f, "missing or invalid 'aud' claim"),
            Self::EmptyClaim(name) => write!(f, "empty '{}' claim", name),
            Self::InvalidSubUuid => write!(f, "invalid 'sub' (expected UUID)"),
        }
    }
}

impl StdError for AccessJwtError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Jwt(e) => Some(e),
            _ => None,
        }
    }
}

impl From<jsonwebtoken::errors::Error> for AccessJwtError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Self::Jwt(e)
    }
}

fn aud_is_present_and_valid(aud: &serde_json::Value) -> bool {
    match aud {
        // Typical: aud is a string
        serde_json::Value::String(s) => !s.trim().is_empty(),
        // Also valid: aud is an array of strings
        serde_json::Value::Array(arr) => arr.iter().any(|v| match v {
            serde_json::Value::String(s) => !s.trim().is_empty(),
            _ => false,
        }),
        // Missing claim ends up as Null due to #[serde(default)]
        _ => false,
    }
}

/// Access token (JWT) claims.
///
/// NOTE:
/// - `aud` in JWT can be either string or array; jsonwebtoken validates it via `Validation::set_audience`.
/// - We keep `scope` (space-separated) and `roles` as optional for now.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    // Keep as Value to accept both string and array. Validation handles audience checks.
    #[serde(default)]
    pub aud: serde_json::Value,

    pub sub: String,
    pub exp: u64,

    #[serde(default)]
    pub nbf: Option<u64>,
    #[serde(default)]
    pub iat: Option<u64>,
    #[serde(default)]
    pub jti: Option<String>,

    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub roles: Option<Vec<String>>,

    #[serde(default)]
    pub cnf: Option<CnfClaim>,
}

/// AuthService が返す「検証済み・アプリ側で使う型」
///
/// - 'sub' はプロジェクト規約として UUID なので、ここでは `Uuid` に昇格させる
/// - `iss/aud/exp` の整合性は `verify_strict` の中（jsonwebtoken + 追加チェック）で保証される前提
#[derive(Debug, Clone)]
pub struct VerifiedAccessToken {
    pub user_id: Uuid,

    pub jti: Option<String>,
    pub scope: Option<String>,
    pub roles: Option<Vec<String>>,

    pub cnf_jkt: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CnfClaim {
    #[serde(default)]
    pub jkt: Option<String>,
}

/// EdDSA (Ed25519) access-token verifier.
///
/// - Key material is intentionally not printable via Debug.
#[derive(Clone)]
pub struct AuthService {
    decoding_key: DecodingKey,
    validation: Validation,
    dpop_policy: DpopPolicy,
    replay_store: Arc<dyn ReplayStore>,
    public_base_url: Option<String>,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not print key material
        f.debug_struct("AuthService")
            .field("validation", &self.validation)
            .field("dpop_policy", &self.dpop_policy)
            .finish()
    }
}

impl AuthService {
    pub fn new(
        access_public_key_pem: &str,
        issuer: &str,
        audience: &str,
        leeway_seconds: u64,
        dpop_policy: DpopPolicy,
        replay_store: Arc<dyn ReplayStore>,
        public_base_url: Option<String>,
    ) -> Result<Self, String> {
        let decoding_key = DecodingKey::from_ed_pem(access_public_key_pem.as_bytes())
            .map_err(|e| format!("invalid ed25519 public key pem: {}", e))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.leeway = leeway_seconds;

        Ok(Self {
            decoding_key,
            validation,
            dpop_policy,
            replay_store,
            public_base_url,
        })
    }

    // Verify and decode a JWT access token.
    pub fn verify(&self, token: &str) -> Result<AccessTokenClaims, jsonwebtoken::errors::Error> {
        let data =
            jsonwebtoken::decode::<AccessTokenClaims>(token, &self.decoding_key, &self.validation)?;

        Ok(data.claims)
    }

    /// Verify + strict claim validation.
    ///
    /// `jsonwebtoken::Validation` already checks:
    /// - signature
    /// - `exp` (unless disabled)
    /// - `iss` and `aud` (because we set them)
    ///
    /// This method additionally checks:
    /// - required claims are present *and not empty* (`iss`, `aud`, `sub`, `exp`)
    pub fn verify_strict(&self, token: &str) -> Result<AccessTokenClaims, AccessJwtError> {
        let claims = self.verify(token)?;

        // Required (non-empty) checks. `exp` is `u64` so serde guarantees presence,
        // but we still defend against a meaningless value.
        if claims.iss.trim().is_empty() {
            return Err(AccessJwtError::EmptyClaim("iss"));
        }
        if claims.sub.trim().is_empty() {
            return Err(AccessJwtError::EmptyClaim("sub"));
        }
        if claims.exp == 0 {
            return Err(AccessJwtError::EmptyClaim("exp"));
        }
        if !aud_is_present_and_valid(&claims.aud) {
            return Err(AccessJwtError::MissingOrInvalidAud);
        }

        // Project convention: subject is a UUID
        if Self::parse_sub_uuid(&claims.sub).is_err() {
            return Err(AccessJwtError::InvalidSubUuid);
        }

        Ok(claims)
    }

    /// Verify + strict claim validation, then convert claims into an application-friendly type.
    ///
    /// This is the recommended entry-point for middleware/handlers.
    pub fn verify_verified(&self, token: &str) -> Result<VerifiedAccessToken, AccessJwtError> {
        let claims = self.verify_strict(token)?;

        let user_id =
            Self::parse_sub_uuid(&claims.sub).map_err(|_| AccessJwtError::InvalidSubUuid)?;

        Ok(VerifiedAccessToken {
            user_id,
            jti: claims.jti,
            scope: claims.scope,
            roles: claims.roles,
            cnf_jkt: claims.cnf.and_then(|c| c.jkt),
        })
    }

    // Helper: parse `sub` into UUID
    pub fn parse_sub_uuid(sub: &str) -> Result<Uuid, ()> {
        Uuid::parse_str(sub).map_err(|_| ())
    }

    pub fn dpop_policy(&self) -> DpopPolicy {
        self.dpop_policy.clone()
    }

    pub fn public_base_url(&self) -> Option<&str> {
        self.public_base_url.as_deref()
    }

    pub fn replay_store(&self) -> &dyn ReplayStore {
        self.replay_store.as_ref()
    }
}
