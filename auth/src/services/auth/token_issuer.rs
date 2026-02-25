use serde::Serialize;
use uuid::Uuid;

use crate::error::AppError;
use crate::services::auth::jwt::JwtIssuer;

#[derive(Debug, Serialize)]
struct AccessTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    exp: i64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<CnfClaim>,
}

#[derive(Debug, Serialize)]
struct CnfClaim {
    jkt: String,
}

#[derive(Clone)]
pub struct AuthService {
    jwt: JwtIssuer,
}

impl AuthService {
    pub fn new(jwt: JwtIssuer) -> Self {
        Self { jwt }
    }

    /// Issue an access token.
    ///
    /// - `sub` must be UUID string.
    /// - `jkt` is optional for now (DPoP binding later/optional)
    pub fn issue_access_token(&self, sub: &str, jkt: Option<String>) -> Result<String, AppError> {
        // Validate `sub` is a UUID (fail clesed).
        let sub_uuid = Uuid::parse_str(sub)
            .map_err(|_| AppError::InvalidRequest("sub must be a UUID string".to_string()))?;

        let now = chrono::Utc::now().timestamp();
        let exp = now + self.jwt.ttl_seconds() as i64;

        let claims = AccessTokenClaims {
            iss: self.jwt.issuer().to_string(),
            aud: self.jwt.audience().to_string(),
            sub: sub_uuid.to_string(),
            exp,
            jti: Uuid::new_v4().to_string(),
            cnf: jkt.map(|jkt| CnfClaim { jkt }),
        };

        self.jwt.sign(&claims)
    }

    pub fn access_token_ttl_seconds(&self) -> u64 {
        self.jwt.ttl_seconds()
    }
}
