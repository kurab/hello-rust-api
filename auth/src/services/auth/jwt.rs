use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use tracing::{error, warn};

use crate::error::AppError;

#[derive(Clone)]
pub struct JwtIssuer {
    issuer: String,
    audience: String,
    ttl_seconds: u64,
    encoding_key: EncodingKey,
}

impl JwtIssuer {
    /// `Private_key_pem` must be an Ed25519 private key in PKCS#8 PEM format.
    pub fn new(
        private_key_pem: &str,
        issuer: String,
        audience: String,
        ttl_seconds: u64,
    ) -> Result<Self, AppError> {
        let encoding_key = EncodingKey::from_ed_pem(private_key_pem.as_bytes())
            .map_err(|e| {
                warn!(error = %e, "failed to parse access JWT private key PEM (expected Ed25519 PKCS#8 PEM)");
                AppError::Internal
            })?;

        Ok(Self {
            issuer,
            audience,
            ttl_seconds,
            encoding_key,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String, AppError> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("JWT".to_string());
        jsonwebtoken::encode(&header, claims, &self.encoding_key).map_err(|e| {
            error!(error = %e, "failed to sign JWT");
            AppError::Internal
        })
    }
}
