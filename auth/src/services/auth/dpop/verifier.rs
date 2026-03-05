use std::collections::HashSet;

use axum::http::Uri;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use tracing::{debug, warn};

use super::ath::compute_ath;
use super::error::{DpopError, IatRangeReason::TooNew, IatRangeReason::TooOld};
use super::normalize::{build_expected_htu, normalize_htu};
use super::policy::DpopPolicy;
use super::thumbprint::jwk_thumbprint_from_jwk;

/// Result of a successful DPoP proof verification.
#[derive(Clone, Debug)]
pub struct VerifiedDpop {
    pub jti: String,
    pub iat: i64,
    pub htm: String,
    pub htu: String,
    pub nonce: Option<String>,
    // RFC7638 thumbprint of the proof JWK (cnf.jkt equivalent)
    pub jkt: String,
}

#[derive(Debug, Deserialize)]
struct DpopClaims {
    /// HTTP method (e.g., "GET")
    pub htm: String,
    /// HTTP target URI (absolute URI)
    pub htu: String,
    /// Issued-at (epoch seconds)
    pub iat: i64,
    /// Unique token identifier
    pub jti: String,

    /// Access token hash (base64url(SHA-256(access_token)))
    #[serde(default)]
    pub ath: Option<String>,

    /// Optional nonce (future/Step3)
    #[serde(default)]
    pub nonce: Option<String>,
}

/// Verifies a DPoP proof JWT.
///
/// This verifier:
/// - Validates the JWT signature using the public key embedded as `jwk` in the header.
/// - Enforces `htm`/`htu` match (with normalization).
/// - Enforces `iat` leeway and max-age.
/// - Optionally enforces `ath`.
/// - Optionally enforces sender-constrained binding by checking the proof's JWK thumbprint
///   against the expected `cnf.jkt` from the access token.
#[derive(Clone, Debug)]
pub struct DpopVerifier {
    policy: DpopPolicy,
    /// Public base URL of this service used for htu normalization (optional).
    public_base_url: Option<String>,
}

impl DpopVerifier {
    pub fn new(policy: DpopPolicy, public_base_url: Option<String>) -> Self {
        Self {
            policy,
            public_base_url,
        }
    }

    pub fn policy(&self) -> &DpopPolicy {
        &self.policy
    }

    /// Verify proof.
    ///
    /// - `method`: incoming HTTP method (e.g. "GET")
    /// - `url`: incoming full request URL (as seen by the server/router)
    /// - `access_token`: required if `policy.require_ath == true`
    /// - `expected_jkt`: the `cnf.jkt` from the access token (sender-constrained binding)
    pub fn verify_proof(
        &self,
        proof_jwt: &str,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        expected_jkt: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDpop, DpopError> {
        let (header, claims) = self.decode_and_verify_signature(proof_jwt)?;

        let jkt = jwk_thumbprint_from_jwk(header.jwk.as_ref().ok_or(DpopError::InvalidJwt)?)
            .map_err(|_| DpopError::InvalidJwt)?;
        // Sender-constrained (cnf.jkt) binding.
        if let Some(expected) = expected_jkt
            && jkt != expected
        {
            warn!(got = %jkt, expected = %expected, "DPoP jkt mismatch");
            return Err(DpopError::JktMismatch);
        }

        // htm
        let expected_htm = method.to_ascii_uppercase();
        if claims.htm.to_ascii_uppercase() != expected_htm {
            warn!(htm = %claims.htm, expected = %expected_htm, "DPoP htm mismatch");
            return Err(DpopError::HtmMismatch);
        }

        // htu (normalize both sides)
        // If this service is behind a proxy, `url` may be the internal URL.
        // When `public_base_url` is configured, we build the expected external htu
        // by combining the public base (scheme/authority) with the request path/query.
        let request_uri: Uri = url.parse().map_err(|_| DpopError::InvalidJwt)?;
        let expected_raw_htu = build_expected_htu(self.public_base_url.as_deref(), &request_uri)
            .ok_or(DpopError::InvalidJwt)?;

        let expected_htu = normalize_htu(&expected_raw_htu).ok_or(DpopError::InvalidJwt)?;
        let got_htu = normalize_htu(&claims.htu).ok_or(DpopError::InvalidJwt)?;

        debug!(
            htu = %claims.htu,
            expected_htu = %expected_raw_htu,
            htu_norm = %got_htu,
            expected_norm = %expected_htu,
            "DPoP htu check"
        );

        if got_htu != expected_htu {
            warn!(htu = %got_htu, expected = %expected_htu, "DPoP htu mismatch");
            return Err(DpopError::HtuMismatch);
        }

        // iat leeway + max age
        self.check_iat(now, claims.iat)?;

        // jti presence
        if claims.jti.trim().is_empty() {
            return Err(DpopError::InvalidJwt);
        }

        // ath
        if self.policy.require_ath {
            let at = access_token.ok_or(DpopError::AthMismatch)?;
            let expected_ath = compute_ath(at);
            let got_ath = claims.ath.as_deref().ok_or(DpopError::AthMismatch)?;
            if got_ath != expected_ath {
                warn!(got = %got_ath, expected = %expected_ath, "DPoP ath mismatch");
                return Err(DpopError::AthMismatch);
            }
        }

        Ok(VerifiedDpop {
            jti: claims.jti,
            iat: claims.iat,
            htm: expected_htm,
            htu: expected_htu,
            nonce: claims.nonce,
            jkt,
        })
    }

    fn check_iat(&self, now: DateTime<Utc>, iat: i64) -> Result<(), DpopError> {
        let iat_dt = DateTime::<Utc>::from_timestamp(iat, 0).ok_or(DpopError::InvalidJwt)?;

        // Future leeway
        let leeway = Duration::seconds(self.policy.iat_leeway_seconds);
        if iat_dt > now + leeway {
            return Err(DpopError::IatOutOfRange(TooNew));
        }

        // Too old
        let max_age = Duration::seconds(self.policy.max_age_seconds);
        if now - iat_dt > max_age {
            return Err(DpopError::IatOutOfRange(TooOld));
        }

        Ok(())
    }

    fn decode_and_verify_signature(
        &self,
        proof_jwt: &str,
    ) -> Result<(jsonwebtoken::Header, DpopClaims), DpopError> {
        // We want to avoid requiring `exp` for DPoP proofs.
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims = HashSet::new();

        // First decode header to obtain jwk
        let header = jsonwebtoken::decode_header(proof_jwt).map_err(|_| DpopError::InvalidJwt)?;
        let jwk = header.jwk.as_ref().ok_or(DpopError::InvalidJwt)?;

        let key = DecodingKey::from_jwk(jwk).map_err(|_| DpopError::InvalidJwt)?;
        let token = decode::<DpopClaims>(proof_jwt, &key, &validation)
            .map_err(|_| DpopError::InvalidJwt)?;

        Ok((header, token.claims))
    }
}
