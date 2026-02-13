//! DPoP proof validation (RFC 9449) - core logic.
//!
//! This module is intentionally "core-only": it does not know about Axum extractors
//! or storage (replay cache). Middleware can call `verify_proof` and then (later)
//! do replay protection and nonce flows.

use axum::http::{HeaderMap, Method, Uri, header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, jwk::Jwk};
use serde::Deserialize;
use tracing::warn;

/// Minimal policy knobs needed by the core verifier.
///
/// Note: We keep this struct here (instead of depending on `Config`) so the core
/// logic stays testable and resusable.
#[derive(Debug, Clone, Copy)]
pub struct DpopPolicy {
    // If false, `verify_proof` becomes a no-op.
    pub required: bool,
    // Allowed iat drift (clock skew), seconds.
    pub iat_leeway_seconds: i64,
    // Maximum acceptable age of the proof (now - iat), seconds.
    pub max_age_seconds: i64,
    // If true, we require `ath` (proof must be bound to the access token).
    pub require_ath: bool,
    // If true, we require `nonce` claim.
    pub require_nonce: bool,
    pub replay_ttl_seconds: u64,
}

/// Verified DPoP proof information useful for downstream checks.
#[derive(Debug, Clone)]
pub struct VerifiedDpop {
    pub jti: String,
    pub iat: i64,
    pub htm: String,
    pub htu: String,
    pub nonce: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DpopError {
    #[error("missing DPoP header")]
    MissingProof,
    #[error("invalid DPoP proof jwt")]
    InvalidJwt,
    #[error("missing jwk in DPoP header")]
    MissingJwk,
    #[error("unsupported DPoP alg: {0:?}")]
    UnsupportedAlg(Algorithm),
    #[error("invalid DPoP typ")]
    InvalidTyp,
    #[error("missing required claim: {0}")]
    MissingClaim(&'static str),
    #[error("htm mismatch")]
    MethodMismatch,
    #[error("htu mismatch")]
    UriMismatch,
    #[error("iat out of range")]
    InvalidIat,
    #[error("ath mismatch")]
    AthMismatch,
    #[error("nonce required")]
    NonceRequired,
    #[error("cnf.jkt mismatch")]
    JktMismatch,
    #[error("unsupported jwk for DPoP")]
    UnsupportedJwk,
}

#[derive(Debug, Deserialize)]
struct DpopClaims {
    // HTTP method
    htm: Option<String>,
    // HTTP URI
    htu: Option<String>,
    // issued-at (seconds since epoch)
    iat: Option<i64>,
    // unique identifier
    jti: Option<String>,
    // Access token hash (base64url(SHA-256(access_token)))
    ath: Option<String>,
    // Server-provided nonce (optional policy)
    nonce: Option<String>,
}

/// Verify DPoP proff signature + core claims.
///
/// - `headers`: request headers (we read the `DPoP` header).
/// - `method`, `uri`: the request target (we validate `htm` / `htu`)
/// - `access_token`: the bearer access token (required if `policy.required_auth`).
///
/// Replay protection (jti storage) is intentionally NOT implemented here.
pub fn verify_proof(
    policy: DpopPolicy,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    access_token: Option<&str>,
    expected_jkt: Option<&str>,
    public_base_url: Option<&str>,
) -> Result<Option<VerifiedDpop>, DpopError> {
    if !policy.required {
        return Ok(None);
    }

    let proof = headers
        .get("DPoP")
        .ok_or(DpopError::MissingProof)?
        .to_str()
        .map_err(|e| {
            warn!(error = ?e, "invalid DPoP header encoding");
            DpopError::InvalidJwt
        })?;

    // 1) Decode header to extract JWK / typ / alg.
    let header = jsonwebtoken::decode_header(proof).map_err(|e| {
        warn!(error = ?e, "invalid DPoP header");
        DpopError::InvalidJwt
    })?;

    // typ SHOULD be "dpop+jwt"
    // Some libs set it in `typ`, some in `cty`; we enforce `typ` when present.
    if let Some(typ) = header.typ.as_deref() {
        if !typ.eq_ignore_ascii_case("dpop+jwt") {
            return Err(DpopError::InvalidTyp);
        }
    } else {
        // If typ is missing, treat as invalid to keep policy strict.
        return Err(DpopError::InvalidTyp);
    }

    // We keep this strict for now: DPoP proof must be EdDSA.
    // (You can widen this later if you want to accept ES256 as well.)
    if header.alg != Algorithm::EdDSA {
        return Err(DpopError::UnsupportedAlg(header.alg));
    }

    let jwk: Jwk = header.jwk.ok_or(DpopError::MissingJwk)?;
    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
        warn!(error = ?e, "invalid DPoP jwk");
        DpopError::InvalidJwt
    })?;

    // sender-constrained: cnf.jkt vs DPoP jwk thumbprint
    if let Some(expected) = expected_jkt {
        let actual = compute_jwk_thumbprint(&jwk)?;
        if actual != expected {
            return Err(DpopError::JktMismatch);
        }
    }

    // 2) Verify signature and parse claims.
    let mut validation = Validation::new(Algorithm::EdDSA);
    // DPoP proof is not an access token , so we don't validate iss/ and here.
    // We do validate exp = none (DPop proof uses iat/max-age instead).
    validation.validate_exp = false;
    validation.required_spec_claims.remove("exp");

    let token_data = decode::<DpopClaims>(proof, &decoding_key, &validation).map_err(|e| {
        warn!(error = ?e, "invalid DPoP proof signature");
        DpopError::InvalidJwt
    })?;

    // 3) Required claims.
    let htm = token_data
        .claims
        .htm
        .ok_or(DpopError::MissingClaim("htm"))?;
    let htu = token_data
        .claims
        .htu
        .ok_or(DpopError::MissingClaim("htu"))?;
    let iat = token_data
        .claims
        .iat
        .ok_or(DpopError::MissingClaim("iat"))?;
    let jti = token_data
        .claims
        .jti
        .ok_or(DpopError::MissingClaim("jti"))?;

    // 4) htm check
    if !htm.eq_ignore_ascii_case(method.as_str()) {
        return Err(DpopError::MethodMismatch);
    }

    // 5) htu check
    // RFC 9449 expects an absolute URI. In practice you often sit behind a proxy.
    // We build an absolute URI from headers when possible.
    let expected_htu = build_expected_htu(headers, uri, public_base_url);

    /*
    warn!(
        htu = %htu,
        expected_htu = %expected_htu,
        htu_norm = %normalize_htu(&htu),
        expected_norm = %normalize_htu(&expected_htu),
        "DPoP htu check"
    );*/

    if normalize_htu(&htu) != normalize_htu(&expected_htu) {
        return Err(DpopError::UriMismatch);
    }

    // 6) iat window check
    let now = chrono::Utc::now().timestamp();
    let leeway = policy.iat_leeway_seconds;

    // iat must not be too far in the future
    if iat > now + leeway {
        return Err(DpopError::InvalidIat);
    }

    // iat must not be too old
    if now - iat > policy.max_age_seconds + leeway {
        return Err(DpopError::InvalidIat);
    }

    // 7) ath check (bind proof to access token)
    if policy.require_ath {
        let access = access_token.ok_or(DpopError::MissingClaim("ath"))?;
        let ath = token_data
            .claims
            .ath
            .ok_or(DpopError::MissingClaim("ath"))?;
        let expected = compute_ath(access);
        if ath != expected {
            return Err(DpopError::AthMismatch);
        }
    }

    // 8) nonce check (optional policy)
    if policy.require_nonce && token_data.claims.nonce.is_none() {
        return Err(DpopError::NonceRequired);
    }

    Ok(Some(VerifiedDpop {
        jti,
        iat,
        htm,
        htu,
        nonce: token_data.claims.nonce,
    }))
}

fn build_expected_htu(headers: &HeaderMap, uri: &Uri, public_base_url: Option<&str>) -> String {
    if let Some(base) = public_base_url {
        if let Ok(url) = build_htu_from_base(base, uri) {
            return url;
        }
        // If PUBLIC_BASE_URL is misconfigured, fall back to forwarded headers.
        // (core stays resilient; caller can log config errors elesewhere if desired).
    }
    build_htu_from_forwarded(headers, uri)
}

fn build_htu_from_base(base: &str, uri: &Uri) -> Result<String, url::ParseError> {
    // Build absolute URL deterministically from configured public base URL.
    // `base` should be like: https://api.example.com
    let mut url = url::Url::parse(base)?;

    // Overwrite path/query from the incoming request target.
    url.set_path(uri.path());
    url.set_query(uri.query());

    Ok(url.to_string())
}

fn build_htu_from_forwarded(headers: &HeaderMap, uri: &Uri) -> String {
    // Prefer proxy headers when present.
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");

    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    format!("{}://{}{}", scheme, host, uri)
}

fn normalize_htu(htu: &str) -> String {
    // Normalization used only for equality comparison.
    // - lower scheme/host
    // - drop default ports
    // - keep path and query
    if let Ok(url) = url::Url::parse(htu) {
        let scheme = url.scheme().to_ascii_lowercase();
        let host = url.host_str().unwrap_or("").to_ascii_lowercase();
        let port = url
            .port()
            .filter(|p| !((scheme == "http" && *p == 80) || (scheme == "https" && *p == 443)));
        let mut out = String::new();
        out.push_str(&scheme);
        out.push_str("://");
        out.push_str(&host);
        if let Some(port) = port {
            out.push(':');
            out.push_str(&port.to_string());
        }
        out.push_str(url.path());
        if let Some(q) = url.query() {
            out.push('?');
            out.push_str(q);
        }
        out
    } else {
        // Fallback (should not happen for valid proofs)
        htu.to_string()
    }
}

fn compute_ath(access_token: &str) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn compute_jwk_thumbprint(jwk: &Jwk) -> Result<String, DpopError> {
    use base64::Engine as _;
    use jsonwebtoken::jwk::AlgorithmParameters;
    use sha2::{Digest, Sha256};

    // OKP / Ed25519 only
    let x = match &jwk.algorithm {
        AlgorithmParameters::OctetKeyPair(params) => {
            // `EllipticCurve` does not implement Display/ToString, so match explicitly.
            match params.curve {
                jsonwebtoken::jwk::EllipticCurve::Ed25519 => params.x.clone(),
                _ => return Err(DpopError::UnsupportedJwk),
            }
        }
        _ => return Err(DpopError::UnsupportedJwk),
    };

    // RFC7638 canonical JSON (lexicographic member order): crv, kty, x
    let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}", x);

    let digest = Sha256::digest(canonical.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}
