use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::services::auth::dpop::error::DpopError;

/// Compute an RFC 7638 JWK thumbprint (JKT) for the DPoP public key.
///
/// For DPoP we currently support the common OKP/Ed25519 JWK form:
///
/// ```json
/// {"kty":"OKP","crv":"Ed25519","x":"..."}
/// ```
///
/// Returns the base64url (no padding) SHA-256 digest of the canonical JWK JSON.
pub fn jwk_thumbprint_okp_ed25519(x_b64url: &str) -> Result<String, DpopError> {
    // Validate `x` as base64url (no padding) and ensure it represents an Ed25519 public key.
    // This makes invalid JWKs fail fast with `InvalidJwk`, which is easier to debug than a
    // later `JktMismatch`.
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x_b64url)
        .map_err(|_| DpopError::InvalidJwk)?;

    // Ed25519 public keys are 32 bytes.
    if x_bytes.len() != 32 {
        return Err(DpopError::InvalidJwk);
    }

    // Canonicalize `x` to a normalized base64url(no-pad) string.
    let x_norm = URL_SAFE_NO_PAD.encode(x_bytes);

    // RFC 7638: the JWK thumbprint is based on a UTF-8 representation of a JSON object
    // with a fixed, required member set and lexicographically sorted member names.
    // For OKP keys: {"crv":...,"kty":...,"x":...}
    // NOTE: We build the canonical JSON string manually to guarantee ordering and
    // absence of whitespace differences.
    let canonical = format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
        x_norm
    );

    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

/// Compute a JWK thumbprint (jkt) from a jsonwebtoken `Jwk`.
///
/// This is used for both:
/// - DPoP proof header `jwk`
/// - access token claim `cnf.jkt`
pub fn jwk_thumbprint_from_jwk(jwk: &jsonwebtoken::jwk::Jwk) -> Result<String, DpopError> {
    // We only support OKP/Ed25519 for now.
    let params = match &jwk.algorithm {
        // jsonwebtoken uses `AlgorithmParameters` under the `algorithm` field.
        jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(params) => params,
        _ => {
            return Err(DpopError::UnsupportedKey);
        }
    };

    // Basic structural validation.
    if params.x.trim().is_empty() {
        return Err(DpopError::InvalidJwk);
    }

    // Curve must be Ed25519.
    // jsonwebtoken's `EllipticCurve` doesn't implement Display/ToString, so match.
    match params.curve {
        jsonwebtoken::jwk::EllipticCurve::Ed25519 => {}
        _ => {
            return Err(DpopError::UnsupportedKey);
        }
    }

    jwk_thumbprint_okp_ed25519(&params.x)
}

/// Compute a JWK thumbprint (jkt) from a DPoP proof JWT header.
///
/// The DPoP JWT header is expected to contain an embedded `jwk`.
pub fn jwk_thumbprint_from_dpop_header(header: &jsonwebtoken::Header) -> Result<String, DpopError> {
    let jwk = header.jwk.as_ref().ok_or(DpopError::MissingHeader("jwk"))?;

    jwk_thumbprint_from_jwk(jwk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_okp_ed25519_is_stable() {
        // This is not a known vector; we just assert determinism and base64url-no-pad shape.
        let x = "DwZqn2CEr7HKyDniHEGRdBEoa_93t5XYIc9D8zeqMZQ";
        let a = jwk_thumbprint_okp_ed25519(x).unwrap();
        let b = jwk_thumbprint_okp_ed25519(x).unwrap();
        assert_eq!(a, b);
        assert!(!a.contains('='));
    }
}
