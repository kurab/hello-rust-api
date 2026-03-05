//! Access Token Hash (ath) calculation for DPoP.
//!
//! `ath` is defined as base64url(SHA-256(ASCII(access_token))).
//!
//! This value is embedded in the DPoP proof JWT when the server policy
//! requires binding the proof to the access token.

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Compute `ath` for a given access token.
///
/// Returns the base64url (no padding) encoded SHA-256 digest of the access token bytes.
pub fn compute_ath(access_token: &str) -> String {
    // base64url without padding
    let digest = Sha256::digest(access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::compute_ath;

    #[test]
    fn ath_is_deterministic_and_url_safe() {
        let token = "header.payload.signature";
        let a = compute_ath(token);
        let b = compute_ath(token);
        assert_eq!(a, b);
        // URL-safe base64 without padding should not include '+' '/' '='
        assert!(!a.contains('+'));
        assert!(!a.contains('/'));
        assert!(!a.contains('='));
        assert!(!a.is_empty());
    }
}
