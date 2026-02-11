use serde::Deserialize;

/// DPoP proof JWT header (RFC 9449)
#[derive(Debug, Deserialize)]
pub struct DPoPHeader {
    pub typ: String,            // must be "dpop+jwt"
    pub alg: String,            // e.g., "ES256 / EdDSA"
    pub jwk: serde_json::Value, // embedded public key (JWK)
}

/// DPoP proof JWT claims
#[derive(Debug, Deserialize)]
pub struct DPopClaims {
    pub htm: String,           // HTTP method
    pub htu: String,           // HTTP URI (absolute)
    pub iat: i64,              // issued at (unix timestamp)
    pub jti: String,           // unique proof ID (replay detection)
    pub ath: Option<String>,   // access token hash (required if configured)
    pub nonce: Option<String>, // optional nonce
}

/// Result of successful DPoP verification
#[derive(Debug, Clone)]
pub struct VerifiedDpop {
    pub jti: String,
    pub public_jwk: serde_json::Value,
}
