use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::Parser;
use ed25519_dalek::{pkcs8::DecodePrivateKey, Signer, SigningKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Generate a DPoP proof JWT (JWS compact serialization) signed with an Ed25519 private key.
///
/// This tool is intentionally minimal and self-contained:
/// - Builds the DPoP header (typ=dpop+jwt, alg=EdDSA, jwk={OKP/Ed25519/x})
/// - Builds the DPoP claims (htu, htm, iat, jti, ath optional, nonce optional)
/// - Signs "base64url(header).base64url(payload)" with Ed25519
/// - Outputs:
///   - DPoP proof token
///   - JWK thumbprint (jkt) suitable for access token cnf.jkt
///   - Access token hash (ath) used in the proof (if access token provided)
#[derive(Parser, Debug)]
#[command(name = "dpop-gen", version, about)]
struct Args {
    /// HTTP method (HTM) e.g. GET/POST/PUT
    #[arg(long, default_value = "GET")]
    method: String,

    /// Full request URL used as HTU (e.g. http://localhost:3001/api/v1/users)
    #[arg(long)]
    url: String,

    /// Path to the client's Ed25519 private key in PEM (PKCS#8)
    #[arg(long, value_name = "FILE")]
    dpop_private_pem: PathBuf,

    /// Access token string. If provided, ath will be included in the proof.
    #[arg(long)]
    access_token: Option<String>,

    /// Optional nonce (if your server requires it)
    #[arg(long)]
    nonce: Option<String>,

    /// Override iat (unix seconds). Default: now.
    #[arg(long)]
    iat: Option<i64>,

    /// Override jti. Default: random UUID v4.
    #[arg(long)]
    jti: Option<String>,

    /// Print only the DPoP token (no extra lines)
    #[arg(long, default_value_t = false)]
    quiet: bool,
}

fn b64url_json(value: &serde_json::Value) -> String {
    let s = serde_json::to_string(value).expect("serialize json");
    URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn b64url_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_b64url(input: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(input);
    b64url_bytes(&h.finalize())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs() as i64
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Load signing key (PKCS#8 PEM).
    let pem = fs::read_to_string(&args.dpop_private_pem)?;
    let signing_key = SigningKey::from_pkcs8_pem(&pem)?;
    let verifying_key = signing_key.verifying_key();

    // JWK: OKP/Ed25519 with x = base64url(raw public key bytes).
    let x_b64 = b64url_bytes(verifying_key.as_bytes());

    // RFC7638 thumbprint canonical JSON for OKP keys uses only {crv,kty,x}.
    // Must be lexicographically ordered keys and no whitespace.
    let jwk_thumbprint_canonical = format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
        x_b64
    );
    let jkt = sha256_b64url(jwk_thumbprint_canonical.as_bytes());

    // ath = base64url(SHA-256(access_token)) if access token provided.
    let ath = args
        .access_token
        .as_deref()
        .map(|t| sha256_b64url(t.as_bytes()));

    let iat = args.iat.unwrap_or_else(now_unix);
    let jti = args.jti.unwrap_or_else(|| Uuid::new_v4().to_string());

    // Header
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_b64,
        }
    });

    // Claims
    let mut claims = serde_json::Map::new();
    claims.insert(
        "htu".to_string(),
        serde_json::Value::String(args.url.clone()),
    );
    claims.insert(
        "htm".to_string(),
        serde_json::Value::String(args.method.to_uppercase()),
    );
    claims.insert("iat".to_string(), serde_json::Value::Number(iat.into()));
    claims.insert("jti".to_string(), serde_json::Value::String(jti.clone()));

    if let Some(ath) = ath.clone() {
        claims.insert("ath".to_string(), serde_json::Value::String(ath));
    }
    if let Some(nonce) = args.nonce.clone() {
        claims.insert("nonce".to_string(), serde_json::Value::String(nonce));
    }

    let payload = serde_json::Value::Object(claims);

    let encoded_header = b64url_json(&header);
    let encoded_payload = b64url_json(&payload);
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);

    let sig = signing_key.sign(signing_input.as_bytes());
    let encoded_sig = b64url_bytes(sig.to_bytes().as_slice());

    let dpop = format!("{}.{}", signing_input, encoded_sig);

    if args.quiet {
        println!("{}", dpop);
        return Ok(());
    }

    println!("DPoP: {}", dpop);
    println!("jkt (cnf.jkt): {}", jkt);
    println!("iat: {}", iat);
    println!("jti: {}", jti);
    if let Some(ath) = ath {
        println!("ath: {}", ath);
    } else {
        println!("ath: (none)");
    }

    Ok(())
}
