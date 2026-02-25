use std::net::SocketAddr;
use std::str::FromStr;
use std::{env, fmt};

use crate::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnv {
    Development,
    Production,
}

impl AppEnv {
    pub fn from_env() -> Self {
        match std::env::var("APP_ENV")
            .unwrap_or_else(|_| "development".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "production" | "prod" => Self::Production,
            _ => Self::Development,
        }
    }

    pub fn is_production(&self) -> bool {
        matches!(self, Self::Production)
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Missing(key) => write!(f, "missing configuration: {}", key),
            ConfigError::Invalid(key) => write!(f, "invalid configuration: {}", key),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Clone, Debug)]
pub struct Config {
    pub addr: SocketAddr,
    pub app_env: AppEnv,
    pub issuer: String,
    pub audience: String,
    // AS signs access tokens with this private key
    pub access_jwt_private_key_pem: String,
    // Token lifetimes (seconds)
    pub access_token_ttl_seconds: u64,
    pub refresh_token_ttl_seconds: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let port: u16 = std::env::var("AUTH_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4000);

        let addr: SocketAddr = SocketAddr::from_str(&format!("0.0.0.0:{}", port))
            .map_err(|_| ConfigError::Invalid("AUTH_PORT"))?;

        let app_env = AppEnv::from_env();

        let issuer = env::var("AUTH_ISSUER").map_err(|_| ConfigError::Missing("AUTH_ISSUER"))?;
        let audience =
            env::var("AUTH_AUDIENCE").map_err(|_| ConfigError::Missing("AUTH_AUDIENCE"))?;
        let access_jwt_private_key_pem = env::var("ACCESS_JWT_PRIVATE_KEY_PEM")
            .map_err(|_| ConfigError::Missing("ACCESS_JWT_PRIVATE_KEY_PEM"))?
            .replace("\\n", "\n");

        let access_token_ttl_seconds = env::var("ACCESS_TOKEN_TTL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(600); // 10 min
        let refresh_token_ttl_seconds = env::var("REFRESH_TOKEN_TTL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2_592_000); // 30 days

        Ok(Config {
            addr,
            app_env,
            issuer,
            audience,
            access_jwt_private_key_pem,
            access_token_ttl_seconds,
            refresh_token_ttl_seconds,
        })
    }
}

impl From<ConfigError> for AppError {
    fn from(_: ConfigError) -> Self {
        AppError::Internal
    }
}
