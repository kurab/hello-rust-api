/*
 * Responsibility
 * - 環境変数や設定の読み込み (DATABASE_URL, CORS 許可、Auth 設定など)
 * - 設定値のバリデーション (不足なら起動失敗)
 */
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

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

pub struct Config {
    pub addr: SocketAddr,
    pub database_url: String,

    pub app_env: AppEnv,
    pub cors_allowed_origins: Vec<String>,

    pub sqids_min_length: usize,
    pub sqids_alphabet: String,

    pub auth_issuer: String,
    pub auth_audience: String,
    pub access_token_leeway_seconds: u64,

    pub access_jwt_public_key_pem: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3000);

        let addr: SocketAddr = SocketAddr::from_str(&format!("0.0.0.0:{}", port))
            .map_err(|_| ConfigError::Invalid("PORT"))?;

        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| ConfigError::Missing("DATABASE_URL"))?;

        let app_env = AppEnv::from_env();

        let cors_allowed_origins = std::env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();

        let sqids_min_length = std::env::var("SQIDS_MIN_LENGTH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10);

        let sqids_alphabet = std::env::var("SQIDS_ALPHABET").unwrap_or_else(|_| {
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string()
        });

        let auth_issuer =
            std::env::var("AUTH_ISSUER").map_err(|_| ConfigError::Missing("AUTH_ISSUER"))?;

        let auth_audience =
            std::env::var("AUTH_AUDIENCE").map_err(|_| ConfigError::Missing("AUTH_AUDIENCE"))?;

        let access_token_leeway_seconds = std::env::var("ACCESS_TOKEN_LEEWAY_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);

        let access_jwt_public_key_pem = std::env::var("ACCESS_JWT_PUBLIC_KEY_PEM")
            .map_err(|_| ConfigError::Missing("ACCESS_JWT_PUBLIC_KEY_PEM"))?
            .replace("\\n", "\n");

        Ok(Self {
            addr,
            database_url,
            app_env,
            cors_allowed_origins,
            sqids_min_length,
            sqids_alphabet,
            auth_issuer,
            auth_audience,
            access_token_leeway_seconds,
            access_jwt_public_key_pem,
        })
    }
}
