/*
 * Responsibility
 * - 環境変数や設定の読み込み (DATABASE_URL, CORS 許可、Auth 設定など)
 * - 設定値のバリデーション (不足なら起動失敗)
 */
use anyhow::Result;
use std::net::SocketAddr;

pub struct Config {
    pub addr: SocketAddr,
    pub database_url: String,
    pub sqids_min_length: usize,
    pub sqids_alphabet: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3000);

        let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL is not set"))?;

        let sqids_min_length = std::env::var("SQIDS_MIN_LENGTH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10);

        let sqids_alphabet = std::env::var("SQIDS_ALPHABET").unwrap_or_else(|_| {
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string()
        });

        Ok(Self {
            addr,
            database_url,
            sqids_min_length,
            sqids_alphabet,
        })
    }
}
