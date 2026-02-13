/*
 * Responsibility
 * - tokio runtime 軌道
 * - app::run() の呼び出し（ロジックは置かない）
 */
use anyhow::Result;

mod api;
mod app;
mod config;
mod error;
mod middleware;
mod repos;
mod services;
mod state;

#[tokio::main]
async fn main() -> Result<()> {
    app::run().await
}
