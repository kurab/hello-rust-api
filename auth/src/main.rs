mod api;
mod app;
mod config;
mod error;
mod services;
mod state;

use crate::error::AppError;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    app::run().await
}
