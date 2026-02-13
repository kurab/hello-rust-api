use std::{future::Future, pin::Pin};

use crate::services::cache::CacheError;

/// Replay check result:
/// - `Ok(true)`: first time (stored)
/// - `Ok(false)`: replay detected (already exists)
/// - `Err(_)`: store failure (treat as fail-closed)
pub trait ReplayStore: Send + Sync {
    // Automatically check whether `key` was already seen and store it with TTL.
    //
    // Returns:
    // - Ok(true)  => first time (stored successfully)
    // - Ok(false) => replay detected (already exists)
    // - Err(_)    => backend failure (caller must treat as authentication failure)
    fn check_and_store<'a>(
        &'a self,
        key: &'a str,
        ttl_secs: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ReplayError>> + Send + 'a>>;
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("valkey error: {0}")]
    Valkey(#[from] redis::RedisError),

    #[error(transparent)]
    Cache(#[from] CacheError),
}
