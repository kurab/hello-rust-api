//! Cache client interface used by higher-level services (auth replay, rate limits, etc.).
use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// Result type for cache operations.
pub type CacheResult<T> = Result<T, CacheError>;

/// Cache-layer errors (transport/command/serialization).
///
/// Not:
/// - We keep this independent from `AppError` so callers can decide how to fail
/// (fail-closed for auth replay, fail-open for metrics, etc.).
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("cache connection error: {0}")]
    BackendConnection(String),
    #[error("cache command error: {0}")]
    BackendCommand(String),
    #[error("cache value error: {0}")]
    InvalidValue(String),
}

/// A minimal cache interface.
///
/// This is intentionally small and string-based:
/// - Auth replay only needs `SET NX` + TTL and occasionally `GET`/`DEL`.
/// - Other features can add method later, but keep the surface area small.
///
/// Implementations musb be cheap to clone (typically `Arc<...>` inside)
#[async_trait]
pub trait CacheClient: Clone + Send + Sync + 'static {
    // Returns the cache backend name (for logging/metrics).
    fn backend_name(&self) -> &'static str;

    // Get UTF-8 string value.
    async fn get_string(&self, key: &str) -> CacheResult<Option<String>>;

    // Set value if the key does not exist, with TTL.
    //
    // Returns:
    // - `Ok(true)`  if the key was set (not seen before)
    // - `Ok(false)` if the key already exists
    async fn set_if_absent_with_ttl(
        &self,
        key: &str,
        value: &str,
        ttl: Duration,
    ) -> CacheResult<bool>;

    // Delete a key. Returns number of deleted keys.
    async fn del(&self, key: &str) -> CacheResult<u64>;
}

/// Convenience helper to build a TTL from seconds.
pub fn ttl_seconds(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}
