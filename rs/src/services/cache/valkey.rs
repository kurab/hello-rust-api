use async_trait::async_trait;
use std::time::Duration;

use crate::services::cache::client::{CacheClient, CacheError, CacheResult};

/// Valkey/Redis-backend cache client.
///
/// This is intentianally small: we only implement the operations needed for
/// DPoP replay protection. (SET NX + EX)
#[derive(Clone, Debug)]
pub struct ValkeyClient {
    manager: redis::aio::ConnectionManager,
}

impl ValkeyClient {
    // Create a Valkey client from a URL like `redis://localhost:6379`
    pub async fn new(url: &str) -> Result<Self, CacheError> {
        let client =
            redis::Client::open(url).map_err(|e| CacheError::BackendConnection(e.to_string()))?;

        let manager = client
            .get_connection_manager()
            .await
            .map_err(|e| CacheError::BackendConnection(e.to_string()))?;

        Ok(Self { manager })
    }
}

#[async_trait]
impl CacheClient for ValkeyClient {
    fn backend_name(&self) -> &'static str {
        "valkey"
    }

    async fn get_string(&self, key: &str) -> CacheResult<Option<String>> {
        // Use a clone of the connection manager
        let mut conn = self.manager.clone();

        let resp: Option<String> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::BackendCommand(e.to_string()))?;

        Ok(resp)
    }

    async fn set_if_absent_with_ttl(
        &self,
        key: &str,
        value: &str,
        ttl: Duration,
    ) -> CacheResult<bool> {
        // Redis/Valkey: `SET key value NX EX <seconds>`
        // returns:
        // - `OK` if set
        // - Nil if not set
        let mut conn = self.manager.clone();

        // Ex expects integer seconds. We clamp to at least 1 sec.
        let ttl_seconds: u64 = ttl.as_secs().max(1);

        let resp: Option<String> = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("NX")
            .arg("EX")
            .arg(ttl_seconds)
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::BackendCommand(e.to_string()))?;

        Ok(resp.is_some())
    }

    async fn del(&self, key: &str) -> CacheResult<u64> {
        let mut conn = self.manager.clone();

        // DEL returns number of keys removed (0 or 1 for a single key).
        let n: u64 = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(|e| CacheError::BackendCommand(e.to_string()))?;

        Ok(n)
    }
}
