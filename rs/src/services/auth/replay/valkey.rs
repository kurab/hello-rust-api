use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use crate::services::{
    auth::replay::store::{ReplayError, ReplayStore},
    cache::{CacheClient, ValkeyClient},
};
/// Valkey-backed replay store (Redis protocol)
///
/// Fail-closed policy is implemented by returning `Err` on any backend error;
/// callers should treat that as authentication failure.
#[derive(Clone)]
pub struct ValkeyReplayStore<C: CacheClient> {
    cache: Arc<C>,
    // Optional key prefix to avoid collisions across environments
    prefix: String,
}

impl ValkeyReplayStore<ValkeyClient> {
    pub async fn new(redis_url: &str) -> Result<Self, ReplayError> {
        Self::new_with_prefix(redis_url, "dpop:replay").await
    }

    pub async fn new_with_prefix(
        redis_url: &str,
        prefix: impl Into<String>,
    ) -> Result<Self, ReplayError> {
        // Build the shared Valkey-backed cache client and use it via the CacheClient trait.
        // Any backend failure is surfaced as ReplayError (fail-closed).
        let client = ValkeyClient::new(redis_url).await?;

        Ok(Self {
            cache: Arc::new(client),
            prefix: prefix.into(),
        })
    }
}

impl<C: CacheClient> ValkeyReplayStore<C> {
    pub fn new_with_cache(cache: Arc<C>, prefix: impl Into<String>) -> Self {
        Self {
            cache,
            prefix: prefix.into(),
        }
    }

    pub fn key(&self, raw: &str) -> String {
        format!("{}:{}", self.prefix, raw)
    }
}

impl<C: CacheClient> ReplayStore for ValkeyReplayStore<C> {
    fn check_and_store<'a>(
        &'a self,
        key: &'a str,
        ttl_secs: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ReplayError>> + Send + 'a>> {
        Box::pin(async move {
            let full_key = self.key(key);

            // SET <key> "1" NX EX <ttl>
            // - returns true when key is newly set
            // - returns false when key already exists
            let res = self
                .cache
                .set_if_absent_with_ttl(&full_key, "1", Duration::from_secs(ttl_secs))
                .await?;

            Ok(res)
        })
    }
}
