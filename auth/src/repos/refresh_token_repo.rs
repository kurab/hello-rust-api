use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::repos::error::RepoError;

/// DB access for refresh token persistence.
///
/// Notes:
/// - We store only a hash of the refresh token (opaque token design).
/// - The schema is assumed to have at least these columns:
///   - refresh_tokens.id (uuid)
///   - refresh_tokens.session_id (uuid)
///   - refresh_tokens.token_hash (bytea)
///   - refresh_tokens.expires_at (timestamptz)
///   - refresh_tokens.issued_at (timestamptz)
///   - refresh_tokens.used_at (timestamptz, nullable) // for rotation/audit
///   - refresh_tokens.revoked_at (timestamptz, nullable)
///   - refresh_tokens.replaced_by (uuid, nullable) // for rotation step
#[derive(Clone, Debug)]
pub struct RefreshTokenRepo {
    pool: PgPool,
}

impl RefreshTokenRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a newly issued refresh token.
    pub async fn insert(
        &self,
        session_id: Uuid,
        token_hash: Vec<u8>,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, RepoError> {
        let id = sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO refresh_tokens (session_id, token_hash, expires_at)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
        )
        .bind(session_id)
        .bind(token_hash)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    /// Fetch a refresh token row by hash, only if it is not revoked and not expired.
    pub async fn find_active_by_hash(
        &self,
        token_hash: Vec<u8>,
        now: DateTime<Utc>,
    ) -> Result<Option<RefreshTokenRow>, RepoError> {
        let row = sqlx::query_as::<_, RefreshTokenRow>(
            r#"
            SELECT
                id,
                session_id,
                token_hash,
                issued_at,
                expires_at,
                used_at,
                revoked_at,
                replaced_by
            FROM refresh_tokens
            WHERE token_hash = $1
                AND revoked_at IS NULL
                AND expires_at > $2
            LIMIT 1
            "#,
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Revoke a refresh token.
    ///
    /// For rotation step later, replaced_by can be filled.
    pub async fn revoke(
        &self,
        id: Uuid,
        replaced_by: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<u64, RepoError> {
        let done = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = $2,
                replaced_by = $3
            WHERE id = $1
                AND revoked_at IS NULL
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(replaced_by)
        .execute(&self.pool)
        .await?;

        Ok(done.rows_affected())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshTokenRow {
    pub id: Uuid,
    pub session_id: Uuid,
    pub token_hash: Vec<u8>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub replaced_by: Option<Uuid>,
}
