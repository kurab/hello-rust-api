use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::repos::error::{RepoError, RepoResult};

#[derive(Clone, Debug)]
pub struct AuthSessionRepo {
    pool: PgPool,
}

impl AuthSessionRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // Create a new auth session.
    //
    // Note: dpop_jkt is nullable for Step1/2
    pub async fn create(
        &self,
        user_id: Uuid,
        dpop_jkt: Option<String>,
    ) -> RepoResult<AuthSessionRow> {
        let row = sqlx::query_as!(
            AuthSessionRow,
            r#"
            INSERT INTO auth_sessions (user_id, dpop_jkt)
            VALUES ($1, $2)
            RETURNING
                id,
                user_id,
                dpop_jkt,
                created_at,
                last_used_at,
                revoked_at
            "#,
            user_id,
            dpop_jkt
        )
        .fetch_one(&self.pool)
        .await
        .map_err(RepoError::Db)?;

        Ok(row)
    }

    // Fetch an active (not revoked) session by id.
    pub async fn get_active_by_id(&self, id: Uuid) -> RepoResult<Option<AuthSessionRow>> {
        let row = sqlx::query_as!(
            AuthSessionRow,
            r#"
            SELECT
                id,
                user_id,
                dpop_jkt,
                created_at,
                last_used_at,
                revoked_at
            FROM auth_sessions
            WHERE id = $1 AND revoked_at IS NULL
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(RepoError::Db)?;

        Ok(row)
    }

    // Minimal lookup for refresh: returns (user_id, dpop_jkt) if session is active.
    pub async fn lookup_refresh_context(
        &self,
        session_id: Uuid,
    ) -> RepoResult<Option<AuthSessionRefreshContext>> {
        let row = sqlx::query_as!(
            AuthSessionRefreshContext,
            r#"
            SELECT
                user_id,
                dpop_jkt
            FROM auth_sessions
            WHERE id = $1 AND revoked_at IS NULL
            "#,
            session_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(RepoError::Db)?;

        Ok(row)
    }

    // Update last_used_at. Caller decides what now is.
    pub async fn touch_last_used(&self, id: Uuid, now: DateTime<Utc>) -> RepoResult<u64> {
        let res = sqlx::query!(
            r#"
            UPDATE auth_sessions
            SET last_used_at = $2
            WHERE id = $1 AND revoked_at IS NULL
            "#,
            id,
            now
        )
        .execute(&self.pool)
        .await
        .map_err(RepoError::Db)?;

        Ok(res.rows_affected())
    }

    // set/overwrite the DPoP binding (cnf.jkt) for a session.
    pub async fn set_dpop_jkt(&self, id: Uuid, dpop_jkt: String) -> RepoResult<u64> {
        let res = sqlx::query!(
            r#"
            UPDATE auth_sessions
            SET dpop_jkt = $2
            WHERE id = $1 AND revoked_at IS NULL
            "#,
            id,
            dpop_jkt
        )
        .execute(&self.pool)
        .await
        .map_err(RepoError::Db)?;

        Ok(res.rows_affected())
    }

    // Revoke a session.
    pub async fn revoke(&self, id: Uuid, revoked_at: DateTime<Utc>) -> RepoResult<u64> {
        let res = sqlx::query!(
            r#"
            UPDATE auth_sessions
            SET revoked_at = $2
            WHERE id = $1 AND revoked_at IS NULL
            "#,
            id,
            revoked_at
        )
        .execute(&self.pool)
        .await
        .map_err(RepoError::Db)?;

        Ok(res.rows_affected())
    }
}

#[derive(Clone, Debug)]
pub struct AuthSessionRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub dpop_jkt: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct AuthSessionRefreshContext {
    pub user_id: Uuid,
    pub dpop_jkt: Option<String>,
}
