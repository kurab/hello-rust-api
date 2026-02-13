/*
 * Responsibility
 * - posts CRUD
 * - authorId の FK (CASCADE) 前提で削除挙動を意識
 */
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::repos::error::RepoError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PostRow {
    #[sqlx(rename = "postId")]
    pub post_id: i64,

    pub title: String,
    pub content: String,

    #[sqlx(rename = "authorId")]
    pub author_id: Uuid,
    /*
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,

    #[sqlx(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,*/
}

pub async fn list(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<PostRow>, RepoError> {
    let rows = sqlx::query_as::<_, PostRow>(
        r#"
        SELECT
            "postId", title, content, "authorId", "createdAt", "updatedAt"
        FROM posts
        ORDER BY "postId" DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    /*
     * in case you need to give meaning to errors
     * .await.map_err(RepoError::from_sqlx)?;
     */

    Ok(rows)
}

pub async fn create(
    pool: &PgPool,
    title: &str,
    content: &str,
    author_id: Uuid,
) -> Result<PostRow, RepoError> {
    let row = sqlx::query_as::<_, PostRow>(
        r#"
        INSERT INTO posts (title, content, "authorId")
        VALUES ($1, $2, $3)
        RETURNING
            "postId", title, content, "authorId", "createdAt", "updatedAt"
        "#,
    )
    .bind(title)
    .bind(content)
    .bind(author_id)
    .fetch_one(pool)
    .await?;
    /*
     * in case you need to give meaning to errors
     * .await.map_err(RepoError::from_sqlx)?;
     */

    Ok(row)
}

pub async fn get(pool: &PgPool, post_id: i64) -> Result<Option<PostRow>, RepoError> {
    let row = sqlx::query_as::<_, PostRow>(
        r#"
        SELECT
            "postId", title, content, "authorId", "createdAt", "updatedAt"
        FROM posts
        WHERE "postId" = $1
        "#,
    )
    .bind(post_id)
    .fetch_optional(pool)
    .await?;
    /*
     * in case you need to give meaning to errors
     * .await.map_err(RepoError::from_sqlx)?;
     */

    Ok(row)
}

pub async fn update(
    pool: &PgPool,
    post_id: i64,
    title: Option<&str>,
    content: Option<&str>,
) -> Result<Option<PostRow>, RepoError> {
    let row = sqlx::query_as::<_, PostRow>(
        r#"
        UPDATE posts
        SET
            title = COALESCE($2, title),
            content = COALESCE($3, content)
        WHERE "postId" = $1
        RETURNING
            "postId", title, content, "authorId", "createdAt", "updatedAt"
        "#,
    )
    .bind(post_id)
    .bind(title)
    .bind(content)
    .fetch_optional(pool)
    .await?;
    /*
     * in case you need to give meaning to errors
     * .await.map_err(RepoError::from_sqlx)?;
     */

    Ok(row)
}

pub async fn delete(pool: &PgPool, post_id: i64) -> Result<bool, RepoError> {
    let result = sqlx::query(
        r#"
        DELETE FROM posts
        WHERE "postId" = $1
        "#,
    )
    .bind(post_id)
    .execute(pool)
    .await?;
    /*
     * in case you need to give meaning to errors
     * .await.map_err(RepoError::from_sqlx)?;
     */

    Ok(result.rows_affected() > 0)
}
