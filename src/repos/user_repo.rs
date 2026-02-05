/*
 * Responsibility
 * - users テーブル向け SQLx 操作
 * - PgPool を受け取り CRUD を提供
 * - DB エラーは RepoError/ApiError に変換しやすい形で返す
 */
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::repos::error::RepoError;

#[derive(Debug, FromRow)]
pub struct UserRow {
    #[sqlx(rename = "userId")]
    pub id: Uuid,
    #[sqlx(rename = "userName")]
    pub user_name: String,
    #[sqlx(rename = "imageUrl")]
    pub image_url: Option<String>,
}

pub async fn list(db: &PgPool) -> Result<Vec<UserRow>, RepoError> {
    let rows = sqlx::query_as::<_, UserRow>(
        r#"
        SELECT "userId", "userName", "imageUrl"
        FROM users
        ORDER BY "createdAt" DESC
        "#,
    )
    .fetch_all(db)
    .await?;
    /*
     * in case you need to give meaning to errors
     * .await.map_err(RepoError::from_sqlx)?;
     */

    Ok(rows)
}

pub async fn create(
    db: &PgPool,
    user_name: &str,
    image_url: Option<&str>,
) -> Result<UserRow, RepoError> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        INSERT INTO users ("userName", "imageUrl")
        VALUES ($1, $2)
        RETURNING "userId", "userName", "imageUrl"
        "#,
    )
    .bind(user_name)
    .bind(image_url)
    .fetch_one(db)
    .await?;
    /*
     * in case you need to give meaning to errors
     * .await.map_err(RepoError::from_sqlx)?;
     */

    Ok(row)
}

pub async fn get(db: &PgPool, user_id: Uuid) -> Result<Option<UserRow>, RepoError> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        SELECT "userId", "userName", "imageUrl"
        FROM users
        WHERE "userId" = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(db)
    .await?;
    /*
     * in case you need to give meaning to errors
     * .await.map_err(RepoError::from_sqlx)?;
     */

    Ok(row)
}

pub async fn update(
    db: &PgPool,
    user_id: Uuid,
    user_name: Option<&str>,
    image_url: Option<Option<&str>>,
) -> Result<Option<UserRow>, RepoError> {
    // image_url: Some(Some(v)) -> set to v
    // image_url: Some(None)    -> set to NULL
    // image_url: None          -> do not update
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        UPDATE users
        SET
            "userName" = COALESCE($2, "userName"),
            "imageUrl" = CASE
                WHEN $3 = false THEN "imageUrl"
                ELSE $4
            END
        WHERE "userId" = $1
        RETURNING "userId", "userName", "imageUrl"
        "#,
    )
    .bind(user_id)
    .bind(user_name)
    .bind(image_url.is_some()) // $3: flag to set image_url
    .bind(image_url.flatten()) // $4: new image_url value
    .fetch_optional(db)
    .await?;
    /*
     * in case you need to give meaning to errors
     * .await.map_err(RepoError::from_sqlx)?;
     */

    Ok(row)
}

pub async fn delete(db: &PgPool, user_id: Uuid) -> Result<bool, RepoError> {
    let result = sqlx::query(
        r#"
        DELETE FROM users
        WHERE "userId" = $1
        "#,
    )
    .bind(user_id)
    .execute(db)
    .await?;
    /*
     * in case you need to give meaning to errors
     * .await.map_err(RepoError::from_sqlx)?;
     */

    Ok(result.rows_affected() > 0)
}
