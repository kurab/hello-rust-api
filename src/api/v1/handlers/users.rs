/*
 * Responsibility
 * - /users 系 CRUD handler
 * - Path/Json を extractor で受け、DTO validation → repo/service 呼び出し
 * - users は UUID をそのまま扱う (復号化なし)
 */
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    api::v1::dto::users::{CreateUserRequest, UpdateUserRequest, UserResponse},
    repos::user_repo,
    state::AppState,
};

pub async fn list_users(
    State(state): State<AppState>,
) -> Result<Json<Vec<UserResponse>>, StatusCode> {
    let rows = user_repo::list(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let res = rows
        .into_iter()
        .map(|u| UserResponse {
            id: u.id,
            user_name: u.user_name,
            image_url: u.image_url,
        })
        .collect();

    Ok(Json(res))
}

pub async fn create_user(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), StatusCode> {
    req.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let row = user_repo::create(&state.db, &req.user_name, req.image_url.as_deref())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id: row.id,
            user_name: row.user_name,
            image_url: row.image_url,
        }),
    ))
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserResponse>, StatusCode> {
    let row = user_repo::get(&state.db, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(UserResponse {
        id: row.id,
        user_name: row.user_name,
        image_url: row.image_url,
    }))
}

pub async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    req.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    // image_url tri-state:
    // - None: do not update
    // - Some(None): set NULL
    // - Some(Some(v)): set v
    let image_url: Option<Option<&str>> = req.image_url.as_ref().map(|inner| inner.as_deref());

    let row = user_repo::update(&state.db, user_id, req.user_name.as_deref(), image_url)
        .await
        .map_err(|e| {
            eprintln!("user_repo::update failed: {e:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(UserResponse {
        id: row.id,
        user_name: row.user_name,
        image_url: row.image_url,
    }))
}

pub async fn delete_user(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let deleted = user_repo::delete(&state.db, user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
