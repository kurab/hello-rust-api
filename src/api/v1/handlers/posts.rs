/*
 * Responsibility
 * - /posts 系 CRUD handler
 * - Path の :path_id は公開 ID → extractor で復号化して内部 ID に変換して受け取る
 * - 認可が必要ならここで AuthContext を参照して service/repo に渡す
 */
use axum::{Json, extract::State, http::StatusCode};
use uuid::Uuid;

use crate::{
    api::v1::{
        dto::posts::{CreatePostRequest, PostResponse, UpdatePostRequest},
        extractors::public_id::PublicPostId,
    },
    repos::post_repo,
    state::AppState,
};

fn row_to_response(state: &AppState, row: post_repo::PostRow) -> Result<PostResponse, StatusCode> {
    let public_id = state
        .id_codec
        .encode(row.post_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(PostResponse {
        id: public_id,
        title: row.title,
        content: row.content,
        author_id: row.author_id.to_string(),
    })
}

pub async fn list_posts(
    State(state): State<AppState>,
) -> Result<Json<Vec<PostResponse>>, StatusCode> {
    let rows = post_repo::list(&state.db, 50, 0)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut res = Vec::with_capacity(rows.len()); // あらかじめ容量が分かっているので確保
    // rows.into_iter().map(|row| {
    //     row_to_response(&state, row)?
    // }).collect()
    // これだと、Closure が Result を返していない・？を使えない
    for row in rows {
        res.push(row_to_response(&state, row)?);
    }

    Ok(Json(res))
}

pub async fn create_post(
    State(state): State<AppState>,
    Json(req): Json<CreatePostRequest>,
) -> Result<(StatusCode, Json<PostResponse>), StatusCode> {
    req.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let author_id = Uuid::parse_str(&req.author_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    let row = post_repo::create(&state.db, &req.title, &req.content, author_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let res = row_to_response(&state, row)?;
    Ok((StatusCode::CREATED, Json(res)))
}

pub async fn get_post(
    State(state): State<AppState>,
    post_id: PublicPostId,
) -> Result<Json<PostResponse>, StatusCode> {
    let row = post_repo::get(&state.db, post_id.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(row_to_response(&state, row)?))
}

pub async fn update_post(
    State(state): State<AppState>,
    post_id: PublicPostId,
    Json(req): Json<UpdatePostRequest>,
) -> Result<Json<PostResponse>, StatusCode> {
    req.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let row = post_repo::update(
        &state.db,
        post_id.id,
        req.title.as_deref(),
        req.content.as_deref(),
    )
    .await
    .map_err(|e| {
        eprintln!("post_repo::update failed: {e:?}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(row_to_response(&state, row)?))
}

pub async fn delete_post(
    State(state): State<AppState>,
    post_id: PublicPostId,
) -> Result<StatusCode, StatusCode> {
    let deleted = post_repo::delete(&state.db, post_id.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
