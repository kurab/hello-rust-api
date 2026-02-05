/*
 * Responsibility
 * - アプリ共通の ApiError 定義
 * - IntoResponse 実装 (HTTP status / JSON error body)
 * - sqlx::Error / validation error / auth error を統一的に変換
 */
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

use crate::repos::error::RepoError;
use crate::services::id_codec::IdCodecError;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{code}: {message}")]
    BadRequest { code: &'static str, message: String },
    #[error("not found: {resource}")]
    NotFound { resource: &'static str },
    //#[error("{code}: {message}")]
    //Conflict { code: &'static str, message: String },
    //#[error("unauthorized")]
    //Unauthorized,
    //#[error("forbidden")]
    //Forbidden,
    #[error("internal server error")]
    Internal,
}

impl AppError {
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::BadRequest {
            code,
            message: message.into(),
        }
    }

    pub fn not_found(resource: &'static str) -> Self {
        Self::NotFound { resource }
    }

    /*
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::Conflict {
            code,
            message: message.into(),
        }
    }*/
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AppError::BadRequest { code, message } => (StatusCode::BAD_REQUEST, code, message),
            AppError::NotFound { resource } => (
                StatusCode::NOT_FOUND,
                "not_found",
                format!("{resource} not found."),
            ),
            //AppError::Conflict { code, message } => (StatusCode::CONFLICT, code, message),
            /*
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "unauthorized".into(),
            ),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN", "forbidden".into()),*/
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERVER_ERROR",
                "internal server error".into(),
            ),
        };

        let body = ErrorResponse {
            error: ErrorBody { code, message },
        };

        (status, Json(body)).into_response()
    }
}

impl From<RepoError> for AppError {
    fn from(e: RepoError) -> Self {
        match e {
            //RepoError::Conflict => AppError::conflict("CONFLICT", "conflict"),
            RepoError::Db(_) => AppError::Internal,
        }
    }
}

impl From<IdCodecError> for AppError {
    fn from(e: IdCodecError) -> Self {
        match e {
            // Client supplied a malformed public id (e.g. /posts/{id})
            IdCodecError::DecodeInvalidFormat | IdCodecError::DecodeOutOfRange => {
                AppError::bad_request("INVALID_PUBLIC_ID", "invalid id")
            }

            // These indicate server-side config / programming errors
            /*
            IdCodecError::InvalidMinLength { .. }
            | IdCodecError::Sqids(_)
            | IdCodecError::NegativeId { .. } => AppError::Internal,*/
            _ => AppError::Internal,
        }
    }
}
