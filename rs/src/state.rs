/*
 * Responsibility
 * - Router に紐づける共有コンテキスト (AppState)
 *   - ex: db: PgPool, id_codec: IdCodec, auth: AuthService など
 * - Clone 前提で持つ (内部は Arc/Clone cheap)
 */
use std::sync::Arc;

use crate::services::{auth::AuthService, id_codec::IdCodec};

#[derive(Clone, Debug)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub id_codec: IdCodec,
    pub auth: Arc<AuthService>,
}

impl AppState {
    pub fn new(db: sqlx::PgPool, id_codec: IdCodec, auth: Arc<AuthService>) -> Self {
        Self { db, id_codec, auth }
    }
}
