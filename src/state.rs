/*
 * Responsibility
 * - Router に紐づける共有コンテキスト (AppState)
 *   - ex: db: PgPool, id_codec: IdCodec, auth: AuthConfig など
 * - Clone 前提で持つ (内部は Arc/Clone cheap)
 */
use crate::services::id_codec::IdCodec;

#[derive(Clone, Debug)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub id_codec: IdCodec,
}

impl AppState {
    pub fn new(db: sqlx::PgPool, id_codec: IdCodec) -> Self {
        Self { db, id_codec }
    }
}
