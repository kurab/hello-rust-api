/*
 * Responsibility
 * - Router に紐づける共有コンテキスト (AppState)
 *   - ex: db: PgPool, id_codec: IdCodec, auth: AuthConfig など
 * - Clone 前提で持つ (内部は Arc/Clone cheap)
 */
#[derive(Clone, Debug)]
pub struct AppState {
    pub db: sqlx::PgPool,
}

impl AppState {
    pub fn new(db: sqlx::PgPool) -> Self {
        Self { db }
    }
}
