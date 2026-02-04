/*
 * Responsibility
 * - Router に紐づける共有コンテキスト (AppState)
 *   - ex: db: PgPool, id_codec: IdCodec, auth: AuthConfig など
 * - Clone 前提で持つ (内部は Arc/Clone cheap)
 */
#[derive(Clone, Debug, Default)]
pub struct AppState;

impl AppState {
    pub fn new() -> Self {
        Self
    }
}
