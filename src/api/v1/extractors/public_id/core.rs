/*
 * Responsibility
 * - Path の String を公開 ID 型として受け、複合して内部 ID 型へ変換する
 * - 失敗時は Api::bad_request/unauthorized などへ変換
 * - posts/bookmarks で共通利用
 * 主な責務
 *  - 公開ID → 内部ID への変換ロジック
 *  - sqids codec を使った decode
 *  - Axum の FromRequestParts 実装
 *  - HTTP レベルのエラー（400 など）への変換
 * 置くもの
 *  - PublicId<T> の定義（ジェネリック本体）
 *  - impl FromRequestParts<AppState> for PublicId<T>
 *  - decode の共通関数
 *  - 必要最低限の trait 実装（Clone, Copy など）
 * 置かないもの
 *  - Post / Bookmark / Comment といった具体リソース名
 *  - scaffold で増える型定義
 *  - 設定的な alias
 * 変更理由
 *  - codec の仕様が変わった
 *  - extractor の挙動を変えたい
 *  - エラー方針を変えたい
 */
use std::marker::PhantomData;

use axum::{
    extract::{FromRequestParts, Path},
    http::{StatusCode, request::Parts},
};

use crate::state::AppState;

#[derive(Clone, Copy)]
pub struct PublicId<T> {
    pub id: i64,
    _marker: PhantomData<T>,
}

impl<T> PublicId<T> {
    fn new(id: i64) -> Self {
        Self {
            id,
            _marker: PhantomData,
        }
    }
}

fn decode_or_bad_request(state: &AppState, public_id: &str) -> Result<i64, StatusCode> {
    state
        .id_codec
        .decode(public_id)
        .map_err(|_| StatusCode::BAD_REQUEST)
}

impl<T> FromRequestParts<AppState> for PublicId<T>
where
    T: Send + Sync, // 非同期・並行安全を型で保証 / Send: スレッド間で move して良い / Sync: 複数スレッドから参照して良い
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Path(public_id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let id = decode_or_bad_request(state, &public_id)?;
        Ok(Self::new(id))
    }
}

impl<T> std::fmt::Debug for PublicId<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // &mut は、この extractor が実装されている際は、request を独占的に加工するという宣言
        // 順序保証、二重読み取り・競合防止
        f.debug_struct("PublicId").field("id", &self.id).finish()
    }
}
