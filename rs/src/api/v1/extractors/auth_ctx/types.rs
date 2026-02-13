/*
 * Responsibility
 * - Handler から見える「認証済みコンテキスト」の型
 * - middleware が検証して request extensions に格納し、handler はこの型だけを受け取る
 *
 * Notes
 * - OAuth2/JWT の検証ロジックや DPoP 検証は middleware/services 側の責務
 * - ここは「型（契約）」として固定化し、Scaffold で増える領域から切り離す
 */

use uuid::Uuid;

/// 認証済みのリクエストに付与されるコンテキスト
///
/// - `user_id` は内部ユーザーID（ここでは UUID を採用）
/// - `scopes` / `roles` は coarse-grained な権限情報（BOLA は policy 層で別途チェック）
/// - `jti` は監査/相関用（denylist 等は必要になった時点で追加）
/// - `dpop_jkt` は sender-constrained (DPoP) の鍵指紋（ログ相関用。必須ではない）
#[derive(Debug, Clone)]
pub struct AuthCtx {
    pub user_id: Uuid,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub jti: Option<String>,
    pub dpop_jkt: Option<String>,
}

impl AuthCtx {
    pub fn new(user_id: Uuid) -> Self {
        Self {
            user_id,
            scopes: Vec::new(),
            roles: Vec::new(),
            jti: None,
            dpop_jkt: None,
        }
    }
}
