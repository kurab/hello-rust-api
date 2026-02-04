/*
 * Responsibility
 * - Bearer トークンの検証 (ヘッダ抽出 → 検証 → 拒否)
 * - 成功時に、認証済み主体 (Claims/UserContext) を request extensions に載せる設計も可
 * - 認可 (Authorization) は原則 handler/service 側で使う (必要なら)
 */
