/*
 * Responsibility
 * - Path の String を公開 ID 型として受け、複合して内部 ID 型へ変換する
 * - 失敗時は Api::bad_request/unauthorized などへ変換
 * - posts/bookmarks で共通利用
 */
