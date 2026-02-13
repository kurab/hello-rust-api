/*!
 * Authentication context extractor
 *
 * Responsibility:
 * - 認証済みリクエストのコンテキスト（AuthCtx）を handler に提供する
 * - HTTP / axum 依存は core に閉じ込め、型定義は types に分離する
 *
 * Public API:
 * - AuthCtx
 * - AuthCtxExtractor
 */

mod core;
mod types;

pub use core::AuthCtxExtractor;
pub use types::AuthCtx;
