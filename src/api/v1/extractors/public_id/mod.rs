/**
 * Responsibility
 *  - core と types を束ねる
 *  - 外部（handlers 等）に公開する型・機能を制御する
 */
mod core;
mod types;

pub use types::*;
