/*
 * Responsibility
 * - v1 の後悔ポイント (routes() の re-export など)
 */
pub mod dto;
pub mod handlers;
mod routes;

pub use routes::routes;
