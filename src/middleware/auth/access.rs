//! access token（JWT+DPoP）検証 → AuthCtx を extensions に入れる
//!
//! Step0 (scaffold):
//! - まず middleware と extractor の配線を確認するため、検証は最小限にする。
//! - `Authorization: Bearer <uuid>` を受け取り、uuid を `AuthCtx.user_id` として extensions に格納する。
//!
//! 次のステップでここを置き換える：
//! - JWT 署名検証 + iss/aud/exp/nbf/jti/cnf
//! - DPoP proof 検証（htu/htm/iat/jti）と cnf.jwk との一致

use axum::{
    Router,
    body::Body,
    extract::{OriginalUri, State},
    http::{Request, header},
    middleware::{self, Next},
    response::Response,
};

use crate::api::v1::extractors::AuthCtx;
use crate::error::AppError;
use crate::services::auth::dpop::core as dpop_core;
use crate::state::AppState;

/// `/api/v1/*` に認証を掛けるための middleware を適用する。
///
/// 例：
/// ```ignore
/// let v1 = api::v1::routes::router(state.clone());
/// let v1 = middleware::auth::access::apply(v1, state.clone());
/// app = app.nest("/api/v1", v1);
/// ```
pub fn apply(router: Router<AppState>, state: AppState) -> Router<AppState> {
    // axum 0.8 の from_fn は State extractor を受け取れないため、`from_fn_with_state` で明示的に state を渡す
    router.layer(middleware::from_fn_with_state(state, access_middleware))
}

async fn access_middleware(
    State(state): State<AppState>,
    OriginalUri(original_uri): OriginalUri,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    // Step0: `Authorization: Bearer <uuid>` を受け取り、AuthCtx を入れるだけ。
    // 本来は JWT を decode/verify して sub を取り出す。
    // Step1: Authorization: Bearer <jwt> を検証し、sub を user_id として AuthCtx に入れる

    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let token = auth.strip_prefix("Bearer ").ok_or(AppError::Unauthorized)?;

    // dev 用の簡易フォーマット: Bearer <uuid>
    //let user_id = Uuid::parse_str(bearer).map_err(|_| AppError::Unauthorized)?;

    // JWT 署名検証 + iss/aud/exp/leeway などは AuthService 側で実施
    /*
    let claims = state
        .auth
        .verify(token)
        .map_err(|_| AppError::Unauthorized)?;
    */
    let claims = match state.auth.verify_verified(token) {
        Ok(claims) => claims,
        Err(err) => {
            tracing::warn!(
                error = ?err,
                "access token verification failed"
            );
            return Err(AppError::Unauthorized);
        }
    };

    let expected_jkt = claims.cnf_jkt.as_deref();
    let uri = &original_uri;

    let verified_dpop = match dpop_core::verify_proof(
        state.auth.dpop_policy(),
        req.headers(),
        req.method(),
        uri,
        Some(token),
        expected_jkt,
        state.auth.public_base_url(),
    ) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = ?err, "dpop verification failed");
            return Err(AppError::Unauthorized);
        }
    };

    if let Some(dpop) = verified_dpop {
        let key = format!("dpop:{}:{}", claims.user_id, dpop.jti);
        let ttl = state.auth.dpop_policy().replay_ttl_seconds;

        let first_time = state
            .auth
            .replay_store()
            .check_and_store(&key, ttl)
            .await
            .map_err(|err| {
                tracing::warn!(error = ?err, "replay backend failure");
                AppError::Unauthorized
            })?;

        if !first_time {
            tracing::warn!(key = %key, "dpop replay detected");
            return Err(AppError::Unauthorized);
        }
    }

    let auth_ctx = AuthCtx::new(claims.user_id);

    // middleware → extractor への受け渡し
    req.extensions_mut().insert(auth_ctx);

    Ok(next.run(req).await)
}
