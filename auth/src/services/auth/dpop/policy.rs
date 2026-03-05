//! DPoP verification policy.
//!
//! Step2では verifier が直接フラグ/数値を保持しても良いが、
//! Step3（rotation / nonce / replay など）で増える前提の設定値は
//! ここに集約しておく。

#[derive(Clone, Debug)]
pub struct DpopPolicy {
    /// Require `ath` claim in DPoP proof.
    pub require_ath: bool,

    /// Allowed clock skew for `iat` (seconds).
    pub iat_leeway_seconds: i64,

    /// Maximum allowed age of DPoP proof (seconds).
    pub max_age_seconds: i64,

    /// Step3: require nonce (not used yet).
    pub require_nonce: bool,
}

impl DpopPolicy {
    pub fn new(
        require_ath: bool,
        iat_leeway_seconds: i64,
        max_age_seconds: i64,
        require_nonce: bool,
    ) -> Self {
        Self {
            require_ath,
            iat_leeway_seconds,
            max_age_seconds,
            require_nonce,
        }
    }
}

impl Default for DpopPolicy {
    fn default() -> Self {
        Self {
            require_ath: false,
            iat_leeway_seconds: 60,
            max_age_seconds: 300,
            require_nonce: false,
        }
    }
}
