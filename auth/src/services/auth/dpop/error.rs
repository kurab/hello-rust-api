use thiserror::Error;

#[derive(Debug)]
pub enum IatRangeReason {
    TooNew,
    TooOld,
}

#[derive(Debug, Error)]
pub enum DpopError {
    #[error("invalid DPoP proof JWT")]
    InvalidJwt,

    #[error("missing required claim: {0}")]
    MissingClaim(&'static str),

    #[error("missing required header: {0}")]
    MissingHeader(&'static str),

    #[error("htm mismatch")]
    HtmMismatch,

    #[error("htu mismatch")]
    HtuMismatch,

    #[error("iat is out of range: {0:?}")]
    IatOutOfRange(IatRangeReason),

    #[error("ath mismatch")]
    AthMismatch,

    #[error("cnf.jkt and DPoP JWK thumbprint mismatch")]
    JktMismatch,

    #[error("unsupported JWK key type or curve")]
    UnsupportedKey,

    #[error("invalid JWK structure")]
    InvalidJwk,
}

// Keep conversions minimal and conservative.
// The verifier can still log the original error, but the public surface stays stable.
impl From<jsonwebtoken::errors::Error> for DpopError {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        DpopError::InvalidJwt
    }
}
