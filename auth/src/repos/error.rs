use thiserror::Error;

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("db error")]
    Db(#[from] sqlx::Error),
}

pub type RepoResult<T> = Result<T, RepoError>;
