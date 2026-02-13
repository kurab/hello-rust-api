/**
 * Responsibility
 * - repo が上位に伝える意味の定義
 */
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("db error")]
    Db(#[from] sqlx::Error),
    //#[error("conflict")]
    //Conflict,
}
/* activate in case you need to give meaning to errors
impl RepoError {
    pub fn from_sqlx(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(dbe) = &e
            && dbe.code().as_deref() == Some("23505")
        {
            return RepoError::Conflict;
        }
        RepoError::Db(e)
    }
}*/
