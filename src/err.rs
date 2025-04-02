use thiserror::Error;

#[derive(Error, Debug)]
pub enum SafeBoxError {
    /// Database error.
    #[error(transparent)]
    DB(#[from] sqlx::error::Error),

    /// Password hashing error.
    #[error(transparent)]
    Argon2(#[from] argon2::Error),

    #[error("user '{0}' does not exist")]
    UserNotExist(String),

    #[error("user '{0}' already exists")]
    UserAlreadyExist(String),

    #[error("invalid database: {0}")]
    InvalidData(String),
}
