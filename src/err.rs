use thiserror::Error;

#[derive(Error, Debug)]
pub enum SafeBoxError {
    /// Internal SQL error.
    #[error(transparent)]
    SQL(#[from] sqlx::error::Error),
    /// Cryptography error with hashed passwords.
    #[error("{0}")]
    Crypto(crypto::password_hash::Error),

    #[error("user '{0}' does not exist")]
    UserNotExist(String),

    #[error("user '{0}' already exists")]
    UserAlreadyExist(String),

    #[error("invalid password '{bad_password}' for user 'username'")]
    BadPassword {
        username: String,
        bad_password: String,
    },

    #[error("invalid token '{0}'")]
    BadToken(String),

    #[error("invalid database: {0}")]
    InvalidData(String),
}

impl From<crypto::password_hash::Error> for SafeBoxError {
    fn from(value: crypto::password_hash::Error) -> Self {
        SafeBoxError::Crypto(value)
    }
}
