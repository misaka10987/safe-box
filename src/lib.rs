pub mod err;

use std::{
    collections::HashMap,
    ops::DerefMut,
    path::Path,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use async_mutex::Mutex as AsyncMutex;
use base64::{prelude::BASE64_STANDARD, Engine};
use sqlx::{query, sqlite::SqliteConnectOptions, Connection, Row, SqliteConnection};

pub use err::Error;
use tracing::{debug, info, trace};

fn gen_salt() -> [u8; 64] {
    let mut buf = [0u8; 64];
    getrandom::fill(&mut buf).unwrap();
    buf
}

struct SafeInst {
    conn: AsyncMutex<SqliteConnection>,
    argon2: argon2::Config<'static>,
    token: RwLock<HashMap<String, (String, SystemTime)>>,
}

/// Interface to the password database.
#[derive(Clone)]
pub struct Safe(Arc<SafeInst>);

/// Initialize the database.
const Q_INIT: &str = "CREATE TABLE IF NOT EXISTS main (user TEXT PRIMARY KEY, phc TEXT);";

impl Safe {
    /// Open an SQLite connection with specified database file and create a `SafeBox`.
    pub async fn new(p: impl AsRef<Path>) -> Result<Self, Error> {
        let opt = SqliteConnectOptions::default()
            .filename(&p)
            .create_if_missing(true);
        let mut conn = SqliteConnection::connect_with(&opt).await?;
        info!("connected to {:?}", p.as_ref());
        query(Q_INIT).execute(&mut conn).await?;
        trace!("password database initialized");
        Ok(Self(Arc::new(SafeInst {
            conn: AsyncMutex::new(conn),
            argon2: argon2::Config::default(),
            token: RwLock::new(HashMap::new()),
        })))
    }

    /// Issue a token to the speficied user.
    pub fn issue_token(&self, user: &str) -> String {
        let mut buf = [0u8; 64];
        getrandom::fill(&mut buf).unwrap();
        let token = BASE64_STANDARD.encode(buf);
        self.0
            .token
            .write()
            .unwrap()
            .insert(token.clone(), (user.to_owned(), SystemTime::now()));
        trace!("issued token '{}**' for '{user}'", &token[0..4]);
        return token;
    }

    /// Invalidate a token.
    /// # Example
    /// ```
    /// use simple_safe::Safe;
    ///
    /// let safe = Safe::new("password.db").await.unwrap();
    ///
    /// let token = safe.issue_token("alice");
    /// assert!(safe.verify_token(&token).unwrap() == "alice");
    ///
    /// safe.invalidate_token(&token);
    /// assert!(safe.verify_token(&token).is_none())
    /// ```
    pub fn invalidate_token(&self, token: &str) {
        self.0.token.write().unwrap().remove(token);
        trace!("invalidated token '{}**'", token);
    }

    /// Invalidate all tokens related to specified user.
    pub fn invalidate_user_token(&self, user: &str) {
        self.0.token.write().unwrap().retain(|_, (u, _)| u != user);
        trace!("invalidated user session '{user}'")
    }

    /// Make all tokens older than `duration` expire.
    pub fn expire_token(&self, duration: Duration) {
        let mut token = self.0.token.write().unwrap();
        let prev = token.len();
        token.retain(|_, (_, time)| {
            SystemTime::now()
                .duration_since(*time)
                .is_ok_and(|d| d < duration)
        });
        let diff = prev - token.len();
        trace!("expired {diff} tokens");
    }

    /// Count the current user number.
    pub async fn user_cnt(&self) -> Result<usize, Error> {
        let cnt: u64 = query("SELECT COUNT(*) FROM main")
            .fetch_one(self.0.conn.lock().await.deref_mut())
            .await?
            .get(0);
        Ok(cnt as usize)
    }

    /// Create new user entry with `user`name and `pass`word.
    pub async fn create(&self, user: &str, pass: &str) -> Result<(), Error> {
        let q = query("SELECT NULL FROM main WHERE user = ?").bind(user);
        let v = q.fetch_all(self.0.conn.lock().await.deref_mut()).await?;
        if v.len() > 0 {
            return Err(Error::UserAlreadyExist(user.to_owned()));
        }
        let hashed = argon2::hash_encoded(pass.as_bytes(), &gen_salt(), &self.0.argon2)?;
        let query = query("INSERT INTO main (user, phc) VALUES (?, ?)")
            .bind(user)
            .bind(hashed);
        query.execute(self.0.conn.lock().await.deref_mut()).await?;
        info!("created user '{user}'");
        Ok(())
    }

    /// Verify the provided `user`name and `pass`word.
    /// Return a new token if successful.
    pub async fn verify(&self, user: &str, pass: &str) -> Result<bool, Error> {
        let query = query("SELECT phc FROM main WHERE user = ?").bind(user);
        let mut conn = self.0.conn.lock().await;
        let v = query.fetch_all(conn.deref_mut()).await?;
        match v.len() {
            0 => return Err(Error::UserNotExist(user.to_owned())),
            2.. => return Err(Error::InvalidData(format!("duplicate user '{user}'"))),
            _ => (),
        };
        let p = v[0].try_get("phc")?;
        let res = argon2::verify_encoded(p, pass.as_bytes())?;
        if res {
            debug!("authorized '{user}' with password");
        }
        Ok(res)
    }

    /// Verify the provided `token`.
    /// Returns the user it belongs to if valid.
    pub fn verify_token(&self, token: &str) -> Option<String> {
        let map = self.0.token.read().unwrap();
        map.get(token).map(|(user, _)| user.clone())
    }

    /// Update a user's password to `new`.
    pub async fn update(&self, user: &str, new_pass: &str) -> Result<(), Error> {
        self.invalidate_user_token(user);
        let hashed = argon2::hash_encoded(new_pass.as_bytes(), &gen_salt(), &self.0.argon2)?;
        let query = query("UPDATE main SET phc = ? WHERE user = ?")
            .bind(hashed)
            .bind(user);
        query.execute(self.0.conn.lock().await.deref_mut()).await?;
        debug!("updated password for '{user}'");
        Ok(())
    }

    /// Delate a user.
    pub async fn delete(&self, user: &str) -> Result<(), Error> {
        let query = query("DELETE FROM main WHERE user = ?").bind(user);
        query.execute(self.0.conn.lock().await.deref_mut()).await?;
        info!("deleted user '{user}'");
        Ok(())
    }
}
